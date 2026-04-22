# Partial Degradation for Middle-End Routing

## Problem

Before this change, conditional ME admission behaved as a global binary switch for new sessions:

- if every configured DC had at least one live ME writer, new sessions used Middle-End;
- if even one configured DC lost writer coverage, the whole admission state moved toward global fallback.

This was safe, but too coarse. A single degraded DC could force unrelated healthy DCs onto direct routing.

## What changed

Telemt now separates two questions:

1. Is the ME pool usable at all for at least some DCs?
2. Is the ME pool usable for the specific DC requested by this session?

This introduces partial degradation for new sessions:

- if all covered DCs are ready, Telemt behaves as before and routes new sessions via Middle-End;
- if only part of the covered DC set is ready, Telemt keeps Middle-End globally enabled for new sessions;
- each new session then checks readiness for its own target DC;
- if the target DC has live ME coverage, the session uses Middle-End;
- if the target DC does not have live ME coverage, only that session falls back to Direct-DC.

## Architectural intent

The change is intentionally narrow:

- it does not replace the existing global `RouteRuntimeController`;
- it does not introduce per-session route subscriptions or a new cutover state machine;
- it only improves route selection for new sessions when ME health is asymmetric across DCs.

This keeps the current relay and cutover model intact while removing a major all-or-nothing failure mode.

## Runtime semantics

### Admission layer

The ME admission gate now distinguishes:

- full readiness: every covered configured DC has at least one live writer;
- partial readiness: at least one covered configured DC has at least one live writer;
- no readiness: no covered configured DC has live writer coverage.

When partial readiness is present, the admission gate remains open and the global route mode stays `Middle`.

### Session routing layer

When a new authenticated session is about to use Middle-End, Telemt additionally checks whether ME is ready for the session target DC.

- ready for target DC: session uses ME;
- not ready for target DC: session falls back to Direct-DC;
- all other sessions are unaffected.

## Why this is useful

This improves real operating behavior in hostile networks:

- healthy DCs continue benefiting from ME even while one DC is degraded;
- localized writer loss no longer causes unnecessary global degradation;
- recovery is smoother because Telemt does not have to swing the entire proxy between all-ME and all-direct as often.

## Invariants preserved

This change preserves existing core behavior:

- only new sessions use the refined routing decision;
- active relay sessions still follow the existing global cutover semantics;
- no MTProto or KDF routing contracts were changed;
- no new blocking work was added to the relay path.

## Limits

This is not a full per-family or per-session routing subsystem.

It should be understood as targeted hardening:

- readiness is still built on top of the existing global route runtime;
- session fallback is per target DC, not a full independent route domain;
- existing sessions are not migrated between ME and direct modes.

## Validation ideas

Useful validation scenarios:

1. Configure ME endpoints for multiple DCs.
2. Make one DC lose all live ME writers while another DC remains healthy.
3. Verify that admission stays open instead of forcing immediate global direct routing.
4. Verify that sessions for the healthy DC still use ME.
5. Verify that sessions for the degraded DC fall back to Direct-DC.

This behavior is also covered by targeted pool-status tests for:

- partial readiness with incomplete DC coverage;
- readiness checks scoped to the requested target DC.

## Admission coverage hardening

During live validation of this feature, one additional failure mode was found.

In an IPv4-only deployment, a single-endpoint outage could temporarily drive the
family runtime state into suppression. The original admission coverage snapshot
used the drain-coverage family gate, so temporary suppression could make the
configured family set appear empty even while healthy writers for other DCs were
still alive.

In practice this produced a bad sequence:

1. partial degradation activated correctly for the affected DC;
2. the admission snapshot briefly collapsed to `covered_dcs=0 ready_dcs=0`;
3. the proxy incorrectly switched new sessions to the global direct fallback.

The fix keeps partial-degradation admission coverage based on configured ME
families rather than the temporary suppression gate used by drain coverage.
This preserves the intended semantics:

- a single degraded DC does not erase admission coverage for unrelated healthy DCs;
- partial degradation stays active instead of collapsing into a false global
  not-ready state;
- full recovery returns admission to `covered_dcs == ready_dcs` without forcing
  an unnecessary global cutover.

The transition log was also tightened so `ME partial degradation cleared` is
emitted only for an actual recovery to full covered readiness, not for an empty
coverage snapshot.

## Live validation procedure

The feature was validated on a real IPv4-only deployment using a controlled
single-endpoint fault injection against DC3 ME routing.

### Baseline

Start Telemt normally and confirm:

- `Conditional-admission gate: open / ME pool READY`
- full ME connectivity for all configured DCs
- `telemt_me_no_writer_failfast_total = 0`
- `telemt_me_hybrid_timeout_total = 0`

### Fault injection

Block only the ME endpoint for one DC, leaving Direct-DC routing intact:

```bash
sudo iptables -I DOCKER-USER 1 \
  -s 172.21.0.2 \
  -d 149.154.175.100 \
  -p tcp --dport 8888 \
  -j DROP
```

This intentionally breaks only the ME path for that DC. Direct connectivity on
port `443` remains available.

### Expected degraded-state behavior

With the fix applied, the expected logs are:

- `ME target DC became unavailable for session routing`
- `ME partial degradation activated covered_dcs=12 ready_dcs=11`
- repeated single-endpoint outage reconnect attempts for the affected DC

The admission metrics should also reflect the degraded state:

- `telemt_me_admission_configured_dcs = 12`
- `telemt_me_admission_ready_dcs < 12`
- `telemt_me_partial_degradation_active = 1`

What should not happen anymore:

- `covered_dcs=0 ready_dcs=0`
- `ME pool not-ready; routing new sessions via Direct-DC (fast mode)`
- global controlled route cutover for unrelated middle sessions

### Recovery

Remove the firewall rule:

```bash
sudo iptables -D DOCKER-USER \
  -s 172.21.0.2 \
  -d 149.154.175.100 \
  -p tcp --dport 8888 \
  -j DROP
```

Expected recovery logs:

- `Single-endpoint outage reconnect succeeded`
- `ME target DC recovered for session routing`
- `ME partial degradation cleared covered_dcs=12 ready_dcs=12`
- `ME writer floor restored for DC`

The admission metrics should return to the healthy baseline:

- `telemt_me_admission_configured_dcs = 12`
- `telemt_me_admission_ready_dcs = 12`
- `telemt_me_partial_degradation_active = 0`

### Observed result

After the admission hardening fix:

- partial degradation activated correctly for the affected DC;
- healthy DCs stayed on Middle-End routing;
- the admission layer no longer collapsed to a false `0/0` state;
- recovery returned the pool to full readiness without a global fallback event.

This confirms the branch now behaves as intended for the original partial
degradation objective: one degraded DC no longer forces an unnecessary
all-or-nothing collapse of ME admission for new sessions.

## Complete test case

The following end-to-end case was executed successfully on the live target.

### 1. Healthy baseline

Observed before fault injection:

- log: `Conditional-admission gate: open / ME pool READY`
- metrics:
  - `telemt_me_admission_configured_dcs 12`
  - `telemt_me_admission_ready_dcs 12`
  - `telemt_me_partial_degradation_active 0`

This confirms the admission layer starts from full coverage.

### 2. Single-endpoint DC3 outage

The ME endpoint `149.154.175.100:8888` was blocked with `iptables`.

Observed during the fault window:

- log: `ME target DC became unavailable for session routing dc=3`
- log: `ME partial degradation activated covered_dcs=12 ready_dcs=11`
- log: repeated `Single-endpoint outage reconnect scheduled` events for `dc=3` and `dc=-3`
- no global `ME pool not-ready` fallback
- no global cutover of unrelated middle sessions

Observed metrics during the degraded state:

- `telemt_me_admission_configured_dcs 12`
- `telemt_me_admission_ready_dcs 10`
- `telemt_me_partial_degradation_active 1`
- `telemt_me_no_writer_failfast_total 0`
- `telemt_me_hybrid_timeout_total 0`

The `ready_dcs` value dropped below the first transition log because both `dc=3`
and `dc=-3` later entered the outage state. This is expected and confirms that
the metrics expose the actual depth of the degradation instead of only a binary
state.

### 3. Recovery after unblocking

After removing the firewall rule, recovery completed without a global fallback.

Observed recovery logs:

- `Single-endpoint outage reconnect succeeded dc=-3`
- `ME target DC recovered for session routing dc=-3`
- `Single-endpoint outage reconnect succeeded dc=3`
- `ME partial degradation cleared covered_dcs=12 ready_dcs=12`
- `ME writer floor restored for DC dc=-3`
- `ME writer floor restored for DC dc=3`

Observed recovery metrics:

- `telemt_me_admission_configured_dcs 12`
- `telemt_me_admission_ready_dcs 12`
- `telemt_me_partial_degradation_active 0`

### Final conclusion

This live test demonstrates the intended behavior end to end:

- a single degraded DC no longer collapses global ME admission;
- healthy DCs remain on Middle-End routing;
- the degraded DC stays in localized retry and recovery handling;
- admission metrics now expose both the transition and the recovery in a
  directly observable form.
