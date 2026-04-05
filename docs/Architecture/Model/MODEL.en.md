# Telemt Runtime Model

## Scope
This document defines runtime concepts used by the Middle-End (ME) transport pipeline and the orchestration logic around it.

It focuses on:
- `ME Pool / Reader / Writer / Refill / Registry`
- `Adaptive Floor`
- `Trio-State`
- `Generation Lifecycle`

## Core Entities

### ME Pool
`ME Pool` is the runtime orchestrator for all Middle-End writers.

Responsibilities:
- Holds writer inventory by DC/family/endpoint.
- Maintains routing primitives and writer selection policy.
- Tracks generation state (`active`, `warm`, `draining` context).
- Applies runtime policies (floor mode, refill, reconnect, reinit, fallback behavior).
- Exposes readiness gates used by admission logic (for conditional accept/cast behavior).

Non-goals:
- It does not own client protocol decoding.
- It does not own per-client business policy (quotas/limits).

### ME Writer
`ME Writer` is a long-lived ME RPC tunnel bound to one concrete ME endpoint (`ip:port`), with:
- Outbound command channel (send path).
- Associated reader loop (inbound path).
- Health/degraded flags.
- Contour/state and generation metadata.

A writer is the actual data plane carrier for client sessions once bound.

### ME Reader
`ME Reader` is the inbound parser/dispatcher for one writer:
- Reads/decrypts ME RPC frames.
- Validates sequence/checksum.
- Routes payloads to client-connection channels via `Registry`.
- Emits close/ack/data events and updates telemetry.

Design intent:
- Reader must stay non-blocking as much as possible.
- Backpressure on a single client route must not stall the whole writer stream.

### Refill
`Refill` is the recovery mechanism that restores writer coverage when capacity drops:
- Per-endpoint restore (same endpoint first).
- Per-DC restore to satisfy required floor.
- Optional outage-mode/shadow behavior for fragile single-endpoint DCs.

Refill works asynchronously and should not block hot routing paths.

### Registry
`Registry` is the routing index between ME and client sessions:
- `conn_id -> client response channel`
- `conn_id <-> writer_id` binding map
- writer activity snapshots and idle tracking

Main invariants:
- A `conn_id` routes to at most one active response channel.
- Writer loss triggers safe unbind/cleanup and close propagation.
- Registry state is the source of truth for active ME-bound session mapping.

## Adaptive Floor

### What it is
`Adaptive Floor` is a runtime policy that changes target writer count per DC based on observed activity, instead of always holding static peak floor.

### Why it exists
Goals:
- Reduce idle writer churn under low traffic.
- Keep enough warm capacity to avoid client-visible stalls on burst recovery.
- Limit needless reconnect storms on unstable endpoints.

### Behavioral model
- Under activity: floor converges toward configured static requirement.
- Under prolonged idle: floor can shrink to a safe minimum.
- Recovery/grace windows prevent aggressive oscillation.

### Safety constraints
- Never violate minimal survivability floor for a DC group.
- Refill must still restore quickly on demand.
- Floor adaptation must not force-drop already bound healthy sessions.

## Trio-State

`Trio-State` is writer contouring:
- `Warm`
- `Active`
- `Draining`

### State semantics
- `Warm`: connected and validated, not primary for new binds.
- `Active`: preferred for new binds and normal traffic.
- `Draining`: no new regular binds; existing sessions continue until graceful retirement rules apply.

### Transition intent
- `Warm -> Active`: when coverage/readiness conditions are satisfied.
- `Active -> Draining`: on generation swap, endpoint replacement, or controlled retirement.
- `Draining -> removed`: after drain TTL/force-close policy (or when naturally empty).

This separation reduces SPOF and keeps cutovers predictable.

## Generation Lifecycle

Generation isolates pool epochs during reinit/reconfiguration.

### Lifecycle phases
1. `Bootstrap`: initial writers are established.
2. `Warmup`: next generation writers are created and validated.
3. `Activation`: generation promoted to active when coverage gate passes.
4. `Drain`: previous generation becomes draining, existing sessions are allowed to finish.
5. `Retire`: old generation writers are removed after graceful rules.

### Operational guarantees
- No partial generation activation without minimum coverage.
- Existing healthy client sessions should not be dropped just because a new generation appears.
- Draining generation exists to absorb in-flight traffic during swap.

### Readiness and admission
Pool readiness is not equivalent to “all endpoints fully saturated”.
Typical gating strategy:
- Open admission when per-DC minimal alive coverage exists.
- Continue background saturation for multi-endpoint DCs.

This keeps startup latency low while preserving eventual full capacity.

## Interactions Between Concepts

- `Generation` defines pool epochs.
- `Trio-State` defines per-writer role inside/around those epochs.
- `Adaptive Floor` defines how much capacity should be maintained right now.
- `Refill` is the actuator that closes the gap between desired and current capacity.
- `Registry` keeps per-session routing correctness while all of the above changes over time.

## Architectural Approach

### Layered Design
The runtime is intentionally split into two planes:
- `Control Plane`: decides desired topology and policy (`floor`, `generation swap`, `refill`, `fallback`).
- `Data Plane`: executes packet/session transport (`reader`, `writer`, routing, acks, close propagation).

Architectural rule:
- Control Plane may change writer inventory and policy.
- Data Plane must remain stable and low-latency while those changes happen.

### Ownership Model
Ownership is centered around explicit state domains:
- `MePool` owns writer lifecycle and policy state.
- `Registry` owns per-connection routing bindings.
- `Writer task` owns outbound ME socket send progression.
- `Reader task` owns inbound ME socket parsing and event dispatch.

This prevents accidental cross-layer mutation and keeps invariants local.

### Control Plane Responsibilities
Control Plane is event-driven and policy-driven:
- Startup initialization and readiness gates.
- Runtime reinit (periodic or config-triggered).
- Coverage checks per DC/family/endpoint group.
- Floor enforcement (static/adaptive).
- Refill scheduling and retry orchestration.
- Generation transition (`warm -> active`, previous `active -> draining`).

Control Plane must prioritize determinism over short-term aggressiveness.

### Data Plane Responsibilities
Data Plane is throughput-first and allocation-sensitive:
- Session bind to writer.
- Per-frame parsing/validation and dispatch.
- Ack and close signal propagation.
- Route drop behavior under missing connection or closed channel.
- Minimal critical logging in hot path.

Data Plane should avoid waiting on operations that are not strictly required for frame correctness.

## Concurrency and Synchronization

### Concurrency Principles
- Per-writer isolation: each writer has independent send/read task loops.
- Per-connection isolation: client channel state is scoped by `conn_id`.
- Asynchronous recovery: refill/reconnect runs outside the packet hot path.

### Synchronization Strategy
- Shared maps use fine-grained, short-lived locking.
- Read-mostly paths avoid broad write-lock windows.
- Backpressure decisions are localized at route/channel boundary.

Design target:
- A slow consumer should degrade only itself (or its route), not global writer progress.

### Cancellation and Shutdown
Writer and reader loops are cancellation-aware:
- explicit cancel token / close command support;
- safe unbind and cleanup via registry;
- deterministic order: stop admission -> drain/close -> release resources.

## Consistency Model

### Session Consistency
For one `conn_id`:
- exactly one active route target at a time;
- close and unbind must be idempotent;
- writer loss must not leave dangling bindings.

### Generation Consistency
Generational consistency guarantees:
- New generation is not promoted before minimum coverage gate.
- Previous generation remains available in `draining` state during handover.
- Forced retirement is policy-bound (`drain ttl`, optional force-close), not immediate.

### Policy Consistency
Policy changes (`adaptive/static floor`, fallback mode, retries) should apply without violating established active-session routing invariants.

## Backpressure and Flow Control

### Route-Level Backpressure
Route channels are bounded by design.
When pressure increases:
- short burst absorption is allowed;
- prolonged congestion triggers controlled drop semantics;
- drop accounting is explicit via metrics/counters.

### Reader Non-Blocking Priority
Inbound ME reader path should never be serialized behind one congested client route.
Practical implication:
- prefer non-blocking route attempt in the parser loop;
- move heavy recovery to async side paths.

## Failure Domain Strategy

### Endpoint-Level Failure
Failure of one endpoint should trigger endpoint-scoped recovery first:
- same endpoint reconnect;
- endpoint replacement within same DC group if applicable.

### DC-Level Degradation
If a DC group cannot satisfy floor:
- keep service via remaining coverage if policy allows;
- continue asynchronous refill saturation in background.

### Whole-Pool Readiness Loss
If no sufficient ME coverage exists:
- admission gate can hold new accepts (conditional policy);
- existing sessions should continue when their path remains healthy.

## Performance Architecture Notes

### Hotpath Discipline
Allowed in hotpath:
- fixed-size parsing and cheap validation;
- bounded channel operations;
- precomputed or low-allocation access patterns.

Avoid in hotpath:
- repeated expensive decoding;
- broad locks with awaits inside critical sections;
- verbose high-frequency logging.

### Throughput Stability Over Peak Spikes
Architecture prefers stable throughput and predictable latency over short peak gains that increase churn or long-tail reconnect times.

## Evolution and Extension Rules

To evolve this model safely:
- Add new policy knobs in Control Plane first.
- Keep Data Plane contracts stable (`conn_id`, route semantics, close semantics).
- Validate generation and registry invariants before enabling by default.
- Introduce new retry/recovery strategies behind explicit config.

## Failure and Recovery Notes

- Single-endpoint DC failure is a normal degraded mode case; policy should prioritize fast reconnect and optional shadow/probing strategies.
- Idle close by peer should be treated as expected when upstream enforces idle timeout.
- Reconnect backoff must protect against synchronized churn while still allowing fast first retries.
- Fallback (`ME -> direct DC`) is a policy switch, not a transport bug by itself.

## Terminology Summary
- `Coverage`: enough live writers to satisfy per-DC acceptance policy.
- `Floor`: target minimum writer count policy.
- `Churn`: frequent writer reconnect/remove cycles.
- `Hotpath`: per-packet/per-connection data path where extra waits/allocations are expensive.
