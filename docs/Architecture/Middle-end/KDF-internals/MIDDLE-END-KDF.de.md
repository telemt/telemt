# Middle-End Proxy

## KDF-Adressierung — Implementierungs-FAQ

### Benötigt die C-Referenzimplementierung sowohl externe IP-Adresse als auch Port für die KDF?

Ja.

In der C-Referenzimplementierung werden **sowohl IP-Adresse als auch Port in die KDF einbezogen** — auf beiden Seiten der Verbindung.

In `aes_create_keys()` enthält der KDF-Input:

- `server_ip + client_port`
- `client_ip + server_port`
- sowie Secret / Nonces

Für IPv6:

- IPv4-Felder werden auf 0 gesetzt
- IPv6-Adressen werden ergänzt

Die **Ports bleiben weiterhin Bestandteil der KDF**.

> Wenn sich externe IP oder Port (z. B. durch NAT, SOCKS oder Proxy) von den erwarteten Werten unterscheiden, entstehen unterschiedliche Schlüssel — der Handshake schlägt fehl.

---

### Kann der Port aus der KDF ausgeschlossen werden (z. B. durch Port = 0)?

**Nein!**

Die C-Referenzimplementierung enthält **keine Möglichkeit, den Port zu ignorieren**:
- `client_port` und `server_port` sind fester Bestandteil der KDF
- Es werden immer reale Socket-Ports übergeben:
  - `c->our_port`
  - `c->remote_port`

Falls ein Port den Wert `0` hat, wird er dennoch als `0` in die KDF übernommen.

Eine „Port-Ignore“-Logik existiert nicht.
