# Development verification — 2026-11-02

Upstream baseline: a0b3dad1e45919c7d61b5dd2af2acac2c4ef91a4.

- Local Python 3.11.9: 12 unittest cases pass using synthetic profiles and a
  fake API; no provider or firewall credentials used.
- CLI help, Python compilation and dependency consistency checks pass.
- Independent cold review identified falsey TLS settings, activation retry,
  instance public-key drift and ignored MTU. Repaired with regression cases;
  MTU now requires explicit manual review, DNS exclusion is documented.
- Source API fields checked against upstream OPNsense controllers/models.
- Healthy repeat: zero writes/reconfigure. Endpoint drift: only the peer is
  updated and reconfigure runs. Failed activation: pending marker survives and
  the next apply retries activation without rewriting matching settings.

Not verified: live OPNsense API compatibility, FreeBSD execution, PureVPN
handshake/exit IP/DNS/kill switch, reconnect after provider expiry, real rollback
or service stability. No deployment occurred, so deployment freshness and visual
firewall validation do not apply to this local build. Online fork/publication
requires authenticated GitHub access. Automated provider renewal is not built.
