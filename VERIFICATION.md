# Development verification — 2026-11-02

Upstream baseline: a0b3dad1e45919c7d61b5dd2af2acac2c4ef91a4.

- Local Python 3.11.9: 22 unittest cases pass using synthetic profiles and a
  fake API; no provider or firewall credentials used.
- CLI help, Python compilation and dependency consistency checks pass.
- Independent cold review identified falsey TLS settings, activation retry,
  instance public-key drift and ignored MTU. Repaired with regression cases;
  MTU now requires explicit manual review, DNS exclusion is documented.
- Source API fields checked against upstream OPNsense controllers/models.
- Healthy repeat: zero writes/reconfigure. Endpoint drift: only the peer is
  updated and reconfigure runs. Failed activation: pending marker survives and
  the next apply retries activation without rewriting matching settings.

- Provider authentication component received a separate cold review (auth and
  >150-line triggers). Stable location IDs, atomic private writes, existing key
  protection, POSIX credential storage and profile field validation were checked.
- Provider source installed inactive at `/conf/purevpn/PureVPNProvider.py` on
  OPNsense; Python 3.13 compilation passed. SHA256 matches local reviewed source:
  `7ccb3a264aa29b2789dc007b3a940b9f25bf7357ce276fafab5239ca14b14665`.
- Before/after `/conf/config.xml` SHA256 unchanged:
  `d40e9263134bbf4367be06f2d296fd7ecf0591b3dae2074e57fbff0960f2deb7`.
  Private rollback copies exist under `/conf/purevpn/pre-migration/`.
- Importer branch published in `sotyland/OPNsensePIAWireguard` at
  `codex/purevpn-import`; this branch includes the provider component and login fix.

- Live login initially returned an invalid-credentials page. Supplying the normal
  form Origin/Referer headers advanced authentication through HTTP 302 redirects.
  The missing headers were fixed, regression-tested and independently reviewed.
- The subsequent member-portal callback returns HTTP 403. A separate unauthenticated
  portal GET from the router returns Cloudflare's explicit blocked page. Browser
  access works. No challenge bypass or browser impersonation was attempted.
  Full provider session establishment and unattended provisioning remain blocked.

- A fresh Sofia profile obtained through the member-area browser UI completed
  an initial handshake (Unix timestamp `1793651061`) on temporary `wg99`.
  After destroying the interface, waiting 10 seconds and recreating it with
  the same profile, another handshake completed (`1793651074`). No profile
  regeneration or paid add-on was used. This proves short-disconnect recovery
  only, not recovery after the setup window or a long outage.
- `WireGuardHandshakeTest.py` compiled locally and on OPNsense and received
  independent cold review. It sets no interface addresses or OS routes.
  Independent post-test checks confirmed `wg99` absent, the WAN default route
  unchanged and the configuration checksum above unchanged. SIGKILL, power loss
  or interruption during interface creation can still require manual cleanup.

## PIASerbia live canary

At the owner's explicit request, the existing `PIASerbia` interface (`opt7`,
`wg4`) was configured with a fresh PureVPN Belgrade WireGuard profile. Instance
and peer names were retained, as was listen port 51818. The tunnel address is
172.21.194.186/32; the existing named gateway uses 172.21.194.185, following
OPNsense's arbitrary WireGuard gateway convention. Only Serbia was removed
from the PIA manager's instance list; the other nine entries were preserved.

The native template generator was run before restarting only the Serbia
instance by UUID. A restart alone initially loaded the stale generated peer
file; runtime endpoint inspection detected this and template generation fixed it.
The running endpoint became 135.136.30.4:51820. Handshakes at Unix timestamps
1793651709 and 1793651835 demonstrate connection and subsequent handshake renewal
over more than two minutes. At 1793651874, received/sent counters were 184/552
bytes. These small values establish control traffic, not a LAN throughput test.
The interface remained UP/RUNNING and the WAN default route was preserved.

A Serbia-only source NAT rule was briefly added before the owner specified
that rules must remain untouched. That addition was removed and applied;
the original filter and NAT XML sections match the pre-test backup exactly,
and the new rule is absent. The owner will configure a machine and test their
existing routing and rules. Do not alter firewall, NAT, aliases or routing
further without a new explicit request.

Private pre-test rollback copies of config.xml and PIAWireguard.json are under
`/conf/purevpn/serbia-test-backup/` on the router. They are not repository files.
Rollback of the full router configuration has not been exercised.

Not verified: importer end-to-end API operation, complete unattended provider
login, LAN exit IP/DNS/kill switch, or recovery after a long outage/provider
expiry. Automatic reconnection management is not built. The owner is handling
the client traffic test; only the Serbia tunnel is configured for this canary.
