# Development and live migration verification — 2026-11-02

Current deployment is described in the full-migration section below. Earlier
sections record intermediate states, not the final configuration.

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

A Serbia-only source NAT rule was initially removed at the owner's request.
After the LAN test exposed missing NAT, the owner authorized the needed NAT
addition. The active Serbia rule now has UUID
`5811dbd2-f17c-49c5-bdc2-fe83c2c5bdb9`, source alias
`WG_VPN_PIA_Serbia_Hosts`, interface opt7 and interface-address translation.
The owner subsequently confirmed public IP 135.136.30.23, M247, Serbia from
the selected LAN client. This supersedes the earlier handshake-only canary.

Private pre-test rollback copies of config.xml and PIAWireguard.json are under
`/conf/purevpn/serbia-test-backup/` on the router. They are not repository files.
Rollback of the full router configuration has not been exercised.

## Full migration and scheduled recovery

The owner explicitly authorized migrating all tunnels, missing NAT additions,
PIA monitoring OFF and PureVPN monitoring ON. Rome and Washington DC replacements
were approved because the manual-profile list did not offer Malta or Baltimore.
All ten existing managed objects now contain PureVPN profiles and have fresh
handshakes. The separate disabled pure-sofia/wg0 object is not managed or enabled.

Native model validation was executed on OPNsense before saving each migration.
A container/model validation API mistake was caught in the first dry run and fixed
before saving. A browser transfer binding initially reused the Sofia payload for
London/Newark; identity readback detected it, the transfer was corrected, and both
were reapplied with an explicit expected-name check. Neither was counted as migrated
until its correct identity and live handshake were verified.

Six missing alias-specific NAT rules were added for Slovakia, Romania, Portugal,
Malta, Luxembourg and Baltimore. Existing Sofia/London/NewJersey rules and the
working Serbia rule were retained. `pfctl -sn` shows exactly one per-alias NAT rule
on each wg1–wg10. Every corresponding LAN policy rule uses the matching alias and
updated WireGuard gateway. The original interfaces, legacy filter, legacy NAT and
native filter-rule XML subtrees compare unchanged with
`/conf/purevpn/full-migration-before.xml`. User alias edits during the session are
preserved. The monitor never edits aliases or routing/filter rules.

Eight inherited gateway ping checks had no custom monitor target and tried to ping
the arbitrary WireGuard gateway address. They showed offline despite fresh handshakes;
a local-router positive-control ping succeeded while the London gateway address
did not answer. The matching managed gateways now use the separately enabled
WireGuard monitor, consistent with already-working Serbia/Slovakia. WAN monitoring
and both default routes were preserved. This change is not an end-to-end traffic
health check; a gateway icon with ICMP disabled must not be treated as one.

PIA cron configuration is disabled; PureVPN cron configuration is enabled. Native
generated scheduling in `/var/cron/tabs/nobody` contains the every-minute
`configctl -d -- purevpn monitor` command and no PIA monitor command. Configd logs
show scheduled runs at 21:32, 21:33 and 21:34 UTC; saved monitor state advances at
minute boundaries. The Cron UI was visually checked: PIA unchecked, PureVPN checked.

Healthy repeated monitor runs reported all ten tunnels healthy and performed no
restarts. London had an empty client alias; stopping only London produced `suspect`
on the first monitor run, `recover` on the second and a fresh handshake (age 8 seconds)
on the next check. The other nine tunnels stayed healthy, including the active
Serbia client tunnel. Backoff, stale/future timestamps and healthy-state reset have
unit coverage. No standing project smoke test exists; these are task-specific checks.

A second test used only the real scheduled job: London was stopped at 21:37:06 UTC,
924 seconds after its private profile payload was saved (generation was earlier).
The 21:38 scheduled run recorded the first failure; the 21:39 scheduled run restored
it. At 21:39:23, wg2 had a 14-second-old handshake and all other nine tunnels had
handshakes under 120 seconds old. No manual monitor invocation or fresh profile was
used during this recovery. This proves a reconnect after the initial 15-minute
setup window, not after a multi-hour outage or provider-side credential revocation.

SHA256 comparison confirmed all nine deployed runtime/helper/mapping files match
the local reviewed source. Reapplying NAT and gateway-health helpers reported zero
changes and left config.xml SHA256 unchanged at
`227c91f8707cafad94fa13fd1963fceab6c5c2a43925013b33d2270dd0d5f2e7`.

The startup hook ran without restarting any services in a healthy installation.
The update hook was tested by moving the custom configd action aside: it recreated
the action, reloaded configd, regenerated cron and restored the callable monitor.
The native POSIX installer test passed failure-marker persistence, retry after
partial activation and healthy no-op behavior. The same test is explicitly skipped
on Windows because it exercises POSIX permissions; 26 other tests pass locally.
Independent cold reviews covered mutation scope, NAT semantics, recovery races and
partial installer failure. Findings were repaired and re-reviewed.

Residual verification limits: no actual router reboot, firmware upgrade, long outage,
provider revocation, full configuration restore, DNS-leak or kill-switch test was
performed. Serbia's LAN exit IP is owner-confirmed; other locations' client exit IPs
still need client testing. A router-originated London curl returned the WAN address;
it does not exercise the alias-selected LAN rule and is not used as VPN traffic proof.
No rule changes were made to broaden router-originated access. The separate API
importer end-to-end path and unattended provider login remain unverified/blocked.
