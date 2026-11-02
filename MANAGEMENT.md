# Native PureVPN management

Deployed on OPNsense 26.7.8_2 / FreeBSD 15.1 on 2026-11-02. This deployment uses
fresh profiles generated through the authenticated PureVPN member-area UI. No
paid extension was purchased. Activate profiles within the portal's displayed
15-minute window; that window is distinct from a proven credential lifetime.

## Location mapping

| Existing interface | Device | PureVPN location |
| --- | --- | --- |
| PIASofia | wg1 | Sofia, Bulgaria |
| PIALondon | wg2 | London, UK |
| PIANewJersey | wg3 | Newark, USA |
| PIASerbia | wg4 | Belgrade, Serbia |
| PIASlovakia | wg5 | Bratislava, Slovakia |
| PIARomania | wg6 | Bucharest, Romania |
| PIAPortugal | wg7 | Lisbon, Portugal |
| PIAMalta | wg8 | Rome, Italy — approved replacement |
| PIALuxembourg | wg9 | Luxembourg |
| PIABaltimore | wg10 | Washington DC, USA — approved replacement |

Interface names, assignments, instance/peer UUIDs, listen ports and existing
policy rules are retained. `managed.json` contains this router's public object
identifiers; adapt it to another router rather than copying it blindly.
Each outbound NAT source is the corresponding `WG_VPN_PIA_*_Hosts` alias. The
existing spelling `WG_VPN_PIA_Baltimor_Hosts` is intentional. Empty aliases send
no clients through their tunnel. Native routes/default gateways and filter rules
are not rewritten by the monitor.

## Recovery behavior

The native Cron job runs `purevpn monitor` every minute through configd.
`PureVPNMonitor.py` defaults to inspection; `--apply` enables recovery and state
updates. A handshake no older than 180 seconds is healthy. A missing/stale
handshake must be observed twice. Recovery regenerates native WireGuard files,
rechecks identity/enabled state and the handshake, then restarts only that UUID.
Restarting resolves the configured endpoint hostname again. Subsequent failed
attempts back off for 5, 10, 20 and at most 30 minutes. Healthy handshakes clear
backoff. Disabled instances or peers are skipped; identity drift is an error.
An exclusive lock prevents overlapping monitor runs.

The old gateway-address ICMP checks are disabled for managed VPN gateways:
their arbitrary gateway addresses are not pingable provider endpoints. The
separate WireGuard monitor checks actual handshakes. A green gateway icon with
ICMP monitoring disabled is not proof of end-to-end internet access. WAN gateway
monitoring is preserved. This follows the unpingable-endpoint option in the
[OPNsense selective-routing guide](https://docs.opnsense.org/manual/how-tos/wireguard-selective-routing.html).

This monitor does not regenerate profiles, change endpoint country, test DNS
leaks, or prove payload delivery. If PureVPN revokes an existing identity,
restarting alone cannot restore it. `PureVPNProvider.py` remains experimental;
router-side portal login currently receives HTTP 403. Long-outage credential
validity remains unverified.

## Persistent installation and controls

Runtime, mapping and state are under `/conf/purevpn/`. Native cron configuration
is saved in `/conf/config.xml`; the generated cron entry is in
`/var/cron/tabs/nobody`, not root's crontab. The installed action is
`/usr/local/opnsense/service/conf/actions.d/actions_purevpn.conf`.

`InstallPureVPNMonitor.py` installs executable `90-purevpn-monitor` hooks under
`/usr/local/etc/rc.syshook.d/start/` and `update/`. They restore a missing/changed
action from the persistent runtime, reload configd and regenerate cron only when
needed. An interrupted activation leaves a pending marker and retries next run.
A healthy repeat performs no service restarts. Hooks never enable the Cron job
or restart VPN tunnels by themselves.

This uses OPNsense's documented [startup/post-update hooks](https://docs.opnsense.org/development/backend/autorun.html)
and [configd actions](https://docs.opnsense.org/development/backend/configd.html).
Hook execution and action-restoration were tested; an actual router reboot or
firmware upgrade was not performed. Future incompatible platform changes, a
factory reset, or deletion of custom hooks are not covered. Back up `/conf/purevpn/`
privately as well as exporting config.xml; the standard XML export does not
include these custom scripts.

On this deployed router, inspect without restarting tunnels:

```sh
python3 /conf/purevpn/PureVPNMonitor.py
python3 /conf/purevpn/AuditPureVPN.py
```

To disable automatic recovery while preserving the tunnels:

```sh
php /conf/purevpn/ConfigurePureVPNCron.php disable
configctl template reload OPNsense/Cron
configctl cron restart
```

To enable the installed monitor again, replace `disable` with `enable`. The UI
equivalent is System > Settings > Cron > PureVPN Monitor. The old PIA job must
remain disabled. Do not edit a runtime script while a monitor process is running.

## Migration helpers and rollback

`ApplyPureVPN.php check|apply` accepts a private JSON payload; it validates exact
existing identities, rejects shared peers and unexpected mutation fields, and
saves the three native models only after validation. Run the native WireGuard
template generator before restarting the specific instance UUID. Private payloads
contain keys and must never be published. This helper does not enable objects.

`AddAliasNAT.php check|apply` accepts reviewed `nat-mappings.json`, verifies
interfaces and aliases, refuses conflicting existing NAT, and adds only missing
rules. Apply with `configctl filter reload`. A healthy repeat makes no additions.
`ConfigurePureVPNGatewayHealth.php check|apply managed.json` disables only blank,
invalid ICMP monitor targets on the matching managed gateways; it refuses custom
monitor targets. Apply gateway changes with `configctl interface routes configure`.

Private pre-migration backup: `/conf/purevpn/full-migration-before.xml`.
Additional earlier backups remain under `/conf/purevpn/pre-migration/` and
`/conf/purevpn/serbia-test-backup/`. Full configuration restore has not been tested
and restores cancelled PIA settings; it is an emergency rollback, not a working
provider fallback. Disabling the PureVPN cron job was tested before activation.
