# PureVPN WireGuard importer

Development build based on FingerlessGlov3s/OPNsensePIAWireguard at
`a0b3dad1e45919c7d61b5dd2af2acac2c4ef91a4`. Original BSD license retained.
The new importer uses the upstream OPNsense API approach and replaces the
PIA provisioning path with a downloaded PureVPN profile.

## Current scope

Implemented: strict single-peer IPv4 profile parsing, imported private identity,
optional pre-shared key, TLS verification, read-only comparison, dedicated-object
checks, update readback, reconfigure only after changes, and healthy no-op repeats.
Preserves object enabled state, local listening port, gateway and other unowned
fields. Does not enable the WireGuard service.

Experimental separate component: `PureVPNProvider.py` implements normal HTTPS
account login, location discovery and profile generation with stable client keys.
It does not modify OPNsense, enable a tunnel or schedule renewal. Live account
authentication advances with the corrected form headers, but the tested router
receives a Cloudflare HTTP 403 block at the member-portal callback. Complete
session establishment and generated profile usability remain unverified.

Not implemented: scheduled renewal/reconnection, failover,
port forwarding, automatic creation of instances/peers, gateway/NAT/firewall/DNS
configuration, IPv6, MTU changes or a tunnel health monitor. DNS and MTU from
the profile require manual configuration. MTU directives are rejected until reviewed
and removed from the import copy. DNS is intentionally excluded from instance
settings to avoid changing the firewall's global resolver configuration.
This is not equivalent to the PIA
script's unattended recovery. Do not install its PIA cron actions for PureVPN.

## Preparation on OPNsense

1. Export a complete firewall configuration using System > Configuration > Backups.
   Keep it securely outside this repository. Confirm console access for recovery.
2. Create a dedicated WireGuard instance named `purevpn` and peer named
   `purevpn-server`. Keep the instance disabled during preparation. Use valid
   temporary values where the UI requires them; the importer replaces the keys,
   tunnel address and remote endpoint. Do not share these objects with other tunnels.
3. Record their UUIDs from the edit URLs or API search results. Create an API user
   with the VPN: WireGuard permission and download its API key/secret privately.
4. Copy `PureVPNWireguard.py` and the example JSON to `/conf/purevpn/`, naming the
   filled configuration `PureVPNWireguard.json`. Supply the exact UUIDs and names.
   Set the HTTPS URL to a hostname matching the firewall certificate. `caBundle`
   must point to the trusted issuing CA certificate; for a public CA you may use
   JSON `true`. No TLS bypass is supported.
5. Confirm `/usr/local/bin/python3` can import `requests`, and `wg pubkey` is
   available on OPNsense. This build was tested locally with Python 3.11.9;
   FreeBSD/OPNsense execution has not yet been tested.
6. Generate a fresh WireGuard profile from PureVPN's member area and copy it
   privately to `/conf/purevpn/purevpn.conf`. PureVPN documents activation within
   30 minutes. Do not commit this file or any filled API configuration.

## Preview and apply

After creating and filling those files, run on OPNsense:

```sh
chmod 600 /conf/purevpn/PureVPNWireguard.json /conf/purevpn/purevpn.conf
/usr/local/bin/python3 /conf/purevpn/PureVPNWireguard.py --config /conf/purevpn/PureVPNWireguard.json --profile /conf/purevpn/purevpn.conf
```

The preview contacts only OPNsense and makes GET requests. It reports how many
objects differ without printing keys. It invokes local `wg pubkey` to check
identity drift. To write the reviewed changes:

```sh
/usr/local/bin/python3 /conf/purevpn/PureVPNWireguard.py --config /conf/purevpn/PureVPNWireguard.json --profile /conf/purevpn/purevpn.conf --apply
```

API writes are not transactional. A failure may leave partially saved settings;
stop and inspect the dedicated objects before retrying. Restore the exported
firewall configuration through the UI/console if needed. Reconfigure affects
the WireGuard service, so schedule application to avoid disrupting other tunnels.
No automated rollback is claimed or tested against a real firewall.
An adjacent `.pending` marker records incomplete activation without credentials.
After resolving a failed apply, rerunning with the same config path retries
reconfigure even if saved settings already match. Do not run concurrently;
keep the configuration path fixed and its parent directory writable.

## Routing and live acceptance checks

Follow the [OPNsense selective-routing guide](https://docs.opnsense.org/manual/how-tos/wireguard-selective-routing.html)
for interface assignment, a gateway, policy rules, outbound NAT, DNS and kill switch.
Use the imported profile address for gateway planning. Configure profile MTU
manually if present. Enable the dedicated instance and WireGuard service only
after preparation. For IPv4-only use, block IPv6 WAN escape for selected clients.

Acceptance requires a recent handshake, transfer counters increasing during a
request from a selected LAN client, a PureVPN exit IP, DNS routed as intended,
and loss of internet for that client when the tunnel is stopped. Check other
clients retain their intended connectivity. Observe at least 60 seconds of
stability and test recovery after a long disconnect with the same profile.
A successful API save or reconfigure is not proof of a healthy tunnel.

## Experimental provider generation

On OPNsense, after securely copying `PureVPNProvider.py` to `/conf/purevpn/`:

```sh
/usr/local/bin/python3 /conf/purevpn/PureVPNProvider.py --credentials /conf/purevpn/credentials.json --output /conf/purevpn/profiles --setup-login --all
```

Enter the account email and hidden password once. Credentials, client identities
and profiles are stored as private files. Omit `--setup-login` on later runs to
reuse the saved credentials. Omit `--all` to authenticate and save only the location
catalogue. A run with `--all` requests fresh profiles for every returned city;
it is a provisioning action, not a passive health check. Do not run concurrently.
No paid add-on is required by this component. Provider challenges stop the run;
the component does not bypass interactive verification. Run credential operations
on OPNsense or another POSIX host; Windows is supported only for synthetic tests.

## Local verification

From this repository, in an isolated Python environment with requirements installed:

```sh
python -m unittest -v test_purevpn test_provider
python PureVPNWireguard.py --help
```

Tests use synthetic keys and a fake OPNsense API. They cover mapping, malformed
profiles, read-only mode, unchanged repeat runs, endpoint repair, API rejection,
readback mismatch, shared-object refusal and TLS/HTTP errors. They are not live
VPN or firewall evidence.

## Sources

- [PureVPN manual setup](https://support.purevpn.com/en_US/purevpn-android/setup-wireguard-on-android)
- [OPNsense peer model](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Wireguard/Client.xml)
- [OPNsense service controller](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Wireguard/Api/ServiceController.php)

Reviewed 2026-11-02. Provider provisioning and live acceptance remain pending.
