#!/usr/local/bin/python3
"""Import a PureVPN profile into dedicated, existing OPNsense WG objects."""
import argparse
import base64
import configparser
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

import requests


def key(value):
    try:
        if len(base64.b64decode(value, validate=True)) == 32:
            return value
    except (ValueError, TypeError):
        pass
    raise ValueError("Invalid WireGuard key")


def profile(text):
    ini = configparser.ConfigParser(interpolation=None, strict=True)
    ini.read_string(text)
    if set(ini.sections()) != {"Interface", "Peer"}:
        raise ValueError("Expected exactly one Interface and one Peer")
    allowed = {"Interface": {"privatekey", "address", "dns", "mtu"},
               "Peer": {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}}
    for section in allowed:
        if set(ini[section]) - allowed[section]:
            raise ValueError("Unsupported profile directive; review before importing")
    interface, peer = ini["Interface"], ini["Peer"]
    if "MTU" in interface:
        raise ValueError("Review MTU manually and remove directive before import")
    address = ipaddress.ip_interface(interface["Address"])
    if address.version != 4:
        raise ValueError("This importer supports a single IPv4 tunnel address")
    networks = [ipaddress.ip_network(n.strip()) for n in peer["AllowedIPs"].split(",")]
    if any(n.version != 4 for n in networks):
        raise ValueError("IPv6 routing is not implemented")
    endpoint = peer["Endpoint"].rsplit(":", 1)
    if len(endpoint) != 2 or not re.fullmatch(r"[A-Za-z0-9.-]+", endpoint[0]):
        raise ValueError("Invalid IPv4/hostname endpoint")
    port = int(endpoint[1])
    keepalive = int(peer.get("PersistentKeepalive", "25"))
    if not 1 <= port <= 65535 or not 0 <= keepalive <= 65535:
        raise ValueError("Port or keepalive out of range")
    return {"private": key(interface["PrivateKey"]), "address": str(address),
            "public": key(peer["PublicKey"]), "psk": key(peer["PresharedKey"]) if peer.get("PresharedKey") else "",
            "host": endpoint[0], "port": str(port), "networks": ",".join(map(str, networks)),
            "keepalive": str(keepalive) if keepalive else ""}


class API:
    def __init__(self, config):
        self.url = config["opnsenseURL"].rstrip("/")
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("opnsenseURL must be an HTTPS URL without credentials")
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = (config["opnsenseKey"], config["opnsenseSecret"])
        self.session.verify = config.get("caBundle", True)
        if self.session.verify is not True and not (isinstance(self.session.verify, str) and self.session.verify.strip() and Path(self.session.verify).is_file()):
            raise ValueError("TLS verification cannot be disabled; supply caBundle")

    def call(self, path, payload=None):
        response = self.session.request("GET" if payload is None else "POST",
                                        self.url + "/api/wireguard/" + path,
                                        json=payload, timeout=20, allow_redirects=False)
        if response.status_code != 200:
            raise ValueError("OPNsense API HTTP " + str(response.status_code))
        return response.json()


def selected(value):
    if isinstance(value, dict):
        return ",".join(sorted(k for k, v in value.items() if str(v.get("selected")) == "1"))
    return str(value)


def synchronize(api, config, data, apply=False, derive=None, pending_file=None):
    ids = [config["serverUUID"], config["peerUUID"]]
    if not all(re.fullmatch(r"[0-9a-fA-F-]{36}", x) for x in ids):
        raise ValueError("Explicit serverUUID and peerUUID are required")
    server_id, peer_id = ids
    server = api.call("server/getServer/" + server_id)["server"]
    peer = api.call("client/getClient/" + peer_id)["client"]
    if server["name"] != config["serverName"] or peer["name"] != config["peerName"]:
        raise ValueError("Object names do not match; refusing to alter unrelated objects")
    if selected(server.get("peers", "")) not in ("", peer_id) or selected(peer.get("servers", "")) not in ("", server_id):
        raise ValueError("Shared objects are not supported; use a dedicated instance and peer")
    desired_server = {"pubkey": key((derive or derive_public)(data["private"])),
                      "privkey": data["private"], "tunneladdress": data["address"],
                      "dns": "", "disableroutes": "1", "peers": peer_id}
    desired_peer = {"pubkey": data["public"], "psk": data["psk"], "serveraddress": data["host"],
                    "serverport": data["port"], "tunneladdress": data["networks"],
                    "keepalive": data["keepalive"], "servers": server_id}
    changes = [("server", "Server", server_id, server, desired_server),
               ("client", "Client", peer_id, peer, desired_peer)]
    pending = [entry for entry in changes if any(selected(entry[3].get(k, "")) != v for k, v in entry[4].items())]
    activation_pending = pending_file is not None and pending_file.exists()
    if not apply or (not pending and not activation_pending):
        return len(pending)
    if pending_file is not None:
        pending_file.write_text("Activation pending; no credentials.\n", encoding="utf-8")
    for controller, suffix, uuid, current, desired in pending:
        result = api.call(f"{controller}/set{suffix}/{uuid}", {controller: desired})
        if result.get("result") != "saved":
            raise ValueError("API rejected update; partial configuration may exist, restore backup")
        actual = api.call(f"{controller}/get{suffix}/{uuid}")[controller]
        if any(selected(actual.get(k, "")) != v for k, v in desired.items()):
            raise ValueError("API readback mismatch; restore backup before continuing")
    result = api.call("service/reconfigure", {})
    if result.get("result") != "ok":
        raise ValueError("Reconfigure failed; restore backup before continuing")
    if pending_file is not None:
        pending_file.unlink()
    return len(pending)


def derive_public(private):
    return subprocess.run(["wg", "pubkey"], input=private + "\n", text=True,
                          capture_output=True, check=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--apply", action="store_true", help="Write changes; default is read-only")
    args = parser.parse_args()
    try:
        for filename in (args.config, args.profile):
            if os.name != "nt" and Path(filename).stat().st_mode & 0o077:
                raise ValueError("Credential files must have mode 0600")
        config = json.loads(Path(args.config).read_text(encoding="utf-8-sig"))
        data = profile(Path(args.profile).read_text(encoding="utf-8-sig"))
        count = synchronize(API(config), config, data, args.apply, derive_public,
                            Path(args.config + ".pending"))
        print(f"{count} object(s) {'updated' if args.apply else 'require update (read-only)'}; tunnel health not tested")
        return 0
    except Exception:
        # Provider and API exceptions can contain secrets; never echo them.
        print("Import failed. Check profile, permissions, TLS and API access. If applying, inspect configuration and restore backup if needed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
