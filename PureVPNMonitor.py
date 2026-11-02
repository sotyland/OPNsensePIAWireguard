#!/usr/local/bin/python3
"""Scoped WireGuard recovery; never changes routing rules or provider identities."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path('/conf/purevpn')
CONTROL = '/usr/local/opnsense/scripts/wireguard/wg-service-control.php'


def report(*parts):
    import syslog
    message = ' '.join(str(part) for part in parts)
    print(message, flush=True)
    syslog.openlog('purevpn-monitor')
    syslog.syslog(syslog.LOG_NOTICE, message)


def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout


def decision(now, handshake, previous):
    if handshake and 0 <= now - handshake <= 180:
        return 'healthy'
    if now < previous.get('next_retry', 0):
        return 'cooldown'
    if previous.get('misses', 0) < 1:
        return 'suspect'
    return 'recover'


def inspect(config, entry):
    servers = config.findall('./OPNsense/wireguard/server/servers/server')
    server = next((s for s in servers if s.get('uuid') == entry['uuid']), None)
    if server is None or server.findtext('name') != entry['name']:
        raise ValueError('Managed instance identity changed')
    if server.findtext('enabled') != '1':
        return None
    if 'wg' + server.findtext('instance', '') != entry['interface']:
        raise ValueError('Managed interface assignment changed')
    if server.findtext('peers') != entry['peer_uuid']:
        raise ValueError('Managed peer assignment changed')
    peers = config.findall('./OPNsense/wireguard/client/clients/client')
    peer = next((p for p in peers if p.get('uuid') == entry['peer_uuid']), None)
    if peer is None:
        raise ValueError('Managed peer is missing')
    if peer.findtext('enabled') != '1':
        return None
    return peer.findtext('pubkey')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    import fcntl  # Native OPNsense only; pure decision tests also run on Windows.
    with open('/var/run/purevpn-monitor.lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            report('Another monitor run is active')
            return
        managed = json.loads((ROOT / 'managed.json').read_text())
        config = ET.parse('/conf/config.xml').getroot()
        if config.findtext('./OPNsense/wireguard/general/enabled') != '1':
            report('WireGuard is disabled; no recovery attempted')
            return
        state_path = ROOT / 'monitor-state.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        now = int(time.time())
        runtime = command(['/usr/bin/wg', 'show', 'all', 'latest-handshakes'])
        handshakes = {(r[0], r[1]): int(r[2]) for line in runtime.splitlines()
                      if len(r := line.split()) == 3}
        failed = False
        for entry in managed:
            name = entry['name']
            previous = state.get(entry['uuid'], {})
            try:
                peer_key = inspect(config, entry)
                if peer_key is None:
                    report(name, 'disabled; skipped')
                    continue
                stamp = handshakes.get((entry['interface'], peer_key), 0)
                action = decision(now, stamp, previous)
                if action == 'healthy':
                    state[entry['uuid']] = {'misses': 0, 'next_retry': 0,
                                             'failures': 0, 'handshake': stamp}
                elif action == 'suspect':
                    state[entry['uuid']] = dict(previous, misses=1)
                    failed = True
                elif action == 'recover' and args.apply:
                    # Regenerate files, then recheck immediately before any restart.
                    command(['/usr/local/sbin/configctl', 'template', 'reload', 'OPNsense/Wireguard'])
                    fresh_config = ET.parse('/conf/config.xml').getroot()
                    if fresh_config.findtext('./OPNsense/wireguard/general/enabled') != '1':
                        report(name, 'disabled before recovery; skipped')
                        continue
                    fresh_key = inspect(fresh_config, entry)
                    if fresh_key is None:
                        report(name, 'disabled before recovery; skipped')
                        continue
                    fresh_rows = command(['/usr/bin/wg', 'show', 'all', 'latest-handshakes'])
                    fresh_stamps = {(r[0], r[1]): int(r[2]) for line in fresh_rows.splitlines()
                                    if len(r := line.split()) == 3}
                    now = int(time.time())
                    if decision(now, fresh_stamps.get((entry['interface'], fresh_key), 0), {}) == 'healthy':
                        state[entry['uuid']] = {'misses': 0, 'failures': 0, 'next_retry': 0}
                        report(name, 'recovered before restart; unchanged')
                        continue
                    # Regenerates files without restarting unrelated instances.
                    # Native restart resolves the configured endpoint hostname again.
                    count = min(previous.get('failures', 0) + 1, 4)
                    state[entry['uuid']] = {'misses': 1, 'failures': count,
                                             'next_retry': now + min(300 * 2 ** (count - 1), 1800)}
                    command([CONTROL, 'restart', entry['uuid']])
                    failed = True
                else:
                    failed = True
                report(name, action, 'handshake_age', now - stamp if stamp else 'none')
            except (ValueError, subprocess.SubprocessError, OSError) as exc:
                # Never print command output: it may contain private configuration.
                report(name, 'ERROR', type(exc).__name__)
                failed = True
        if args.apply:
            temporary = state_path.with_suffix('.new')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(state, stream)
            os.replace(temporary, state_path)
        if failed:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
