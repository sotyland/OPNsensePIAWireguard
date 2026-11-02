#!/usr/local/bin/python3
"""Read-only deployment audit; emits no keys or account credentials."""
import json
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET


def canonical(node):
    if node is None:
        return None
    return (node.tag, (node.text or '').strip(), sorted(node.attrib.items()),
            [canonical(child) for child in node])


def main():
    root = Path('/conf/purevpn')
    before = ET.parse(root / 'full-migration-before.xml').getroot()
    current = ET.parse('/conf/config.xml').getroot()
    for old_interface in before.findall('./interfaces/*'):
        new_interface = current.find('./interfaces/' + old_interface.tag)
        if new_interface is not None and old_interface.findtext('descr') != new_interface.findtext('descr'):
            print('LABEL', old_interface.tag, old_interface.findtext('descr'), '->', new_interface.findtext('descr'))
            old_interface.find('descr').text = new_interface.findtext('descr')
    for path in ('interfaces', 'filter', 'nat', 'OPNsense/Firewall/Filter/rules'):
        print(path, 'UNCHANGED' if canonical(before.find(path)) == canonical(current.find(path)) else 'CHANGED')
    managed = json.loads((root / 'managed.json').read_text())
    handshakes = {}
    for line in subprocess.check_output(['wg', 'show', 'all', 'latest-handshakes'], text=True).splitlines():
        interface, key, stamp = line.split()
        handshakes[(interface, key)] = int(stamp)
    rules = subprocess.check_output(['pfctl', '-sr'], text=True)
    nat = subprocess.check_output(['pfctl', '-sn'], text=True)
    for item in managed:
        server = next(s for s in current.findall('./OPNsense/wireguard/server/servers/server') if s.get('uuid') == item['uuid'])
        peer = next(p for p in current.findall('./OPNsense/wireguard/client/clients/client') if p.get('uuid') == item['peer_uuid'])
        stamp = handshakes.get((item['interface'], peer.findtext('pubkey')), 0)
        route = 'route-to (' + item['interface'] + ' ' + server.findtext('gateway') + ')'
        matched = [line for line in rules.splitlines() if route in line]
        nats = [line for line in nat.splitlines() if line.startswith('nat on ' + item['interface'] + ' ')]
        print(item['name'], item['interface'], 'age', int(time.time()) - stamp if stamp else 'NONE',
              'policy_rules', len(matched), 'NAT_rules', len(nats))
        for line in matched + nats:
            print(line)
    for job in current.findall('./OPNsense/cron/jobs/job'):
        print('CRON', job.findtext('command'), 'enabled', job.findtext('enabled'))


if __name__ == '__main__':
    main()
