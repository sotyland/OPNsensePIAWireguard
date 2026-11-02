#!/usr/local/bin/python3
"""Restore monitor integration, without enabling jobs or restarting tunnels."""
import os
from pathlib import Path
import subprocess

ROOT = Path('/conf/purevpn')
ACTION = Path('/usr/local/opnsense/service/conf/actions.d/actions_purevpn.conf')
HOOK_ROOT = Path('/usr/local/etc/rc.syshook.d')
ACTION_TEXT = '''[monitor]
command:/usr/local/bin/python3 /conf/purevpn/PureVPNMonitor.py --apply
parameters:
type:script_output
message:Checking managed PureVPN WireGuard tunnels
description:PureVPN Monitor
'''
HOOK_TEXT = '''#!/bin/sh
exec /usr/local/bin/python3 /conf/purevpn/InstallPureVPNMonitor.py
'''


def ensure(path, text, mode):
    if path.exists() and path.read_text() == text and path.stat().st_mode & 0o777 == mode:
        return False
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as stream:
        stream.write(text)
    temporary.chmod(mode)
    os.replace(temporary, path)
    return True


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root on OPNsense')
    for name in ('PureVPNMonitor.py', 'managed.json'):
        if not (ROOT / name).is_file():
            raise SystemExit('Missing required file: ' + name)
    pending = ROOT / 'integration-pending'
    changed = (pending.exists() or not ACTION.exists() or
               ACTION.read_text() != ACTION_TEXT or ACTION.stat().st_mode & 0o777 != 0o644)
    if changed:
        pending.touch(mode=0o600, exist_ok=True)
        ensure(ACTION, ACTION_TEXT, 0o644)
    for stage in ('start', 'update'):
        path = HOOK_ROOT / stage / '90-purevpn-monitor'
        if ensure(path, HOOK_TEXT, 0o700):
            print('Installed', stage, 'hook')
    if changed:
        subprocess.run(['/usr/sbin/service', 'configd', 'restart'], check=True, timeout=60)
        subprocess.run(['/usr/local/sbin/configctl', 'template', 'reload', 'OPNsense/Cron'], check=True, timeout=60)
        subprocess.run(['/usr/local/sbin/configctl', 'cron', 'restart'], check=True, timeout=60)
        pending.unlink()
        print('Monitor integration restored; job enablement unchanged')
    else:
        print('Monitor integration unchanged; no services restarted')


if __name__ == '__main__':
    main()
