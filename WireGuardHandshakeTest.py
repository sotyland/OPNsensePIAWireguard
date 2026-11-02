"""Temporary handshake-only test. Does not install IP addresses or routes."""
import configparser
import io
import signal
import subprocess
import time

NAME = "wg99"


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=10).stdout


def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Test interrupted")
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    if NAME in run("ifconfig", "-l").split():
        raise RuntimeError("Test interface already exists; refusing to alter it")
    ini = configparser.ConfigParser(interpolation=None)
    ini.optionxform = str
    ini.read("/conf/purevpn/sofia-test.conf")
    clean = configparser.ConfigParser(interpolation=None)
    clean.optionxform = str
    clean["Interface"] = {"PrivateKey": ini["Interface"]["PrivateKey"]}
    clean["Peer"] = {k: ini["Peer"][k] for k in ("PublicKey", "Endpoint", "AllowedIPs")}
    clean["Peer"]["PersistentKeepalive"] = "5"
    if "PresharedKey" in ini["Peer"]:
        clean["Peer"]["PresharedKey"] = ini["Peer"]["PresharedKey"]
    buf = io.StringIO()
    clean.write(buf)
    owned = False
    try:
        for phase in ("initial", "reconnect"):
            run("ifconfig", NAME, "create")
            owned = True
            subprocess.run(["wg", "setconf", NAME, "/dev/stdin"], input=buf.getvalue(),
                           text=True, capture_output=True, check=True, timeout=10)
            run("ifconfig", NAME, "up")
            deadline = time.monotonic() + 45
            stamp = 0
            while time.monotonic() < deadline:
                rows = run("wg", "show", NAME, "latest-handshakes").splitlines()
                stamp = max((int(row.split()[1]) for row in rows), default=0)
                if stamp:
                    break
                time.sleep(2)
            print(phase, "handshake_timestamp", stamp, flush=True)
            if not stamp:
                raise RuntimeError("No handshake observed; test did not pass")
            run("ifconfig", NAME, "destroy")
            owned = False
            if phase == "initial":
                time.sleep(10)
    finally:
        if owned:
            run("ifconfig", NAME, "destroy")
        print("Test interface removed", flush=True)


if __name__ == "__main__":
    main()
