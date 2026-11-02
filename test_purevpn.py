import base64
import copy
import unittest
from unittest.mock import Mock
from unittest.mock import patch
import tempfile
from pathlib import Path

import PureVPNWireguard as app

KEY = base64.b64encode(bytes(range(32))).decode()
PROFILE = f"""[Interface]
PrivateKey = {KEY}
Address = 10.2.3.4/32
DNS = 1.1.1.1
[Peer]
PublicKey = {KEY}
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
"""
SERVER = "11111111-1111-4111-8111-111111111111"
PEER = "22222222-2222-4222-8222-222222222222"
CONFIG = dict(serverUUID=SERVER, peerUUID=PEER, serverName="purevpn", peerName="purevpn-server")


class FakeAPI:
    def __init__(self):
        self.objects = {"server": {"name": "purevpn", "peers": "", "enabled": "0", "port": "51821"},
                        "client": {"name": "purevpn-server", "servers": "", "enabled": "0"}}
        self.writes = []
        self.reject = False
        self.mismatch = False

    def call(self, path, payload=None):
        kind = path.split("/")[0]
        if payload is None:
            return {kind: copy.deepcopy(self.objects[kind])}
        self.writes.append(path)
        if kind == "service":
            return {"result": "ok"}
        if self.reject:
            return {"result": "failed"}
        if not self.mismatch:
            self.objects[kind].update(payload[kind])
        return {"result": "saved"}


class Tests(unittest.TestCase):
    def setUp(self):
        mock = patch.object(app, "derive_public", return_value=KEY)
        mock.start()
        self.addCleanup(mock.stop)

    def test_mapping(self):
        data = app.profile(PROFILE)
        self.assertEqual(data["host"], "vpn.example.com")
        self.assertEqual(data["private"], KEY)
        self.assertEqual(data["address"], "10.2.3.4/32")

    def test_invalid_profiles(self):
        for bad in ("", PROFILE.replace(KEY, "bad"), PROFILE + "PostUp = evil\n",
                    PROFILE.replace("10.2.3.4/32", "::1/128"),
                    PROFILE.replace("0.0.0.0/0", "::/0"),
                    PROFILE.replace(":51820", ":99999"), PROFILE + "[Peer]\n"):
            with self.subTest(bad=bad), self.assertRaises((ValueError, app.configparser.Error, KeyError)):
                app.profile(bad)

    def test_read_only(self):
        api = FakeAPI()
        self.assertEqual(app.synchronize(api, CONFIG, app.profile(PROFILE)), 2)
        self.assertEqual(api.writes, [])

    def test_update_and_healthy_repeat(self):
        api = FakeAPI()
        data = app.profile(PROFILE)
        self.assertEqual(app.synchronize(api, CONFIG, data, True, lambda _: KEY), 2)
        self.assertEqual(api.objects["server"]["enabled"], "0")
        self.assertEqual(api.objects["server"]["port"], "51821")
        self.assertEqual(api.objects["client"]["serveraddress"], "vpn.example.com")
        api.writes.clear()
        self.assertEqual(app.synchronize(api, CONFIG, data, True, lambda _: KEY), 0)
        self.assertEqual(api.writes, [])

    def test_repair_changed_endpoint(self):
        api = FakeAPI()
        data = app.profile(PROFILE)
        app.synchronize(api, CONFIG, data, True, lambda _: KEY)
        api.objects["client"]["serveraddress"] = "old.example.com"
        api.writes.clear()
        self.assertEqual(app.synchronize(api, CONFIG, data, True, lambda _: KEY), 1)
        self.assertEqual(api.writes, ["client/setClient/" + PEER, "service/reconfigure"])

    def test_api_rejection_and_readback_failure(self):
        for mode in ("reject", "mismatch"):
            api = FakeAPI()
            setattr(api, mode, True)
            with self.assertRaises(ValueError):
                app.synchronize(api, CONFIG, app.profile(PROFILE), True, lambda _: KEY)
            self.assertNotIn("service/reconfigure", api.writes)

    def test_unrelated_or_shared_objects(self):
        for field, value in (("name", "other"), ("peers", PEER + ",other")):
            api = FakeAPI()
            api.objects["server"][field] = value
            with self.assertRaises(ValueError):
                app.synchronize(api, CONFIG, app.profile(PROFILE), True, lambda _: KEY)
            self.assertEqual(api.writes, [])

    def test_opnsense_selection_objects(self):
        api = FakeAPI()
        data = app.profile(PROFILE)
        app.synchronize(api, CONFIG, data, True, lambda _: KEY)
        api.objects["server"]["peers"] = {PEER: {"selected": 1}, "other": {"selected": 0}}
        api.objects["client"]["servers"] = {SERVER: {"selected": "1"}}
        api.writes.clear()
        self.assertEqual(app.synchronize(api, CONFIG, data, True, lambda _: KEY), 0)
        self.assertEqual(api.writes, [])

    def test_tls_and_http_errors(self):
        config = dict(opnsenseURL="https://firewall.example.com", opnsenseKey="test", opnsenseSecret="test")
        api = app.API(config)
        api.session.request = Mock(return_value=Mock(status_code=401))
        with self.assertRaises(ValueError):
            api.call("server/searchServer")
        with self.assertRaises(ValueError):
            app.API(dict(config, caBundle=False))
        with self.assertRaises(ValueError):
            app.API(dict(config, opnsenseURL="http://firewall.example.com"))
        for value in (False, None, 0, "", "missing-ca.pem"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.API(dict(config, caBundle=value))

    def test_public_key_drift(self):
        api = FakeAPI()
        data = app.profile(PROFILE)
        app.synchronize(api, CONFIG, data, True)
        api.objects["server"]["pubkey"] = "stale"
        self.assertEqual(app.synchronize(api, CONFIG, data, True), 1)
        self.assertEqual(api.objects["server"]["pubkey"], KEY)

    def test_pending_activation_retry(self):
        api = FakeAPI()
        data = app.profile(PROFILE)
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pending"
            original = api.call
            def failed(path, payload=None):
                return {"result": "failed"} if path == "service/reconfigure" else original(path, payload)
            api.call = failed
            with self.assertRaises(ValueError):
                app.synchronize(api, CONFIG, data, True, pending_file=marker)
            self.assertTrue(marker.exists())
            api.call = original
            api.writes.clear()
            self.assertEqual(app.synchronize(api, CONFIG, data, True, pending_file=marker), 0)
            self.assertEqual(api.writes, ["service/reconfigure"])
            self.assertFalse(marker.exists())

    def test_mtu_requires_review(self):
        with self.assertRaises(ValueError):
            app.profile(PROFILE.replace("DNS =", "MTU = 1380\nDNS ="))


if __name__ == "__main__":
    unittest.main()
