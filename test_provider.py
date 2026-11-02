import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import requests
import PureVPNProvider as app

KEY = base64.b64encode(bytes(range(32))).decode()
PUBLIC = base64.b64encode(bytes(reversed(range(32)))).decode()


def response(body=None, status=200, text=""):
    result = Mock(status_code=status, text=text, headers={})
    result.json.return_value = body
    return result


class Tests(unittest.TestCase):
    def session(self):
        session = Mock()
        session.cookies = requests.cookies.RequestsCookieJar()
        return session

    def test_tls_and_destination_boundary(self):
        session = self.session()
        provider = app.Provider(session)
        self.assertIs(session.verify, True)
        for destination in ("http://my.purevpn.com", "https://my.purevpn.com.evil.example/", "https://user@my.purevpn.com/"):
            with self.assertRaises(app.ProviderError):
                provider.request("POST", destination, data={"password": "secret"})
        session.request.assert_not_called()

    def test_login_and_account_selection(self):
        session = self.session()
        session.cookies.set("fa_token", "test-token", domain=".purevpn.com")
        session.request.side_effect = [
            response(text='<input type="hidden" name="csrf" value="test-csrf">'),
            response(),
            response({"status": True, "body": {"subscriptions": [{"id": 5, "vpnusernames": ["vpn-user"]}]}}),
            response({"status": True, "body": {"encrypPass": "test-encrypted"}}),
        ]
        provider = app.Provider(session)
        provider.login("test@example.com", "test-password")
        self.assertEqual(provider.subscription, 5)
        self.assertEqual(provider.username, "vpn-user")
        submitted = session.request.call_args_list[1].kwargs["data"]
        self.assertEqual(submitted["csrf"], "test-csrf")
        self.assertEqual(submitted["password"], "test-password")
        headers = session.request.call_args_list[1].kwargs["headers"]
        self.assertEqual(headers["Origin"], app.AUTH)
        self.assertEqual(headers["Referer"], app.AUTH + "/")
        self.assertEqual(headers["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(session.request.call_args_list[2].kwargs["headers"]["Authorization"], "Bearer test-token")

    def test_interactive_login_is_not_bypassed(self):
        session = self.session()
        session.request.return_value = response(text="interactive verification required")
        with self.assertRaises(app.ProviderError):
            app.Provider(session).login("test@example.com", "test-password")
        self.assertEqual(session.request.call_count, 2)

    def test_redirect_to_other_host_rejected(self):
        session = self.session()
        first = response(status=302)
        first.headers = {"Location": "https://other.example/collect"}
        with self.assertRaises(app.ProviderError):
            app.Provider(session).follow(first, app.AUTH)
        session.request.assert_not_called()

    def test_api_rejects_failures(self):
        for result in (response({"status": False}), response(status=403), response(status=302)):
            session = self.session()
            session.request.return_value = result
            with self.assertRaises(app.ProviderError):
                app.Provider(session).api("on-boarding")
        session = self.session()
        session.request.return_value.json.side_effect = ValueError("html")
        session.request.return_value.status_code = 200
        with self.assertRaises(app.ProviderError):
            app.Provider(session).api("on-boarding")

    def test_location_values(self):
        session = self.session()
        session.request.return_value = response({"status": True, "body": [
            {"name": "Bulgaria", "iso_code": "BG", "cities": [{"name": "Sofia", "id": 123}]}]})
        self.assertEqual(app.Provider(session).locations(), [{"country": "Bulgaria", "country_code": "BG", "city": "Sofia", "city_id": 123}])
        session.request.return_value = response({"status": True, "body": []})
        with self.assertRaises(app.ProviderError):
            app.Provider(session).locations()

    def test_identity_preserved_and_validated(self):
        session = self.session()
        config = "[Interface]\nPrivateKey={clientPrivateKey}\nAddress=172.21.7.1\n[Peer]\nPublicKey=" + PUBLIC + "\nAllowedIPs=0.0.0.0/0\nEndpoint=vpn.example.com:51820\n"
        session.request.return_value = response({"status": True, "body": [{"wireguard_configuration": config}]})
        provider = app.Provider(session)
        provider.username = "vpn-user"
        provider.encrypted_password = "test-encrypted"
        provider.subscription = 5
        location = {"country_code": "BG", "city_id": 123}
        generated = provider.provision(location, KEY, PUBLIC)
        self.assertIn("PrivateKey=" + KEY, generated)
        payload = session.request.call_args.kwargs["data"]
        self.assertEqual(payload["sClientPublicKey"], PUBLIC)
        self.assertNotIn(KEY, payload.values())
        session.request.return_value = response({"status": True, "body": [{"wireguard_configuration": config.replace("{clientPrivateKey}", "wrong")}]})
        with self.assertRaises(app.ProviderError):
            provider.provision(location, KEY, KEY)

    def test_atomic_private_output(self):
        Path("private").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir="private") as directory:
            path = Path(directory) / "private" / "profile.conf"
            app.private_write(path, "first")
            app.private_write(path, "second")
            self.assertEqual(path.read_text(), "second")
            self.assertFalse(path.with_name(path.name + ".tmp").exists())

    def test_stable_identifiers_avoid_name_collisions(self):
        self.assertEqual(app.location_label({"country_code": "BG", "city_id": 123, "city": "renamed"}), "bg-123")
        self.assertNotEqual(app.location_label({"country_code": "BG", "city_id": 123}), app.location_label({"country_code": "BG", "city_id": 124}))

    def test_invalid_profiles_rejected(self):
        for text in ("", "[Interface]\nPrivateKey=" + KEY + "\n[Peer]\nEndpoint=vpn.example.com:51820\n"):
            with self.assertRaises(app.ProviderError):
                app.validate_profile(text, KEY)


if __name__ == "__main__":
    unittest.main()
