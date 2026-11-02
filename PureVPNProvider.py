#!/usr/local/bin/python3
"""Authenticated PureVPN profile provisioning. Never logs credentials or keys."""
import argparse
import base64
import configparser
import getpass
import ipaddress
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urljoin, urlsplit

import requests

AUTH = "https://auth.purevpn.com"
APP = "https://my.purevpn.com"
CLIENT = "ed1ee674-0a34-4265-b4a1-141b721036eb"
REDIRECT = APP + "/v2/api/fusionauth/login"


class ProviderError(RuntimeError):
    pass


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("type") == "hidden" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")


def private_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise


def location_label(location):
    country = location["country_code"].lower()
    city_id = int(location["city_id"])
    if not re.fullmatch(r"[a-z]{2}", country) or city_id <= 0:
        raise ProviderError("Invalid location identifier")
    return country + "-" + str(city_id)


def validate_profile(text, private_key):
    ini = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        ini.read_string(text)
        if set(ini.sections()) != {"Interface", "Peer"}:
            raise ValueError()
        interface, peer = ini["Interface"], ini["Peer"]
        if interface["PrivateKey"] != private_key:
            raise ValueError()
        for value in (private_key, peer["PublicKey"]):
            if len(base64.b64decode(value, validate=True)) != 32:
                raise ValueError()
        for value in interface["Address"].split(","):
            ipaddress.ip_interface(value.strip())
        for value in peer["AllowedIPs"].split(","):
            ipaddress.ip_network(value.strip(), strict=False)
        endpoint = urlsplit("//" + peer["Endpoint"])
        if not endpoint.hostname or endpoint.username or not 1 <= endpoint.port <= 65535:
            raise ValueError()
        if "MTU" in interface and not 1280 <= int(interface["MTU"]) <= 9000:
            raise ValueError()
        if "PersistentKeepalive" in peer and not 0 <= int(peer["PersistentKeepalive"]) <= 65535:
            raise ValueError()
        if "PresharedKey" in peer and len(base64.b64decode(peer["PresharedKey"], validate=True)) != 32:
            raise ValueError()
    except (ValueError, KeyError, TypeError, configparser.Error):
        raise ProviderError("Invalid or unexpected provider configuration") from None
    return ini


class Provider:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.trust_env = False
        self.session.verify = True
        self.token = None
        self.subscription = None
        self.username = None
        self.encrypted_password = None

    def request(self, method, url, **kwargs):
        if urlsplit(url).scheme != "https" or urlsplit(url).netloc not in ("auth.purevpn.com", "my.purevpn.com"):
            raise ProviderError("Unexpected provider destination")
        response = self.session.request(method, url, timeout=30, allow_redirects=False, **kwargs)
        if response.status_code not in (200, 301, 302, 303, 307, 308):
            raise ProviderError("Provider HTTP " + str(response.status_code))
        return response

    def follow(self, response, url):
        for _ in range(10):
            if response.status_code == 200:
                return response
            destination = urljoin(url, response.headers.get("Location", ""))
            response = self.request("GET", destination)
            url = destination
        raise ProviderError("Provider redirect limit reached")

    def api(self, path, data=None, method="POST"):
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        response = self.request(method, APP + "/v2/api/" + path, data=data, headers=headers)
        if response.status_code != 200:
            raise ProviderError("Provider requires a new login")
        try:
            result = response.json()
        except ValueError:
            raise ProviderError("Provider returned an interactive page; no bypass attempted") from None
        if result.get("status") is not True:
            raise ProviderError("Provider rejected " + path)
        return result.get("body")

    def login(self, email, password, vpn_username=None):
        url = AUTH + "/oauth2/authorize"
        initial = self.request("GET", url, params={"client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code"})
        initial = self.follow(initial, url)
        form = LoginForm()
        form.feed(initial.text)
        fields = form.fields
        fields.update({"client_id": CLIENT, "redirect_uri": REDIRECT,
                       "response_type": "code", "loginId": email, "password": password,
                       "showPasswordField": "true", "timezone": "Europe/London"})
        result = self.request("POST", url, data=fields, headers={
            "Origin": AUTH, "Referer": AUTH + "/",
            "Content-Type": "application/x-www-form-urlencoded"})
        self.follow(result, url)
        tokens = [c.value for c in self.session.cookies if c.name == "fa_token" and c.domain.lstrip(".") in ("purevpn.com", "my.purevpn.com")]
        if not tokens or len(set(tokens)) != 1:
            raise ProviderError("Login did not complete; interactive verification may be required")
        self.token = tokens[0]
        body = self.api("on-boarding")
        candidates = []
        for subscription in body.get("subscriptions", []):
            for username in subscription.get("vpnusernames", []):
                if vpn_username is None or username == vpn_username:
                    candidates.append((subscription["id"], username))
        if len(candidates) != 1:
            raise ProviderError("Choose exactly one VPN username in the credential file")
        self.subscription, self.username = candidates[0]
        credentials = self.api("wireguard/get-encrypt-password", {"username": self.username})
        self.encrypted_password = credentials["encrypPass"]

    def locations(self):
        body = self.api("manual/configuration", method="GET")
        if not isinstance(body, list):
            raise ProviderError("Unexpected location catalogue structure")
        locations = []
        for country in body:
            for city in country.get("cities", []):
                locations.append({"country": country["name"], "country_code": country["iso_code"],
                                  "city": city["name"], "city_id": int(city["id"])})
        if not locations:
            raise ProviderError("Provider returned an empty location catalogue")
        return locations

    def provision(self, location, private_key, public_key):
        payload = {"sUsername": self.username, "sPassword": self.encrypted_password,
                   "sCountrySlug": location["country_code"], "iCityId": str(location["city_id"]),
                   "sDeviceType": "linux", "sClientPublicKey": public_key,
                   "sSubsId": str(self.subscription), "natServer": "1"}
        body = self.api("wireguard/get-wg-server", payload)
        if isinstance(body, list):
            if len(body) != 1:
                raise ProviderError("Ambiguous provider configuration")
            body = body[0]
        text = body.get("wireguard_configuration", "") if isinstance(body, dict) else ""
        text = text.replace("{clientPrivateKey}", private_key)
        validate_profile(text, private_key)
        return text


def keypair(path):
    path = Path(path)
    if path.exists():
        if path.is_symlink() or not path.is_file() or (os.name == "posix" and path.stat().st_mode & 0o077):
            raise ProviderError("Client identity must be a private regular file")
        private = path.read_text(encoding="utf-8").strip()
    else:
        private = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
        private_write(path, private + "\n")
    if len(base64.b64decode(private, validate=True)) != 32:
        raise ProviderError("Invalid saved client identity")
    public = subprocess.run(["wg", "pubkey"], input=private + "\n", capture_output=True, text=True, check=True).stdout.strip()
    return private, public


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--setup-login", action="store_true")
    parser.add_argument("--all", action="store_true", help="Generate a profile for every returned city")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Run credential operations on OPNsense or another POSIX host with mode-0600 file protection")
    try:
        if args.setup_login:
            email = input("PureVPN account email: ").strip()
            password = getpass.getpass("PureVPN account password (hidden): ")
            private_write(args.credentials, json.dumps({"email": email, "password": password}))
        credentials_path = Path(args.credentials)
        if os.name != "nt" and credentials_path.stat().st_mode & 0o077:
            raise ProviderError("Credential file must have mode 0600")
        credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
        provider = Provider()
        provider.login(credentials["email"], credentials["password"], credentials.get("vpn_username"))
        locations = provider.locations()
        output = Path(args.output)
        private_write(output / "locations.json", json.dumps(locations, indent=2))
        print("Authenticated; found", len(locations), "city locations", flush=True)
        if args.all:
            completed = []
            for location in locations:
                label = location_label(location)
                private, public = keypair(output / (label + ".key"))
                text = provider.provision(location, private, public)
                private_write(output / (label + ".conf"), text)
                completed.append({**location, "file": label + ".conf"})
                private_write(output / "manifest.json", json.dumps(completed, indent=2))
                print("Saved", label, flush=True)
        return 0
    except (ProviderError, requests.RequestException, KeyError, ValueError, OSError, subprocess.SubprocessError):
        print("Provisioning failed; no firewall changes made. Check authentication or provider response.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
