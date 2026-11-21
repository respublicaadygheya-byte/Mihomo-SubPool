#!/usr/bin/env python3
"""Offline unit tests for the upgraded pipeline (no network needed)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from name_registry import NameRegistry
from parser import parse_links
from filters import compile_group_filter, filter_names
from util import ParseError, ProxyBudget, parse_query, first_query_values


class TestNameRegistry(unittest.TestCase):
    def test_zero_padded(self):
        r = NameRegistry()
        self.assertEqual(r.register("HK"), "HK")
        self.assertEqual(r.register("HK"), "HK-01")
        self.assertEqual(r.register("HK"), "HK-02")


class TestParser(unittest.TestCase):
    def test_vless_tls_ws(self):
        link = "vless://abc-123@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fws&host=example.com#Test%20Node"
        p = parse_links(link)[0]
        self.assertEqual(p["type"], "vless")
        self.assertEqual(p["server"], "example.com")
        self.assertEqual(p["port"], 443)
        self.assertTrue(p["tls"])
        self.assertEqual(p["network"], "ws")
        self.assertEqual(p["ws-opts"]["path"], "/ws")
        self.assertEqual(p["name"], "Test Node")

    def test_vless_reality_grpc(self):
        link = "vless://uuid@host.net:8443?security=reality&pbk=KEY123&sid=abc&type=grpc&serviceName=svc&fp=chrome#Reality"
        p = parse_links(link)[0]
        self.assertEqual(p["reality-opts"]["public-key"], "KEY123")
        self.assertEqual(p["reality-opts"]["short-id"], "abc")
        self.assertEqual(p["grpc-opts"]["grpc-service-name"], "svc")

    def test_trojan(self):
        link = "trojan://pass@trojan.example.com:443?sni=trojan.example.com&alpn=h2,http/1.1#Trojan"
        p = parse_links(link)[0]
        self.assertEqual(p["type"], "trojan")
        self.assertEqual(p["password"], "pass")
        self.assertEqual(p["alpn"], ["h2", "http/1.1"])

    def test_hysteria2(self):
        link = "hysteria2://authpass@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=secret#HY2"
        p = parse_links(link)[0]
        self.assertEqual(p["type"], "hysteria2")
        self.assertEqual(p["password"], "authpass")
        self.assertEqual(p["obfs"], "salamander")

    def test_ss_base64(self):
        import base64
        cred = base64.b64encode(b"aes-256-gcm:passwd").decode().rstrip("=")
        link = f"ss://{cred}@ss.example.com:8388#SS-Node"
        p = parse_links(link)[0]
        self.assertEqual(p["type"], "ss")
        self.assertEqual(p["cipher"], "aes-256-gcm")
        self.assertEqual(p["password"], "passwd")

    def test_bad_link_raises(self):
        with self.assertRaises(ParseError):
            parse_links("vless://broken-no-at-sign#name")

    def test_multiple_protocols(self):
        text = "\n".join([
            "vless://u1@a.com:443?security=tls#V1",
            "trojan://p1@b.com:443#T1",
            "hysteria2://h1@c.com:443#H1",
        ])
        self.assertEqual(len(parse_links(text)), 3)


class TestFilters(unittest.TestCase):
    def test_regex_group(self):
        patterns, remote = compile_group_filter("Telegram|WhatsApp")
        names = ["Telegram US", "France BL", "WhatsApp SG"]
        self.assertEqual(filter_names(patterns, names), ["Telegram US", "WhatsApp SG"])


class TestBudget(unittest.TestCase):
    def test_node_limit(self):
        b = ProxyBudget(max_nodes=2)
        b.add({"name": "a"})
        b.add({"name": "b"})
        with self.assertRaises(ParseError):
            b.add({"name": "c"})


class TestQuery(unittest.TestCase):
    def test_repeated_and_invalid(self):
        q = parse_query("a=1&a=2&bad=%ZZ&b=x")
        self.assertEqual(q["a"], ["1", "2"])
        self.assertEqual(q["b"], ["x"])
        self.assertEqual(first_query_values(q)["a"], "1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
