
import base64
import json
import unittest

from filter import filter_links, matches


def vmess(name):
    payload = json.dumps({"v": "2", "ps": name, "add": "example.com", "port": "443"}).encode()
    return "vmess://" + base64.b64encode(payload).decode()


class FilterTests(unittest.TestCase):
    def test_aetris_names(self):
        names = [
            "AetrisVPN White list",
            "AETRISVPN WHITE LIST",
            "AetrisVPN White-list",
            "AetrisVPN White_list",
            "AetrisVPN White list RU",
        ]
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(matches("vless://test@example.com:443#" + name))

    def test_unrelated_names(self):
        names = [
            "White list", "Whitelist", "bypass", "Обход белых списков",
            "AetrisVPN", "AetrisVPN обход", "OtherVPN White list",
            "AetrisVPN White listing",
        ]
        for name in names:
            with self.subTest(name=name):
                self.assertFalse(matches("vless://test@example.com:443#" + name))

    def test_only_name_not_sni_or_path(self):
        link = "vless://test@example.com:443?security=reality&sni=AetrisVPN.White.list&path=%2Fwhite#DE"
        self.assertFalse(matches(link))

    def test_percent_encoded_name(self):
        self.assertTrue(matches("vless://test@example.com:443#AetrisVPN%20White%20list"))

    def test_vmess_ps(self):
        self.assertTrue(matches(vmess("AetrisVPN White list")))
        self.assertFalse(matches(vmess("Regular server")))

    def test_preserve_bytes_and_dedup(self):
        first = "vless://one@example.org:443?security=reality#AetrisVPN%20White%20list"
        second = "vless://one@example.org:443?security=reality#AetrisVPN%20White-list"
        third = "trojan://pass@example.org:443#AetrisVPN%20White%20list"
        other = "vless://third@example.org:443#Germany"
        content = "#profile-title: example\n" + "\n".join([first, second, third, other])
        links, total = filter_links(content)
        self.assertEqual(total, 4)
        self.assertEqual(links, [first, third])


if __name__ == "__main__":
    unittest.main()
