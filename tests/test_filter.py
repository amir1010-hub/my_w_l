import base64
import json
import unittest
from filter import filter_links, matches


def vmess(name):
    payload = json.dumps({
        "v": "2", "ps": name, "add": "example.com", "port": "443"
    }).encode("utf-8")
    return "vmess://" + base64.b64encode(payload).decode("ascii")


class FilterTests(unittest.TestCase):
    def test_only_aetrisvpn_white_list_is_accepted(self):
        names = [
            "AetrisVPN White list",
            "AetrisVPN White list 🇷🇺",
            "aetrisvpn white list",
            "AetrisVPN White-list",
            "AetrisVPN White_list",
            "AetrisVPN.White.list",
        ]
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(matches("vless://test@example.com:443#" + name))

    def test_other_names_are_rejected(self):
        names = [
            "White list", "Whitelist", "white-list", "WHITE", "Allow List",
            "bypass", "Обход белых списков", "БЕЛЫЕ", "белых",
            "белый список", "вайтлист", "разблокировка",
            "AetrisVPN", "AetrisVPN bypass", "AetrisVPN White listExtra",
            "Россия", "Белгород", "Беларусь", "Normal proxy",
        ]
        for name in names:
            with self.subTest(name=name):
                self.assertFalse(matches("vless://test@example.com:443#" + name))

    def test_only_name_not_sni_or_path(self):
        link = (
            "vless://test@example.com:443?security=reality"
            "&sni=aetrisvpn-white-list.example.com"
            "&path=%2FAetrisVPN%20White%20list#Germany"
        )
        self.assertFalse(matches(link))

    def test_percent_encoded_name(self):
        self.assertTrue(matches(
            "vless://test@example.com:443#AetrisVPN%20White%20list"
        ))
        self.assertFalse(matches(
            "vless://test@example.com:443#%D0%9E%D0%B1%D1%85%D0%BE%D0%B4"
        ))

    def test_vmess_ps(self):
        self.assertTrue(matches(vmess("AetrisVPN White list")))
        self.assertFalse(matches(vmess("Белых списков")))
        self.assertFalse(matches(vmess("Regular server")))

    def test_preserve_bytes_and_dedup(self):
        first = "vless://one@example.org:443?security=reality#AetrisVPN%20White%20list"
        duplicate = "vless://one@example.org:443?security=reality#AetrisVPN%20White-list"
        third = "trojan://pass@example.org:443#AetrisVPN%20White%20list"
        excluded = "vless://third@example.org:443#White%20list"
        text = "#profile-title: example\n" + "\n".join(
            [first, duplicate, third, excluded]
        )
        links, total = filter_links(text)
        self.assertEqual(total, 4)
        self.assertEqual(links, [first, third])


if __name__ == "__main__":
    unittest.main()
