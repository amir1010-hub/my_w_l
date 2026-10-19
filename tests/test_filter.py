import base64
import json
import unittest
from filter import proxy_name, filter_links, matches


def vmess(name):
    payload = json.dumps({"v": "2", "ps": name, "add": "example.com", "port": "443"}).encode()
    return "vmess://" + base64.b64encode(payload).decode()


class FilterTests(unittest.TestCase):
    def test_labels_russian_and_english(self):
        names = ["AetrisVPN White list", "AetrisVPN White-list", "AETRISVPN WHITE LIST", "AetrisVPN White_list"]
       # names = ["White list", "Whitelist", "white-list", "WHITE", "Allow List", "bypass", "Обход белых списков", "БЕЛЫЕ", "белых", "белый список", "вайтлист", "разблокировка"]
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(matches("vless://test@example.com:443#" + name))

    def test_unrelated_names(self):
        for name in ["Россия", "Белгород", "Беларусь", "Normal proxy", "not-whitefish", "Whitehouse"]:
            with self.subTest(name=name):
                self.assertFalse(matches("vless://test@example.com:443#" + name))

    def test_only_name_not_sni_or_path(self):
                self.assertTrue(matches("vless://test@example.com:443#AetrisVPN%20White%20list"))
      #  link = "vless://test@example.com:443?security=reality&sni=whitelist.example.com&path=%2Fbypass#DE"
        self.assertFalse(matches(link))

    def test_percent_encoded_name(self):
         self.assertTrue(matches(vmess("AetrisVPN White list")))
      #  self.assertTrue(matches("vless://test@example.com:443#%D0%9E%D0%B1%D1%85%D0%BE%D0%B4%20%D0%91%D0%A1"))

    def test_vmess_ps(self):
        self.assertTrue(matches(vmess("Белых списков")))
        self.assertFalse(matches(vmess("Regular server")))

    def test_preserve_bytes_and_dedup(self):
                first = "vless://one@example.org:443?security=reality#AetrisVPN%20White%20list"
        second = "vless://one@example.org:443?security=reality#AetrisVPN%20White-list"
        third = "trojan://pass@example.org:443#AetrisVPN%20White%20list"
      #  first = "vless://one@example.org:443?security=reality#White%20List"
        #second = "vless://one@example.org:443?security=reality#bypass"
       # third = "trojan://pass@example.org:443#%D0%BE%D0%B1%D1%85%D0%BE%D0%B4"
        text = "#profile-title: example\n" + "\n".join([first, second, third, "vless://third@example.org:443#Germany"])
        links, total = filter_links(text)
        self.assertEqual(total, 4)
        self.assertEqual(links, [first, third])


if __name__ == "__main__":
    unittest.main()
