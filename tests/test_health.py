import base64
import json
import unittest
from health_check import endpoint, ProbeResult, build_live_set


def b64(x):
    return base64.b64encode(x.encode()).decode().rstrip('=')


class HealthTests(unittest.TestCase):
    def test_parse_vless(self):
        self.assertEqual(endpoint('vless://uuid@1.2.3.4:443?security=reality#white'), ('1.2.3.4', 443))

    def test_parse_vmess(self):
        payload = b64(json.dumps({'add':'example.net', 'port':'8443', 'ps':'WHITE'}))
        self.assertEqual(endpoint('vmess://'+payload), ('example.net',8443))

    def test_parse_ss_b64(self):
        self.assertEqual(endpoint('ss://'+b64('aes-256-gcm:pw')+'@ex.org:8388#white'), ('ex.org',8388))
        self.assertEqual(endpoint('ss://'+b64('aes-256-gcm:pw@ex.org:8388')+'#white'), ('ex.org',8388))

    def test_udp_never_tcp_probed(self):
        self.assertIsNone(endpoint('hy2://password@example.org:443#white'))
        self.assertIsNone(endpoint('tuic://uuid:pw@example.org:443#white'))

    def test_no_zero_wipe(self):
        with self.assertRaisesRegex(ValueError, 'All TCP'):
            build_live_set(['a','b'],[ProbeResult('failed'),ProbeResult('failed')],10)

    def test_mass_failure_guard(self):
        with self.assertRaisesRegex(ValueError, 'Under 25%'):
            build_live_set(['a']*8,[ProbeResult('ok',12)] + [ProbeResult('failed')]*7,4)

    def test_previous_count_guard(self):
        with self.assertRaisesRegex(ValueError,'Abrupt drop'):
            build_live_set(['a']*3, [ProbeResult('ok',12)]*3,25)

    def test_keep_udp_and_success(self):
        items=['a','b','c']
        live, summary = build_live_set(items,[ProbeResult('ok',30),ProbeResult('failed'),ProbeResult('unsupported')])
        self.assertEqual(live,['a','c'])
        self.assertEqual(summary['published'],2)

    def test_no_reorder(self):
        items=['a','b']
        live,_ = build_live_set(items,[ProbeResult('ok',70),ProbeResult('ok',10)])
        self.assertEqual(live, items)


if __name__=='__main__':
    unittest.main()
