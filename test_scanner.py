import unittest
from nginx2root_scan import nginx_version, evaluate_version, config_flags, parse_target

class ScannerTests(unittest.TestCase):
    def test_affected(self):
        for ver in ['nginx version: nginx/1.30.6', 'nginx version: nginx/1.31.8', 'nginx version: nginx/1.28.3']:
            self.assertTrue(all(v == 'AFFECTED_UPSTREAM_VERSION' for v in evaluate_version(nginx_version(ver)).values()))
    def test_fixed(self):
        for ver in ['nginx version: nginx/1.30.7', 'nginx version: nginx/1.31.9']:
            self.assertTrue(all(v == 'FIXED_UPSTREAM' for v in evaluate_version(nginx_version(ver)).values()))
    def test_older_range(self):
        values = evaluate_version(nginx_version('nginx version: nginx/1.15.2'))
        self.assertEqual(values['CVE-2026-123007'], 'AFFECTED_UPSTREAM_VERSION')
        self.assertEqual(values['CVE-2026-123633'], 'OUTSIDE_KNOWN_RANGE')
    def test_fork(self):
        self.assertTrue(all(v == 'FORK_REQUIRES_VENDOR_ADVISORY' for v in evaluate_version(nginx_version('nginx version: openresty/1.27.1.2')).values()))
    def test_flags(self):
        flags = config_flags('listen 443 ssl http2; proxy_pass http://backend; # http2 off;')
        self.assertTrue(flags['http2_listen'])
        self.assertTrue(flags['proxying'])
        self.assertFalse(flags['http2_off'])
    def test_target(self):
        self.assertEqual(parse_target('example.com:8443')['port'], 8443)
        with self.assertRaises(ValueError):
            parse_target('http://example.com')

if __name__ == '__main__':
    unittest.main()
