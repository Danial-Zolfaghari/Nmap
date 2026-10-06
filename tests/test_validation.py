import unittest

from nmap_wrapper import is_valid_hostname, is_valid_ip, is_valid_network


class TargetValidationTests(unittest.TestCase):
    def test_ip_validation(self):
        self.assertTrue(is_valid_ip("192.0.2.10"))
        self.assertTrue(is_valid_ip("2001:db8::1"))
        self.assertFalse(is_valid_ip("999.1.1.1"))

    def test_network_validation(self):
        self.assertTrue(is_valid_network("192.0.2.0/24"))
        self.assertTrue(is_valid_network("2001:db8::/32"))
        self.assertFalse(is_valid_network("example.com/24"))

    def test_hostname_validation(self):
        self.assertTrue(is_valid_hostname("example.com"))
        self.assertTrue(is_valid_hostname("sub-domain.example.com"))
        self.assertTrue(is_valid_hostname("example.com."))
        self.assertFalse(is_valid_hostname(""))
        self.assertFalse(is_valid_hostname("."))
        self.assertFalse(is_valid_hostname("-bad.example"))
        self.assertFalse(is_valid_hostname("bad-.example"))


if __name__ == "__main__":
    unittest.main()
