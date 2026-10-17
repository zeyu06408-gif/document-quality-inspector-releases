import unittest
from verify_windows_payload import MARKER, verify


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.compiled = b'MZ-content' + MARKER + b'UNK\xc0\x00-code-and-resources'
        self.installed = self.compiled.replace(MARKER + b'UNK', MARKER + b'NSS')

    def test_only_bundle_patch_is_allowed(self):
        self.assertTrue(verify(self.compiled, self.installed, self.installed)['verified'])

    def test_other_changes_are_rejected(self):
        for bad in [b'X' + self.installed[1:], self.installed + b'X', self.installed[:-1], self.compiled]:
            with self.assertRaises(ValueError):
                verify(self.compiled, bad, bad)

    def test_missing_duplicate_or_wrong_markers_are_rejected(self):
        for bad in [b'MZ-no-marker', self.compiled + MARKER + b'UNK', self.installed]:
            with self.assertRaises(ValueError):
                verify(bad, self.installed, self.installed)

    def test_extraction_and_install_must_agree(self):
        with self.assertRaises(ValueError):
            verify(self.compiled, self.installed, self.installed + b'X')


if __name__ == '__main__':
    unittest.main()
