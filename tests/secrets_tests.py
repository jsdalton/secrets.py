import base64
import filecmp
import os
import shutil
import unittest

from secrets import (encrypt, decrypt, verified_encrypt, verified_decrypt,
                     verify, encrypt_file, decrypt_file, verified_encrypt_file,
                     verified_decrypt_file, verify_file)

from tests import TEST_FILES_DIR

TEST_KEY = "foobar1234"


class SecretsTest(unittest.TestCase):
    def setUp(self):
        self.filepath = {
            'unencrypted': os.path.join(TEST_FILES_DIR, "config.ini"),
            'encrypted': os.path.join(TEST_FILES_DIR, "config.ini.encrypted"),
            'test': os.path.join(TEST_FILES_DIR, "config.ini.test"),
            'encryption-test-result': os.path.join(TEST_FILES_DIR,
                                                   "config.ini.test.encrypted"),
            'decryption-test-result': os.path.join(TEST_FILES_DIR,
                                                   "config.ini.test.decrypted"),
        }

    def tearDown(self):
        for f in self.filepath.keys():
            if "test" in f and os.path.exists(self.filepath[f]):
                os.remove(self.filepath[f])

    def test_encrypt_and_decrypt_should_be_reversible(self):
        # setup
        msg = "This is my party."

        encrypted_msg = encrypt(TEST_KEY, msg, base64_encode=False)
        decrypted_msg = decrypt(TEST_KEY, encrypted_msg, base64_decode=False)

        self.assertEqual(msg, decrypted_msg)

    def test_encrypt_and_decrypt_should_optionally_encode_and_decode_in_b64(self):
        # setup
        msg = "This is my verrry fun message."

        encrypted_msg = encrypt(TEST_KEY, msg, base64_encode=True)

        # Should not raise TypeError
        base64.b64decode(encrypted_msg)

        decrypted_msg = decrypt(TEST_KEY, encrypted_msg, base64_decode=True)

        self.assertEqual(msg, decrypted_msg)

    def test_verified_encrypt_and_decrypt_should_be_reversible(self):
        msg = "This is my party."

        encrypted_msg = verified_encrypt(TEST_KEY, msg, base64_encode=False)
        decrypted_msg = verified_decrypt(TEST_KEY, encrypted_msg, base64_decode=False)

        self.assertEqual(decrypted_msg, msg)

    def test_verified_decrypt_should_return_none_with_bad_key(self):
        msg = "This is my party."
        encrypted_msg = verified_encrypt(TEST_KEY, msg, base64_encode=False)

        decrypted_msg = verified_decrypt("bad key!", encrypted_msg, base64_decode=False)

        self.assertEqual(decrypted_msg, None)

    def test_verified_decrypt_should_return_none_with_bad_msg(self):
        msg = "This is my party."
        bad_msg = "blah1" # Incorrect base64 padding

        # base 64
        encrypted_msg = verified_encrypt(TEST_KEY, msg, base64_encode=True)
        decrypted_msg = verified_decrypt(TEST_KEY, bad_msg, base64_decode=True)
        self.assertEqual(decrypted_msg, None)

        # not base 64
        encrypted_msg = verified_encrypt(TEST_KEY, msg, base64_encode=False)
        decrypted_msg = verified_decrypt(TEST_KEY, bad_msg, base64_decode=False)
        self.assertEqual(decrypted_msg, None)

    def test_verified_encrypt_and_decrypt_in_base64_should_be_reversible(self):
        msg = "This is my party."

        encrypted_msg = verified_encrypt(TEST_KEY, msg, base64_encode=True)

        # Should not raise TypeError.
        base64.b64decode(encrypted_msg)

        decrypted_msg = verified_decrypt(TEST_KEY, encrypted_msg, base64_decode=True)

        self.assertEqual(msg, decrypted_msg)

    def test_verify(self):
        msg = "This is my party."
        encrypted_msg = verified_encrypt(TEST_KEY, msg, base64_encode=False)

        self.assertEqual(verify(TEST_KEY, encrypted_msg, base64_decode=False), True)
        self.assertEqual(verify("bad key!", encrypted_msg, base64_decode=False), False)

        # base 64 check
        encrypted_msg = verified_encrypt(TEST_KEY, msg, base64_encode=True)
        self.assertEqual(verify(TEST_KEY, "blah1", base64_decode=True), False)

    def test_verify_base64(self):
        msg = "This is my party."
        encrypted_msg = verified_encrypt(TEST_KEY, msg, base64_encode=True)

        self.assertTrue(verify(TEST_KEY, encrypted_msg, base64_decode=True))

    def test_encrypt_and_decrypt_file_are_reversible(self):
        # setup - create test file
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['test'])

        # test encrypt
        encrypt_file(TEST_KEY, self.filepath['test'],
                     self.filepath['encryption-test-result'])

        # assert is different from the original
        self.assertFalse(filecmp.cmp(self.filepath['encryption-test-result'],
                                     self.filepath['test']))

        decrypt_file(TEST_KEY, self.filepath['encryption-test-result'],
                     self.filepath['test'])

        # assert back to original
        self.assertTrue(filecmp.cmp(self.filepath['test'],
                                    self.filepath['unencrypted']),
                        "Files don't match!")

    def test_encrypt_and_decrypt_file_verified_are_reversible(self):
        # setup - create test file
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['test'])

        # test encrypt
        verified_encrypt_file(TEST_KEY,
                              self.filepath['test'],
                              self.filepath['encryption-test-result'])

        # assert is different from the original
        self.assertFalse(filecmp.cmp(self.filepath['encryption-test-result'],
                                     self.filepath['test']))

        verified_decrypt_file(TEST_KEY,
                              self.filepath['encryption-test-result'],
                              self.filepath['test'])

        # assert back to original
        self.assertTrue(filecmp.cmp(self.filepath['test'],
                                    self.filepath['unencrypted']),
                        "Files don't match!")

    def test_verify_file(self):
        # setup - create test file
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['test'])
        verified_encrypt_file(TEST_KEY,
                              self.filepath['test'],
                              self.filepath['encryption-test-result'])

        self.assertEqual(verify_file(TEST_KEY,
                                     self.filepath['encryption-test-result']),
                         True)
        self.assertEqual(verify_file("Bad password!",
                                     self.filepath['encryption-test-result']),
                         False)
        # Test bad file input
        self.assertEqual(verify_file("Bad password!",
                                     self.filepath['test']),
                         False)
