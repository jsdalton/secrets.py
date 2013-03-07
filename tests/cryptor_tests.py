import filecmp
from mock import Mock
import hmac
import hashlib
import os
import shutil
import unittest
from Crypto.Cipher import AES, DES, Blowfish

from secrets.cryptors import FileCryptor, Cryptor
from tests import TEST_FILES_DIR


TEST_KEY = 'foobar1234'


class FileCryptorTest(unittest.TestCase):
    def setUp(self):
        self.filepath = {
            'unencrypted': os.path.join(TEST_FILES_DIR, "config.ini"),
            'encrypted': os.path.join(TEST_FILES_DIR, "config.ini.encrypted"),
            'test': os.path.join(TEST_FILES_DIR, "config.ini.test"),
            'encryption-test-result': os.path.join(TEST_FILES_DIR, "config.ini.test.encrypted"),
            'decryption-test-result': os.path.join(TEST_FILES_DIR, "config.ini.test.decrypted"),
        }
        self.initialize_cryptor()

    def tearDown(self):
        for f in self.filepath.keys():
            if "test" in f and os.path.exists(self.filepath[f]):
                os.remove(self.filepath[f])

    def initialize_cryptor(self):
        self.cryptor = FileCryptor()

    def test_encrypt_and_decrypt_are_reversible(self):
        # setup - create test file
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['test'])

        # test encrypt
        self.cryptor.encrypt_file(TEST_KEY,
                                  self.filepath['test'],
                                  self.filepath['encryption-test-result'],
                                  verify=False)

        # assert is different from the original
        self.assertFalse(filecmp.cmp(self.filepath['encryption-test-result'],
                                     self.filepath['test']))

        self.cryptor.decrypt_file(TEST_KEY,
                                  self.filepath['encryption-test-result'],
                                  self.filepath['test'],
                                  verify=False)

        # assert back to original
        self.assertTrue(filecmp.cmp(self.filepath['test'],
                                    self.filepath['unencrypted']),
                                    "Files don't match!")

    def test_encrypt_and_decrypt_verified_are_reversible(self):
        # setup - create test file
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['test'])

        # test encrypt
        self.cryptor.encrypt_file(TEST_KEY,
                                  self.filepath['test'],
                                  self.filepath['encryption-test-result'],
                                  verify=True)

        # assert is different from the original
        self.assertFalse(filecmp.cmp(self.filepath['encryption-test-result'],
                                     self.filepath['test']))

        self.cryptor.decrypt_file(TEST_KEY,
                                  self.filepath['encryption-test-result'],
                                  self.filepath['test'], verify=True)

        # assert back to original
        self.assertTrue(filecmp.cmp(self.filepath['test'],
                                    self.filepath['unencrypted']),
                                    "Files don't match!")



    def test_decrypt_file_should_create_new_file_with_decrypted_extension(self):
        # setup - create test file
        self.cryptor.encrypt_file(TEST_KEY,
                                  self.filepath['unencrypted'], self.filepath['test'])

        # test
        self.cryptor.decrypt_file(TEST_KEY, self.filepath['test'])

        # assert
        self.assertTrue(os.path.exists(self.filepath['decryption-test-result']), "Decrypted file not created")

    def test_decrypt_file_should_create_new_file_with_provided_output_filename(self):
        # setup
        specified_output_file_path = os.path.join(TEST_FILES_DIR, "foobar.test")
        assert not os.path.exists(specified_output_file_path)

        # setup - create test file
        self.cryptor.encrypt_file(TEST_KEY, self.filepath['unencrypted'], self.filepath['test'])

        try:
            # test
            self.cryptor.decrypt_file(TEST_KEY, self.filepath['test'], specified_output_file_path)

            # assert
            self.assertTrue(os.path.exists(specified_output_file_path), "Decrypted file not created")

        # cleanup
        finally:
            if os.path.exists(specified_output_file_path):
                os.remove(specified_output_file_path)

    def test_decrypt_file_should_remove_encrypted_extension_if_exists(self):
        # setup - create test file
        self.cryptor.encrypt_file(TEST_KEY, self.filepath['unencrypted'], self.filepath['encryption-test-result'])

        # test
        self.cryptor.decrypt_file(TEST_KEY, self.filepath['encryption-test-result'])

        # assert
        self.assertTrue(os.path.exists(self.filepath['test']), "Decrypted file '%s' not created" % self.filepath['test'])

    def test_decrypt_file_should_not_allow_input_and_output_to_match(self):
        # setup - create test file
        self.cryptor.encrypt_file(TEST_KEY, self.filepath['unencrypted'], self.filepath['test'])

        with self.assertRaises(AssertionError):
            self.cryptor.decrypt_file(TEST_KEY, self.filepath['test'], self.filepath['test'])

    def test_decrypt_file_should_not_overwrite_existing_file_if_overwrite_is_false(self):
        # setup - create test file
        self.cryptor.encrypt_file(TEST_KEY, self.filepath['unencrypted'], self.filepath['test'])
        shutil.copyfile(self.filepath['encrypted'], self.filepath['encryption-test-result'])

        with self.assertRaises(IOError):
            # test
            self.cryptor.decrypt_file(TEST_KEY, self.filepath['test'], self.filepath['encryption-test-result'], overwrite_existing=False)

    def test_decrypt_file_should_handle_encrypted_file_where_line_break_is_in_initialization_vector(self):
        # setup

        # Inject an artifical iv with linebreaks in it
        iv_with_line_break = "123\n1234\n2341234\nt3jgeggggg\ng43g33g3g3af1"[:self.cryptor.block_size]

        random_generator = Mock()
        random_generator.read = Mock()
        random_generator.read.return_value = iv_with_line_break

        try:
            original_random_generator = self.cryptor.random_generator
            self.cryptor.random_generator = random_generator

            # test
            self.cryptor.encrypt_file(TEST_KEY, self.filepath['unencrypted'], self.filepath['test'])

            # Ensure ValueError is not raised
            self.cryptor.decrypt_file(TEST_KEY, self.filepath['test'], self.filepath['decryption-test-result'])
        finally:
            self.cryptor.random_generator = original_random_generator


    def test_decrypt_file_verified_should_raise_value_error_if_password_incorrect(self):
        # setup
        shutil.copyfile(self.filepath['encrypted'], self.filepath['test'])
        self.cryptor.encrypt_file(TEST_KEY, self.filepath['test'], verify=True)

        with self.assertRaises(ValueError):
            # test
            self.cryptor.decrypt_file("bad key!",
                                      self.filepath['encryption-test-result'],
                                      self.filepath['decryption-test-result'],
                                      verify=True)

    def test_decrypt_file_should_not_raise_value_error_if_password_incorrect(self):
        # setup
        shutil.copyfile(self.filepath['encrypted'], self.filepath['test'])
        self.cryptor.encrypt_file(TEST_KEY, self.filepath['test'], verify=False)

        # test doesn't raise Value Error
        self.cryptor.decrypt_file("bad key!", self.filepath['encryption-test-result'], self.filepath['decryption-test-result'], verify=False)

    def test_decrypt_file_should_not_create_file_if_decryption_fails(self):
        # setup
        shutil.copyfile(self.filepath['encrypted'], self.filepath['test'])
        self.cryptor.encrypt_file(TEST_KEY, self.filepath['test'], verify=True)

        # test
        try:
            self.cryptor.decrypt_file("bad key!",
                                      self.filepath['encryption-test-result'],
                                      self.filepath['decryption-test-result'],
                                      verify=True)
        except ValueError:
            pass

        # assert
        self.assertFalse(os.path.exists(self.filepath['decryption-test-result']),
                         "File '%s' should not be created if decryption fails." % self.filepath['decryption-test-result'])

    def test_encrypt_file_should_create_new_file_with_default_encrypted_extension(self):
        # setup - create test file
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['test'])

        # test
        self.cryptor.encrypt_file(TEST_KEY, self.filepath['test'])

        # assert
        self.assertTrue(os.path.exists(self.filepath['encryption-test-result']), "Encrypted file not created")

    def test_encrypt_file_should_create_new_file_with_provided_output_filename(self):
        # setup
        specified_output_filename = "foobar.encrypted"
        specified_output_file_path = os.path.join(TEST_FILES_DIR, specified_output_filename)
        assert not os.path.exists(specified_output_file_path)

        try:
            # test
            self.cryptor.encrypt_file(TEST_KEY, self.filepath['unencrypted'], specified_output_file_path)

            # assert
            self.assertTrue(os.path.exists(specified_output_file_path), "Encrypted file not created")

        # cleanup
        finally:
            if os.path.exists(specified_output_file_path):
                os.remove(specified_output_file_path)

    def test_encrypt_file_should_not_allow_input_and_output_to_match(self):
        # setup
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['test'])

        # test and assert
        with self.assertRaises(AssertionError):
            self.cryptor.encrypt_file(TEST_KEY, self.filepath['test'], self.filepath['test'])

    def test_encrypt_file_should_not_overwrite_existing_file_if_overwrite_is_false(self):
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['test'])
        shutil.copyfile(self.filepath['unencrypted'], self.filepath['decryption-test-result'])

        with self.assertRaises(IOError):
            # test
            self.cryptor.encrypt_file(TEST_KEY,
                                      self.filepath['test'],
                                      self.filepath['decryption-test-result'],
                                      overwrite_existing=False)


    def test_verify_file_should_return_true_if_key_and_file_are_valid(self):
        # setup - create test file
        self.cryptor.encrypt_file(TEST_KEY,
                                  self.filepath['unencrypted'],
                                  self.filepath['test'],
                                  verify=True)

        # test
        result = self.cryptor.verify_file(TEST_KEY, self.filepath['test'])

        # assert
        self.assertTrue(result)

    def test_verify_file_should_return_false_if_key_is_wrong(self):
        # setup - create test file
        self.cryptor.encrypt_file(TEST_KEY,
                                  self.filepath['unencrypted'],
                                  self.filepath['test'], verify=True)

        # test
        result = self.cryptor.verify_file("bad key!", self.filepath['test'])

        # assert
        self.assertFalse(result)

    def test_verify_file_should_return_false_if_file_is_corrupt(self):
        # setup - create test file
        self.cryptor.encrypt_file(TEST_KEY,
                                  self.filepath['unencrypted'],
                                  self.filepath['test'], verify=True)
        with open(self.filepath['test'], 'rb+') as test_file:
            test_file.write("Some junk!")

        # test
        result = self.cryptor.verify_file(TEST_KEY, self.filepath['test'])

        # assert
        self.assertFalse(result)


class CryptorTest(unittest.TestCase):
    def setUp(self):
        self.cryptor = Cryptor()

    def test_encrypt_and_decrypt_should_be_reversible(self):
        # setup
        value = "Roses are red\nViolets are blue"

        # test
        encrypted_value = self.cryptor.encrypt(TEST_KEY, value)
        decrypted_value = self.cryptor.decrypt(TEST_KEY, encrypted_value)

        # assert
        self.assertTrue(encrypted_value)
        self.assertTrue(decrypted_value)
        self.assertEqual(value, decrypted_value)

    def test_encrypt_verified_and_decrypt_verified_should_be_reversible(self):
        # setup
        value = "Roses are red\nViolets are blue"

        # test
        encrypted_value = self.cryptor.encrypt(TEST_KEY, value, verify=True)
        decrypted_value = self.cryptor.decrypt(TEST_KEY, encrypted_value, verify=True)

        # assert
        self.assertTrue(encrypted_value)
        self.assertTrue(decrypted_value)
        self.assertEqual(value, decrypted_value)

    def test_decrypt_should_raise_value_error_if_bad_key(self):
        # setup
        encrypted_value = self.cryptor.encrypt(TEST_KEY,
                                               "You are my sunshine...",
                                               verify=True)

        # test
        with self.assertRaises(ValueError):
            self.cryptor.decrypt("bad key!", encrypted_value, verify=True)

    def test_decrypt_unverified_should_not_raise_value_error_if_bad_key(self):
        # setup
        encrypted_value = self.cryptor.encrypt(TEST_KEY, "You are my sunshine...")

        # test should not raise value error
        self.cryptor.decrypt("bad key!", encrypted_value)
    
    def test_verify_should_return_digest_size_if_key_and_msg_are_valid(self):
        # setup
        digest_size = hmac.new("foo", digestmod=self.cryptor.digestmod).digest_size
        encrypted_value = self.cryptor.encrypt(TEST_KEY,
                                               "You are my sunshine...",
                                               verify=True)

        # test
        result = self.cryptor.verify(TEST_KEY, encrypted_value)

        # assert
        self.assertEqual(result, digest_size)

    def test_verify_should_return_false_if_key_is_invalid(self):
        # setup
        encrypted_value = self.cryptor.encrypt(TEST_KEY, "You are my sunshine...", verify=True)

        # test
        result = self.cryptor.verify("bad key!", encrypted_value)

        # assert
        self.assertFalse(result)

class Sha512DigestModCryptorTest(CryptorTest):
    def setUp(self):
        self.cryptor = Cryptor(digestmod=hashlib.sha512)

class Sha512DigestModFileCryptorTest(FileCryptorTest):
    def initialize_cryptor(self):
        self.cryptor = FileCryptor(digestmod=hashlib.sha512)

class DESCipherTest(CryptorTest):
    def setUp(self):
        self.cryptor = Cryptor(cipher_cls=DES)

class DESFileCipherTest(FileCryptorTest):
    def initialize_cryptor(self):
        self.cryptor = FileCryptor(cipher_cls=DES)

class BlowfishCipherTest(CryptorTest):
    def setUp(self):
        self.cryptor = Cryptor(cipher_cls=Blowfish)

class BlowfishFileCipherTest(FileCryptorTest):
    def initialize_cryptor(self):
        self.cryptor = FileCryptor(cipher_cls=Blowfish)
