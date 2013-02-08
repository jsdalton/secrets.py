from Crypto.Cipher import AES, blockalgo
from Crypto import Random
import hashlib
import hmac
import os
import collections


class BaseCryptor(object):
    """
    A simple value encryptor / decryptor. Uses CFB mode for encryption
    """
    def __init__(self, key, cipher_cls=AES, random_generator_cls=Random, digestmod=hashlib.sha256):
        self.mode = blockalgo.MODE_CFB
        self.digestmod = digestmod
        self.cipher_cls = cipher_cls
        self.block_size = cipher_cls.block_size
        self.key = self.hash_key(key)
        self.random_generator = random_generator_cls.new()

    def hash_key(self, key):
        """
        Hashing the key does not provide additional security, but merely ensures that the provided key is the appopriate
        block size for the cipher.
        """
        hash_key = self.digestmod(key).digest()
        hash_key_size = len(hash_key)

        # in the PyCrypto library, key_size can be a tuple or a single integer
        if isinstance(self.cipher_cls.key_size, collections.Sequence):
            acceptable_key_sizes = self.cipher_cls.key_size
        else:
            acceptable_key_sizes = [self.cipher_cls.key_size]

        # If the full hash_key is an acceptable size for this cipher, use it
        if hash_key_size in acceptable_key_sizes:
            return hash_key

        # Ciphers list acceptable key sizes from smallest to biggest. Find the biggest
        # acceptable key and trim the hash_key to fit it
        for cipher_key_size in reversed(acceptable_key_sizes):
            if hash_key_size >= cipher_key_size:
                return hash_key[:cipher_key_size]

        # If no acceptable sizes were found it means the digest function did not
        # create a large enough key for this cipher
        raise ValueError("digestmod '%s' does not yield a key of acceptable length" % self.digestmod.__name__)

    def initialization_vector(self, random=True):
        if random:
            return self.random_generator.read(self.cipher_cls.block_size)
        else:
            return b'1'*self.cipher_cls.block_size

    def cipher(self, iv):
        return self.cipher_cls.new(self.key, self.mode, iv)


class Cryptor(BaseCryptor):
    """
    A simple message encryptor / decryptor. Uses CFB mode for encryption
    """
    def encrypt(self, msg, verify=False):
        iv = self.initialization_vector()
        cipher = self.cipher(iv)
        encrypted_msg = iv + cipher.encrypt(msg)

        if verify:
            h = hmac.new(self.key, msg=msg, digestmod=self.digestmod)
            encrypted_msg = h.digest() + encrypted_msg

        return encrypted_msg

    def decrypt(self, encrypted_msg, verify=False):
        iv = self.initialization_vector(random=False)
        cipher = self.cipher(iv)

        if verify:
            digest_size = self.verify(encrypted_msg)
            if digest_size is False:
                raise ValueError("Bad key or encrypted message.")
            raw_msg = encrypted_msg[digest_size:]
        else:
            raw_msg = encrypted_msg

        return cipher.decrypt(raw_msg)[self.cipher_cls.block_size:]

    def verify(self, encrypted_msg):
        """
        Returns True if key and encrypted message are valid (and the message
        was a verified encryption), False otherwise.
        """
        iv = self.initialization_vector(random=False)
        cipher = self.cipher(iv)

        h = hmac.new(self.key, digestmod=self.digestmod)
        digest, raw_msg = (encrypted_msg[:h.digest_size], encrypted_msg[h.digest_size:])
        decrypted_msg = cipher.decrypt(raw_msg)[self.cipher_cls.block_size:]
        h.update(decrypted_msg)

        if digest == h.digest():
            return h.digest_size
        else:
            return False


class FileCryptor(BaseCryptor):
    def __init__(self, key, cipher_cls=AES, random_generator_cls=Random, digestmod=hashlib.sha256):
        super(FileCryptor, self).__init__(key, cipher_cls, random_generator_cls, digestmod)
        self.file_chunk_size = 1024

    def encrypt_file(self, input_filename, output_filename=None, verify=False, overwrite_existing=True):
        """
        Encrypts the file at the given file path input_filename with the key provided at initialization.
        """
        if not output_filename:
            output_filename = "%s.encrypted" % input_filename
        assert output_filename != input_filename, "Output file and input file '%s' should not match!" % input_filename

        if not overwrite_existing and os.path.exists(output_filename):
            raise IOError("File '%s' exists and overwite_existing was set to False.")

        with open(input_filename, 'rb') as input_file:
            with open(output_filename, 'wb') as output_file:
                self.encrypt_file_obj(input_file, output_file, verify)

    def decrypt_file(self, input_filename, output_filename=None, verify=False, overwrite_existing=True):
        file_path, extension = os.path.splitext(input_filename)
        if not output_filename:
            if extension == '.encrypted':
                output_filename = file_path
            else:
                output_filename = "%s.decrypted" % input_filename
        assert output_filename != input_filename, "Output file and input file '%s' should not match!" % input_filename

        if not overwrite_existing and os.path.exists(output_filename):
            raise IOError("File '%s' exists and overwite_existing was set to False.")

        with open(input_filename, 'rb') as input_file:
            if verify:
                digest_size = self.verify_file_obj(input_file)
                if digest_size is False:
                    raise ValueError("Bad key or contents of input_filename.")
            else:
                digest_size = 0

            with open(output_filename, 'wb') as output_file:
                self.decrypt_file_obj(input_file, output_file, digest_size=digest_size)

    def verify_file(self, filename):
        """
        Returns True if key is valided for given encrypted file. If either key *or*
        encrypted_filename are not valid, returns False.
        """
        with open(filename, 'rb') as input_file:
            return self.verify_file_obj(input_file)

    def encrypt_file_obj(self, input_file, output_file, verify=False):
        iv = self.initialization_vector()
        cipher = self.cipher(iv)

        if verify:
            h = hmac.new(self.key, digestmod=self.digestmod)
            for line in input_file:
                h.update(line)
            output_file.write(h.digest())

        output_file.write(iv)

        input_file.seek(0)
        for line in input_file:
            output_file.write(cipher.encrypt(line))

    def decrypt_file_obj(self, input_file, output_file, digest_size):
        iv = self.initialization_vector(random=False)
        cipher = self.cipher(iv)

        input_file.seek(digest_size)

        iv_padding = ''
        while True:
            chunk = input_file.read(self.file_chunk_size)
            if len(chunk) == 0:
                break
            output = cipher.decrypt(chunk)
            if not iv_padding:
                output, iv_padding = (output[self.cipher_cls.block_size:], output[:self.cipher_cls.block_size])
            output_file.write(output)

    def verify_file_obj(self, file_):
        iv = self.initialization_vector(random=False)
        cipher = self.cipher(iv)

        h = hmac.new(self.key, digestmod=self.digestmod)
        digest = file_.read(h.digest_size)

        iv_padding = ''
        while True:
            chunk = file_.read(self.file_chunk_size)
            if len(chunk) == 0:
                break
            output = cipher.decrypt(chunk)
            if not iv_padding:
                output, iv_padding = (output[self.cipher_cls.block_size:], output[:self.cipher_cls.block_size])
            h.update(output)

        if digest == h.digest():
            return h.digest_size
        else:
            return False

