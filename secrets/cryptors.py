from Crypto.Cipher import AES, blockalgo
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
import hashlib
import hmac
import os
import collections


class BaseCryptor(object):
    """
    A simple value encryptor / decryptor. Uses CFB mode for encryption
    """
    def __init__(self, cipher_cls=AES, random_generator_cls=Random,
                 digestmod=hashlib.sha256, key_deriver=PBKDF2, salt_length=64):
        self.mode = blockalgo.MODE_CFB
        self.cipher_cls = cipher_cls
        self.block_size = cipher_cls.block_size
        self.random_generator = random_generator_cls.new()
        self.digestmod = digestmod
        self.key_deriver = key_deriver
        self.salt_length = salt_length
        self.mac_size = hmac.new("1", digestmod=self.digestmod).digest_size

    def derive_key(self, key, salt=None):
        """
        Derives a key from the function provided by self.key_deriver (assumed
        to be PBKDF2.
        """
        # in the PyCrypto library, key_size can be a tuple or a single integer
        if isinstance(self.cipher_cls.key_size, collections.Sequence):
            acceptable_key_sizes = self.cipher_cls.key_size
        else:
            acceptable_key_sizes = [self.cipher_cls.key_size]
        max_key_size = max(acceptable_key_sizes)

        if salt is None:
            salt = self.generate_salt(self.salt_length)

        return (self.key_deriver(key, salt, dkLen=max_key_size), salt)

    def generate_salt(self, length):
        return self.random_generator.read(length)

    def initialization_vector(self, random=True):
        if random:
            return self.random_generator.read(self.cipher_cls.block_size)
        else:
            return b'1'*self.cipher_cls.block_size

    def cipher(self, derived_key, iv):
        return self.cipher_cls.new(derived_key, self.mode, iv)


class Cryptor(BaseCryptor):
    """
    A simple message encryptor / decryptor. Uses CFB mode for encryption
    """
    def encrypt(self, key, msg, verify=False):
        """
        Encrypts msg with key provided. If verify is True, the encrypted
        msg can be verified.
        """
        derived_key, salt = self.derive_key(key)
        iv = self.initialization_vector()
        cipher = self.cipher(derived_key, iv)
        encrypted_msg = iv + cipher.encrypt(msg)

        if verify:
            h = hmac.new(derived_key, msg=msg, digestmod=self.digestmod)
            encrypted_msg = salt + h.digest() + encrypted_msg
        else:
            encrypted_msg = salt + encrypted_msg

        return encrypted_msg

    def decrypt(self, key, encrypted_msg, verify=False):
        """
        Decrypts msg encrypted with key. If msg was encrypted with verify=True,
        then verify must be set to True.
        """
        if verify:
            verified = self.verify(key, encrypted_msg)
            if not verified:
                raise ValueError("Bad key or encrypted message.")
        parsed = self._parse(encrypted_msg, verified=verify)
        derived_key, _ = self.derive_key(key, salt=parsed['salt'])
        iv = self.initialization_vector(random=False)
        cipher = self.cipher(derived_key, iv)
        return cipher.decrypt(parsed['raw_msg'])[self.cipher_cls.block_size:]

    def verify(self, key, encrypted_msg):
        """
        Returns True if key and encrypted message are valid (and the message
        was a verified encryption), False otherwise. Only works if encrypted_msg
        was encrypted with verify=True.
        """
        parsed = self._parse(encrypted_msg, verified=True)
        derived_key, _ = self.derive_key(key, salt=parsed['salt'])
        h = hmac.new(derived_key, digestmod=self.digestmod)
        iv = self.initialization_vector(random=False)
        cipher = self.cipher(derived_key, iv)
        decrypted_msg = cipher.decrypt(parsed['raw_msg'])[self.cipher_cls.block_size:]
        h.update(decrypted_msg)
        return parsed['digest'] == h.digest()

    def _parse(self, encrypted_msg, verified):
        salt = encrypted_msg[:self.salt_length]
        if verified:
            msg_breakpoint = self.salt_length + self.mac_size
            digest = encrypted_msg[self.salt_length:msg_breakpoint]
            raw_msg = encrypted_msg[msg_breakpoint:]
        else:
            digest = None
            raw_msg = encrypted_msg[self.salt_length:]
        return {
            'salt': salt,
            'digest': digest,
            'raw_msg': raw_msg,
        }


class FileCryptor(BaseCryptor):
    def __init__(self, cipher_cls=AES, random_generator_cls=Random,
                 digestmod=hashlib.sha256, key_derivor=PBKDF2, salt_length=64):
        super(FileCryptor, self).__init__(cipher_cls, random_generator_cls,
                                          digestmod, key_derivor, salt_length)
        self.file_chunk_size = 1024

    def encrypt_file(self, key, input_filename, output_filename=None,
                     verify=False, overwrite_existing=True):
        """
        Encrypts the file at the given file path input_filename with the key
        provided. If verify is True, adds a digest which allows encrypted file
        to be verified.
        """
        if not output_filename:
            output_filename = "%s.encrypted" % input_filename
        assert output_filename != input_filename, "Output file and input file '%s' should not match!" % input_filename

        if not overwrite_existing and os.path.exists(output_filename):
            raise IOError("File '%s' exists and overwite_existing was set to False.")

        with open(input_filename, 'rb') as input_file:
            with open(output_filename, 'wb') as output_file:
                self.encrypt_file_obj(key, input_file, output_file, verify)

    def decrypt_file(self, key, input_filename, output_filename=None,
                     verify=False, overwrite_existing=True):
        """
        Decrypts the file at the given file path input_filename with the key
        provided. If file was encrypted with verify=True, then verify must be
        True.
        """
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
                verified = self.verify_file_obj(key, input_file)
                if not verified:
                    raise ValueError("Bad key or contents of input_filename.")
            with open(output_filename, 'wb') as output_file:
                self.decrypt_file_obj(key, input_file, output_file, verified=verify)

    def verify_file(self, key, filename):
        """
        Returns True if key is valided for given encrypted file. If either key
        *or* encrypted_filename are not valid, returns False. Only works if
        file was encrypted with verify=True.
        """
        with open(filename, 'rb') as input_file:
            return self.verify_file_obj(key, input_file)

    def encrypt_file_obj(self, key, input_file, output_file, verify=False):
        derived_key, salt = self.derive_key(key)
        iv = self.initialization_vector()
        cipher = self.cipher(derived_key, iv)

        output_file.write(salt)

        if verify:
            h = hmac.new(derived_key, digestmod=self.digestmod)
            for line in input_file:
                h.update(line)
            output_file.write(h.digest())

        output_file.write(iv)

        input_file.seek(0)
        for line in input_file:
            output_file.write(cipher.encrypt(line))

    def decrypt_file_obj(self, key, input_file, output_file, verified):
        parsed = self._parse_file_obj(input_file, verified=verified)
        derived_key, _ = self.derive_key(key, salt=parsed['salt'])

        input_file.seek(parsed['msg_breakpoint'])

        iv = self.initialization_vector(random=False)
        cipher = self.cipher(derived_key, iv)
        iv_padding = ''
        while True:
            chunk = input_file.read(self.file_chunk_size)
            if len(chunk) == 0:
                break
            output = cipher.decrypt(chunk)
            if not iv_padding:
                output, iv_padding = (output[self.cipher_cls.block_size:], output[:self.cipher_cls.block_size])
            output_file.write(output)

    def verify_file_obj(self, key, file_):
        parsed = self._parse_file_obj(file_, verified=True)
        derived_key, _ = self.derive_key(key, parsed['salt'])
        h = hmac.new(derived_key, digestmod=self.digestmod)

        file_.seek(parsed['msg_breakpoint'])

        iv = self.initialization_vector(random=False)
        cipher = self.cipher(derived_key, iv)
        iv_padding = ''
        while True:
            chunk = file_.read(self.file_chunk_size)
            if len(chunk) == 0:
                break
            output = cipher.decrypt(chunk)
            if not iv_padding:
                output, iv_padding = (output[self.cipher_cls.block_size:],
                                      output[:self.cipher_cls.block_size])
            h.update(output)

        return parsed['digest'] == h.digest()

    def _parse_file_obj(self, file_, verified):
        file_.seek(0)
        salt = file_.read(self.salt_length)
        if verified:
            digest = file_.read(self.mac_size)
            msg_breakpoint = self.salt_length + self.mac_size
        else:
            digest = ''
            msg_breakpoint = self.salt_length
        file_.seek(0)
        return {
            'salt': salt,
            'digest': digest,
            'msg_breakpoint': msg_breakpoint
        }
