import base64
from .cryptors import Cryptor, FileCryptor

__version__ = '0.1'


def encrypt(key, msg, base64_encode=True):
    cryptor = Cryptor(key=key)
    encrypted_msg = cryptor.encrypt(msg)
    return base64.b64encode(encrypted_msg) if base64_encode else encrypted_msg


def decrypt(key, msg, base64_decode=True):
    cryptor = Cryptor(key=key)
    raw_msg = base64.b64decode(msg) if base64_decode else msg
    return cryptor.decrypt(raw_msg)


def verified_encrypt(key, msg, base64_encode=True):
    cryptor = Cryptor(key=key)
    encrypted_msg = cryptor.encrypt(msg, verify=True)
    return base64.b64encode(encrypted_msg) if base64_encode else encrypted_msg


def verified_decrypt(key, msg, base64_decode=True):
    cryptor = Cryptor(key=key)
    raw_msg = base64.b64decode(msg) if base64_decode else msg
    return cryptor.decrypt(raw_msg, verify=True)


def verify(key, msg, base64_decode=True):
    cryptor = Cryptor(key=key)
    raw_msg = base64.b64decode(msg) if base64_decode else msg
    return cryptor.verify(raw_msg)


def encrypt_file(key, input_filename, output_filename=None):
    cryptor = FileCryptor(key=key)
    return cryptor.encrypt_file(input_filename, output_filename)


def decrypt_file(key, input_filename, output_filename=None):
    cryptor = FileCryptor(key=key)
    return cryptor.decrypt_file(input_filename, output_filename)


def verified_encrypt_file(key, input_filename, output_filename=None):
    cryptor = FileCryptor(key=key)
    return cryptor.encrypt_file(input_filename, output_filename, verify=True)


def verified_decrypt_file(key, input_filename, output_filename=None):
    cryptor = FileCryptor(key=key)
    return cryptor.decrypt_file(input_filename, output_filename, verify=True)
