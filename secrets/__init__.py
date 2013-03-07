import base64
from .cryptors import Cryptor, FileCryptor

__version__ = '0.1'


def encrypt(key, msg, base64_encode=True):
    cryptor = Cryptor()
    encrypted_msg = cryptor.encrypt(key, msg)
    return base64.b64encode(encrypted_msg) if base64_encode else encrypted_msg


def decrypt(key, msg, base64_decode=True):
    cryptor = Cryptor()
    raw_msg = base64.b64decode(msg) if base64_decode else msg
    return cryptor.decrypt(key, raw_msg)


def verified_encrypt(key, msg, base64_encode=True):
    cryptor = Cryptor()
    encrypted_msg = cryptor.encrypt(key, msg, verify=True)
    return base64.b64encode(encrypted_msg) if base64_encode else encrypted_msg


def verified_decrypt(key, msg, base64_decode=True):
    cryptor = Cryptor()
    try:
        raw_msg = base64.b64decode(msg) if base64_decode else msg
    except TypeError:
        # Malformed base64
        return
    try:
        decrypted_msg = cryptor.decrypt(key, raw_msg, verify=True)
    except ValueError:
        # Bad key or msg
        return
    return decrypted_msg


def verify(key, msg, base64_decode=True):
    cryptor = Cryptor()
    try:
        raw_msg = base64.b64decode(msg) if base64_decode else msg
    except TypeError:
        # Malformed base64
        return False
    return bool(cryptor.verify(key, raw_msg))


def encrypt_file(key, input_filename, output_filename=None):
    cryptor = FileCryptor()
    return cryptor.encrypt_file(key, input_filename, output_filename)


def decrypt_file(key, input_filename, output_filename=None):
    cryptor = FileCryptor()
    return cryptor.decrypt_file(key, input_filename, output_filename)


def verified_encrypt_file(key, input_filename, output_filename=None):
    cryptor = FileCryptor()
    return cryptor.encrypt_file(key, input_filename, output_filename, verify=True)


def verified_decrypt_file(key, input_filename, output_filename=None):
    cryptor = FileCryptor()
    return cryptor.decrypt_file(key, input_filename, output_filename, verify=True)


def verify_file(key, input_filename):
    cryptor = FileCryptor()
    return bool(cryptor.verify_file(key, input_filename))
