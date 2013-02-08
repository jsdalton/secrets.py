# Secrets.py

Secrets.py is a small Python library that makes it easy to encrypt and decrypt both messages and values. It's really just a friendly interface to some of the cryptographic tools in the [PyCrypto](https://www.dlitz.net/software/pycrypto/) library.

## Usage
### Encrypt and Decrypt

To simply encrypt or decrypt a string, all that's required is a key.

````
>>> import secrets
>>> msg = "One if by land; two if by sea"
>>> key = "swordfish"
>>> encrypted_msg = secrets.encrypt(key, msg)
>>> encrypted_msg
'ZnSzzAj6q9Ug2bDWB3RBFjFCEANLgYUC9Ji/uVpx9n+GP9OVBRZIW+50M24J'
>>> secrets.decrypt(key, encrypted_msg)
'One if by land; two if by sea'
````

By default, encrypted messages are base64 encoded. Messages can be binary encoded by passing `base64_encode=False` to `encrypt()` (and `base64_decode=False` to `decrypt()` the message).

### Verified Encrypt and Decrypt

Messages can also be encrypted in a "verifiable" format ()via `verify_encrypt()`), which allows you to `verify()` a key:

````
>>> msg = "One if by land; two if by sea"
>>> key = "swordfish"
>>> encrypted_msg = secrets.verified_encrypt(key, msg)
>>> secrets.verify("Bad password!", encrypted_msg)
False
>>> secrets.verify(key, encrypted_msg)
True
````

`verified_decrypt()` will return `None` if the key is wrong or the message is corrupt:

````
>>> print secrets.verified_decrypt("Bad password!", encrypted_msg)
None
>>> print secrets.verified_decrypt(key, "blahblahblah")
None
````
Whereas the correct key results in the original message:

````
>>> secrets.verified_decrypt(key, encrypted_msg)
'One if by land; two if by sea'
````

Without using verified decryption, it's difficult (but not impossible) to determine programatically if a decrypted message is "correct" or not. Compare:

````
>>> encrypted_msg = secrets.encrypt(key, msg)
>>> secrets.decrypt(key, encrypted_msg)
'One if by land; two if by sea'
>>> secrets.decrypt("Bad password!", encrypted_msg)
'\xbf\xfd \x88W3\x11\xf4\xc3_J\xd0p\xbd\xf9d\x8bBn\x12\xea7\xf7\xdb\x87\x8d\x02zh'
````
### Encrypt and Decrypt Files

You can also encrypt and decrypt files via a similar API:

````
>>> import secrets
>>> key = "swordfish"
>>> with open('config.ini', 'r') as f:
...   f.read()
... 
'[Values]\nfoo = bar\nbar = baz\n\n[More Values]\nthis = that\nsalt = pepper\n'
>>> secrets.encrypt_file(key, 'config.ini')
>>> with open('config.ini.encrypted', 'r') as f:
...   f.read()
... 
'r\xbc\x1a\xf9\x82\xa1\xb4r&\xce\xf6r\xc3\x1fTJ\x9a\x1bi\xb3\x89oh.?\xcc\xfc\x86<\x0b\xc8|\xfb\xd5\x91\xe0\x91\xe1\ni\xe1\xed\xa7\xfba\x90]\xbc\xb6R\x9b&d]3hC#\xe2\xc4\xa2\xe7+\x7ff\x82D\xca\xce\xc7\xd8\xa6\x9f\x91\x9b\x95\xe8u\x0b\xd1\xd1\x80\xfe\xed3\xc7'
>>> secrets.decrypt_file(key, 'config.ini.encrypted', output_filename='config.ini.decrypted')
>>> with open('config.ini.decrypted', 'r') as f:
...   f.read()
... 
'[Values]\nfoo = bar\nbar = baz\n\n[More Values]\nthis = that\nsalt = pepper\n'
````

Files are encrypted in binary format.

### Verified Encrypt and Decrypt Files

As you might expect, there is a also a "verified" version of encrypt and decrypt for files:

````
>>> key = "swordfish"
>>> secrets.verified_encrypt_file(key, 'config.ini')
>>> with open('config.ini.encrypted', 'r') as f:
...   f.read()
... 
'\xd0`\xea`\x04X>2P\x82\x1eo\xc1\xc0\x19\t\x8a\xc6\x8d\xd4\x89j\xfeT\\\xbcDiT{\xa83\x8b<b\xfbO\x0f1T\xc6\xbc\xe3\xca\x03|[\x93\xcbY\x08\xb0l&\x87\xadJ>\x87\xdd\xb9\x0e(\x1c\x1b\xffs\x02\x19\xd8R\xefT\xff\x10\xbd\x1b\x89M\xc8O\xc5X\xa3\xd2rf\x1d\x80\xdb\xd1?\xfd\xfaX\xde\xe6\x87\x9f\xa0\xd0\xc1\xaa\x88\r\xf8\x11\xbe\xe1\x83m\xc6\xbbz\xae\xccgX'
````

`verify_file()` confirms that the key and file contents are correct:

````
>>> secrets.verify_file("Bad password!", 'config.ini.encrypted')
False
>>> secrets.verify_file(key, 'config.ini')
False
>>> secrets.verify_file(key, 'config.ini.encrypted')
True
````

If either the key or file contents are incorrect, `verified_file_decrypt()` raises a `ValueError`:

````
>>> secrets.verified_decrypt_file("Bad password!", 'config.ini.encrypted')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "secrets/__init__.py", line 67, in verified_decrypt_file
  File "secrets/cryptors.py", line 143, in decrypt_file
ValueError: Bad key or contents of input_filename.
>>> secrets.verified_decrypt_file(key, 'config.ini')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "secrets/__init__.py", line 67, in verified_decrypt_file
  File "secrets/cryptors.py", line 143, in decrypt_file
ValueError: Bad key or contents of input_filename.
````

Whereas the correct key will silently succeed:

````
>>> secrets.verified_decrypt_file(key, 'config.ini.encrypted', output_filename='config.ini.decrypted')
>>> with open('config.ini.decrypted', 'r') as f:
...   f.read()
... 
'[Values]\nfoo = bar\nbar = baz\n\n[More Values]\nthis = that\nsalt = pepper\n'
````
As with `decrypt()`, the unverified `decrypt_file()` will result in binary garbage if the key is wrong or the encrypted message is corrupt.


## Granular Control

If you need finer control than the main API provides, use the `Cryptor` and `FileCryptor` classes. These classes offer additional input/output options as well as a choice of the cipher and digest modes used, while still offering a more straightforward API than PyCrypto.

## Security Notes

Secrets is just a simplified wrapper around PyCrypto, which handles the majority of the actual cryptography. A few notes:

* By default, Secrets uses the [AES cipher](https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html) in [CFB mode](https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.blockalgo-module.html#MODE_CFB). The `Cryptor` class can optionally be initialized with other cipher classes from PyCrypto. It has been tested with [DES](https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.DES-module.html) and [Blowfish](https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.Blowfish-module.html). Padding is set automatically with the PyCrypto Random module.
* Secrets hashes the provided key, by default with [hashlib.sha256](http://docs.python.org/2/library/hashlib.html) though other digest modes can be specified. Note that hashing the key does not provide additional security, but is simply a means to normalize the key size required by the cipher. Secrets will attempt to use the longest key size available for the cipher and digest mode selected.
* The `verified_*` functions all work by prepending an [HMAC](http://docs.python.org/2/library/hmac.html) digest to the encrypted message. HMAC provides a high degree of security, since the correct digest can only be derived from the key *and* the correctly decrypted message. (The purpose of these functions is, for example, to protect a correctly decrypted file from being overwritten with garbate if an incorrect key is inadvertently provided.) The HMAC digest is computed with specified digest mode (hashlib.sha256 by default).
* Please contact me directly or open an issue if you observe any security flaws minor or severe in this library.







