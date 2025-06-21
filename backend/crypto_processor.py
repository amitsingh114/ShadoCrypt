

import sys
import json
import hashlib
import base64
import binascii
import urllib.parse
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

try:
    from Crypto.Cipher import AES as PyCryptoAES
    from Crypto.Cipher import DES as PyCryptoDES
    from Crypto.Cipher import DES3 as PyCryptoDES3
    from Crypto.Cipher import Blowfish as PyCryptoBlowfish
    from Crypto.Cipher import ARC4 as PyCryptoARC4
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    PyCryptoAES, PyCryptoDES, PyCryptoDES3, PyCryptoBlowfish, PyCryptoARC4 = None, None, None, None, None
    sys.stderr.write("Warning: PyCryptodome not fully installed or some ciphers missing.\n")

try:
    import bcrypt
except ImportError:
    bcrypt = None
    sys.stderr.write("Warning: bcrypt library not installed.\n")

try:
    import scrypt as scrypt_lib
except ImportError:
    scrypt_lib = None
    sys.stderr.write("Warning: scrypt library not installed.\n")

try:
    import base58 as base58_lib
except ImportError:
    base58_lib = None
    sys.stderr.write("Warning: base58 library not installed.\n")

def rot13(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    ))

def encrypt_symmetric(text, key_str, algorithm):
    try:
        data = text.encode('utf-8')
        key_bytes = hashlib.sha256(key_str.encode('utf-8')).digest()

        if algorithm == 'AES':
            if not PyCryptoAES: raise ImportError("AES not available.")
            key = key_bytes
            iv = os.urandom(PyCryptoAES.block_size)
            cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_CBC, iv)
            padded_data = pad(data, PyCryptoAES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return {'ciphertext': base64.b64encode(iv + ciphertext).decode('utf-8')}

        elif algorithm == 'DES':
            if not PyCryptoDES: raise ImportError("DES not available.")
            key = key_bytes[:8]
            iv = os.urandom(PyCryptoDES.block_size)
            cipher = PyCryptoDES.new(key, PyCryptoDES.MODE_CBC, iv)
            padded_data = pad(data, PyCryptoDES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return {'ciphertext': base64.b64encode(iv + ciphertext).decode('utf-8')}

        elif algorithm == 'TripleDES':
            if not PyCryptoDES3: raise ImportError("TripleDES not available.")
            key = key_bytes[:24]
            iv = os.urandom(PyCryptoDES3.block_size)
            cipher = PyCryptoDES3.new(key, PyCryptoDES3.MODE_CBC, iv)
            padded_data = pad(data, PyCryptoDES3.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return {'ciphertext': base64.b64encode(iv + ciphertext).decode('utf-8')}

        elif algorithm == 'Blowfish':
            if not PyCryptoBlowfish: raise ImportError("Blowfish not available.")
            key = key_bytes[:16]
            iv = os.urandom(PyCryptoBlowfish.block_size)
            cipher = PyCryptoBlowfish.new(key, PyCryptoBlowfish.MODE_CBC, iv)
            padded_data = pad(data, PyCryptoBlowfish.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return {'ciphertext': base64.b64encode(iv + ciphertext).decode('utf-8')}

        elif algorithm == 'RC4':
            if not PyCryptoARC4: raise ImportError("RC4 not available.")
            key = key_bytes[:16]
            cipher = PyCryptoARC4.new(key)
            ciphertext = cipher.encrypt(data)
            return {'ciphertext': base64.b64encode(ciphertext).decode('utf-8')}

        elif algorithm == 'ChaCha20':
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            chacha_key = key_bytes
            nonce = os.urandom(12)
            chacha = ChaCha20Poly1305(chacha_key)
            ciphertext = chacha.encrypt(nonce, data, None)
            return {'ciphertext': base64.b64encode(nonce + ciphertext).decode('utf-8')}

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    except Exception as e:
        raise Exception(f"Failed to encrypt with {algorithm}: {e}")

def decrypt_symmetric(text, key_str, algorithm):
    try:
        decoded_data = base64.b64decode(text)
        key_bytes = hashlib.sha256(key_str.encode('utf-8')).digest()

        if algorithm == 'AES':
            iv = decoded_data[:PyCryptoAES.block_size]
            ciphertext = decoded_data[PyCryptoAES.block_size:]
            cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), PyCryptoAES.block_size)
            return {'plaintext': plaintext.decode('utf-8')}

        elif algorithm == 'DES':
            iv = decoded_data[:PyCryptoDES.block_size]
            ciphertext = decoded_data[PyCryptoDES.block_size:]
            cipher = PyCryptoDES.new(key_bytes[:8], PyCryptoDES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), PyCryptoDES.block_size)
            return {'plaintext': plaintext.decode('utf-8')}

        elif algorithm == 'TripleDES':
            iv = decoded_data[:PyCryptoDES3.block_size]
            ciphertext = decoded_data[PyCryptoDES3.block_size:]
            cipher = PyCryptoDES3.new(key_bytes[:24], PyCryptoDES3.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), PyCryptoDES3.block_size)
            return {'plaintext': plaintext.decode('utf-8')}

        elif algorithm == 'Blowfish':
            iv = decoded_data[:PyCryptoBlowfish.block_size]
            ciphertext = decoded_data[PyCryptoBlowfish.block_size:]
            cipher = PyCryptoBlowfish.new(key_bytes[:16], PyCryptoBlowfish.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), PyCryptoBlowfish.block_size)
            return {'plaintext': plaintext.decode('utf-8')}

        elif algorithm == 'RC4':
            cipher = PyCryptoARC4.new(key_bytes[:16])
            plaintext = cipher.decrypt(decoded_data)
            return {'plaintext': plaintext.decode('utf-8')}

        elif algorithm == 'ChaCha20':
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            nonce = decoded_data[:12]
            ciphertext = decoded_data[12:]
            chacha = ChaCha20Poly1305(key_bytes)
            plaintext = chacha.decrypt(nonce, ciphertext, None)
            return {'plaintext': plaintext.decode('utf-8')}

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    except Exception as e:
        raise Exception(f"Failed to decrypt with {algorithm}: {e}")

def hash_data(text, algorithm):
    data_bytes = text.encode('utf-8')
    try:
        if algorithm == 'SHA3':
            return {'hash': hashlib.sha3_256(data_bytes).hexdigest()}
        elif algorithm == 'BLAKE2':
            return {'hash': hashlib.blake2b(data_bytes).hexdigest()}
        elif algorithm == 'bcrypt':
            if not bcrypt: raise ImportError("bcrypt not installed")
            salt = bcrypt.gensalt()
            return {'hash': bcrypt.hashpw(data_bytes, salt).decode('utf-8')}
        elif algorithm == 'scrypt':
            if not scrypt_lib: raise ImportError("scrypt not installed")
            salt = os.urandom(16)
            hashed = scrypt_lib.hash(data_bytes, salt, N=2**14, r=8, p=1, dklen=64)
            return {'hash': f"scrypt:{salt.hex()}:{hashed.hex()}"}
        elif algorithm == 'PBKDF2':
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(data_bytes)
            return {'hash': f"pbkdf2:{salt.hex()}:{key.hex()}"}
        else:
            return {'hash': hashlib.new(algorithm.lower(), data_bytes).hexdigest()}
    except Exception as e:
        raise Exception(f"Failed to hash with {algorithm}: {e}")

def encode_data(text, method):
    data_bytes = text.encode('utf-8')
    try:
        if method == 'Base64':
            return {'encoded': base64.b64encode(data_bytes).decode('utf-8')}
        elif method == 'Hex':
            return {'encoded': binascii.hexlify(data_bytes).decode('utf-8')}
        elif method == 'Base32':
            return {'encoded': base64.b32encode(data_bytes).decode('utf-8').rstrip('=')}
        elif method == 'Base58':
            if not base58_lib: raise ImportError("base58 not installed")
            return {'encoded': base58_lib.b58encode(data_bytes).decode('utf-8')}
        elif method == 'ROT13':
            return {'encoded': rot13(text)}
        elif method == 'URL Encoding':
            return {'encoded': urllib.parse.quote_plus(text)}
        else:
            raise ValueError(f"Unsupported encoding: {method}")
    except Exception as e:
        raise Exception(f"Failed to encode with {method}: {e}")

def decode_data(text, method):
    try:
        if method == 'Base64':
            return {'decoded': base64.b64decode(text).decode('utf-8')}
        elif method == 'Hex':
            return {'decoded': binascii.unhexlify(text).decode('utf-8')}
        elif method == 'Base32':
            padded_text = text + '=' * (-len(text) % 8)
            return {'decoded': base64.b32decode(padded_text).decode('utf-8')}
        elif method == 'Base58':
            if not base58_lib: raise ImportError("base58 not installed")
            return {'decoded': base58_lib.b58decode(text).decode('utf-8')}
        elif method == 'ROT13':
            return {'decoded': rot13(text)}
        elif method == 'URL Encoding':
            return {'decoded': urllib.parse.unquote_plus(text)}
        else:
            raise ValueError(f"Unsupported decoding: {method}")
    except Exception as e:
        raise Exception(f"Failed to decode with {method}: {e}")

if __name__ == '__main__':
    try:
        payload = json.loads(sys.stdin.read())
        operation = payload.get('operation')
        result = {}
        if operation == 'encrypt':
            result = encrypt_symmetric(payload['text'], payload['key'], payload['algorithm'])
        elif operation == 'decrypt':
            result = decrypt_symmetric(payload['text'], payload['key'], payload['algorithm'])
        elif operation == 'hash':
            result = hash_data(payload['text'], payload['algorithm'])
        elif operation == 'encode':
            result = encode_data(payload['text'], payload['method'])
        elif operation == 'decode':
            result = decode_data(payload['text'], payload['method'])
        else:
            raise ValueError(f"Unknown operation: {operation}")
        sys.stdout.write(json.dumps(result))
    except Exception as e:
        sys.stderr.write(json.dumps({'error': str(e)}))
        sys.exit(1)
