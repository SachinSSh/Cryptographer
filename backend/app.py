# backend/app.py
import datetime
import traceback
from flask import Flask, render_template, request, jsonify
import base64
import hashlib
from Crypto.Cipher import DES3, AES, Blowfish
from Crypto.PublicKey import RSA, ECC
#from Crypto.Signature import DSA, pkcs1_15
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import x25519
from flask import Flask, render_template, request, jsonify

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, x25519, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



import struct
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__, template_folder='../frontend')

######

class CryptoToolkit:
    @staticmethod
    def caesar_cipher(text, shift, decrypt=False):
        if decrypt:
            shift = -shift
        return ''.join(
            chr((ord(char) + shift - 65) % 26 + 65) if char.isupper() else
            chr((ord(char) + shift - 97) % 26 + 97) if char.islower() else
            char for char in text
        )

    @staticmethod
    def vigenere_cipher(text, keyword, decrypt=False):
        key = (keyword * (len(text) // len(keyword) + 1))[:len(text)].lower()
        result = []
        for i, char in enumerate(text):
            if char.isalpha():
                shift = ord(key[i]) - 97
                if decrypt:
                    shift = -shift
                if char.isupper():
                    result.append(chr((ord(char) + shift - 65) % 26 + 65))
                else:
                    result.append(chr((ord(char) + shift - 97) % 26 + 97))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def rail_fence_cipher(text, rails, decrypt=False):
        if not decrypt:
            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1
            for char in text:
                fence[rail].append(char)
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction = -direction
            return ''.join([''.join(row) for row in fence])
        else:
            length = len(text)
            fence = [[] for _ in range(rails)]
            chars_per_rail = [0] * rails
            rail = 0
            direction = 1
            for i in range(length):
                chars_per_rail[rail] += 1
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction = -direction
            pos = 0
            for i in range(rails):
                fence[i] = text[pos:pos + chars_per_rail[i]]
                pos += chars_per_rail[i]
            result = [''] * length
            rail = 0
            direction = 1
            for i in range(length):
                result[i] = fence[rail][0]
                fence[rail] = fence[rail][1:]
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction = -direction
            return ''.join(result)

    @staticmethod
    def des3_encrypt(text, key):
        key = hashlib.sha256(key.encode()).digest()[:24]
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
        encryptor = cipher.encryptor()
        padded_text = text.encode().ljust((len(text) + 7) // 8 * 8)
        return base64.b64encode(encryptor.update(padded_text) + encryptor.finalize()).decode()

    @staticmethod
    def des3_decrypt(encrypted_text, key):
        key = hashlib.sha256(key.encode()).digest()[:24]
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(base64.b64decode(encrypted_text)) + decryptor.finalize()
        return decrypted.rstrip().decode()

    @staticmethod
    def aes_encrypt(text, key, mode='ECB'):
        key = hashlib.sha256(key.encode()).digest()
        if mode == 'ECB':
            cipher = Cipher(algorithms.AES(key), modes.ECB())
        else:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_text = text.encode().ljust((len(text) + 15) // 16 * 16)
        return base64.b64encode(encryptor.update(padded_text) + encryptor.finalize()).decode()

    @staticmethod
    def aes_decrypt(encrypted_text, key, mode='ECB'):
        key = hashlib.sha256(key.encode()).digest()
        if mode == 'ECB':
            cipher = Cipher(algorithms.AES(key), modes.ECB())
        else:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(base64.b64decode(encrypted_text)) + decryptor.finalize()
        return decrypted.rstrip().decode()

    @staticmethod
    def rsa_generate_key_pair(key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        return (
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        )

    @staticmethod
    def rsa_encrypt(text, public_key):
        public_key = serialization.load_pem_public_key(public_key.encode())
        encrypted = public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def rsa_decrypt(encrypted_text, private_key):
        private_key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None
        )
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_text),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

    @staticmethod
    def blowfish_encrypt(text, key):
        key = hashlib.sha256(key.encode()).digest()[:16]
        cipher = Cipher(algorithms.Blowfish(key), modes.ECB())
        encryptor = cipher.encryptor()
        padded_text = text.encode().ljust((len(text) + 7) // 8 * 8)
        return base64.b64encode(encryptor.update(padded_text) + encryptor.finalize()).decode()

    @staticmethod
    def blowfish_decrypt(encrypted_text, key):
        key = hashlib.sha256(key.encode()).digest()[:16]
        cipher = Cipher(algorithms.Blowfish(key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(base64.b64decode(encrypted_text)) + decryptor.finalize()
        return decrypted.rstrip().decode()

    @staticmethod
    def dsa_generate_key_pair():
        private_key = dsa.generate_private_key(key_size=2048)
        public_key = private_key.public_key()
        return (
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        )

    @staticmethod
    def dsa_sign(message, private_key):
        private_key = serialization.load_pem_private_key(private_key.encode(), password=None)
        hash_obj = hashes.Hash(hashes.SHA256())
        hash_obj.update(message.encode())
        digest = hash_obj.finalize()
        signature = private_key.sign(
            digest,
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    @staticmethod
    def elliptic_curve_key_pair():
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return (
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        )

# Additional algorithms would be implemented similarly

class AdvancedCrypto:
    @staticmethod
    def twofish_encrypt(text, key):
        key = hashlib.sha256(key.encode()).digest()[:32]
        iv = os.urandom(16)
        cipher = Cipher(algorithms.Twofish(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_text = text.encode().ljust((len(text) + 15) // 16 * 16)
        encrypted = encryptor.update(padded_text) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode()

    @staticmethod
    def twofish_decrypt(encrypted_text, key):
        key = hashlib.sha256(key.encode()).digest()[:32]
        decoded = base64.b64decode(encrypted_text)
        iv, ciphertext = decoded[:16], decoded[16:]
        cipher = Cipher(algorithms.Twofish(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.rstrip().decode()

    @staticmethod
    def pike_stream_cipher(text, key):
        # Simple Pike-like stream cipher
        key_stream = hashlib.sha256(key.encode()).digest()
        encrypted = bytearray()
        for i, char in enumerate(text.encode()):
            key_byte = key_stream[i % len(key_stream)]
            encrypted.append(char ^ key_byte)
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def wake_cipher_encrypt(text, key):
        # Basic WAKE-like stream cipher
        key_bytes = hashlib.sha256(key.encode()).digest()
        state = list(struct.unpack('IIII', key_bytes))
        encrypted = bytearray()
        
        for char in text.encode():
            # Simple key schedule and mixing
            state[0] = (state[0] + state[1]) & 0xFFFFFFFF
            state[1] = ((state[1] << 3) | (state[1] >> 29)) & 0xFFFFFFFF
            state[2] = (state[2] ^ state[3]) & 0xFFFFFFFF
            state[3] = ((state[3] << 4) | (state[3] >> 28)) & 0xFFFFFFFF
            
            keystream_byte = state[0] & 0xFF
            encrypted.append(char ^ keystream_byte)
        
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def sober_cipher_encrypt(text, key):
        # Simplified SOBER-like stream cipher
        key_bytes = hashlib.sha256(key.encode()).digest()
        state = list(struct.unpack('IIII', key_bytes))
        encrypted = bytearray()
        
        for char in text.encode():
            # Nonlinear key generation
            state[0] = (state[0] * 1103515245 + 12345) & 0xFFFFFFFF
            state[1] = (state[1] ^ state[2]) & 0xFFFFFFFF
            state[2] = ((state[2] << 5) | (state[2] >> 27)) & 0xFFFFFFFF
            
            keystream_byte = state[0] & 0xFF
            encrypted.append(char ^ keystream_byte)
        
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def diffie_hellman_key_exchange(private_key=None):
        if private_key is None:
            private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return (
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )

    @staticmethod
    def el_gamal_key_pair(key_size=2048):
        # Generate El Gamal key pair
        p = secrets.randbits(key_size)
        g = 2  # primitive root
        x = secrets.randbelow(p - 2) + 1  # private key
        h = pow(g, x, p)  # public key
        return {
            'private_key': x,
            'public_key': {
                'p': p,
                'g': g,
                'h': h
            }
        }

    @staticmethod
    def crystals_kyber_mock_encrypt(message, public_key):
        # Mock implementation due to complexity
        # In reality, CRYSTALS-Kyber is a post-quantum key encapsulation mechanism
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(public_key.encode())
        
        # Simple XOR encryption
        encrypted = bytearray()
        for i, m in enumerate(message.encode()):
            encrypted.append(m ^ key[i % len(key)])
        
        return {
            'ciphertext': base64.b64encode(encrypted).decode(),
            'salt': base64.b64encode(salt).decode()
        }

    @staticmethod
    def sphincs_plus_mock_sign(message, private_key):
        # Mock signature generation
        hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_obj.update(message.encode())
        digest = hash_obj.finalize()
        
        # Simulate signature with hash of private key and message
        signature = hashlib.sha3_256(
            private_key.encode() + digest
        ).digest()
        
        return base64.b64encode(signature).decode()

    @staticmethod
    def falcon_mock_sign(message, private_key):
        # Mock signature for Falcon (lattice-based signature)
        hash_obj = hashes.Hash(hashes.SHAKE256(512), backend=default_backend())
        hash_obj.update(message.encode())
        digest = hash_obj.finalize()
        
        # Simulate signature with probabilistic approach
        signature = hashlib.sha3_512(
            private_key.encode() + digest + 
            os.urandom(32)  # Add randomness
        ).digest()
        
        return base64.b64encode(signature).decode()
    
####



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.json
        cipher_type = data.get('cipherType')
        action = data.get('action')
        text = data.get('text', '')
        params = data.get('params', {})

        # Comprehensive algorithm mapping
        crypto_algorithms = {
            'caesar': {
                'encrypt': lambda t, p: CryptoToolkit.caesar_cipher(t, p.get('shift', 3)),
                'decrypt': lambda t, p: CryptoToolkit.caesar_cipher(t, p.get('shift', 3), decrypt=True)
            },
            'vigenere': {
                'encrypt': lambda t, p: CryptoToolkit.vigenere_cipher(t, p.get('keyword', '')),
                'decrypt': lambda t, p: CryptoToolkit.vigenere_cipher(t, p.get('keyword', ''), decrypt=True)
            },
            'railfence': {
                'encrypt': lambda t, p: CryptoToolkit.rail_fence_cipher(t, p.get('rails', 3)),
                'decrypt': lambda t, p: CryptoToolkit.rail_fence_cipher(t, p.get('rails', 3), decrypt=True)
            },
            'des3': {
                'encrypt': lambda t, p: CryptoToolkit.des3_encrypt(t, p.get('key', '')),
                'decrypt': lambda t, p: CryptoToolkit.des3_decrypt(t, p.get('key', ''))
            },
            'aes': {
                'encrypt': lambda t, p: CryptoToolkit.aes_encrypt(t, p.get('key', '')),
                'decrypt': lambda t, p: CryptoToolkit.aes_decrypt(t, p.get('key', ''))
            },
            'rsa': {
                'encrypt': lambda t, p: CryptoToolkit.rsa_encrypt(t, p.get('publicKey', '')),
                'decrypt': lambda t, p: CryptoToolkit.rsa_decrypt(t, p.get('privateKey', ''))
            },
            'twofish': {
                'encrypt': lambda t, p: AdvancedCrypto.twofish_encrypt(t, p.get('key', '')),
                'decrypt': lambda t, p: AdvancedCrypto.twofish_decrypt(t, p.get('key', ''))
            },
            'pike': {
                'encrypt': lambda t, p: AdvancedCrypto.pike_stream_cipher(t, p.get('key', '')),
                'decrypt': lambda t, p: AdvancedCrypto.pike_stream_cipher(t, p.get('key', ''))
            },
            'wake': {
                'encrypt': lambda t, p: AdvancedCrypto.wake_cipher_encrypt(t, p.get('key', '')),
                'decrypt': lambda t, p: AdvancedCrypto.wake_cipher_encrypt(t, p.get('key', ''))
            },
            'sober': {
                'encrypt': lambda t, p: AdvancedCrypto.sober_cipher_encrypt(t, p.get('key', '')),
                'decrypt': lambda t, p: AdvancedCrypto.sober_cipher_encrypt(t, p.get('key', ''))
            },
            'el-gamal': {
                'generate': lambda t, p: AdvancedCrypto.el_gamal_key_pair(p.get('keySize', 2048)),
                'encrypt': lambda t, p: 'Mock encryption for El Gamal',
                'decrypt': lambda t, p: 'Mock decryption for El Gamal'
            },
            'diffie-hellman': {
                'generate': lambda t, p: AdvancedCrypto.diffie_hellman_key_exchange(),
                'exchange': lambda t, p: 'Key Exchange Simulation'
            },
            'crystals-kyber': {
                'encrypt': lambda t, p: AdvancedCrypto.crystals_kyber_mock_encrypt(t, p.get('publicKey', '')),
                'decrypt': lambda t, p: 'Mock Kyber Decryption'
            },
            'sphincs': {
                'sign': lambda t, p: AdvancedCrypto.sphincs_plus_mock_sign(t, p.get('privateKey', '')),
                'verify': lambda t, p: 'Mock SPHINCS+ Verification'
            },
            'falcon': {
                'sign': lambda t, p: AdvancedCrypto.falcon_mock_sign(t, p.get('privateKey', '')),
                'verify': lambda t, p: 'Mock Falcon Signature Verification'
            }
        }

        # Validate cipher type and action
        if cipher_type not in crypto_algorithms:
            raise ValueError(f"Unsupported cipher type: {cipher_type}")
        
        if action not in crypto_algorithms[cipher_type]:
            raise ValueError(f"Unsupported action for {cipher_type}: {action}")

        # Execute the specific crypto operation
        result = crypto_algorithms[cipher_type][action](text, params)

        return jsonify({
            'result': result,
            'algorithm': cipher_type,
            'action': action
        })

    except ValueError as ve:
        return jsonify({
            'error': 'Validation Error',
            'message': str(ve)
        }), 400
    except KeyError as ke:
        return jsonify({
            'error': 'Missing Parameter',
            'message': f'Required parameter missing: {str(ke)}'
        }), 400
    except Exception as e:
        return jsonify({
            'error': 'Processing Error',
            'message': str(e),
            'details': traceback.format_exc()
        }), 500

if __name__ == '__main__':
    app.run(debug=True)

#######

