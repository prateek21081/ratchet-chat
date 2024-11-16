import pickle

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.backends import default_backend

def KEY_TO_BYTES(key: PublicKeyTypes) -> bytes:
    """Returns the serialized PEM format key bytes."""
    return key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

def BYTES_TO_KEY(key: bytes) -> PublicKeyTypes:
    """Returns the deserialized key from PEM bytes."""
    return load_pem_public_key(key, backend=default_backend())

MAX_SKIP = 10 # Maximum number of message keys that can be skipped in a single chain.
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

def GENERATE_DH(DHr: dh.DHPublicKey | None = None) -> tuple[dh.DHPrivateKey, dh.DHPublicKey]:
    """Returns a new Diffie-Hellman key pair."""
    if DHr:
        global DH_PARAMETERS
        DH_PARAMETERS = DHr.parameters()
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return (private_key, public_key)

def DH(dh_pair: tuple[dh.DHPrivateKey, dh.DHPublicKey], dh_pub: dh.DHPublicKey) -> bytes:
    """Returns the output from the Diffie-Hellman calculation between the
    private key from the DH key pair dh_pair and the DH public key dh_pub."""
    shared_key = dh_pair[0].exchange(dh_pub)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
        backend=default_backend(),
    ).derive(shared_key)
    return derived_key

def KDF_RK(RK: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Returns a pair (32-byte root key, 32-byte chain key) as the output of
    applying a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output
    dh_out."""
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=RK,
        info=b'KDF_RK',
        backend=default_backend(),
    ).derive(dh_out)
    chain_key = key[:32]
    msg_key = key[32:]
    return chain_key, msg_key

def KDF_CK(CK: bytes) -> tuple[bytes, bytes]:
    """Returns a pair (32-byte chain key, 32-byte message key) as the output of
    applying a KDF keyed by a 32-byte chain key ck to some constant."""
    h_ck = hmac.HMAC(CK, hashes.SHA256())
    h_mk = hmac.HMAC(CK, hashes.SHA256())
    h_ck.update(b'\x01')
    h_ck.update(b'\x02')
    chain_key = h_ck.finalize()
    msg_key = h_mk.finalize()
    return chain_key, msg_key

def ENCRYPT(mk: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """Returns an AEAD encryption of plaintext with message key mk."""
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=b' '*80,
        info=b'',
        backend=default_backend(),
    ).derive(mk)
    enc_key, auth_key, iv = key[:32], key[32:64], key[64:]
    padder = PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    # TODO: add HMAC operation.
    return ciphertext

def DECRYPT(mk: bytes, ciphertext: bytes, associated_data: bytes):
    """Returns the AEAD decryption of ciphertext with message key mk."""
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=b' '*80,
        info=b'',
        backend=default_backend(),
    ).derive(mk)
    dec_key, auth_key, iv = key[:32], key[32:64], key[64:]
    cipher = Cipher(algorithms.AES256(dec_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(256).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    # TODO: add HMAC operation.
    return plaintext

class HEADER:
    """Creates a new message header containing the DH ratchet public key from
    the key pair in dh_pair, the previous chain length pn, and the message
    number n."""
    def __init__(self, dh_pair: tuple[dh.DHPrivateKey, dh.DHPublicKey], pn: int, n: int):
        self.dh: dh.DHPublicKey = dh_pair[1]
        self.pn: int = pn
        self.n: int = n

    def state(self) -> dict:
        _header = {
            'dh': KEY_TO_BYTES(self.dh),
            'pn': self.pn,
            'n': self.n,
        }
        return _header

def CONCAT(ad: bytes, header: HEADER) -> bytes:
    """Encodes a message header into a parseable byte sequence, prepends the ad
    byte sequence, and returns the result."""
    return ad + pickle.dumps(header.state())
