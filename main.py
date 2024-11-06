import json
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

MAX_SKIP = 10 # Maximum number of message keys that can be skipped in a single chain.
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048)

def GENERATE_DH() -> tuple[dh.DHPrivateKey, dh.DHPublicKey]:
    """Returns a new Diffie-Hellman key pair."""
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

def CONCAT(ad: bytes, header: dict) -> bytes:
    """Encodes a message header into a parseable byte sequence, prepends the ad
    byte sequence, and returns the result."""
    return ad + bytes(json.dumps(header))

def HEADER(dh_pair: tuple[dh.DHPrivateKey, dh.DHPublicKey], pn: int, n: int) -> dict:
    """Creates a new message header containing the DH ratchet public key from
    the key pair in dh_pair, the previous chain length pn, and the message
    number n."""
    header = {
        'dh': dh_pair[1].public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo),
        'pn': pn,
        'n': n,
    }
    return header

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

@dataclass
class Header():
    dh: bytes
    pn: int
    n: int

class User():
    def __init__(self):
        # DH Ratchet key pair (the "sending" or "self" ratchet key)
        self.DHs = GENERATE_DH()
        # DH Ratchet public key (the "received" or "remote" key)
        self.DHr = b'' 
        # 32-byte Root Key
        self.RK = b'' 
        # 32-byte Chain Key for sending and receiving
        self.CKs = b'' 
        self.CKr = b''
        # Message numbers for sending and receiving
        self.Ns = 0
        self.Nr = 0
        # Number of messages in previous sending chain
        self.PN = 0 
        # Dictionary of skipped-over message keys, indexed by ratchet public
        # key and message number.
        self.MKSKIPPED = dict() 

        self.IK = X25519PrivateKey.generate()
        self.SPK = X25519PrivateKey.generate()
        self.SK = b''

    def perform_x3dh_start(self, IKr: X25519PublicKey, SPKr: X25519PublicKey):
        EK = X25519PrivateKey.generate()
        DH1 = self.IK.exchange(SPKr)
        DH2 = EK.exchange(IKr)
        DH3 = EK.exchange(SPKr)
        self.SK = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            info=b'',
            backend=default_backend()
        ).derive(DH1 + DH2 + DH3)
        return EK.public_key()
    
    def perform_x3dh_finish(self, IKr: X25519PublicKey, EKr: X25519PublicKey):
        DH1 = self.SPK.exchange(IKr)
        DH2 = self.IK.exchange(EKr)
        DH3 = self.SPK.exchange(EKr)
        self.SK = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            info=b'',
            backend=default_backend()
        ).derive(DH1 + DH2 + DH3)

    def dh(self, peer_dh_public_key: dh.DHPublicKey):
        self.DHr = peer_dh_public_key
        self.SK = DH(self.DHs, self.DHr)

    def ratchet_encrypt(self, plaintext: bytes, AD: bytes):
        self.CKs, mk = KDF_CK(self.CKs)
        header = HEADER(self.DHs, self.PN, self.Ns)
        self.Ns += 1
        return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
    
    def ratchet_decrypt(self, header, ciphertext: bytes, AD: bytes):
        plaintext = self.try_skipped_message_keys(header, ciphertext, AD)
        if plaintext != None:
            return plaintext
        if header['dh'] != self.DHr:
            self.skip_message_keys(header['pn'])
            self.dh_ratchet(header)
        self.skip_message_keys(header['n'])
        self.CKr, mk = KDF_CK(self.CKr)
        self.Nr += 1
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def try_skipped_message_keys(self, header, ciphertext: bytes, AD: bytes):
        if (header['dh'], header['n']) not in self.MKSKIPPED:
            return None
        mk = self.MKSKIPPED[header['dh'], header['n']]
        del self.MKSKIPPED[header['dh'], header['n']]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def skip_message_keys(self, until: int):
        if self.Nr + MAX_SKIP < until:
            raise RuntimeError()
        if self.CKr != None:
            while self.Nr < until:
                self.CKr, mk = KDF_CK(self.CKr)
                self.MKSKIPPED[self.DHr, self.Nr] = mk
                self.Nr += 1

    def dh_ratchet(self, header):
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr = header['dh']
        self.RK, self.CKr = KDF_RK(self.RK, DH(self.DHs, self.DHr))
        self.DHs = GENERATE_DH()
        self.RK, self.CKs = KDF_RK(self.RK, DH(self.DHs, self.DHr))

if __name__ == "__main__":
    alice = User()
    bob = User()

    EK_pub = alice.perform_x3dh_start(bob.IK.public_key(), bob.SPK.public_key())

    bob.perform_x3dh_finish(alice.IK.public_key(), EK_pub)

    print("Alice's secret key:", alice.SK.hex())
    print("Bob's secret key:", bob.SK.hex())

    ciphertext = ENCRYPT(alice.SK, b'Hello, world!', b'')
    print(ciphertext)
    plaintext = DECRYPT(alice.SK, ciphertext, b'')
    print(plaintext)
