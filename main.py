import json
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend

MAX_SKIP = 10
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048)

def GENERATE_DH() -> tuple[dh.DHPrivateKey, dh.DHPublicKey]:
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return (private_key, public_key)

def DH(dh_pair: tuple[dh.DHPrivateKey, dh.DHPublicKey], dh_pub: dh.DHPublicKey):
    shared_key = dh_pair[0].exchange(dh_pub)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
        backend=default_backend(),
    ).derive(shared_key)
    return derived_key

def KDF_CK(CK):
    h_ck = hmac.HMAC(CK, hashes.SHA256())
    h_mk = hmac.HMAC(CK, hashes.SHA256())
    h_ck.update(b'\x01')
    h_ck.update(b'\x02')
    chain_key = h_ck.finalize()
    msg_key = h_mk.finalize()
    return chain_key, msg_key

def KDF_RK(RK, dh_out):
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=RK,
        info=b'kdf_rk',
        backend=default_backend(),
    ).derive(dh_out)
    chain_key = key[:32]
    msg_key = key[32:]
    return chain_key, msg_key

def CONCAT(ad, header):
    return bytes(ad + json.dumps(header))

def HEADER(dh_pair, pn, n):
    header = {
        'dh': dh_pair[1],
        'pn': pn,
        'n': n,
    }
    return header

def ENCRYPT(mk, plaintext, associated_data):
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=b' '*80,
        info=b'',
        backend=default_backend(),
    ).derive(mk)
    enc_key, auth_key, iv = key[:32], key[32:64], key[64:]
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    # TODO: complete encryption

def DECRYPT(mk, ciphertext, associated_data):
    # TODO: implement decryption
    pass

class User():
    def __init__(self, username:str = ''):
        self.username = username
        self.IK = X25519PrivateKey.generate()
        self.SPK = X25519PrivateKey.generate()
        self.SK = None

        self.DHs = GENERATE_DH()
        self.DHr = None
        self.RK = None
        self.CKs = None
        self.CKr = None
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.MKSKIPPED = dict()

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

    def ratchet_encrypt(self, plaintext, AD):
        self.CKs, mk = KDF_CK(self.CKs)
        header = HEADER(self.DHs, self.PN, self.Ns)
        self.Ns += 1
        return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
    
    def ratchet_decrypt(self, header, ciphertext, AD):
        plaintext = self.try_skipped_message_keys(header, ciphertext, AD)
        if plaintext != None:
            return plaintext
        if header.dh != self.DHr:
            self.skip_message_keys(header.pn)
            self.dh_ratchet(header)
        self.skip_message_keys(header.n)
        self.CKr, mk = KDF_CK(self.CKr)
        self.Nr += 1
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def try_skipped_message_keys(self, header, ciphertext, AD):
        if (header.dh, header.n) not in self.MKSKIPPED:
            return None
        mk = self.MKSKIPPED[header.dh, header.n]
        del self.MKSKIPPED[header.dh, header.n]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def skip_message_keys(self, until):
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
        self.DHr = header.dh
        self.RK, self.CKr = KDF_RK(self.RK, DH(self.DHs, self.DHr))
        self.DHs = GENERATE_DH()
        self.RK, self.CKs = KDF_RK(self.RK, DH(self.DHs, self.DHr))

if __name__ == "__main__":
    alice = User("Alice")
    bob = User("Bob")

    EK_pub = alice.perform_x3dh_start(bob.IK.public_key(), bob.SPK.public_key())

    bob.perform_x3dh_finish(alice.IK.public_key(), EK_pub)

    print("Alice's secret key:", alice.SK.hex())
    print("Bob's secret key:", bob.SK.hex())
    '''
    alice = User()
    bob = User()

    alice.dh(bob.DHs[1])
    bob.dh(alice.DHs[1])
    
    print(alice.SK, bob.SK)
    '''
