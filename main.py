from sre_constants import MARK
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
    ).derive(dh_out)
    chain_key = key[:32]
    msg_key = key[32:]
    return chain_key, msg_key

class User():
    def __init__(self):
        self.DHs = GENERATE_DH()
        self.DHr = None
        self.RK = None
        self.CKs = None
        self.CKr = None
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.MKSKIPPED = dict()

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
    alice = User()
    bob = User()

    alice.dh(bob.DHs[1])
    bob.dh(alice.DHs[1])
    
    print(alice.SK, bob.SK)
