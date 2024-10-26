from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
    h_mk = h_ck.copy()
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
        self.MSKIPPED = dict()

    def dh(self, peer_dh_public_key: dh.DHPublicKey):
        self.DHr = peer_dh_public_key
        self.SK = DH(self.DHs, self.DHr)

if __name__ == "__main__":
    alice = User()
    bob = User()

    alice.dh(bob.DHs[1])
    bob.dh(alice.DHs[1])
    
    print(alice.SK, bob.SK)
