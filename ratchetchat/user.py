from .base import *

class User():
    def __init__(self, DHr: dh.DHPublicKey | None = None):
        # DH Ratchet key pair (the "sending" or "self" ratchet key)
        self.DHs: tuple[dh.DHPrivateKey, dh.DHPublicKey] = GENERATE_DH(DHr)
        # DH Ratchet public key (the "received" or "remote" key)
        self.DHr: dh.DHPublicKey | None = DHr
        # 32-byte Root Key
        self.RK: bytes = b''
        # 32-byte Chain Key for sending and receiving
        self.CKs: bytes = b''
        self.CKr: bytes = b''
        # Message numbers for sending and receiving
        self.Ns: int = 0
        self.Nr: int = 0
        # Number of messages in previous sending chain
        self.PN: int = 0
        # Dictionary of skipped-over message keys, indexed by ratchet public
        # key and message number.
        self.MKSKIPPED = dict()

        self.IK = X25519PrivateKey.generate()
        self.SPK = X25519PrivateKey.generate()
        self.SK = b''

    def x3dh_start(self, IKr: X25519PublicKey, SPKr: X25519PublicKey):
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

    def x3dh_finish(self, IKr: X25519PublicKey, EKr: X25519PublicKey):
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

    def ratchet_init(self):
        self.RK = self.SK
        if self.DHr:
            self.RK, self.CKs = KDF_RK(self.SK, DH(self.DHs, self.DHr))

    def ratchet_encrypt(self, plaintext: bytes, AD: bytes):
        self.CKs, mk = KDF_CK(self.CKs)
        header = HEADER(self.DHs, self.PN, self.Ns)
        self.Ns += 1
        return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))

    def ratchet_decrypt(self, header: HEADER, ciphertext: bytes, AD: bytes):
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

    def try_skipped_message_keys(self, header: HEADER, ciphertext: bytes, AD: bytes):
        if (KEY_TO_BYTES(header.dh), header.n) not in self.MKSKIPPED:
            return None
        mk = self.MKSKIPPED[header.dh, header.n]
        del self.MKSKIPPED[header.dh, header.n]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))

    def skip_message_keys(self, until: int):
        if self.Nr + MAX_SKIP < until:
            raise RuntimeError()
        if self.CKr != None:
            while self.Nr < until:
                self.CKr, mk = KDF_CK(self.CKr)
                self.MKSKIPPED[self.DHr, self.Nr] = mk
                self.Nr += 1

    def dh_ratchet(self, header: HEADER):
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr = header.dh
        self.RK, self.CKr = KDF_RK(self.RK, DH(self.DHs, self.DHr))
        self.DHs = GENERATE_DH()
        self.RK, self.CKs = KDF_RK(self.RK, DH(self.DHs, self.DHr))
