from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class User:

    def __init__(self, user_name: str):
        self.user_name = user_name
        self.IK = X25519PrivateKey.generate()
        self.SPK = X25519PrivateKey.generate()
        self.SK = None

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


if __name__ == "__main__":
    alice = User("Alice")
    bob = User("Bob")

    EK_pub = alice.perform_x3dh_start(bob.IK.public_key(), bob.SPK.public_key())

    bob.perform_x3dh_finish(alice.IK.public_key(), EK_pub)

    print("Alice's secret key:", alice.SK.hex())
    print("Bob's secret key:", bob.SK.hex())







