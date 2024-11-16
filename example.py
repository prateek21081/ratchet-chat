from ratchetchat import user

if __name__ == "__main__":
    # Create two parties wanting to message each other.
    alice = user.User()
    bob = user.User()

    # Perform X3DH and derive shared secret SK.
    alice_EK_pub = alice.x3dh_start(bob.IK.public_key(), bob.SPK.public_key())
    bob.x3dh_finish(alice.IK.public_key(), alice_EK_pub)

    # Share Bob's DHPublicKey with Alice.
    alice.DHr = bob.DHs[1]

    # Intialize ratchets for both parties.
    alice.ratchet_init()
    bob.ratchet_init()

    # Alice encrypts a message and sends it to Bob.
    message = b'Hello, Bob!'
    header, ciphertext = alice.ratchet_encrypt(message, b'')
    # Bob receives a message from Alice and decrypts it.
    plaintext = bob.ratchet_decrypt(header, ciphertext, b'')
    print(message, ciphertext.hex(), plaintext, sep=' => ')
    
    # Bob replies in a similary fashion.
    message = b'Hey, Alice!'
    header, ciphertext = bob.ratchet_encrypt(message, b'')
    plaintext = alice.ratchet_decrypt(header, ciphertext, b'')
    print(message, ciphertext.hex(), plaintext, sep=' => ')
