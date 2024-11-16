from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy
from threading import Thread
import cmd
import argparse

from ratchetchat.user import User
from ratchetchat.base import *

parser = argparse.ArgumentParser(prog='ratchetchat')
parser.add_argument('--host-ip', type=str, default='0.0.0.0')
parser.add_argument('--peer-ip', type=str, default='127.0.0.1')
parser.add_argument('--host-port', type=int, default=8000)
parser.add_argument('--peer-port', type=int, default=8000)
args = parser.parse_args()

# Double Ratchet user instance
user = User()

# Host an XML RPC server to provide public access to some user data and messaging functionality
host = SimpleXMLRPCServer((args.host_ip, args.host_port), allow_none=True, use_builtin_types=True, logRequests=False)
host_thread = Thread(target=host.serve_forever)
host_thread.start()

# Connect to peer's XML RPC server
peer = ServerProxy(f"http://{args.peer_ip}:{args.peer_port}", allow_none=True, use_builtin_types=True)
peer_connected = False # peer connection is not verified yet.

@host.register_function()
def get_dh_pub() -> bytes:
    """Get user DHPublicKey as PEM bytes."""
    return KEY_TO_BYTES(user.DHs[1])

@host.register_function()
def get_ik_pub() -> bytes:
    """Get user IK as PEM bytes."""
    return KEY_TO_BYTES(user.IK.public_key())

@host.register_function()
def get_spk_pub() -> bytes:
    """Get user SPK as PEM bytes."""
    return KEY_TO_BYTES(user.SPK.public_key())

@host.register_function()
def x3dh(IK_pub: bytes, EK_pub: bytes) -> None:
    """Finalize X3DH key exchange for user."""
    IKr = BYTES_TO_KEY(IK_pub)
    EKr = BYTES_TO_KEY(EK_pub)
    user.x3dh_finish(IKr, EKr)
    
@host.register_function()
def init_ratchet() -> None:
    """Initialize user ratchet."""
    user.ratchet_init()
    # Connection is considered established from here on.
    global peer_connected
    peer_connected = True

@host.register_function()
def send_message(header: dict, ciphertext: bytes) -> bool:
    """Get header and encrypted message bytes and print decrypted message."""
    _header = HEADER((user.DHs[0], BYTES_TO_KEY(header['dh'])), header['pn'], header['n'])
    plaintext = user.ratchet_decrypt(_header, ciphertext, b'')
    print("\rpeer: " + plaintext.decode())
    print("\rself: ", end='') # reset the prompt state for chat interface.
    return True

@host.register_function()
def send_plainmsg(plaintext: bytes) -> bool:
    """Get unencrypted message bytes and print them."""
    print("\rpeer: " + plaintext.decode())
    print("\rself: ", end='') # reset the prompt state for chat interface.
    return True

@host.register_function()
def ping() -> bool:
    """Utility function to check for peer online status."""
    return True

def connect_to_peer() -> bool:
    """Intiate a Double Ratchet chat session with peer."""
    global user, peer_connected
    DHr: DHPublicKey = BYTES_TO_KEY(peer.get_dh_pub())
    user = User(DHr) # update user instance with peer's DH public key.
    # Perform X3DH key exchange
    IKr: X25519PublicKey = BYTES_TO_KEY(peer.get_ik_pub())
    SPKr: X25519PublicKey = BYTES_TO_KEY(peer.get_spk_pub())
    EK_pub: X25519PublicKey = user.x3dh_start(IKr, SPKr)
    peer.x3dh(KEY_TO_BYTES(user.IK.public_key()), KEY_TO_BYTES(EK_pub))
    # Initialize ratchets at both ends
    user.ratchet_init()
    peer.init_ratchet()
    peer_connected = True
    return True

class ChatShell(cmd.Cmd):
    prompt = 'self: ' # prompt for user side message input

    def default(self, line: str) -> None:
        """The default input operation is considered as sending encrypted message."""
        if not peer_connected: connect_to_peer()
        header, ciphertext = user.ratchet_encrypt(bytes(line, encoding='utf-8'), b'')
        peer.send_message(header.state(), ciphertext)

    def do_plainmsg(self, arg):
        """Send an unencrypted message."""
        peer.send_msg(bytes(arg, encoding='utf-8'))

    def do_ping(self, arg):
        """Ping the peer."""
        print(peer.ping())

    def do__exit(self, arg):
        """Exit from app."""
        exit()

print("Waiting for peer to be available...", end='', flush=True)
while True:
    try:
        peer.ping()
        break
    except:
        pass
print("Connected!", flush=True)

ChatShell().cmdloop()
