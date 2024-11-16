from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy
from threading import Thread
import cmd
import argparse

from ratchetchat.user import User
from ratchetchat.base import *

parser = argparse.ArgumentParser(prog='chat')
parser.add_argument('--host-ip', type=str, default='0.0.0.0')
parser.add_argument('--peer-ip', type=str, default='127.0.0.1')
parser.add_argument('--host-port', type=int, default=8000)
parser.add_argument('--peer-port', type=int, default=8000)
args = parser.parse_args()

user = User()

host = SimpleXMLRPCServer((args.host_ip, args.host_port), allow_none=True, use_builtin_types=True, logRequests=False)
host_thread = Thread(target=host.serve_forever)
host_thread.start()

peer = ServerProxy(f"http://{args.peer_ip}:{args.peer_port}", allow_none=True, use_builtin_types=True)
peer_connected = False

@host.register_function()
def get_dh_pub() -> bytes:
    return KEY_TO_BYTES(user.DHs[1])

@host.register_function()
def init_ratchet():
    user.ratchet_init()
    global peer_connected
    peer_connected = True

@host.register_function()
def send_message(header: dict, ciphertext: bytes):
    _header = HEADER((user.DHs[0], BYTES_TO_KEY(header['dh'])), header['pn'], header['n'])
    plaintext = user.ratchet_decrypt(_header, ciphertext, b'')
    print("\rpeer: " + plaintext.decode())
    print("\rself: ", end='')

@host.register_function()
def send_msg(plaintext: bytes):
    print("\rpeer: " + plaintext.decode())
    print("\rself: ", end='')

@host.register_function()
def ping():
    return True

def connect_to_peer():
    DHr = BYTES_TO_KEY(peer.get_dh_pub())
    if not isinstance(DHr, dh.DHPublicKey):
        raise TypeError() 
    global user, peer_connected
    user = User(DHr)
    user.ratchet_init()
    peer.init_ratchet()
    peer_connected = True

class ChatShell(cmd.Cmd):
    prompt = 'self: '

    def default(self, line: str) -> None:
        if not peer_connected: connect_to_peer()
        header, ciphertext = user.ratchet_encrypt(bytes(line, encoding='utf-8'), b'')
        peer.send_message(header.state(), ciphertext)

    def do_plainmsg(self, arg):
        peer.send_msg(bytes(arg, encoding='utf-8'))

    def do_ping(self, arg):
        print(peer.ping())

    def do__exit(self):
        exit()

print("Waiting for peer to be available...", end='')
while True:
    try:
        peer.ping()
        break
    except:
        pass
print("Connected!")

ChatShell().cmdloop()
