from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy
from threading import Thread
import argparse
from ratchetchat.user import User
import cmd
from ratchetchat.base import *

parser = argparse.ArgumentParser(prog='chat')
parser.add_argument('--host-ip', type=str, default='0.0.0.0')
parser.add_argument('--peer-ip', type=str, default='127.0.0.1')
parser.add_argument('--host-port', type=int, default=8000)
parser.add_argument('--peer-port', type=int, default=8000)
args = parser.parse_args()

host = SimpleXMLRPCServer((args.host_ip, args.host_port), allow_none=True, use_builtin_types=True, logRequests=False)
host_thread = Thread(target=host.serve_forever)
host_thread.start()
user = User()

@host.register_function()
def get_dh_pub() -> bytes:
    return KEY_TO_BYTES(user.DHs[1])

@host.register_function()
def init_ratchet():
    user.ratchet_init()

@host.register_function()
def send_message(header: dict, ciphertext: bytes):
    _header = HEADER((user.DHs[0], BYTES_TO_KEY(header['dh'])), header['pn'], header['n'])
    plaintext = user.ratchet_decrypt(_header, ciphertext, b'')
    print(f"(peer) {plaintext}")

@host.register_function()
def send_msg(plaintext: bytes):
    print(f"(peer) {plaintext}")

@host.register_function()
def ping():
    return True

peer = ServerProxy(f"http://{args.peer_ip}:{args.peer_port}", allow_none=True, use_builtin_types=True)

print("Waiting for peer to be available...")
while True:
    try:
        peer.ping()
        break
    except:
        pass

class ChatShell(cmd.Cmd):
    prompt = '(chat) '

    def do_ping(self, arg):
        print(peer.ping())

    def do_get_peer_dh_pub(self, arg):
        dh_pub = peer.get_dh_pub()
        print(dh_pub)
        dh_obj = load_pem_public_key(dh_pub, backend=default_backend())
        if isinstance(dh_obj, dh.DHPublicKey):
            global user
            user = User(dh_obj.parameters())
            user.DHr = dh_obj
            print(KEY_TO_BYTES(user.DHr))
            print("New user instance created!!")

    def do_self_init_ratchet(self, arg):
        user.ratchet_init()

    def do_peer_init_ratchet(self, arg):
        peer.init_ratchet()

    def do_msg(self, arg):
        peer.send_msg(bytes(arg, encoding='utf-8'))

    def do_message(self, arg):
        header, ciphertext = user.ratchet_encrypt(bytes(arg, encoding='utf-8'), b'')
        peer.send_message(header.state(), ciphertext)

    def do_exit(self):
        exit()

ChatShell().cmdloop()
