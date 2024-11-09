from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy
from threading import Thread
import argparse
from ratchetchat.user import User
import cmd
import time

parser = argparse.ArgumentParser(prog='chat')
parser.add_argument('--host-ip', type=str, default='0.0.0.0')
parser.add_argument('--peer-ip', type=str, default='127.0.0.1')
parser.add_argument('--host-port', type=int, default=8000)
parser.add_argument('--peer-port', type=int, default=8000)
args = parser.parse_args()

host = SimpleXMLRPCServer((args.host_ip, args.host_port), allow_none=True, use_builtin_types=True)
host_thread = Thread(target=host.serve_forever)
host_thread.start()

time.sleep(5)

peer = ServerProxy(f"http://{args.peer_ip}:{args.peer_port}", allow_none=True, use_builtin_types=True)

user = User()

host.register_function(user.get_self_dh_pub)
host.register_function(user.set_peer_dh_pub)
host.register_function(user.ratchet_init)

@host.register_function()
def send_message(header: dict, ciphertext: bytes):
    _header = user.parse_header(header)
    plaintext = user.ratchet_decrypt(_header, ciphertext, b'')
    print(f"(peer) {plaintext}")

peer.set_peer_dh_pub(user.get_self_dh_pub())

user.ratchet_init()
peer.ratchet_init()

class ChatShell(cmd.Cmd):
    prompt = '(chat) '

    def do_ratchet_init(self):
        user.ratchet_init()
        peer.ratchet_init()

    def do_set_peer_dh_pub(self):
        peer.set_peer_dh_pub(user.get_self_dh_pub())

    def do_msg(self, arg):
        header, ciphertext = user.ratchet_encrypt(bytes(arg, encoding='utf-8'), b'')
        peer.send_message(header.state(), ciphertext)

    def do_exit(self):
        exit()

ChatShell().cmdloop()
