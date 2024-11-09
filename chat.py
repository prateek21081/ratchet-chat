from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy
from threading import Thread
import argparse
from ratchetchat.user import User

parser = argparse.ArgumentParser(prog='chat')
parser.add_argument('--host-ip', type=str, default='0.0.0.0')
parser.add_argument('--peer-ip', type=str, default='0.0.0.0')
parser.add_argument('--host-port', type=int, default=8000)
parser.add_argument('--peer-port', type=int, default=8000)
args = parser.parse_args()

host = SimpleXMLRPCServer((args.host_ip, args.host_port))
host_thread = Thread(target=host.serve_forever)
host_thread.start()

peer = ServerProxy(f"http://{args.peer_ip}:{args.peer_port}")

user = User()

host.register_function(user.get_self_dh_pub)
print(peer.get_self_dh_pub())
