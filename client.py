import configparser
import logging
import pickle
import socket
import ssl
import sys
import threading
from datetime import datetime
from time import sleep

import oscrypto.asymmetric as osc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from hybrid_rsa_aes import HybridCipher

from logger import configure_logging

configure_logging("client.log")

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

DEFAULT_PORT = 8080
size = 2048


def set_port(port):
    if port < 1024 or port > 65535:
        port = DEFAULT_PORT
        print(f"Invalid port number, using {DEFAULT_PORT}")
    return port


def set_host(host):
    try:
        socket.inet_aton(host)
    except socket.error:
        print("Invalid host address")
        exit(0)
    return host


class Client:
    def __init__(self, port, host):
        self.port = set_port(port)
        self.host = set_host(host)
        self.socket = None
        self.is_connect = False
        self.is_open = False

        self.priv_key = osc.dump_private_key(osc.load_private_key(read_config("User", "user.key")), None)
        self.server_pubkey = None
        self.user_keys = dict()

        self.chat_with = None

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
        # -- wrapping socket in ssl context --
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False
            ctx.load_verify_locations(cafile=read_config("RootCA", "root.cert"))
            ctx.load_cert_chain(keyfile=read_config("User", "user.key"),
                                certfile=read_config("User", "user.cert"))
            self.socket = ctx.wrap_socket(sock, server_side=False)

            self.socket.connect((self.host, self.port))

            # -- get servers cert and pubkey --
            server_der = self.socket.getpeercert(True)
            cert = osc.load_certificate(server_der)
            self.server_pubkey = osc.dump_public_key(cert.public_key)

            self.is_connect = True
            self.is_open = True
            self.client_print(f'Connected to {self.host}:{self.port}\n')
        except ssl.SSLError as e:
            self.client_print("Invalid certfile or keyfile")
            sys.exit()
        except Exception as e:
            self.client_print('Unable to connect')
            self.client_print(e)
            sys.exit()

    def print_commands(self):
        print("-------------------------------------------------------")
        print("Commands menu:")
        print("1. [nick] message        - private message to user")
        print("2. /allUsers             - list all users")
        print("3. /privateChat `nick`   - start private chat with user")
        print("4. /endChat              - end private chat with user")
        print("5. /exit                 - exit server")
        print("-------------------------------------------------------")

    def log_on(self):
        try:
            # checking certificate
            received = pickle.loads(self.socket.recv(size))
            logger.debug(f"Received data: {received}")
            is_valid_certificate = received["valid"]
            self.client_print(received["message"])

            if not is_valid_certificate:
                self.client_print("Bye bye")
                return False

            # checking alias
            received = pickle.loads(self.socket.recv(size))
            is_valid_alias = received["valid"]
            while not is_valid_alias:
                self.client_print(received["message"])
                alias = input()
                message = {"alias": alias}
                logger.debug(f"Sent data: {message}")
                self.socket.send(pickle.dumps(message))
                received = pickle.loads(self.socket.recv(size))
                is_valid_alias = received["valid"]
                logger.debug(f"Received data: {received}")

            self.client_print(received["message"])

            self.print_commands()

            return True
        except ConnectionResetError:
            self.client_print("Certificate refused by server")
            self.socket.close()
            self.is_open = False
            exit()

    def start(self):
        if self.log_on():
            self.client_print("Start")
            self.listening_thread = threading.Thread(target=self.receive)
            self.sending_thread = threading.Thread(target=self.send)

            self.sending_thread.start()
            self.listening_thread.start()

    def receive(self):
        try:
            while self.is_connect:
                received = self.socket.recv(size)
                data = pickle.loads(received)

                logger.debug(f"Received data: {data}")

                sender = data["sender"]
                message = data["message"]

                if data["encrypted"]:
                    self.client_print(f"{sender}: {decrypt_message(self.priv_key, message)['message']}")
                elif data["key"]:
                    self.user_keys[data["sender"]] = data["key"]
                    self.client_print(f"You don't have public key of user {data['sender']}. Getting key...")
                    self.client_print(f"Public key of {data['sender']} saved")
                elif data["sender"] == "server":
                    self.client_print(message)
                elif data["command"] == "privateChat":
                    sender = data["sender"]
                    self.client_print(f"You are in private chat with {sender}")
                    self.chat_with = sender
                elif data["command"] == "noClient":
                    self.client_print(f"User {data['sender']} doesn't exist")
                elif data["command"] == "endChat":
                    self.client_print(f"You are not in private chat with {self.chat_with}")
                    self.chat_with = None
                else:
                    self.client_print(f"{sender}: {message}")

        except EOFError as e:
            if self.is_connect:
                raise Exception("Ran out of data or server closed")
        except Exception as e:
            print(f"Exception in receive: {e}")
        finally:
            self.is_connect = False
            if self.is_open:
                print("Close socket... Bye bye")
                self.socket.close()
                self.is_open = False
            sys.exit()

    def client_print(self, msg):
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[{current_time}] {msg}')
        logger.debug(msg)

    def prepare_data(self, message, data_type, receiver, encrypted, command):
        data = {
            "type": data_type,
            "receiver": receiver,
            "message": message,
            "encrypted": encrypted,
            "command": command
        }

        logger.debug(f"Sent data: {data}")
        return pickle.dumps(data)

    def send(self):
        try:
            while self.is_connect:
                message = input()
                if not message:
                    continue

                receiver = None
                command = None
                data_type = None
                encrypted = None

                if (message[0] == "[" and "]" in message) or (self.chat_with and message[0] != "/"):
                    if self.chat_with:
                        receiver = self.chat_with
                    else:
                        receiver, _, message = message[1:].partition("] ")

                    if receiver not in self.user_keys.keys():
                        
                        data_type = "command"
                        command = "getKey"
                    else:
                        data_type = "directMessage"
                        message = encrypt_message(self.user_keys[receiver], message)
                        encrypted = True

                elif message[0] == "/":
                    data_type = "command"
                    command = message[1:].split(" ")[0]
                    if command == "privateChat":
                        receiver = message[1:].split(" ")[1]
                        self.chat_with = receiver
                    elif command == "endChat":
                        receiver = self.chat_with
                        self.chat_with = None
                    elif command not in ("allUsers", "exit"):
                        self.client_print("Unknown command")
                        continue
                    message = None
                else:
                    self.client_print("Unknown request")
                    continue

                pkl_data = self.prepare_data(message, data_type, receiver, encrypted, command)

                try:
                    self.socket.send(pkl_data)
                except socket.error:
                    self.is_connect = False
                    self.socket = socket.socket()
                    self.client_print("Connection lost - reconnecting")
                    while not self.is_connect:
                        try:
                            self.connect()
                        except socket.error:
                            sleep(1)

                if command == "exit":
                    self.is_connect = False
                    break

        except Exception as e:
            self.client_print(f"Exception while send: {e}")
        finally:
            if self.is_open:
                self.client_print("Close socket... Bye bye")
                self.socket.close()
                self.is_open = False


def encrypt_message(key, message):
    key = load_pem_public_key(key, default_backend())
    return HybridCipher().encrypt(rsa_public_key=key, data={"message": message})


def decrypt_message(key, message):
    key = load_pem_private_key(key, password=None, backend=default_backend())
    return HybridCipher().decrypt(rsa_private_key=key, cipher_text=message)


def read_config(section, param):
    config = configparser.RawConfigParser()
    config.read("config.properties")
    return config.get(section, param)


def main():
    client = Client(8080, '127.0.0.1')
    client.connect()
    client.start()


if __name__ == '__main__':
    main()
