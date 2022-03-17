import configparser
import logging
import pickle
import re
import socket
import ssl
import sys
import threading
from datetime import datetime

import oscrypto.asymmetric as osc

from logger import configure_logging
from rootCA import RootCA

configure_logging("server.log")

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class MultipleClientsServer:
    def __init__(self, port, host):
        self.port = port
        self.host = host
        self.socket = None
        self.clientsInfo = {}
        self.keys = {}

    def server_configuration(self):
        try:
            server_print('Creating socket...')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_print('Socket created.')

            server_print(f'Binding server to {self.host}:{self.port}...')
            sock.bind((self.host, self.port))
            server_print(f'Server binded to {self.host}:{self.port}...')

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=read_config("RootCA", "root.cert"))
            ctx.load_cert_chain(certfile=read_config("Server", "server.cert"), keyfile=read_config("Server", "server.key"))
            self.socket = ctx.wrap_socket(sock, server_side=True)
        except ssl.SSLError:
            server_print("Invalid certfile or keyfile")
            sys.exit()

    def broadcast(self, message, current_client):
        pkl_data = self.prepare_data(message=message, sender="server")
        for socket in self.clientsInfo.values():
            if socket != current_client:
                socket.send(pkl_data)

    def get_alias(self, client_socket):
        message = {
            "message": 'Write your alias: ',
            "valid": False
        }
        logger.debug(f"Sent data {message}")
        client_socket.send(pickle.dumps(message))
        received = pickle.loads(client_socket.recv(2048))
        alias = received["alias"]

        logger.debug(f"Received data: {received}")

        while alias in self.clientsInfo.keys():
            message = {
                "message": 'Alias is already in use!\nWrite your alias: ',
                "valid": False
            }
            logger.debug(f"Sent data {message}")
            client_socket.send(pickle.dumps(message))
            received = pickle.loads(client_socket.recv(2048))
            alias = received["alias"]

        self.clientsInfo[alias] = client_socket

        return alias

    def log_on_client(self, client_socket):
        root_ca = RootCA(read_config("RootCA", "root.cert"), read_config("RootCA", "crl"))
        # -- get client cert and pubkey --
        client_der = client_socket.getpeercert(True)
        if not root_ca.verify_cert(client_der):
            server_print("CLIENT CERTIFICATE HAS BEEN REVOKED!")
            message = {
                "message": 'Your certificate is invalid. Close connection',
                "valid": False
            }
            logger.debug(f"Sent data {message}")
            client_socket.send(pickle.dumps(message))
            return False
        else:
            message = {
                "message": 'Your certificate is valid. Continue',
                "valid": True
            }
            logger.debug(f"Sent data {message}")
            client_socket.send(pickle.dumps(message))

        cert = osc.load_certificate(client_der)
        pubkey = osc.dump_public_key(cert.public_key, "pem")

        alias = self.get_alias(client_socket)

        self.keys[alias] = pubkey

        server_print(f'The alias of this client is {alias}')
        self.broadcast(f'{alias} has connected to the chat room', client_socket)
        message = {
            "message": 'You are now connected.',
            "valid": True}
        client_socket.send(pickle.dumps(message))

        return True

    def waiting_for_client(self):
        try:
            server_print('Listening for connection...')
            self.socket.listen(10)

            while True:
                client_socket, client_address = self.socket.accept()
                server_print(f'Connection from {client_address} accepted.')

                if self.log_on_client(client_socket):
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                    client_thread.start()

        except KeyboardInterrupt:
            server_print("Server stopped by user")
            self.server_shut_down()
        except ssl.SSLCertVerificationError:
            server_print("Client certificate invalid")
            self.waiting_for_client()

    def is_already_logged_in(self, dest_client):
        for client in self.clients:
            if client == dest_client:
                return True
            return False

    def get_alias_by_socket(self, socket):
        for alias, clientSocket in self.clientsInfo.items():
            if clientSocket == socket:
                return alias
        return None

    def send_all_clients(self, current_client):
        message = '\nList of all users:\n'
        receiver = self.get_alias_by_socket(current_client)
        for alias in self.clientsInfo.keys():
            message += f'#{alias}\n'

        pkl_data = self.prepare_data(sender="server", receiver=receiver, message=message)
        current_client.send(pkl_data)

    def prepare_data(self, sender=None, receiver=None, message=None, key=None, encrypted=None, command=None):
        data = {
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "encrypted": encrypted,
            "key": key,
            "command": command
        }
        logger.debug(f"Sent data {data}")
        return pickle.dumps(data)

    def set_private_chat(self, data, client_socket):
        sender = self.get_alias_by_socket(client_socket)
        receiver = data["receiver"]
        command = "privateChat"

        username = data["receiver"]
        if username in self.clientsInfo.keys():
            pkl_data = self.prepare_data(sender=sender, receiver=receiver, command=command)
            self.clientsInfo[receiver].send(pkl_data)
        else:
            pkl_data = self.prepare_data(message=f"User {username} doesn't exist", sender="server")
            client_socket.send(pkl_data)


    def end_private_chat(self, data, client_socket):
        sender = self.get_alias_by_socket(client_socket)
        receiver = data["receiver"]
        command = data["command"]

        pkl_data = self.prepare_data(sender=sender, receiver=receiver, command=command)

        self.clientsInfo[receiver].send(pkl_data)

    def send_key(self, data, client_socket):
        key_owner = data["receiver"]
        key = self.keys.get(key_owner)
        command = None
        if not key:
            command = "noClient"
        alias = self.get_alias_by_socket(client_socket)
        pkl_data = self.prepare_data(sender=key_owner, key=key, receiver=alias, command=command)
        client_socket.send(pkl_data)

    def send_direct_message(self, data, client_socket):
        username = data["receiver"]
        if username not in self.clientsInfo.keys():
            pkl_data = self.prepare_data(message=f"User doesn't exist", sender="server")
            client_socket.send(pkl_data)
        elif data["encrypted"]:
            self.send_private_message(data["message"], username, client_socket, data["encrypted"])
        else:
            self.send_private_message(data["message"], username, client_socket)

    def handle_client(self, client_socket, client_address):
        try:
            data_encrypted = client_socket.recv(2048)
            while data_encrypted:
                data = pickle.loads(data_encrypted)
                logger.debug(f"Received data: {data}")
                if data["type"] == "command":
                    if data["command"] == 'allUsers':
                        self.send_all_clients(client_socket)
                    elif data["command"] == "getKey":
                        self.send_key(data, client_socket)
                    elif data["command"] == 'privateChat':
                        self.set_private_chat(data, client_socket)
                    elif data["command"] == "endChat":
                        self.end_private_chat(data, client_socket)
                    elif data["command"] == 'exit':
                        break

                elif data["type"] == "directMessage":
                    self.send_direct_message(data, client_socket)

                data_encrypted = client_socket.recv(2048)
            server_print(f'Connection closed by {client_address}')

        except OSError as e:
            server_print(e)
        except Exception as e:
            server_print(e)
        finally:
            del self.clientsInfo[self.get_alias_by_socket(client_socket)]

            server_print(f'Closing socket for {client_address}...')
            client_socket.close()
            server_print(f'Socket closed for {client_address}.')

    def server_shut_down(self):
        server_print('Shutting down server...')
        self.socket.close()

    def send_private_message(self, message, username, sender_socket, encrypted=None):
        alias = self.get_alias_by_socket(sender_socket)
        pkl_data = self.prepare_data(sender=alias, receiver=username,
                                     message=message, encrypted=encrypted)
        for key, value in self.clientsInfo.items():
            name = re.search(r"([A-Za-z0-9_]+)", key).group(0)
            if name == username:
                try:
                    value.send(pkl_data)
                except:
                    value.close()


def read_config(section, param):
    config = configparser.RawConfigParser()
    config.read("config.properties")
    return config.get(section, param)


def server_print(msg):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{current_time}] {msg}')
    logger.debug(msg)


def main():
    host = socket.gethostbyname(socket.gethostname() + '.local')
    server = MultipleClientsServer(8080, "127.0.0.1")
    server.server_configuration()
    server.waiting_for_client()


if __name__ == '__main__':
    main()
