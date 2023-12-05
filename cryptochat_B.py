from itertools import count
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from dataclasses import dataclass
from glob import glob
import socket
import threading
import time
import os

@dataclass
class Cryptography:
    @staticmethod
    def generate_token(size=16):
        return os.urandom(size).hex().encode()
    
    @staticmethod
    def load_RSA_keys(private_key_path, public_key_path):
        private_key = RSA.import_key(open(private_key_path).read())
        public_key = RSA.import_key(open(public_key_path).read())
        return private_key, public_key
    
    @staticmethod
    def generate_RSA_keys(size=1024, save_folder=None):
        private_key = RSA.generate(size, os.urandom)
        public_key = private_key.publickey()
        if save_folder is not None:
            os.makedirs(save_folder)
            with open(f'{save_folder}/private_key.pem', 'xb') as p:
                p.write(private_key.export_key())
                p.close()
            with open(f'{save_folder}/public_key.pem', 'xb') as p:
                p.write(public_key.export_key())
                p.close()
        return private_key, public_key

    @staticmethod
    def encrypt_RSA(public_key, message):
        return PKCS1_OAEP.new(public_key).encrypt(message)
    
    @staticmethod
    def decrypt_RSA(private_key, message):
        return PKCS1_OAEP.new(private_key).decrypt(message)


@dataclass(kw_only=True)
class User(Cryptography):
    user_id: str
    private_key: PKCS1_OAEP = None
    public_key: PKCS1_OAEP = None
    friends: list[dict] = None
    unknown_friend_string: str = 'Desconhecido'

    def __post_init__(self):
        assert self.user_id.isalpha(), '"user_id" deve conter apenas letras.'
    
    def login(self):
        user_path = f'users/{self.user_id}'
        if not os.path.exists(user_path):
            print(f'Usuário não encontrado, criando o usuário "{self.user_id}"')
            self.generate_RSA_keys(save_folder=user_path)
            print(f'Usuário "{self.user_id}" criado com sucesso.')
        self.private_key = RSA.import_key(open(f"{user_path}/private_key.pem").read())
        self.public_key = RSA.import_key(open(f"{user_path}/public_key.pem").read())
        print(f'Usuário "{self.user_id}" logado com sucesso.')
        return self

    def search_friend(self, friend_public_key):
        friends_path = glob(f'users/{self.user_id}/friends/*')
        for friend_path in friends_path:
            friend_public_key_path = f"{friend_path}/public_key.pem"
            if friend_public_key.export_key().decode() == open(friend_public_key_path).read():
                return Path(friend_path).stem # friend_id
        return self.unknown_friend_string

    def add_friend(self, friend_id, friend_public_key):
        if not friend_id.isalpha():
            print(f'<friend_id> deve conter apenas letras.')
            return self.unknown_friend_string
        if self.search_friend(friend_public_key) != self.unknown_friend_string:
            print(f'Usuário já adicionado.')
            return self.unknown_friend_string
        else:
            friend_path = f'users/{self.user_id}/friends/{friend_id}'
            os.makedirs(friend_path)
            with open(f'{friend_path}/public_key.pem', 'xb') as p:
                p.write(friend_public_key.export_key())
                p.close()
            with open(f'{friend_path}/chat.txt', 'xb') as c:
                c.close()
            print(f'Amigo {friend_id} adicionado.')
        return friend_id


@dataclass(kw_only=True)
class Authentication(Cryptography):
    session_token: str = os.urandom(16).hex()
    received_token: str = None
    received_public_key: PKCS1_OAEP = None

    def verify_token(self, sent, received):
        print(f"Token enviado: {sent}")
        print(f"Token recebido: {received}")
        if sent == received:
            print(f'Usuário autenticado.')
            return True
        print('Usuário não autenticado.')
        self.client.close()
        return False

    def authenticate_first(self, user):
        self.client.send(user.public_key.exportKey())
        print(f"[{user.user_id}] send: user.public_key")
        self.received_public_key = RSA.import_key(self.server.recv(2048))
        print(f"[{user.user_id}] recv: received_public_key")
        self.client.send(self.encrypt_RSA(self.received_public_key, self.session_token.encode()))
        print(f"[{user.user_id}] send: session_token")
        received_encrypted_token = self.server.recv(2048)
        print(f"[{user.user_id}] recv: received_encrypted_token")
        received_decrypted_token = self.decrypt_RSA(user.private_key, received_encrypted_token)
        self.client.send(self.encrypt_RSA(self.received_public_key, received_decrypted_token))
        print(f"[{user.user_id}] send: received_decrypted_token")
        received_encrypted_session_token = self.server.recv(2048)
        print(f"[{user.user_id}] recv: received_encrypted_session_token")
        received_decrypted_session_token = self.decrypt_RSA(user.private_key, received_encrypted_session_token)
        self.received_token = received_decrypted_token.decode()
        return self.verify_token(self.session_token, received_decrypted_session_token.decode())

    def authenticate_second(self, user):
        self.received_public_key = RSA.import_key(self.server.recv(2048))
        print(f"[{user.user_id}] recv: received_public_key")
        self.client.send(user.public_key.exportKey())
        print(f"[{user.user_id}] send: user.public_key")
        received_encrypted_token = self.server.recv(2048)
        print(f"[{user.user_id}] recv: received_encrypted_token")
        received_decrypted_token = self.decrypt_RSA(user.private_key, received_encrypted_token)
        self.client.send(self.encrypt_RSA(self.received_public_key, self.session_token.encode()))
        print(f"[{user.user_id}] send: session_token")
        received_encrypted_session_token = self.server.recv(2048)
        print(f"[{user.user_id}] recv: received_encrypted_session_token")
        received_decrypted_session_token = self.decrypt_RSA(user.private_key, received_encrypted_session_token)
        self.client.send(self.encrypt_RSA(self.received_public_key, received_decrypted_token))
        print(f"[{user.user_id}] send: received_decrypted_token")
        self.received_token = received_decrypted_token.decode()
        return self.verify_token(self.session_token, received_decrypted_session_token.decode())


@dataclass(kw_only=True)
class Connection(Authentication):
    client_ip: str
    client_port: int
    local_server_ip: str
    local_server_port: int
    server: socket.socket = None
    client: socket.socket = None
    server_is_online: bool = False
    first_to_auth: bool = True
    time_limit: int = 60

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f'... Escutando a porta {self.local_server_ip}.')
        server_socket.bind((self.local_server_ip, self.local_server_port))
        server_socket.listen()
        self.server, address = server_socket.accept()
        self.first_to_auth = False
        self.server_is_online = True
        print(f'... Servidor iniciado na porta {self.local_server_port}.')

    def connect_to_client(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for t in range(self.time_limit*2):
            time.sleep(0.5)
            try:
                self.client.connect((self.client_ip, self.client_port))
                self.first_to_auth = True
                print(f'... Cliente iniciado na porta {self.client_port}.')
                print('>> Aguardando servidor...')
                while not self.server_is_online:
                    time.sleep(0.1)
                print(f"{self.first_to_auth = }")
                return
            except:
                dot_string = '.'*(t%3+1)
                print(f'({t//2}) Conectando {dot_string}')
        self.client.close()
        print('\nTimeout.')

    def send_encrypted_message(self, message):
        encrypted_message = self.encrypt_RSA(self.received_public_key, message.encode())
        self.client.send(encrypted_message)
        return message
    
    def receive_encrypted_message(self, private_key):
        received_encrypted_message = self.server.recv(2048)
        received_decrypted_message = self.decrypt_RSA(
            private_key, received_encrypted_message).decode()
        token, message = received_decrypted_message.split(':', 1)
        if token != self.session_token:
            print(f'Token inválido. A conexão pode ter sido invadido.')
            print(f'Token recebido: {token}')
            print(f'Token original: {self.session_token}')
            return None
        return message

    def authenticate(self, user):
        while True:
            if self.first_to_auth: 
                self.authenticate_first(user)
            else: 
                self.authenticate_second(user)
            if self.received_public_key is not None:
                break
            self.client.close()
            self.server.close()
            print('Tentando novamente a autenticação...')
            self.connection.connect()
        return self
    
    def connect(self):
        threading.Thread(target=self.start_server).start()
        self.connect_to_client()
        return self

@dataclass(kw_only=True)
class VpnDestination:
    vpn_destination_ip: str = None
    vpn_destination_port: int = None
    vpn_destination_connection: Connection = None

    def serialize(self):
        return f"{self.vpn_destination_ip}:{self.vpn_destination_port}".encode()
    
    def deserialize(self, serialized):
        print(f"Deserializando {serialized}")
        ip, port = serialized.decode().split(':')
        self.vpn_destination_ip = ip
        self.vpn_destination_port = int(port)

@dataclass(kw_only=True)
class VpnServer(VpnDestination):
    vpn_user: User
    local_server_ip: str
    local_server_port_source: int
    local_server_port_destination: int

    source_ip: str
    source_port: int
    source_connection: Connection = None

    def intermediate_communication(self, connection_A, connection_B, communications):
        def threaded():
            for i in count(communications):
                received = connection_A.server.recv(2048)
                send = connection_B.client.send(received)
                print(f"Recebido de << {connection_A.client_ip}:{connection_A.client_port}")
                print(f"Enviado para >> {connection_B.client_ip}:{connection_B.client_port}\n{received}\n")
        threading.Thread(target=threaded).start()

    def authenticate_between_source_and_destination(self):
        self.intermediate_communication(
            connection_A=self.source_connection,
            connection_B=self.destination_connection,
            communications=3)
        self.intermediate_communication(
            connection_A=self.destination_connection,
            connection_B=self.source_connection,
            communications=3)

    def chat_between_source_and_destination(self):
        self.intermediate_communication(
            connection_A=self.source_connection,
            connection_B=self.destination_connection,
            communications=0)
        self.intermediate_communication(
            connection_A=self.destination_connection,
            connection_B=self.source_connection,
            communications=0)

    def connect_to_source(self):
        self.source_connection = Connection(
            client_ip=self.source_ip,
            client_port=self.source_port,
            local_server_ip=self.local_server_ip,
            local_server_port=self.local_server_port_source
        ).connect()
        destination_info = self.source_connection.server.recv(2048)
        self.deserialize(destination_info)
        print(f"Conectando com {self.vpn_destination_ip}:{self.vpn_destination_port}")
    
    def connect_to_destination(self):
        self.destination_connection = Connection(
            client_ip=self.vpn_destination_ip,
            client_port=self.vpn_destination_port,
            local_server_ip=self.local_server_ip,
            local_server_port=self.local_server_port_destination
        ).connect()


@dataclass(kw_only=True)
class CryptoChatVpn(Cryptography, VpnDestination):
    user: User
    connection: Connection
    vpn: VpnDestination = None
    friend_id: str = None
    friend_public_key: PKCS1_OAEP = None
    history: list[str] = None

    def send_message(self, message):
        if message.strip() == '':
            return
        if message.startswith('/add-friend '):
            new_friend_id = message.split(' ', 1)[1]
            self.friend_id = self.user.add_friend(new_friend_id, self.friend_public_key)
        message_with_token = f"{self.connection.received_token}:{message}"
        self.connection.send_encrypted_message(message_with_token)
        with threading.Lock():
            self.history.append(f"{self.user.user_id}: {message}\n")
            self.save_history()
        return f"{self.user.user_id}: {message}\n"
    
    def receive_message(self):
        message = self.connection.receive_encrypted_message(self.user.private_key)
        if message.strip() == '':
            return
        with threading.Lock():
            self.history.append(f"{self.friend_id}: {message}\n")
            self.save_history()
        return f"{self.friend_id}: {message}\n"

    def _test_threaded_chat(self):
        def receive():
            while True:
                received_message = self.receive_message()
                print(received_message, end='')
        def send():
            while True:
                sent_message = self.send_message(input(f"{self.user.user_id}: "))
        threading.Thread(target=receive).start()
        threading.Thread(target=send).start()

    def save_history(self):
        if self.friend_id == self.user.unknown_friend_string:
            return
        chat_history_path = f'users/{self.user.user_id}/friends/{self.friend_id}/chat.txt'
        with open(chat_history_path, 'w') as c:
            c.writelines(self.history)
            c.close()

    def get_history(self):
        if self.friend_id == self.user.unknown_friend_string:
            return []
        chat_history_path = f'users/{self.user.user_id}/friends/{self.friend_id}/chat.txt'
        if not os.path.exists(chat_history_path):
            return []
        with open(chat_history_path, 'r') as c:
            chat_history = c.readlines()
            c.close()
        return chat_history

    def start(self):
        self.connection.connect()
        if isinstance(self.vpn, VpnDestination):
            self.connection.client.send(self.vpn.serialize())
        self.connection.authenticate(self.user)

        self.friend_public_key = self.connection.received_public_key
        self.friend_id = self.user.search_friend(self.friend_public_key)
        print(f'Inicando conversa com {self.friend_id}...')
        self.history = self.get_history()
        return self


if __name__ == '__main__':
    user_B = User(user_id='B').login()
    B_connection = Connection(
        client_ip='127.0.0.1',
        client_port=60_002,
        local_server_ip='127.0.0.1',
        local_server_port=60_000,
    )
    
    chat = CryptoChatVpn(
        user=user_B, 
        connection=B_connection,
    ).start()._test_threaded_chat()