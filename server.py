import socket
import ssl
import sys
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os

class ChatServer:

    clients_list = []
    senders_list=[]

    last_received_message = ""

    def __init__(self):
        self.key_socket = None
        self.server_socket = None
        self.public_key=None
        self.private_key=None
        self.init_keys()
        self.create_listening_server()
    #listen for incoming connection

    def init_keys(self):
        key = RSA.generate(1024)
        pri = key.exportKey()
        pub = key.publickey().exportKey()
        self.private_key = RSA.importKey(pri)
        self.public_key = RSA.importKey(pub)
        #print(self.public_key.exportKey())


    def create_listening_server(self):

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create a socket using TCP port and ipv4
        #self.key_socket = ssl.create_default_context().wrap_socket(self.server_socket, server_side=Tru
        local_ip = '127.0.0.1'
        local_port = 10319
        # this will allow you to immediately restart a TCP server
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # this makes the server listen to requests coming from other computers on the network
        self.server_socket.bind((local_ip, local_port))
        print("Listening for incoming messages..\n The amount of users in parallel is: "+str(sys.argv[1]))
        self.server_socket.listen(int(sys.argv[1])) #listen for incomming connections / max 5 clients
        self.receive_messages_in_a_new_thread()
    #fun to receive new msgs

    def receive_messages(self, client):
        so,(ip,port)=client[0]
        key=client[1]
        while True:
            incoming_buffer = so.recv(1024) #initialize the buffer
            if not incoming_buffer:
                break
            try:
                if incoming_buffer[:3].decode()=="key" and not key:
                    key=self.private_key.decrypt(incoming_buffer[3:])
                    print("--------private-key-decrypt--------")
                    print(key)
                    client= (client[0],key)
                    self.senders_list.append(client)
                    incoming_buffer=None
                    #print(client)
            except:
                print ("worng init client")
            if incoming_buffer:
                print(self.last_received_message)
                self.last_received_message=self.decrypt_msg(incoming_buffer,key)
                self.broadcast_to_all_clients(so)  # send to all clients
        so.close()
    #broadcast the message to all clients
    def broadcast_to_all_clients(self, senders_socket):
        for client in self.senders_list:
            socket, (ip, port) = client[0]
            key=client[1]
            if socket is not senders_socket:
                socket.sendall(self.encrypt_msg(self.last_received_message,key))

    def receive_messages_in_a_new_thread(self):
        while True:
            client = so, (ip, port) = self.server_socket.accept()
            key=None
            client=(client,key)
            self.add_to_clients_list(client)
            print('Connected to ', ip, ':', str(port))
            t = threading.Thread(target=self.receive_messages, args=(client,))
            t.start()

    #add a new client
    def add_to_clients_list(self, client):
        if client not in self.clients_list:
            soc,(ip,port)=client[0]
            key=client[1]
            print(self.public_key.exportKey())
            soc.sendall(self.public_key.exportKey())
            self.clients_list.append(client)

    def padd_message(self,msg):
        while len(msg)%16!=0:
            msg+=" "
        return msg

    def unpadd_message(self,msg):
        return msg.strip(" ")

    def encrypt_msg(self,msg,key):
        msg=self.padd_message(msg)
        rand_vector= os.urandom(16)
        enc_chiper = AES.new(key,AES.MODE_CBC,rand_vector)
        return rand_vector+enc_chiper.encrypt(msg)

    def decrypt_msg(self,msg,key):
        rand_vector=msg[:16]
        print("----------------rand_vector----------------")
        print(rand_vector)
        print("-----------message before decrypt----------")
        print(msg)
        dec_chiper = AES.new(key,AES.MODE_CBC,rand_vector)
        return dec_chiper.decrypt(msg[16:])


if __name__ == "__main__":
    ChatServer()