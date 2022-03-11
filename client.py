from tkinter import Tk, Frame, Scrollbar, Label, END, Entry, Text, VERTICAL, Button, messagebox, Toplevel, StringVar
import socket
import threading
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
import os
class GUI:
    client_socket = None
    last_received_message = None

    def __init__(self, master):
        self.root = master
        self.chat_transcript_area = None
        self.name_widget = None
        self.pass_widget= None
        self.pass_button = None
        self.enter_text_widget = None
        self.join_button = None
        self.key=None
        self.pub = None
        self.initialize_socket()
        self.initialize_gui()
        self.flag=None
        self.enc=hashlib.sha256()
        self.enc_chiper=None
        self.dec_chiper = None

        self.listen_for_incoming_messages_in_a_thread()
    def initialize_socket(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # initialazing socket with TCP and IPv4
        remote_ip = '127.0.0.1' # IP address
        remote_port = 10319 #TCP port
        self.client_socket.connect((remote_ip, remote_port)) #connect to the remote server
        self.share_key()


    def share_key(self):
        tmppub=""
        while True:
            tmppub=self.client_socket.recv(1024)
            if tmppub:
                break
        self.pub=RSA.importKey(tmppub)
        print("-------RSA-obj-key------")
        print(self.pub)

    def initialize_gui(self,password=None): # GUI initializer
        #self.display_popup_password()
        self.root.title("A&D Chat")
        self.root.resizable(0, 0)
        self.display_chat_box()
        self.display_name_section()
        #self.display_pass_section()
        self.display_chat_entry_box()
        self.display_popup_password()

    def listen_for_incoming_messages_in_a_thread(self):
        thread = threading.Thread(target=self.receive_message_from_server, args=(self.client_socket,)) # Create a thread for the send and receive in same time
        thread.start()
    #function to recieve msg
    def receive_message_from_server(self, so):
        while True:
            buffer = so.recv(256)
            if not buffer:
                break
            message = self.unpadd_message(self.decrypt_msg(buffer))

            if "joined" in message:
                user = message.split(":")[1]
                message = user + " has joined"
                self.chat_transcript_area.insert('end', message + '\n')
                self.chat_transcript_area.yview(END)
            else:
                self.chat_transcript_area.insert('end', message + '\n')
                self.chat_transcript_area.yview(END)

        so.close()
    def disable_event(self):
        pass
    def display_popup_password(self):
        self.popup = Toplevel(bg="light blue")
        self.popup.wm_title("Password-Key")
        Label(self.popup, text="Please Choose Password",font="Helvetica 16 bold italic").pack(side="left", fill="x", pady=10, padx=10)
        mystring = StringVar(self.popup)
        self.pass_widget = Entry(self.popup, width=30, borderwidth=9)
        self.pass_widget.pack(side='left', anchor='e')
        self.pass_button = Button(self.popup,    bd=0,
                                            relief="groove",
                                            bg="blue",
                                            fg="black",
                                            activeforeground="light blue",
                                            activebackground="white",
                                            font="arial 14", text="Accept", command=self.on_enter)
        self.pass_button.pack(side='left')
        self.popup.lift()
        self.popup.protocol("WM_DELETE_WINDOW", self.disable_event)
        #self.popup.mainloop()

    def display_name_section(self):
        frame = Frame()
        Label(frame, text='Enter your name:',bg="light blue", font=("Helvetica", 16)).pack(side='left', padx=10)
        self.name_widget = Entry(frame, width=30, borderwidth=6)
        self.name_widget.pack(side='left', anchor='e')
        self.join_button = Button(frame,bd=0,
                                            relief="groove",
                                            bg="blue",
                                            fg="black",
                                            activeforeground="light blue",
                                            activebackground="white",
                                            font="arial 14", text="Join", command=self.on_join)
        self.join_button.pack(side='left')
        frame.pack(side='top', anchor='nw')

    def display_pass_section(self):
        frame = Frame()
        Label(frame, text='Enter Password: ', bg="light blue", font=("Helvetica", 16)).pack(side='left', padx=10)
        self.pass_widget = Entry(frame, width=50, borderwidth=2)
        self.pass_widget.pack(side='left', anchor='e')
        self.pass_button = Button(frame, text="Enter pass", width=10, command=self.on_enter).pack(side='left')
        #self.pass_button.config(state="disabled")
        frame.pack(side='top', anchor='nw')

    def display_chat_box(self):
        frame = Frame(bg="light blue")
        Label(frame, text='Chat Box:',bg="light blue", font=("Serif", 12)).pack(side='top', anchor='w')
        self.chat_transcript_area = Text(frame, width=60, height=10, font=("Serif", 12))
        scrollbar = Scrollbar(frame, command=self.chat_transcript_area.yview, orient=VERTICAL)
        self.chat_transcript_area.config(yscrollcommand=scrollbar.set)
        self.chat_transcript_area.bind('<KeyPress>', lambda e: 'break')
        self.chat_transcript_area.pack(side='left', padx=10)
        scrollbar.pack(side='right', fill='y')
        frame.pack(side='top')

    def display_chat_entry_box(self):
        frame = Frame(bg="light blue")
        Label(frame, text='Enter message:',bg="light blue", font=("Serif", 12)).pack(side='top', anchor='w')
        self.enter_text_widget = Text(frame, width=60, height=3, font=("Serif", 12))
        self.enter_text_widget.pack(side='left', pady=15)
        self.enter_text_widget.bind('<Return>', self.on_enter_key_pressed)
        frame.pack(side='top')

    def on_join(self):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror(
                "Enter your name", "Enter your name to send a message")
            return
        self.name_widget.config(state='disabled')
        self.client_socket.send(self.encrypt_msg("joined:" + self.name_widget.get()))

    def on_enter(self):
        if len(self.pass_widget.get()) == 0:
            messagebox.showerror(
                "Enter Password", "Enter your Password to create encryption key")
            return
        self.pass_widget.config(state='disabled')
        self.key=hashlib.sha256(self.pass_widget.get().encode()).digest()
        self.popup.destroy()
        print("-------RSA-private-key------")
        print(self.key)
        print("-------AES-RSA-private-key------")
        print(self.pub.encrypt(self.key,16))
        self.client_socket.send(b"key" +self.pub.encrypt(self.key,16)[0])

    def encrypt_msg(self,msg):
        msg=self.padd_message(msg)
        rand_vector= os.urandom(16)
        enc_chiper = AES.new(self.key,AES.MODE_CBC,rand_vector)
        return rand_vector+enc_chiper.encrypt(msg)

    def decrypt_msg(self,msg):
        rand_vector=msg[:16]
        print("-------RSA-Vector------")
        print(rand_vector)
        dec_chiper = AES.new(self.key,AES.MODE_CBC,rand_vector)
        return dec_chiper.decrypt(msg[16:]).decode()

    def on_enter_key_pressed(self, event):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror("Enter your name", "Enter your name to send a message")
            return
        self.send_chat()
        self.clear_text()

    def clear_text(self):
        self.enter_text_widget.delete(1.0, 'end')

    def send_chat(self):
        senders_name = self.name_widget.get().strip() + ": "
        data = self.enter_text_widget.get(1.0, 'end').strip()
        #data=self.encrypt_msg(data)
        message = self.encrypt_msg(senders_name + data)
        self.chat_transcript_area.insert('end', senders_name + data + '\n')
        self.chat_transcript_area.yview(END)
        print("-------Message------")
        print(message)
        self.client_socket.send(message)
        self.enter_text_widget.delete(1.0, 'end')
        return 'break'

    def padd_message(self,msg):
        while len(msg)%16!=0:
            msg+=" "
        return msg

    def unpadd_message(self,msg):
        return msg.strip(" ")

    def on_close_window(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
            self.client_socket.close()
            exit(0)

#the mail function
if __name__ == '__main__':
    root = Tk()
    root.configure(bg='light blue')
    gui = GUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_close_window)
    root.mainloop()