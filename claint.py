import socket
from cryptography.fernet import Fernet
import cryptography
import threading
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sys

nickname = input("Choose your nickname: ")
password_provided = input("Enter the master password: ")
password_provided2 = input("Enter the second password: ")
ipcon = input("Enter the server's IP address: ")
portcon = input("Enter the server's port: ")

password = password_provided.encode()
salt = password_provided2.encode()
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
systemmsg = [""]
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try :
	client.connect((ipcon, int(portcon)))
except TypeError :
	print("Error.")
	sys.exit()
except socket.gaierror :
	print(f"Port {portcon} Not found on {ipcon}".format(portcon,ipcon))
	sys.exit()
	

def receive():
	while True:
		try:
			encrypted = client.recv(1024).decode('ascii')
			
			if encrypted=='NICK':
				client.send(nickname.encode('ascii'))
			else:
				message = f.decrypt(encrypted.encode('ascii'))
				print(message.decode('ascii'))
		except cryptography.fernet.InvalidToken:
			if encrypted.startswith('systemmsgbro_'):
				encrypted=encrypted.replace('systemmsgbro_','')
				print(encrypted)
		except :	
			print("An error occured!")
			client.close()
			break
def write():
	while True:
		message = '{}: {}'.format(nickname, input(''))
		encrypted = f.encrypt(message.encode('ascii'))
		client.send(encrypted)

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
