import sys
import threading  # for multi-thread support
import time

import actions
import database
import passwords
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import base64
from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
from getpass import getpass
import hashlib, hmac, binascii
from KriptaRSA import KriptaRSA
from aes_encrypt import Encryptor


class ClientHandler(threading.Thread):
	def __init__(self, _socket):
		threading.Thread.__init__(self)
		self.socket = _socket

	def receive(self):
		"""
		receives and returns message from client
		catch an error if connection brakes
		"""
		input_line = None
		try:
			#input_line = self.socket.recv(config.BUFFER_SIZE)
			input_line = self.socket.recv(1024)
		except Exception:
			print("Unexpected error:", sys.exc_info()[0])

		return input_line

	def send(self, message):
		"""
		sends message through socket to client
		catch an error if connection brakes
		"""
		try:
			self.socket.send(message + "\n")
		except Exception:
			print("Unexpected error:", sys.exc_info()[0])

	def register(self):
		"""
		register user function
		create user in database if everything succeed
		"""
		print("Registering....")

		is_taken = True
		username = None

		while is_taken:
			self.send(actions.USERNAME_ACTION)
			username = self.receive()  # get username
			if not database.is_username_taken(username):  # check if is free
				is_taken = False
			else:
				self.send("Username already taken, try something else")

		# username is free

		is_valid = False
		password = None

		while not is_valid:
			self.send(actions.PASSWORD_ACTION)
			password = self.receive()  # get password
			self.send("Repeat password \n")
			self.send(actions.PASSWORD_ACTION)
			password_repeat = self.receive()  # get repeated password
			if password_repeat != password:  # compare them
				self.send("Passwords are not the same, try again")  # passwords not the same
				continue  # prompt for passwords again
			if passwords.is_password_valid(password):  # passwords the same -> check if pass is valid
				is_valid = True
			else:
				self.send("Password is invalid (should have more than 7 characters,"  # pass invalid
						  " at last one digit, one lowercase and one uppercase),"  # send validate pass rules
						  " try something else.")

		# password is valid

		hashed_password, salt = passwords.hash_password_generate_salt(password)  # create hash
		database.create_user(username, hashed_password, salt)  # create user into database

		self.send("User successfully registered! \nNow you can log in")  # confirm successful registration

	def mac_integrity(self, message):
	 	print("Message from message: ",message)
	 	mac = hmac.new(b'key_ma', message, hashlib.sha256).digest()
	 	return binascii.hexlify(mac)

	def mac_check(self,m1,m2):
		if(m1==m2):
			print("MAC Verified\n")
		else:
			print("MAC is NOT verified, the message has been changed!\n")

	def login(self):
		"""
		login user function
		give an access for successfully logged user
		"""
		print("Login....")

		self.send(actions.USERNAME_ACTION)
		username = self.receive()  # get username

		print(username)

		hashed_password = None
		salt = None
		hash_and_salt = database.get_password(username)  # get salt and hashed password from database
		if hash_and_salt:
			hashed_password = hash_and_salt[0]
			salt = hash_and_salt[1]

		if not salt:  # user does not exist in database
			salt = passwords.get_salt()  # to not reveal if username exist or not
			# behave naturally with newly generated salt
		nonce = passwords.get_salt()
		self.send(actions.NONCE_ACTION + ":" + salt + ":" + nonce)
		self.send(actions.PASSWORD_ACTION)
		password = self.receive()  # get password

		if hashed_password is not None and passwords.check_password(password, nonce, hashed_password):
			self.send("Successfully login")  # passwords matched
			self.logged(username)  # access granted
		else:
			self.send("User or password incorrect")  # passwords mismatch

	def change_password(self, username):
		"""
		change password user function
		change password for user in database if everything succeed
		"""
		print("Changing password....")

		is_valid = False
		password = None

		while not is_valid:
			self.send(actions.PASSWORD_ACTION)
			password = self.receive()  # get password
			self.send("Repeat password \n")
			self.send(actions.PASSWORD_ACTION)
			password_repeat = self.receive()  # get repeated password
			if password_repeat != password:  # compare them
				self.send("Passwords are not the same, try again")  # passwords not the same
				continue  # prompt for passwords again
			if passwords.is_password_valid(password):  # passwords the same -> check if pass is valid
				is_valid = True
			else:
				self.send("Password is invalid (should have more than 7 characters,"  # pass invalid
						  " at last one digit, one lowercase and one uppercase),"  # send validate pass rules
						  " try something else.")

		# password is valid

		hashed_password, salt = passwords.hash_password_generate_salt(password)  # create hash
		database.change_password(username, hashed_password, salt)  # change password for user into database

		self.send("Password successfully changed \nNow you can log in with a new one")  # confirm successful action

	def logged(self, username):
		"""
		function to handle logged user
		shows menu with actions for logged users
		"""

		self.send("Access granted!")

		while True:
			self.send(" \nWhat do you want to do? (message/change_password/logout/delete_account)")  # menu for logged user
			self.send(actions.TYPE_ACTION)
			current_type = self.receive()  # get type
			if current_type is None:  # if
				print("Connection lost")  # error occurred
				return  # leave function
			elif current_type == "change_password":
				self.change_password(username)
			elif current_type == "delete_account":  # give possibility to resign of the account
				database.delete_user(username)  # delete user from database
				self.send("Your account was removed from the system")
				return
			elif current_type == "message":
				self.message()
				
			elif current_type == "logout":  # end of work
				return  # leave function
			else:
				self.send("unrecognized type")

	def message(self):
		#encryption_type = int(input("Which encryption do you want to use? 1. RSA 2. AES"))
		self.send("Which encryption do you want to use? 1. RSA 2. AES")
		self.send(actions.TYPE_ACTION)
		encryption_type = int(self.receive())
		if encryption_type == 1:
			time.sleep(1)
			print("\n\n**************STARTING RSA ENCRYPTION*************")
			k = KriptaRSA()

			# You can generate KeyPairs here:
			# print(k.generate_RSA())

			# You can set/get PublicKey or Private key :
			k.setPublicKey('-----BEGIN PUBLIC KEY-----\n' +
						   'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCb8Jqk7U9RMEzb4bvO63EtDTHR\n' +
						   'LUQg8cJD5/0OQB1yx0Tro6sWNHScn40Px5+SHQYtH9VQPAcydJ+3wS/K7gA5D+r3\n' +
						   'RqqJMLWV1EkXQ6U0/3QR38twXN4eP9gqI1WaAW4Fad8kiuxfaVtEmmng9BN2ccg0\n' +
						   'RP80PMCLjDP0gv+umwIDAQAB\n' +
						   '-----END PUBLIC KEY-----')

			k.setPrivateKey('-----BEGIN RSA PRIVATE KEY-----\n' +
							'MIICXAIBAAKBgQCb8Jqk7U9RMEzb4bvO63EtDTHRLUQg8cJD5/0OQB1yx0Tro6sW\n' +
							'NHScn40Px5+SHQYtH9VQPAcydJ+3wS/K7gA5D+r3RqqJMLWV1EkXQ6U0/3QR38tw\n' +
							'XN4eP9gqI1WaAW4Fad8kiuxfaVtEmmng9BN2ccg0RP80PMCLjDP0gv+umwIDAQAB\n' +
							'AoGBAJPhemYJfnyZ92lWCsrR0ERPDP03ljI/0mCfcgW/m62rd5qXXbnzCNs3G4jp\n' +
							'YFQqHh9Q3vP12UVp/8U8+VvSlHYMSmWH0Tzcm2G894+V5WKfPAadYnTfRWIdhZs8\n' +
							'eMpKmBL/R4ITprAIapz/2JkHoXMVVhjsmvSuR/UpXb4BfmYBAkEAtvITL7Z8z2tu\n' +
							'Yi8Vn5dEvqlyha1my6hVeEvPI14RYfSSJUAVROGsjfz1Gfe6jJb53DBd7rylYcSZ\n' +
							'62KwGjo6gQJBANo10imgQWjX0MurYen1kWWMIOx/DotPf39gB/vfWgOdm+8j72da\n' +
							'iSSHUogPQX+fPYr8W55rFZfdjkEenAIsAxsCQED/72szZlL386c03XTvdQBdChCO\n' +
							'1IgljgCIxtblFD3+fHJ5u1TW7c0hBCCu0PwkpC/ki2tIYWZESP/F95XJ/IECQEpy\n' +
							'KERpV0eEsch6rQob7MH/X9AvvO+MbMwxICgvWE95exTIZsoVGkrrHB4tTkRTOLTt\n' +
							'SfivQguw2/Kdlc4r49cCQEgULygEDSzkkz3FD0KCy9jprYs9Pdswc5Log19kW3Ih\n' +
							'ELBTlo8/pPOqTVTgJ2XNCsXrZDtkM2j0e8MiFhXhDZ0=\n' +
							'-----END RSA PRIVATE KEY-----')
			self.send("Enter your message")
			self.send(actions.RSA_ACTION)
			enc_msg=self.receive()
			em_rsa_full=enc_msg.split(':')
			em_rsa=str(em_rsa_full[0])
			mac_client_rsa=str(em_rsa_full[1])
			print(" ") #new line
			print("PublicKey : ", k.getPublicKey().decode("utf-8"))
			print(" ") #new line
			print("Encrypted-Message : ", em_rsa)
			print("Decrypting Message")
			time.sleep(1)
			print("Decrypted-Message : ", str(k.decrypt(em_rsa)))
			mac_server_rsa=self.mac_integrity(k.decrypt(em_rsa))
			print("MAC Server: ", mac_server_rsa)
			print("MAC Client: ", mac_client_rsa)
			self.mac_check(mac_server_rsa,mac_client_rsa)

		elif encryption_type == 2:
			time.sleep(1)
			print("\n\n*********************Starting AES Encryption*****************")

			key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02}j\xdf\xcb\xc4\x94\x9d(\x9e'
			enc_aes = Encryptor(key)
			self.send("Enter your message")
			self.send(actions.AES_ACTION)
			encrypted_message = self.receive()
			em_aes_full=encrypted_message.split(':')
			em_aes=str(em_aes_full[0])
			mac_client_aes=str(em_aes_full[1])
			#enc_aes = Encryptor(key)
			print("Encrypted-Message: ",em_aes)
			print("Decrypting Message")
			time.sleep(1)
			print("Decrypted-Message : ", str(enc_aes.decrypt(em_aes,key)))
			mac_server_aes=self.mac_integrity(enc_aes.decrypt(em_aes,key))
			print("MAC Server: ", mac_server_aes)
			print("MAC Client: ", mac_client_aes)
			self.mac_check(mac_server_aes, mac_client_aes)

		else:
			self.send("Unrecognized type")


	def run(self):
		"""
		main function when thread starts
		to manage connection with client
		"""
		self.send("Connected to server")

		while True:
			self.send(" \nWhat do you want to do? (register/login/message/quit)")
			self.send(actions.TYPE_ACTION)
			current_type = self.receive()  # get type
			if current_type is None:  # connection broken
				break
			elif current_type == "login":
				self.login()  # login action
			elif current_type == "register":
				self.register()  # register action
			elif current_type == "message":
				message = input("Enter your message!!")
				self.message(message)
			elif current_type == "quit":
				self.send(actions.QUIT_ACTION)  # quit action
				break
			else:
				self.send("Unrecognized type")

		# user quit from server
		print("Client disconnected")
		self.socket.close()  # Close the connection

'''class Encryptor:
	def __init__(self,key):
		self.key=key

	def pad(self, s):
		return s+b"\0" * (AES.block_size - len(s)%AES.block_size)

	def encrypt(self, message, key, key_size = 256):
		message = self.pad(message)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return iv + cipher.encrypt(message)

	def decrypt(self,cipherText, key):
		iv = cipherText[:AES.block_size]
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plaintext = cipher.decrypt(cipherText[AES.block_size:])
		return plaintext.rstrip(b"\0")

	def decrypt_all_file(self):
		dirs= self.getAllFiles()
		for file_name in dirs:
			self.decrypt_file(file_name)'''