from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
from getpass import getpass
import hashlib, hmac, binascii


class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, "rb") as fo:
            plaintext = fo.read()

        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", "wb") as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, cipherText, key):
        iv = cipherText[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(cipherText[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            cipherText = fo.read()
        dec = self.decrypt(cipherText, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subDirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname != 'encrypt.py' and fname != 'data.txt.enc'):
                    dirs.append(dirName + "\\" + fname)
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_file(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)
