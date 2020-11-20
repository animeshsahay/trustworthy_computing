import getpass
import sys
import time

from KriptaRSA import KriptaRSA
from past.builtins import raw_input

import config
import actions
import passwords
from aes_encrypt import Encryptor

class Client:
    """
    Simple client class to handle connection to server
    """

    def __init__(self, _socket):
        self.socket = _socket
        self.nonce = 0
        self.salt = 0
        self.nonce_send = False

    def send(self, message):
        """
        sends message through socket to server
        """
        try:
            self.socket.send(message)
        except Exception:
            print("Unexpected error:", sys.exc_info()[0])

    def receive(self):
        """
        receives and returns message from server
        """
        input_line = None
        try:
            input_line = self.socket.recv(config.BUFFER_SIZE)
        except Exception:
            print("Unexpected error:", sys.exc_info()[0])

        return input_line

    def take_action(self, action_name):
        """
        decides on base of action_name what action should be taken
        in some actions sends respond to the server
        """
        if action_name == actions.QUIT_ACTION or len(action_name) == 0:
            return
        elif action_name == actions.USERNAME_ACTION:
            input_line = raw_input("Username: ")  # get username
        elif action_name == actions.PASSWORD_ACTION:
            input_line = getpass.getpass("Password: ")  # get password (with no echo)
            if self.nonce_send:
                hashed_password = passwords.hash_password(input_line, self.salt)[0]  # hash pass
                input_line = passwords.hash_password(hashed_password, self.nonce)[0]  # add nonce and hash again
                self.nonce_send = False
        elif action_name == actions.OLD_PASSWORD_ACTION:
            input_line = getpass.getpass("Old_password: ")  # get password (with no echo)
        elif action_name == actions.NEW_PASSWORD_ACTION:
            input_line = getpass.getpass("New_password: ")  # get password (with no echo)
        elif action_name == actions.TYPE_ACTION:
            input_line = raw_input(">> ")  # get action type
        elif action_name == actions.RSA_ACTION:
            input_l = raw_input(">> ")
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
            print("PublicKey : ", k.getPublicKey().decode("utf-8"))
            print("PrivateKey : ", k.getPrivateKey().decode("utf-8"))
            print("Encrypting Message")
            input_line = k.encrypt(k.getPublicKey(), input_l.encode())
            time.sleep(1)
            print("Sending encrypted message")
            
        elif action_name == actions.AES_ACTION:
            input_l = raw_input(">> ")
            key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02}j\xdf\xcb\xc4\x94\x9d(\x9e'
            enc_aes = Encryptor(key)
            print("Encrypting Message")
            input_line=enc_aes.encrypt(input_l,key)
            time.sleep(1)
            print("Sending encrypted message")
            
        elif action_name.find(actions.NONCE_ACTION.encode()) != -1:
            action, salt_value, nonce_value = action_name.decode().split(':')
            self.salt = salt_value
            self.nonce = nonce_value
            self.nonce_send = True
            return
        else:  # other communicate from server
            print(action_name)  # show it
            return

        if len(input_line) == 0:
            input_line = "__"
        self.send(input_line)  # send answer to server if needed

    def handle_connection(self):
        """
        main function to handle connection with server
        """

        action_name = "_"
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
        while action_name != actions.QUIT_ACTION and len(action_name) != 0:
            action_name = self.receive()

            actions_array = action_name.splitlines()

            for action in actions_array:
                self.take_action(action)
        print("Connection closed")
        self.socket.close()  # Close the socket when done
