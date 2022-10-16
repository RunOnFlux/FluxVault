'''This module is a single file that supports the loading of secrets into a Flux Node'''
import binascii
import json
import sys
import time
from datetime import datetime
import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

VAULT_NAME = ""
BOOTFILES = []
FILE_DIR = ""

MAX_MESSAGE = 8192

DISCONNECTED = "DISCONNECTED"
CONNECTED = "CONNECTED"
KEYSENT = "KEYSENT"
STARTAES = "STARTAES"
PASSED = "PASSED"
READY = "READY"
REQUEST = "REQUEST"
DONE = "DONE"
AESKEY = "AESKEY"
FAILED = "FAILED"

# Agent Responses

# Use PASSED as initial dummy state
DATA = "DATA"

# Utility routines used by Node, Vault or Both

def encrypt_data(keypem, data):
    '''Used by the Vault to create and send a AES session key protected by RSA'''
    key = RSA.import_key(keypem)
    session_key = get_random_bytes(16)
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    msg = {
        "enc_session_key":enc_session_key.hex(),
        "nonce": cipher_aes.nonce.hex(),
        "tag": tag.hex(),
        "cipher": ciphertext.hex()
    }
    return msg

def decrypt_data(keypem, cipher):
    '''Used by Node to decrypt and return the AES Session key using the RSA Key'''
    private_key = RSA.import_key(keypem)
    enc_session_key = bytes.fromhex(cipher["enc_session_key"])
    nonce = bytes.fromhex(cipher["nonce"])
    tag = bytes.fromhex(cipher["tag"])
    ciphertext = bytes.fromhex(cipher["cipher"])

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data

def decrypt_aes_data(key, data):
    '''
    Accept out cipher text object
    Decrypt data with AES key
    '''
    try:
        jdata = json.loads(data)
        nonce = bytes.fromhex(jdata["nonce"])
        tag = bytes.fromhex(jdata["tag"])
        ciphertext = bytes.fromhex(jdata["ciphertext"])

        # let's assume that the key is somehow available again
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        msg = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return { "State": FAILED}
    return json.loads(msg)

def encrypt_aes_data(key, message):
    '''
    Take a json object, dump it in plain text
    Encrypt message with AES key
    Create a json object with the cipher text and digest
    Then return that object in plain text to send to our peer
    '''
    msg = json.dumps(message)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode("utf-8"))
    jdata = {
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    data = json.dumps(jdata)
    return data

def send_receive(sock, request):
    '''
    Send a request message and wait for a reply
    '''
    request += "\n"

    try:
        sock.sendall(request.encode("utf-8"))
    except socket.error:
        print('Send failed')
        sys.exit()

    # Receive data
    try:
        reply = sock.recv(MAX_MESSAGE)
    except TimeoutError:
        print('Receive time out')
        return None
    reply = reply.decode("utf-8")
    return reply

# pylint: disable=W0702
def receive_only(sock):
    '''
    Wait for a message from our peer
    '''
    # Receive data
    try:
        reply = sock.recv(MAX_MESSAGE)
        reply = reply.decode("utf-8")
    except:
        reply = ""
    return reply

def receive_public_key(sock):
    '''Receive Public Key from the Node or return None on error'''
    try:
        reply = receive_only(sock)
    except TimeoutError:
        return None

    if len(reply) == 0:
        return None
    try:
        jdata = json.loads(reply)
        public_key = jdata["PublicKey"].encode("utf-8")
    except ValueError:
        return None
    return public_key

class FluxNode:
    '''Create a small server that runs on the Node waiting for Vault to connect'''
    vault_name = ""
    user_files = []
    file_dir = ""
    def __init__(self) -> None:
        self.nkdata = { "State": DISCONNECTED }
        self.user_request_count = 1
        self.reply = "reply"
        self.request = ""
        self.agent_response = {}
        self.agent_response[PASSED] = self.agent_passed
        self.agent_response[DATA] = self.agent_data

    def connected(self, peer_ip: str) -> bool:
        '''Call when connection is established to verify correct source IP'''
         # Verify the connection came from our Vault IP Address
        if len(self.vault_name) == 0:
            print("Vault Name not configured in FluxNode class or child class")
            return False
        hname = self.vault_name
        try:
            result = socket.gethostbyname(hname)
        except socket.gaierror:
            print("Vault name not vaild DNS ", hname)
            return False
        if peer_ip[0] != result:
            # Delay invalid peer to defend against DOS attack
            time.sleep(15)
            print( "Reject Connection, wrong IP:" + peer_ip[0] + " Expected " + result)
            return False
        self.nkdata = { "State": CONNECTED }
        self.user_request_count = 1
        return True

    def handle(self, read, write):
        '''Gets called from socket thread to handle incoming data'''
        reply = self.create_send_public_key()

        while True:
            if len(reply) > 0:
                write(reply.encode("utf-8"))

            data = read()
            if not data:
                # No Message - Get Out
                break
            state = self.process_message(data)
            if state == READY:
                state = self.agent_action() # process agent commands
            if state == FAILED:
                # Something went wrong, abort
                break
            reply = self.reply
        # When we return the connection is closed

    def current_state(self) -> str:
        '''Returns current state of the Node Key Data'''
        return self.nkdata["State"]

    def create_send_public_key(self):
        '''
        New incoming connection from Vault
        Create a new RSA key and send the Public Key the Vault
        The message should be signed by the Flux Node we are running on
        so we can authenticate the message

        This is the only message sent unencrypted.
        This is Ok because the Public Key can be Public
        '''
        self.nkdata["RSAkey"] = RSA.generate(2048)
        self.nkdata["Private"] = self.nkdata["RSAkey"].export_key()
        self.nkdata["Public"] = self.nkdata["RSAkey"].publickey().export_key()
        self.nkdata["State"] = KEYSENT
        jdata = { "State": KEYSENT, "PublicKey": self.nkdata["Public"].decode("utf-8")}
        reply = json.dumps(jdata) + "\n"
        # Add this signed_reply = flux_node_sign_message(reply)
        return reply

    def process_message(self, data) -> str:
        '''Process incoming message to get to the Ready state and then capture incoming request'''
        try:
            self.reply = ""
            # We send our Public key and expect an AES Key for our session, if not Get Out
            if self.nkdata["State"] == KEYSENT:
                jdata = json.loads(data)
                if jdata["State"] != AESKEY:
                    self.nkdata["State"] = FAILED # Tollerate no errors
                else:
                    # Decrypt with our RSA Private Key
                    self.nkdata["AESKEY"] = decrypt_data(self.nkdata["Private"], jdata)
                    self.nkdata["State"] = STARTAES
                    # Send a test encryption message, always include random data
                    random = get_random_bytes(16).hex()
                    jdata = { "State": STARTAES, "Text": "Test", "fill": random}
                    # Encrypt with AES Key and send reply
                    self.reply = encrypt_aes_data(self.nkdata["AESKEY"], jdata) + "\n"
            else:
                if self.nkdata["State"] == STARTAES:
                    # Do we both have the same AES Key?
                    jdata = decrypt_aes_data(self.nkdata["AESKEY"], data)
                    if jdata["State"] == STARTAES and jdata["Text"] == "Passed":
                        self.nkdata["State"] = PASSED # We are good to go!
                    else:
                        self.nkdata["State"] = FAILED # Tollerate no errors
            if self.nkdata["State"] == READY:
                # Decrypt message from Vault so user code can handle it
                # This will be a reply to a request the Node made
                # The user code will then issue a new request or call done
                self.request = decrypt_aes_data(self.nkdata["AESKEY"], data)
            if self.nkdata["State"] == PASSED:
                self.nkdata["State"] = READY
                self.request = {"State": PASSED} # Initial state, no reply, send first request
        except ValueError:
            # Decryption error or unhandled exception with close connection
            self.nkdata["State"] = FAILED
            print("process message failed")
        return self.current_state()

    def agent_action(self):
        '''
        Handle Agent replies, the response "State" field tells us what action is needed.
        Each State should be unique because the state value (string) is used to
        define the function called in the self.agent_response dict

        If the none of the agent functions do not handle the request we abort the connection,
        otherwise the agent calls the user_request function to with a step number 1..n
        The default user_request function will request all files define in the bootfiles array
        The MyFluxNode class (example in vault_node.py) can redefine teh user_request function
        '''
        if self.agent_response[self.request["State"]]():
            # The Received message was processed, generate the next request
            if self.user_request(self.user_request_count):
                self.user_request_count = self.user_request_count + 1
                random = get_random_bytes(16).hex()
                self.request["fill"] = random
                self.reply = encrypt_aes_data(self.nkdata["AESKEY"], self.request)
                return PASSED
        return FAILED

    def agent_passed(self) -> bool:
        '''Node side processing of vault replies for all predefined actions'''
        if self.request["State"] == PASSED:
            return True
        return False

    def agent_data(self) -> bool:
        '''Node side processing of vault replies for all predefined actions'''
        if self.request["State"] == DATA:
            if self.request["Status"] == "Success":
                with open(self.file_dir+self.request["FILE"], "w", encoding="utf-8") as file:
                    file.write(self.request["Body"])
                    file.close()
                    print(self.request["FILE"], " received!")
                    return True
            if self.request["Status"] == "Match":
                print(self.request["FILE"], " Match!")
                return True
            if self.request["Status"] == "FileNotFound":
                print(self.request["FILE"], " was not found?")
                return True
        return False

    def request_done(self) -> None:
        '''Tell vault we are done'''
        self.request = { "State": DONE }
        return True

    def request_file(self, fname) -> None:
        '''Open the file and compute the crc, set crc=0 if not found'''
        try:
            with open(self.file_dir+fname, encoding="utf-8") as file:
                content = file.read()
                file.close()
            crc = binascii.crc32(content.encode("utf-8"))
            # File exists
        except FileNotFoundError:
            crc = 0
        self.request = { "State": REQUEST, "FILE": fname, "crc32": crc }

    def user_request(self, step) -> bool:
        '''Defined by User class, if needed'''
        if step == len(self.user_files)+1:
            return self.request_done()
        if step-1 in range(len(self.user_files)):
            self.request_file(self.user_files[step-1])
            return True
        return False

# Routines for fluxVault class
def open_connection(port, appip):
    '''Open socket to Node'''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        return 'Failed to create socket'

    try:
        remote_ip = socket.gethostbyname( appip )
    except socket.gaierror:
        return 'Hostname could not be resolved'

    # Set short timeout
    sock.settimeout(30)

    # Connect to remote server
    try:
        error = None
        #  print('# Connecting to server, ' + appip + ' (' + remote_ip + ')')
        sock.connect((remote_ip , port))
    except ConnectionRefusedError:
        error = appip + " connection refused"
        sock.close()
        sock = None
    except TimeoutError:
        error = appip + " Connect TimeoutError"
        sock.close()
        sock = None
    except socket.error:
        error = appip + " No route to host"
        sock.close()
        sock = None

    if sock is None:
        return error

    sock.settimeout(None)
    # Set longer timeout
    sock.settimeout(60)
    return sock

class FluxAgent:
    '''Class for the Secure Vault Agent, runs on secured trusted server or PC behind firewall'''
# pylint: disable=too-many-instance-attributes
    def __init__(self) -> None:
        # super(fluxVault, self).__init__()
        self.request = {}
        self.file_dir = ""
        self.vault_port = 0
        self.result = "Initialized"
        self.agent_requests = {DONE: self.node_done, REQUEST: self.node_request}
        self.log = []
        self.verbose = False
        self.matched = False

    def add_log(self, msg):
        '''Add logging of notable events'''
        cur_time = datetime.now()
        now = cur_time.strftime("%b-%d-%Y %H:%M:%S ")
        self.log.append(now+msg)
        if self.verbose:
            print(now+msg)

    def vault_agent(self):
        '''Invokes requested agent action defined by FluxVault or user defined class'''
        node_func = self.agent_requests.get(self.request["State"], None)
        if node_func is None:
            return None
        jdata = node_func()
        return jdata

    def node_done(self):
        '''Node is done with this session'''
        # The Node is done with us, Get Out!
        return self.request

    def node_request(self):
        '''Node is requesting a file'''
        fname = self.request["FILE"]
        crc = int(self.request["crc32"])
        self.request["State"] = "DATA"
        # Open the file, read contents and compute the crc
        # if the CRC matches no need to resent
        # if it does not exist locally report the error
        try:
            with open(self.file_dir+fname, encoding="utf-8") as file:
                secret = file.read()
                file.close()
            mycrc = binascii.crc32(secret.encode("utf-8"))
            if crc == mycrc:
                if self.verbose:
                    print("File " + fname + " Matched!")
                self.request["Status"] = "Match"
                self.request["Body"] = ""
            else:
                self.add_log("File " + fname + " sent!")
                self.request["Body"] = secret
                self.request["Status"] = "Success"
                self.matched = False
        except FileNotFoundError:
            self.add_log("File Not Found: " + self.file_dir+fname)
            self.request["Body"] = ""
            self.request["Status"] = "FileNotFound"
            self.matched = False
        return self.request

    def do_encrypted(self, sock, aeskey, jdata):
        '''
        This function will send the reply and process any file requests it receives
        The rest of the session will use the aeskey to protect the session
        send_files(sock, jdata, aeskey, file_dir)'''
        while True:
            # Encrypt the latest reply
            data = encrypt_aes_data(aeskey, jdata)
            reply = send_receive(sock, data)
            if reply is None:
                self.result = 'Receive Time out'
                self.add_log(self.result)
                break
            # Reply sent and next command received, decrypt and process
            self.request = decrypt_aes_data(aeskey, reply)
            # call vault_agent functions
            jdata = self.vault_agent()
            if jdata is None:
                break
            if jdata["State"] == DONE:
                self.result = "Completed"
                break

    def node_vault_ip(self, appip):
        '''
        This is where all the Vault work is done.
        Use the port and appip to connect to a Node and give it files it asks for
        '''

        if self.vault_port == 0:
            self.result = "vault_port Not set!"
            self.add_log(self.result)
            return
        # Open socket to the node
        sock = open_connection(self.vault_port, appip)
        if isinstance(sock, str):
            self.result = sock
            if self.verbose:
                print('Could not connect to Node')
            self.add_log(self.result)
            return

        self.result = "Connected"
        # Use While loop to allow graceful escape on error
        while True:
            # Node will generate a RSA Public/Private key pair and send us the Public Key
            # this message will be signed by the Flux Node private key so we can authenticate
            # that we are connected to node we expect (no man in the middle)

            public_key = receive_public_key(sock)
            if public_key is None:
                self.result = "No Public Key Received"
                self.add_log(self.result)
                break

            # Generate and send AES Key encrypted with PublicKey just received
            # These are only used for this session and are memory resident
            aeskey = get_random_bytes(16).hex().encode("utf-8")
            # Create a cypher message (json) and the data is simply the aeskey we will use
            jdata = encrypt_data(public_key, aeskey)
            # The State reflects what format the cypher message is
            jdata["State"] = AESKEY
            data = json.dumps(jdata)

            # Send the message and wait for the reply to verify the key exchange was successful
            reply = send_receive(sock, data)
            if reply is None:
                self.result = 'Receive Time out'
                self.add_log(self.result)
                break
            # AES Encryption should be started now, decrypt the message and validate the reply
            jdata = decrypt_aes_data(aeskey, reply)
            if jdata["State"] != STARTAES:
                self.result = "StartAES not found"
                self.add_log(self.result)
                break
            if jdata["Text"] != "Test":
                self.result = "StartAES Failed"
                self.add_log(self.result)
                break
            # Form and format looks good, prepare reply and indicate we Passed
            jdata["Text"] = "Passed"

            self.result = "Connected and Encrypted"
            self.do_encrypted(sock, aeskey, jdata)
            break
        sock.close()
        return
