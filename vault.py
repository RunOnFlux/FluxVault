#!/usr/bin/python
'''This module is a single file that supports the loading of secrets into a Flux Node'''
import binascii
import json
import sys
import os
import time
import socketserver
import threading
import socket
import requests
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# pylint: disable=W0603
VAULT_NAME = ""
BOOTFILES = []
FILE_DIR = ""

MAX_MESSAGE = 8192

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
    jdata = json.loads(data)
    nonce = bytes.fromhex(jdata["nonce"])
    tag = bytes.fromhex(jdata["tag"])
    ciphertext = bytes.fromhex(jdata["ciphertext"])

    # let's assume that the key is somehow available again
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    msg = cipher.decrypt_and_verify(ciphertext, tag)
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

def receive_only(sock):
    '''
    Wait for a message from our peer
    '''
    # Receive data
    reply = sock.recv(MAX_MESSAGE)
    reply = reply.decode("utf-8")
    return reply

CONNECTED = "CONNECTED"
KEYSENT = "KEYSENT"
STARTAES = "STARTAES"
READY = "READY"
REQUEST = "REQUEST"
DONE = "DONE"
AESKEY = "AESKEY"

def create_send_public_key(nkdata):
    '''
    New incoming connection from Vault
    Create a new RSA key and send the Public Key the Vault
    The message should be signed by the Flux Node we are running on
    so we can authenticate the message

    This is the only message sent unencrypted.
    This is Ok because the Public Key can be Public
    '''
    nkdata["RSAkey"] = RSA.generate(2048)
    nkdata["Private"] = nkdata["RSAkey"].export_key()
    nkdata["Public"] = nkdata["RSAkey"].publickey().export_key()
    nkdata["State"] = KEYSENT
    jdata = { "State": KEYSENT, "PublicKey": nkdata["Public"].decode("utf-8")}
    reply = json.dumps(jdata) + "\n"
    # Add this signed_reply = flux_node_sign_message(reply)
    return reply, nkdata

def file_request_or_done(nkdata, boot_files, data):
    '''
    Create File Request or Done message

    The first pass through we have no reply from Vault since we consumed it
    verifying that the encryption was started correctly len(data) == 0

    The app will be responsible for checking for or handling any missing files
    this server does not require any of the BOOTFILES to be received, that is
    an application problem.

    The application could use any of these files as a way to apply updates to the
    config, this is only a tool to securely pass a file from a secure server to the node
    It is also the responsibility of the node to store the data received in a secure location
    From testing it appears that storing files in a tmpfs (RAM Disk) does provide a resaonable
    level of security. Only the app developer can evaluate how precious the data is and
    what safeguards need to be taken.
    '''
    if len(data) == 0:
        jdata = {"State": READY}
    else:
        jdata = decrypt_aes_data(nkdata["AESKEY"], data)
    if jdata["State"] == "DATA":
        # We have received data and the status is Success, save the data in the file
        # Notice that Match and File Not Found are silently ignored, see notes above.
        if jdata["Status"] == "Success":
            with open(FILE_DIR+boot_files[0], "w", encoding="utf-8") as file:
                file.write(jdata["Body"])
                file.close()
        boot_files.pop(0)
    # Send request for first (or next file)
    # If no more we are Done (close connection?)
    random = get_random_bytes(16).hex()
    if len(boot_files) == 0:
        jdata = { "State": DONE, "fill": random }
    else:
        # Open the file and compute the crc, set crc=0 if not found
        try:
            with open(FILE_DIR+boot_files[0], encoding="utf-8") as file:
                content = file.read()
                file.close()
            crc = binascii.crc32(content.encode("utf-8"))
            # File exists
        except FileNotFoundError:
            crc = 0
        jdata = { "State": REQUEST,
                    "FILE": boot_files[0],
                    "crc32": crc, "fill": random }
    # Return the next file request or Done message
    reply = encrypt_aes_data(nkdata["AESKEY"], jdata)
    return reply

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    '''Define threaded server'''
    daemon_threads = True
    allow_reuse_address = True

class NodeKeyClient(socketserver.StreamRequestHandler):
    '''
    ThreadedTCPServer creates a new thread and calls this function for each
    TCP connection received
    '''
    def handle(self):
        client = f'{self.client_address} on {threading.current_thread().name}'
        print(f'Connected: {client}')
        # Verify the connection came from our Vault IP Address
        peer_ip = self.connection.getpeername()
        result = socket.gethostbyname(VAULT_NAME)
        if peer_ip[0] != result:
            print("Reject Connection, wrong IP:", peer_ip[0], result)
            # Delay invalid peer to defend against DOS attack
            time.sleep(15)
            return
        nkdata = { "State": CONNECTED }
        # Copy file list into local variable
        boot_files = BOOTFILES.copy()

        while True:
            try:
                reply = ""
                if nkdata["State"] == CONNECTED:
                    reply, nkdata = create_send_public_key(nkdata)
                    self.wfile.write(reply.encode("utf-8"))
                    continue
                data = self.rfile.readline()
                if not data:
                    # No Message - Get Out
                    break
                # We send our Public key and expect an AES Key for our session, if not Get Out
                if nkdata["State"] == KEYSENT:
                    jdata = json.loads(data)
                    if jdata["State"] != AESKEY:
                        break # Tollerate no errors
                    # Decrypt with our RSA Private Key
                    nkdata["AESKEY"] = decrypt_data(nkdata["Private"], jdata)
                    nkdata["State"] = STARTAES
                    # Send a test encryption message, always include random data
                    random = get_random_bytes(16).hex()
                    jdata = { "State": STARTAES, "Text": "Test", "fill": random}
                    # Encrypt with AES Key and send reply
                    reply = encrypt_aes_data(nkdata["AESKEY"], jdata) + "\n"
                    self.wfile.write(reply.encode("utf-8"))
                    continue
                if nkdata["State"] == STARTAES:
                    # Do we both have the same AES Key?
                    jdata = decrypt_aes_data(nkdata["AESKEY"], data)
                    if jdata["State"] == STARTAES and jdata["Text"] == "Passed":
                        nkdata["State"] = READY # We are good to go!
                        data = ""
                    else:
                        break # Failed - Get Out!
                if nkdata["State"] == READY:
                    # Send a file request for each file we care about (BOOTFILES)
                    reply = file_request_or_done(nkdata, boot_files, data) +"\n"
                    self.wfile.write(reply.encode("utf-8"))
                    continue
                break # Unhandled case, abort
            except ValueError:
                # Decryption error or unhandled exception with close connection
                print("try failed")
                break
        print(f'Closed: {client}')

def node_server(port, vaultname, bootfiles, base):
    '''This server runs on the Node, waiting for the Vault to connect'''
    global VAULT_NAME
    global BOOTFILES
    global FILE_DIR

# We should Pass these to the created thread that calls NodeKeyCllient instead of using Globals
    VAULT_NAME = vaultname
    BOOTFILES = bootfiles
    FILE_DIR = base
    print("node_server ", VAULT_NAME)
    if len(BOOTFILES) > 0:
        with ThreadedTCPServer(('', port), NodeKeyClient) as server:
            print("The NodeKeyClient server is running on port " + str(port))
            server.serve_forever()
    else:
        print("BOOTFILES missing from comamnd line, see usage")

def open_connection(port, appip):
    '''Open socket to Node'''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('Failed to create socket')
        return None

    try:
        remote_ip = socket.gethostbyname( appip )
    except socket.gaierror:
        print('Hostname could not be resolved')
        return None

    # Set short timeout
    sock.settimeout(30)

    # Connect to remote server
    try:
        print('# Connecting to server, ' + appip + ' (' + remote_ip + ')')
        sock.connect((remote_ip , port))
    except ConnectionRefusedError:
        print(appip, "connection refused")
        sock.close()
        return None
    except socket.timeout:
        print(appip, "Connect timed out")
        sock.close()
        return None

    sock.settimeout(None)
    # Set longer timeout
    sock.settimeout(60)
    return sock

def send_files(sock, jdata, aeskey, file_dir):
    '''
    This is called once the connection has successfully performed and verifyed the key exchange
    The jdata passed in has the Passed message which will be sent first and then the
    file requests will be processed.

    At the moment only a file REQUEST command is supported, it may be of use to add
    additional comands such as 'CSR' to create an ssl certificate or some other actions
    that must be executed on a secure server
    '''
    while True:
        # Encrypt the latest reply
        data = encrypt_aes_data(aeskey, jdata)
        reply = send_receive(sock, data)
        if reply is None:
            print('Receive Time out')
            return
        # Reply sent and next command received, decrypt and process
        jdata = decrypt_aes_data(aeskey, reply)
        reply = ""
        # The Node is done with us, Get Out!
        if jdata["State"] == DONE:
            break
        # The Node wants an update of a file
        if jdata["State"] == REQUEST:
            fname = jdata["FILE"]
            crc = int(jdata["crc32"])
            jdata["State"] = "DATA"
            # Open the file, read contents and compute the crc
            # if the CRC matches no need to resent
            # if it does not exist locally report the error
            try:
                with open(file_dir+fname, encoding="utf-8") as file:
                    secret = file.read()
                    file.close()
                mycrc = binascii.crc32(secret.encode("utf-8"))
                if crc == mycrc:
                    print("File ", fname, " Match!")
                    jdata["Status"] = "Match"
                    jdata["Body"] = ""
                else:
                    print("File ", fname, " sent!")
                    jdata["Body"] = secret
                    jdata["Status"] = "Success"
            except FileNotFoundError:
                print("File Not Found: " + file_dir+fname)
                jdata["Body"] = ""
                jdata["Status"] = "FileNotFound"
        else:
            jdata["Body"] = ""
            jdata["Status"] = "Unknown Command"

def node_vault_ip(port, appip, file_dir):
    '''
    This is where all the Vault work is done.
    Use the port and appip to connect to a Node and give it files it asks for
    '''

    # Open socket to the node
    sock = open_connection(port, appip)
    if sock is None:
        print('Could not connect to Node')
        return

    while True:
        # Node will generate a RSA Public/Private key pair and send us the Public Key
        # this message will be signed by the Flux Node private key so we can authenticate
        # that we are connected to node we expect (no man in the middle)

        try:
            reply = receive_only(sock)
        except TimeoutError:
            print('Receive Public Key timed out')
            break

        if len(reply) == 0:
            print("No Public Key message received")
            break

        try:
            jdata = json.loads(reply)
            public_key = jdata["PublicKey"].encode("utf-8")
        except ValueError:
            print("No Public Key received:", reply)
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
            print('Receive Time out')
            break
        # AES Encryption should be started now, decrypt the message and validate the reply
        jdata = decrypt_aes_data(aeskey, reply)
        if jdata["State"] != STARTAES:
            print("StartAES not found")
            break
        if jdata["Text"] != "Test":
            print("StartAES Failed")
            break
        # Form and format looks good, prepare reply and indicate we Passed
        jdata["Text"] = "Passed"

        # This function will send the reply and process any file requests it receives
        # The rest of the session will use the aeskey to protect the session
        send_files(sock, jdata, aeskey, file_dir)
        break
    sock.close()
    return

def node_vault(port, appname, file_dir):
    '''Vault runs this to poll every Flux node running their app'''
    url = "https://api.runonflux.io/apps/location/" + appname
    req = requests.get(url)
    # Get the list of nodes where our app is deplolyed
    if req.status_code == 200:
        values = json.loads(req.text)
        if values["status"] == "success":
            # json looks good and status correct, iterate through node list
            nodes = values["data"]
            for node in nodes:
                ipadr = node['ip'].split(':')[0]
                print(node['name'], ipadr)
                node_vault_ip(port, ipadr, file_dir)
        else:
            print("Error", req.text)
    else:
        print("Error", url, "Status", req.status_code)

NODE_OPTS = ["--port", "--vault", "--dir"]
VAULT_OPTS = ["--port", "--app", "--ip", "--dir"]

def usage(argv):
    '''Display command usage'''
    print("Usage:")
    print(argv[0] + " Node --port port --vault VaultDomain [--dir dirname] file1 [file2 file3 ...]")
    print("")
    print("Run on node with the port and Domain/IP of the Vault and the list of files")
    print("")
    print(argv[0] + " Vault --port port --app AppName --dir dirname")
    print("")
    print("Run on Vault the AppName will be used to get the list of nodes where the App is running")
    print("The vault will connect to each node : Port and provide the files requested")
    print("")
    print(argv[0] + " VaultIP --port port --ip IPadr [--dir dirname]")
    print("")
    print("The Vault will connect to a single ip : Port to provide files")
    print("")

# Routines to check Node and Vault command line arguments
def check_port(args, port):
    '''check and return port number'''
    if len(args) > 0 and args[0].lower() == "--port":
        try:
            port = int(args[1])
            args.pop(0)
            args.pop(0)
        except ValueError:
            print(args[1] + " invalid port number")
            sys.exit()
    return args, port

def check_vault(args, vault):
    '''check and return vault name/ip'''
    if len(args) > 0 and args[0].lower() == "--vault":
        vault = args[1]
        args.pop(0)
        args.pop(0)
    return args, vault

def check_dir(args, base_dir):
    '''check and return src/dest dir'''
    if len(args) > 0 and args[0].lower() == "--dir":
        base_dir = args[1]
        if base_dir.endswith("/") is False:
            base_dir = base_dir + "/"
        args.pop(0)
        args.pop(0)
    return args, base_dir

def check_app(args, app_name):
    '''check and return app name'''
    if len(args) > 0 and args[0].lower() == "--app":
        app_name = args[1]
        args.pop(0)
        args.pop(0)
    return args, app_name

def check_ip(args, ipadr):
    '''check and return ip adr'''
    if len(args) > 0 and args[0].lower() == "--ip":
        ipadr = args[1]
        args.pop(0)
        args.pop(0)
    return args, ipadr

def check_vault_args(base_dir, myport, app_name, ipadr):
    '''
    The Vault requires a Port Number and either App Name or IP Address
    If a base_dir is specified it must exist
    '''
    error = False
    if len(base_dir) > 0 and os.path.isdir(base_dir) is False:
        print(base_dir + " is not a directory or does not exist")
        error = True
    if myport == -1:
        print("Port number must be specified like --port 31234")
        error = True
    if len(app_name) == 0 and len(ipadr) == 0:
        print("Application Name OR IP must be set but not Both!",
            " like: --appname myapp or --ip 2.3.45.6")
        error = True
    if len(app_name) > 0 and len(ipadr) > 0:
        print("Application Name OR IP must be set but not Both!",
            " like: --appname myapp or --ip 2.3.45.6")
        error = True
    return error

def check_node_args(base_dir, myport, vault, files):
    '''
    The Node requires a Port Number, a list of files and either a Vault DNS name or IP
    If a base_dir is specified it must exist
    '''
    error = False
    if len(base_dir) > 0 and os.path.isdir(base_dir) is False:
        print(base_dir + " is not a directory or does not exist")
        error = True
    if myport == -1:
        print("Port number must be specified like --port 31234")
        error = True
    if len(vault) == 0:
        print("Vault Domain or IP must be set like:",
            " --vault 1.2.3.4 or --vault my.vault.host.io")
        error = True
    if len(files) == 0:
        print("Secret files must be listed after all other arguments")
        error = True
    return error

# The Vault client runs on a trusted server and contains private data needed by the
#applications it is responsible for.
#
# Vault only connects to a single IP (--ip ipadr) from the command line or a list of
#IPs associated with a Named Flux App specificed (--app appname) on the command line
#
# The Vault and Node also need to agree on which port (--port myport) the Node listens on,
# within the Flux Application Port range (30000-39999)
#
# The Node also needs to know the DNS or IP Address of the Vault (--vault DNS-IP),
# any other source will be rejected as untrusted.
#
# Both the Node and Vault assume files sent/received are in the current directory unless
# --dir base_dir is set
#
# The Node will typically get the PORT and VAULT setting from the app Environment setting

def run_node(args):
    '''
    Require parameters:

    --port  - TCP Port number to use for contact from the Vault
    --vault - The IP Address or DNS name of the vault
    files   - The list of files the Node will request from the Vault
    '''
    files = []
    myport = -1
    vault = ""
    base_dir = ""
    error = False
    while len(args) > 0:
        if args[0] in NODE_OPTS:
            args, myport = check_port(args, myport)
            args, vault = check_vault(args, vault)
            args, base_dir = check_dir(args, base_dir)
        else:
            # All recognized arguments processed, rest are considered file names
            files = args
            break
    # Verify command arguments are valid
    error = check_node_args(base_dir, myport, vault, files)
    if error is True:
        usage(sys.argv)
    else:
        node_server(myport, vault, files, base_dir)

def run_vault(args):
    '''
    Required parameters:

    --port - TCP Port number to use for contact to the Node
    --app  - Flux Application name - Required if --ip is not specified
    --ip   - IP Address of Application - Required if --app is not specified
             The IP does not need to be a Flux Node, for testing eg localhost, etc
    '''
    myport = -1
    base_dir = ""
    ipadr = ""
    app_name = ""
    error = False
    while len(args) > 0:
        if args[0] in VAULT_OPTS:
            args, myport = check_port(args, myport)
            args, app_name = check_app(args, app_name)
            args, ipadr = check_ip(args, ipadr)
            args, base_dir = check_dir(args, base_dir)
        else:
            print("Unknown option: ", args[0])
            args.pop(0)
    # Verify command arguments are valid
    error = check_vault_args(base_dir, myport, app_name, ipadr)
    if error is True:
        usage(sys.argv)
    else:
        # Are we checking an app or single IP?
        if len(app_name) > 0:
            node_vault(myport, app_name, base_dir)
        else:
            node_vault_ip(myport, ipadr, base_dir)

def main():
    '''
    Main function
    This file defines two programs
    Node - a server process that runs inside a container
    Vault - a client process that periodically (cron?) connects to each Node app
    '''
    args = []

    if sys.argv[1].upper() == "NODE":
        args = sys.argv[2:]
        run_node(args)
        sys.exit()

    if sys.argv[1].upper() == "VAULT":
        args = sys.argv[2:]
        run_vault(args)
        sys.exit()

main()
