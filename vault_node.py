#!/usr/bin/python3
'''This module is a single file that supports the loading of secrets into a Flux Node'''
import socketserver
import threading
import time
import os
from fluxvault import FluxNode

BOOTFILES = ["quotes.txt", "readme.txt"]    # EDIT ME

VAULT_NAME = os.getenv('VAULT_NAME')        # EDIT ME
VAULT_PORT = os.getenv('VAULT_PORT')        # EDIT ME
FILE_DIR = os.getenv('VAULT_FILE_DIR')      # EDIT ME

if VAULT_NAME is None:
    VAULT_NAME = 'localhost'
if VAULT_PORT is None:
    VAULT_PORT = 39898
else:
    VAULT_PORT = int(VAULT_PORT)
if FILE_DIR is None:
    FILE_DIR = "/tmp/node/"

class MyFluxNode(FluxNode):
    '''User class to allow easy congiguration, edit lines above  at EDIT ME'''
    vault_name = VAULT_NAME
    user_files = BOOTFILES
    file_dir = FILE_DIR

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    '''Define threaded server'''
    daemon_threads = True
    allow_reuse_address = True

class NodeKeyClient(socketserver.StreamRequestHandler):
    '''
    ThreadedTCPServer creates a new thread and calls this function for each
    TCP connection received
    '''
    node = MyFluxNode()

    def handle(self):
        '''Handle new thread that accepted a new connection'''
        client = f'{self.client_address} on {threading.current_thread().name}'
        print(f'Connected: {client}')
        peer_ip = self.connection.getpeername()
        # Create new fluxVault Object
        if self.node.connected(peer_ip):
            # Correct IP
            self.node.handle(self.rfile.readline, self.wfile.write)
        print(f'Closed: {client}')

def node_server():
    '''This server runs on the Node, waiting for the Vault to connect'''

    print("node_server ", VAULT_NAME)
    with ThreadedTCPServer(('', VAULT_PORT), NodeKeyClient) as server:
        print("The NodeKeyClient server is running on port " + str(VAULT_PORT))
        server.serve_forever()

if __name__ == '__main__':
    while True:
        if VAULT_NAME == "localhost" and VAULT_PORT == 39898:
            print("Running in Demo Mode files will be placed in ", FILE_DIR)
        if os.path.isdir(FILE_DIR):
            print(FILE_DIR, " exists")
        else:
            print("Creating ", FILE_DIR)
            os.makedirs(FILE_DIR)
        if os.path.exists(FILE_DIR):
            node_server()
        else:
            print(FILE_DIR, " does not exist!")
            time.sleep(60)
        print("********************* node_server Exited!!!! Restarting ***********************")
