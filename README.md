# FluxVault
Flux Vault - load private data into running docker

The goal of this is to provide a way to securely load passwords on a running FLux Docker

There are two modes for the script NODE and VAULT

The NODE is run in an Application running on a Flux Node
The VAULT runs on a single secure system, typically behind a firewall.

In my case the Vault is in my Home LAN and the Nodes are running on Flux

The Node will only accept connections from a predefined host name, which could be controlled by dyn-dns

The Vault will query FluxOS to determine what IP addresses are running the application the Vault supports.
The Vault will connect to the nodes periodically to see if they need any files sent securely.

This is not designed to send large files, just simple configuration files and passwords

The communication flow is as follows:

1. Vault connect to Node on a predefined Application port.
2. The Node will generate a RSA Key Pair and send the Public Key to the Vault.
3. The Vault will use that Public Key to encrypt a message that contains and AES Key
4. The Node will send a test message using the provided AES Key to the Vault
5. If the Vault suceesfully decrypts the message it sends a Test Passed message, also encrypted.
   (All further messages are encrypted with this AES Key)
6. The Node will send Request a message for a named file
7. The Vault will return the contents of that file if it is missing or has changed or an error status

Steps 6-7 repeat until the Node needs nothing else and sends a DONE message.

At the socket level the messages are JSON strings terminated with Newline. Presently the maximum length of the JSON message is 8192, this could be increased but the data is limited to a single JSON structure.

It is a simple proof of concept that can clearly be improved as well as implemented in other langauges as needed.

One big area of improvement is in step 2, it would be valuable if the Application could have the message containing the Public Key be signed by the Flux Node it is running on and then the Vault would have greater assurance the message was valid.

# Usage

In the Proof of Concept form you can open two terminal windows, one as the Node and the other as the Vault

In the Node enter the command:
```
mkdir /tmp/node
./vault.py Node --port 39898 --vault localhost --dir /tmp/node quotes.txt readme.txt
```
Where 39898 is TCP port that will be used and localhost is the Domain name (or IP) that the Vault resides and the files will be stored in /tmp/node

This will come up as a server and always be availble to the Vault. If a connection comes in from a different address the connection will be rejected.

This server will continue to run getting updates from the vault whenever it connects

In a different shell start the Vault push with the command: (typically run from cron)
```
./vault.py Vault --port 39898 --ip 127.0.0.1 --dir files
```
Where 39898 is the TCP port used and 127.0.0.1 is the IP address of the Flux Node where the App is running and the files will be read from ./files

This will connect, negociate and the node will request the files it wants (quotes.txt and readme.txt) which will be sent if the files are missing or have changed abd placed in /temp/node

In a production environment the --ip will be replaced with --app appName and the vault will connect to all Flux instances named appName

# Dependencies

The code was written to Python 3

It uses the following python libraries

- from Crypto.PublicKey import RSA
- from Crypto.Random import get_random_bytes
- from Crypto.Cipher import AES, PKCS1_OAEP
- import binascii
- import json
- import sys
- import os
- import time
- import requests

Crypto is obtained from the pycryptodome library, installed with 
```
sudo apt install python3-pycryptodome
```
The rest are standard python libraries

# TODO

- Write code to periodically poll FluxOs for a list of nodes and see if aany need config
- Explore a Windows GUI solution, right now it is command line only (Only tested on Ubuntu)
