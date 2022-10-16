#!/usr/bin/bash

export VAULT_PORT=38285
export VAULT_APP=VaultDemo
export VAULT_FILE_DIR=./app_demo/files/

python3 vault_agent.py
