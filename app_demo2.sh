#!/usr/bin/bash

export VAULT_PORT=39281
export VAULT_APP=VaultDemo2
export VAULT_FILE_DIR=./app_demo/files/

python3 vault_agent.py
