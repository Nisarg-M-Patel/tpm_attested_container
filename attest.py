import os
import json
import subprocess
import time
import secrets

#file references
REG_FILE = "instance_registry.json"
CHALLENGE_FILE = "challenge.txt"
SIG_FILE = "signature.txt"
TPM_CONTEXT = "id_tpm.ctx"
NONCE_LEN = 16

def menu():
    print("\nSelect an action:")
    print("1. Register instance")
    print("2. Verify instance once")
    print("3. Enforce continuous verification policy")
    print("4. Remove instance")
    print("5. Exit")

def get_user_input():
    try:
        choice = int(input("Enter option: ").strip())
        if 1 <= choice <= 5:
            return choice
        else:
            print("invalid choice")
    except:
        return 5


def main():

    while True:
        menu()
        choice = get_user_input()
        print(choice)

if __name__ == "__main__":
    main()
