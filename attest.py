import os
import json
import subprocess
import time
import secrets

#file references
REG_FILE = "instance_registry.json"
CHALLENGE_FILE = "challenge.txt"
SIG_FILE = "signature.bin"
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
    while True:
        try:
            choice = int(input("Enter option: ").strip())
            if 1 <= choice <= 5:
                return choice
            else:
                print("choice not in range [1,5]")
        except ValueError:
            print("invalid input, select a number [1,5]")

def load_registry():
    '''
    load registry from disk or create an empty registry if it doesnt exist
    '''
    try:
        with open(REG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        empty_reg = {"instances" : {}}
        save_registry(empty_reg)
        return empty_reg
    except json.JSONDecodeError:
        print(f"error: {REG_FILE} is corrupted, creating a new registry")
        empty_reg = {"instances" : {}}
        save_registry(empty_reg)
        return empty_reg

def save_registry(registry):
    '''
    save registry dict to disk
    '''
    with open(REG_FILE, 'w') as f:
        json.dump(registry, f, indent=2)

def add_instance(registry, instance_id, pub_key_path):
    '''
    register new instance, return bool success
    '''
    if instance_id in registry["instances"]:
        print(f"{instance_id} already registered")
        return False
    if not os.path.exists(pub_key_path):
        print("public key file not found")
        return False
    else:
        registry["instances"][instance_id] = {
            "public_key_path" : pub_key_path,
            "registered_time" : time.strftime("%Y-%m-%dT%H:%M:%S")
        }
    return True

def handle_option_1(registry):
    '''
    handler for menu option 1
    '''
    instance_id = input("Instance ID: ").strip()
    pub_key_path = input("Path to instance public key: ").strip()

    if add_instance(registry, instance_id, pub_key_path):
        save_registry(registry)
        print(f"instance {instance_id} registered")

def main():

    registry = load_registry()

    while True:
        menu()
        choice = get_user_input()
        print(choice)

        if choice == 1:
            handle_option_1(registry)
            
        if choice == 5:
            break

if __name__ == "__main__":
    main()
