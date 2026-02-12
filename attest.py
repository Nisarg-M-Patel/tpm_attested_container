import os
import json
import subprocess
import time
import secrets
import sys
os.environ["TPM2TOOLS_TCTI"] = "swtpm:host=127.0.0.1,port=2321"

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
        print(f"FAILURE: instance {instance_id} already registered")
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

def generate_nonce():
    return secrets.token_hex(NONCE_LEN)

def write_challenge(nonce):
    with open(CHALLENGE_FILE, 'w') as f:
        f.write(nonce)

def tpm_sign():
    res = subprocess.run(["tpm2_sign", "-c", TPM_CONTEXT, "-g", "sha256", "-o", SIG_FILE, CHALLENGE_FILE],
                         capture_output=True, text=True, check=False)
    #print(f"sign returncode: {res.returncode}")
    #print(f"sign stderr: {res.stderr}")
    return res.returncode == 0

def tpm_verify():
    res = subprocess.run(["tpm2_verifysignature", "-c", TPM_CONTEXT, "-g", "sha256", "-s", SIG_FILE, "-m", CHALLENGE_FILE],
                         capture_output=True, text=True, check=False)
    return res.returncode == 0

def tpm_flush():
    subprocess.run(["tpm2_flushcontext", "-t"], capture_output=True, check=False)

def corrupt_sig():
    with open(SIG_FILE, 'r+b') as f:
        f.write(b'corruption text')
    

def verify_instance(registry, instance_id):
    if instance_id not in registry["instances"]:
        print(f"FAILURE: instance {instance_id} not registered")
        return False
    

    #flush before to ensure clean slate
    tpm_flush()

    nonce = generate_nonce()
    write_challenge(nonce)

    try:
        if not tpm_sign():
            print(f"attestation failed, could not sign {instance_id}")
            return False
        
        #corruption test
        #corrupt_sig()

        if not tpm_verify():
            print(f"attestation failed, could not verify {instance_id}")
            return False
        print(f"instance {instance_id} verified")
        return True
    finally:
        tpm_flush()
        
def verify_continous(registry, instance_id, rounds, delay, kill_after_round=None):
    if instance_id not in registry["instances"]:
        print(f"instance {instance_id} not registered")
        return False
    
    for round in range(1, rounds + 1):
        tpm_flush()
        nonce = generate_nonce()
        write_challenge(nonce)

        try:
            if not tpm_sign() or not tpm_verify():
                print(f"continuous verification failed at round {round} for instance {instance_id}")
                tpm_flush()
                return False
        except Exception:
            print(f"continuous verification failed at round {round} for instance {instance_id}")
            tpm_flush()
            return False
        
        print(f"round: {round} succeeded")

        if kill_after_round and round == kill_after_round:
            kill_swtpm()
        if round < rounds:
            time.sleep(delay)
    
    tpm_flush()
    print(f"Success: continous verification passed for instance {instance_id}")
    return True

def kill_swtpm():
    subprocess.run(["pkill", "-f", "swtpm"], capture_output=True, check=False)


def handle_option_1(registry):
    '''
    handler for menu option 1
    '''
    instance_id = input("Instance ID: ").strip()
    pub_key_path = input("Path to instance public key: ").strip()

    if add_instance(registry, instance_id, pub_key_path):
        save_registry(registry)
        print(f"SUCCESS: instance {instance_id} registered")

def remove_instance(registry, instance_id):
    if instance_id not in registry["instances"]:
        print(f"FAILURE: instance {instance_id} not registered")
        return False
    del registry["instances"][instance_id]
    return True

def main():

    if "--init" in sys.argv:
        subprocess.run(["bash", "init_tpm.sh"])

    registry = load_registry()

    while True:
        menu()
        choice = get_user_input()
        print(choice)

        if choice == 1:
            handle_option_1(registry)
        
        if choice == 2:
            instance_id = input("Instance ID: ").strip()
            verify_instance(registry, instance_id)
        
        if choice == 3:
            instance_id = input("Instance ID: ").strip()
            while True:
                try:
                    rounds = int(input("Number of verification rounds: ").strip())
                    if rounds > 0:
                        break
                    print("enter a positive number")
                except ValueError:
                    print("enter a number")
            while True:
                try:
                    delay = int(input("Delay between rounds (seconds): ").strip())
                    if delay > 0:
                        break
                    print("enter a positive number")
                except ValueError:
                    print("enter a number")
            verify_continous(registry, instance_id, rounds, delay)
        
        if choice == 4:
            instance_id = input("Instance ID: ").strip()
            if remove_instance(registry, instance_id):
                save_registry(registry)
                print(f"SUCCESS: Instance {instance_id} removed")
        if choice == 5:
            break

if __name__ == "__main__":
    main()
