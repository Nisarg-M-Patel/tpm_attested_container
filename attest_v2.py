import os
import json
import subprocess
import time
import secrets
import sys
import re
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
    print("--- Lab2 ---")
    print("6. Write to Top Secret Log")
    print("7. Access Confidential Secret")
    print("8. Access Top-secret secret")
    print("9. Append Signed Ledger Entry (Clark-Wilson TP)")
    print("10. Verify Ledger Integrity (Clark-Wilson IVP)")
    print("11. Generate Certified Platform Quote (Clark-Wilson Certification)")

def get_user_input():
    while True:
        try:
            choice = int(input("Enter option: ").strip())
            if 1 <= choice <= 11:
                return choice
            else:
                print("choice not in range [1,11]")
        except ValueError:
            print("invalid input, select a number [1,11]")

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

'''
LAB 2 FILE REFS
'''
PCR_GOOD_FILE = 'pcr16_good.txt'
AUDIT_LOG_FILE = 'audit_log.txt'
SECRET_CONF_CTX = 'secret_conf.ctx'
SECRET_TS_CTX = 'secret_ts.ctx'
SESSION_FILE = 'session.dat'
LEDGER_FILE = 'ledger.json'

#############################################################
#helpers to read the pcr regs
def read_pcr(pcr_num):
    #read the current value of pcr_num pcr reg
    result = subprocess.run(
        ["tpm2_pcrread", f"sha256:{pcr_num}"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return None
    
    #strip out the 0x prefix to get plaintext string
    match = re.search(r'0x([0-9A-Fa-f]+)', result.stdout)
    return match.group(1) if match else None
    

def load_pcr_baseline(filepath):
    #load the stored golden pcr value
    try:
        with open(filepath, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"ERROR: baseline file {filepath} not found, run measure_tp.sh to reconcile")
        return None
    
#############################################################


#############################################################
#BIBA 2.2
def check_biba_integrity():
    #read pcr16 and pcr16 baseline, return bool match
    curr_pcr16 = read_pcr(16)
    baseline = load_pcr_baseline(PCR_GOOD_FILE)
    if curr_pcr16 is None or baseline is None:
        return False
    return curr_pcr16.lower() == baseline.lower()
def write_top_secret_log(entry):
    #check biba integrity, if true append to audit log
    if not check_biba_integrity():
        print("FAILURE: integrity check failed - write denied - Biba violation")
        return
    #append timestamped entry to audit log
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(AUDIT_LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {entry}\n")
    print("SUCCESS: entry written to audit log")
#############################################################

#############################################################
#BELL LAPADULA 3.3
def unseal_secret(ctx_file, pcr_policy):
    pass
def access_confidential():
    #unseal secret, print success or fail
    pass
def access_top_secret():
    #unseal secret, print success or fail
    pass
#############################################################

#############################################################
#CLARK-WILSON 4.1,4.2,4.3
def load_ledger():
    pass
def save_ledger(ledger):
    pass
def tpm_sign_file(input_file, sig_file):
    pass
def tpm_verify_file(input_file, sig_file):
    pass
def append_ledger_entry(entry_text):
    pass
def verify_ledger():
    pass
def generate_platform_quote():
    pass


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

        if choice == 6:
            entry = input("Log entry: ").strip()
            write_top_secret_log(entry)

if __name__ == "__main__":
    main()
