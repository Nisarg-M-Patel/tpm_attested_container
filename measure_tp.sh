#!/bin/bash

#abort on command failure to avoid bad state
set -e

#set tpm2-tools swtpm communication port
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"

#define variables
SCRIPT="attest_v2.py"
PCR_GOOD_FILE="pcr16_good.txt"
PCR_NUM=16

#hash the file and extract just the hash
HASH=$(sha256sum $SCRIPT | awk '{print $1}')
echo "SHA-256 of $SCRIPT: $HASH"

#reset pcr 16 in the simulator
tpm2_pcrreset $PCR_NUM
echo "PCR $PCR_NUM reset to all-zeros"

#extend the hash into pcr16, computes sha256(current value || hash)
tpm2_pcrextend $PCR_NUM:sha256=$HASH
echo "PCR $PCR_NUM extended with script hash"

#read back the resulting pcr value, get the plaintext hash string for easier
#comparisons down the line
PCR_VALUE=$(tpm2_pcrread sha256:$PCR_NUM | grep -oP '(?<=0x)[0-9A-Fa-f]+')
echo "PCR $PCR_NUM value: $PCR_VALUE"


#save the plain text hash string as the golden value depending on flag
if [ "$1" == "--baseline" ]; then
    echo $PCR_VALUE > $PCR_GOOD_FILE
    echo "Baseline saved to $PCR_GOOD_FILE"
else
    echo "No --baseline flag, skipping save"
fi

