#!/bin/bash
# init_tpm.sh

pkill -f swtpm 2>/dev/null
sleep 1

swtpm socket --tpm2 --daemon \
  --server port=2321 \
  --ctrl type=tcp,port=2322 \
  --flags not-need-init \
  --tpmstate dir=/tmp \
  --log file=/tmp/swtpm.log,level=5

sleep 1
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"

tpm2_startup -c
tpm2_createprimary -C o -c primary.ctx -g sha256 -G rsa
tpm2_create -C primary.ctx -g sha256 -G rsa2048 -u id_tpm.pub -r id_tpm.priv
tpm2_load -C primary.ctx -u id_tpm.pub -r id_tpm.priv -c id_tpm.ctx
tpm2_flushcontext -t

echo "tpm initialized successfuly"