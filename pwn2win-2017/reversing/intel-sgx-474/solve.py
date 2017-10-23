#!/usr/bin/python

from pwn import *
from sgx_crypto_wrapper import SGXCryptoWrapper
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

context(endian='little')

bytes_to_ints = lambda l : [ord(x) for x in l]
array_to_str = lambda x : str(bytearray(x))

p = remote('enclave.butcher.team', 8088)

def menu_choice(x):
	p.recvuntil('3: Abort.\n')
	p.sendline(str(x))

def attestation():
	menu_choice(2)
	sgx = SGXCryptoWrapper()
	# generate SP EC256-DHKE key pair
	sp_privkey, sp_pubkey = sgx.CreateECC256_keyPair()
	sp_pubkey_bytes = array_to_str(sp_pubkey)
	# send SP pubkey
	p.recvuntil('Give me your public key encoded as base64.\n')
	p.sendline(b64e(sp_pubkey_bytes))
	# get client's pubkey
	p.recvuntil('Here goes MSG1 encoded as base64:\n')
	client_pubkey_bytes = b64d(p.recvline())[:64]
	# derive ECDH shared key
	shared_key = sgx.ComputeSharedSecret(sp_privkey, bytes_to_ints(client_pubkey_bytes))
	# derive other shared keys
	sm_key = sgx.DeriveKey(shared_key, 'SMK\x00')
	s_key = sgx.DeriveKey(shared_key, 'SK\x00')
	m_key = sgx.DeriveKey(shared_key, 'MK\x00')
	v_key = sgx.DeriveKey(shared_key, 'VK\x00')
	# build msg2
	gb_ga = sp_pubkey_bytes + client_pubkey_bytes
	msg2  = sp_pubkey_bytes # g_b
	msg2 += '\x00'*16 # spid (unused)
	msg2 += p16(1) # quote_type = linkable
	msg2 += p16(1) # kdf_id
	msg2 += array_to_str(sgx.SignECDSA(bytes_to_ints(gb_ga), sp_privkey)) # sign_gb_ga
	msg2 += array_to_str(sgx.Rijndael128_CMAC(bytes_to_ints(msg2), sm_key)) # mac
	msg2 += p32(0) # sig_rl_size
	# send msg2
	p.recvuntil('anyway.\n')
	p.sendline(b64e(msg2))
	return array_to_str(s_key)

def decrypt_flag(s_key, flag_enc):
	iv = flag_enc[:12]
	tag = flag_enc[12:28]
	cipher = flag_enc[28:]
	dec = Cipher(algorithms.AES(s_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
	return dec.update(cipher) + dec.finalize()

s_key = attestation()
p.recvuntil('base64:\n')
flag_enc = b64d(p.recvline())
p.close()

flag = decrypt_flag(s_key, flag_enc)
print('[+] Flag: {}'.format(flag))
