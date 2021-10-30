from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import time, os, struct 

print("************")
print("    AES")
print("************")

def enc_file(key, mode, ip_file,  filesize):
	d=0
	op_file = ip_file+'.enc'
	cipher = AES.new(key, mode, iv, use_aesni=1 )
	with open(ip_file, 'rb') as ifile:
		with open(op_file, 'wb') as ofile:
			ofile.write(struct.pack('<Q', filesize))
			
			while True:			
				text = ifile.read(16)
				if len(text)==0:
					break
				elif len(text)%16!=0:
					text += b' '*(16- len(text)%16)
				enc_st=time.time()
				block=cipher.encrypt(text)
				enc_end=time.time()
				ofile.write(block)
				d+=enc_end-enc_st
	ifile.close()
	ofile.close()
	print("\tTime taken to encrypt file",pow(10,6)*(d),"micro sec" )
	print("\tPer-byte encryption speed",pow(10,6)*(d/filesize),"micro sec\n")

def dec_file(key, mode, ipd_file, opd_file, filesize):
	d=0
	cipher = AES.new(key, mode, iv, use_aesni=1 )
	with open(ipd_file, 'rb') as ifile:
		truncate_last = struct.unpack('<Q', ifile.read(struct.calcsize('Q')))[0]
		with open(opd_file, 'wb') as ofile:
			
			while True:			
				text = ifile.read(512)
				if len(text)==0:
					break
				dec_st =time.time()
				block = cipher.decrypt(text)
				dec_end=time.time()
				ofile.write(block)
				d+= dec_end - dec_st
			ofile.truncate(truncate_last)
	ifile.close()
	ofile.close()
	print("\tTime taken to decrypt file",pow(10,6)*(d),"micro sec" )
	print("\tPer-byte decryption speed",pow(10,6)*(d/filesize),"micro sec\n")

def verify_enc_dec(ip_file, opd_file):
	with open(ip_file, 'rb') as ifile:
		with open(opd_file, 'rb') as ofile:
			if ifile.read()==ofile.read():
				print("\tMATCH - Encryption and Decryption\n")		
			else:
				print("\tDON'T-MATCH - Encryption and Decryption\n")
	ifile.close()
	ofile.close()

####################     CBC mode     #######################################
key1_st=time.time()
key = get_random_bytes(16)
key1_end=time.time()
print("CBC mode")
print("Time taken to generate 128-bit key",pow(10,6)*(key1_end-key1_st),"micro sec\n")

mode =AES.MODE_CBC
iv = get_random_bytes(AES.block_size)
print("---------------------------------------------------------------------")
print("filesize - 1kb")
ip_file = "./1kbfile"

filesize = os.path.getsize(ip_file)

ipd_file= ip_file+".enc"
opd_file = ip_file+".dec"
filesize2 = os.path.getsize(ipd_file)
#print(ip_file,op_file,ipd_file, opd_file, filesize, filesize2)
enc_file(key, mode, ip_file, filesize)
dec_file(key, mode, ipd_file,opd_file, filesize)

verify_enc_dec(ip_file,opd_file)
print("---------------------------------------------------------------------")
print("filesize - 10mb")
ip_file = "./10mbfile"

filesize = os.path.getsize(ip_file)
ipd_file= ip_file+".enc"
opd_file = ip_file+".dec"
filesize2 = os.path.getsize(ipd_file)
#print(ip_file,op_file,ipd_file, opd_file, filesize, filesize2)
enc_file(key, mode, ip_file, filesize)
dec_file(key, mode, ipd_file,opd_file, filesize)

verify_enc_dec(ip_file,opd_file)

print("*********************************************************************")
####################     CTR mode     ####################################### 

print("CTR mode")
key2_st=time.time()
key2 = get_random_bytes(16)
key2_end=time.time()
print("Time taken to generate 128-bit key",pow(10,6)*(key2_end-key2_st),"micro sec\n")
mode = AES.MODE_CTR
ctr=Counter.new(128)
print("---------------------------------------------------------------------")
print("filesize - 1kb")
ip_file = "./1kbfile"
op_file = ip_file+'.enc'
filesize = os.path.getsize(ip_file)

ipd_file= ip_file+".enc"
opd_file = ip_file+".dec"
filesize2 = os.path.getsize(ipd_file)

#print(ip_file,op_file,ipd_file, opd_file, filesize, filesize2)
with open(ip_file, 'rb') as ifile:
	cipher = AES.new(key2, mode, counter=ctr, use_aesni=1 )
	with open(ipd_file, 'wb') as ofile:
		enc_st=time.time()
		ofile.write(cipher.encrypt(ifile.read()))
		enc_end=time.time()
print("\tTime taken to encrypt file",pow(10,6)*(enc_end-enc_st),"micro sec" )
print("\tPer-byte encryption speed",pow(10,6)*((enc_end-enc_st)/filesize),"micro sec\n")


with open(ipd_file, 'rb') as ifile:
	cipher = AES.new(key2, mode, counter=ctr, use_aesni=1 )
	with open(opd_file, 'wb') as ofile:
		dec_st=time.time()
		ofile.write(cipher.decrypt(ifile.read()))
		dec_end=time.time()
print("\tTime taken to decrypt file",pow(10,6)*(dec_end-dec_st),"micro sec" )
print("\tPer-byte decryption speed",pow(10,6)*((dec_end-dec_st)/filesize2),"micro sec\n")


verify_enc_dec(ip_file,opd_file)
##########
print("---------------------------------------------------------------------")

print("filesize - 10mb")
ip_file = "./10mbfile"
op_file = ip_file+'.enc'

ipd_file= ip_file+".enc"
opd_file = ip_file+".dec"

#print(ip_file,op_file,ipd_file, opd_file, filesize, filesize2)
with open(ip_file, 'rb') as ifile:
	cipher = AES.new(key2, mode, counter=ctr, use_aesni=1 )
	with open(ipd_file, 'wb') as ofile:
		enc_St=time.time()
		ofile.write(cipher.encrypt(ifile.read()))
		enc_end=time.time()
print("\tTime taken to encrypt file",pow(10,6)*(enc_end-enc_st),"micro sec" )
print("\tPer-byte encryption speed",pow(10,6)*((enc_end-enc_st)/filesize),"micro sec\n")


with open(ipd_file, 'rb') as ifile:
	cipher = AES.new(key2, mode, counter=ctr, use_aesni=1 )
	with open(opd_file, 'wb') as ofile:
		dec_st=time.time()
		ofile.write(cipher.decrypt(ifile.read()))
		dec_end=time.time()
print("\tTime taken to decrypt file",pow(10,6)*(dec_end-dec_st),"micro sec" )
print("\tPer-byte decryption speed",pow(10,6)*((dec_end-dec_st)/filesize2),"micro sec\n")


verify_enc_dec(ip_file,opd_file)

####################     CTR mode 256 bit key   ################################ 

key3_st=time.time()
key3 = get_random_bytes(32)
key3_end=time.time()
print("Time taken to generate 256-bit key",pow(10,6)*(key3_end-key3_st),"micro sec\n")
mode = AES.MODE_CTR
ctr=Counter.new(128)
print("---------------------------------------------------------------------")
print("filesize - 1kb")
ip_file = "./1kbfile"
op_file = ip_file+'.enc'
filesize = os.path.getsize(ip_file)

ipd_file= ip_file+".enc"
opd_file = ip_file+".dec"
filesize2 = os.path.getsize(ipd_file)
#print(ip_file,op_file,ipd_file, opd_file, filesize, filesize2)
with open(ip_file, 'rb') as ifile:
	cipher = AES.new(key3, mode, counter=ctr, use_aesni=1 )
	with open(ipd_file, 'wb') as ofile:
		enc_st=time.time()
		ofile.write(cipher.encrypt(ifile.read()))
		enc_end=time.time()
print("\tTime taken to encrypt file",pow(10,6)*(enc_end-enc_st),"micro sec" )
print("\tPer-byte encryption speed",pow(10,6)*((enc_end-enc_st)/filesize),"micro sec\n")


with open(ipd_file, 'rb') as ifile:
	cipher = AES.new(key3, mode, counter=ctr, use_aesni=1 )
	with open(opd_file, 'wb') as ofile:
		dec_st=time.time()
		ofile.write(cipher.decrypt(ifile.read()))
		dec_end=time.time()
print("\tTime taken to decrypt file",pow(10,6)*(dec_end-dec_st),"micro sec" )
print("\tPer-byte decryption speed",pow(10,6)*((dec_end-dec_st)/filesize2),"micro sec\n")


verify_enc_dec(ip_file,opd_file)
##########
print("---------------------------------------------------------------------")
print("filesize - 10mb")
ip_file = "./10mbfile"
op_file = ip_file+'.enc'

ipd_file= ip_file+".enc"
opd_file = ip_file+".dec"

#print(ip_file,op_file,ipd_file, opd_file, filesize, filesize2)
with open(ip_file, 'rb') as ifile:
	cipher = AES.new(key3, mode, counter=ctr, use_aesni=1 )
	with open(ipd_file, 'wb') as ofile:
		enc_st=time.time()
		ofile.write(cipher.encrypt(ifile.read()))
		enc_end=time.time()
print("\tTime taken to encrypt file",pow(10,6)*(enc_end-enc_st),"micro sec" )
print("\tPer-byte encryption speed",pow(10,6)*((enc_end-enc_st)/filesize),"micro sec\n")


with open(ipd_file, 'rb') as ifile:
	cipher = AES.new(key3, mode, counter=ctr, use_aesni=1 )
	with open(opd_file, 'wb') as ofile:
		dec_st=time.time()
		ofile.write(cipher.decrypt(ifile.read()))
		dec_end=time.time()
print("\tTime taken to decrypt file",pow(10,6)*(dec_end-dec_st),"micro sec" )
print("\tPer-byte decryption speed",pow(10,6)*((dec_end-dec_st)/filesize2),"micro sec\n")


verify_enc_dec(ip_file,opd_file)


















