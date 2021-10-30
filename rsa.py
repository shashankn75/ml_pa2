from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify 
import os, time, struct
#from rsa import key, common
print('***********')
print('    RSA')
print('***********')

file1='./1kbfile'
file2='./1mbfile'

key1_st=time.time()
rsa_key = RSA.generate(2048)
key1_end=time.time()
print("Time taken to generate 2048-bit key", pow(10,6)*(key1_end-key1_st),"micro sec")
pvt_key = rsa_key.exportKey("PEM")
pub_key = rsa_key.publickey().exportKey("PEM")
#print(pvt_key)
#print(pub_key)
pr_key = RSA.import_key(pvt_key)
pu_key = RSA.import_key(pub_key)

def enc_file_rsa(file,pu_key,filesize):
	cipher = PKCS1_OAEP.new(key=pu_key)
	enc_file = file+'.enc'
	d=0
	with open(file, 'rb') as f:
		
		with open(enc_file, 'wb') as ef:
			ef.write(struct.pack('<Q', filesize))
			while True:
				a =f.read(214)
				if len(a)==0:
					break
				elif len(a)%214!=0:
					a+=b' '*(214-len(a))			
				enc_st=time.time()
				cipher_text = cipher.encrypt(a)
				enc_end=time.time()
				ef.write(cipher_text)
				d+= enc_end - enc_st
	f.close()
	ef.close()
	print("\tTime to encrypt file", pow(10,6)*d,"micro sec")
	print("\tPer-byte encryption speed",pow(10,6)*(d/filesize),"micro sec\n" )

def dec_file_rsa(file,orig_file, pr_key, cipher):
	d=0
	decryp = PKCS1_OAEP.new(key=pr_key)
	dec_file=orig_file+'.dec'
	filesize = os.path.getsize(orig_file)
	with open(file, 'rb') as f:
		truncate_last = struct.unpack('<Q', f.read(struct.calcsize('Q')))[0]
		with open(dec_file, 'wb') as df:
			
			while True:
				block= f.read(cipher)
				if len(block)==0:
					break
				dec_st=time.time()
				decrypted_message = decryp.decrypt(block)
				dec_end=time.time()
				df.write(decrypted_message)
				d+=dec_end- dec_st		
			df.truncate(truncate_last)			
	f.close()
	df.close()
	print("\tTime to decrypt file", pow(10,6)*(d),"micro sec")
	print("\tPer-byte decryption speed",pow(10,6)*(d/filesize),"micro sec\n" )

def verify_enc_dec(file,dec_file):
	#print(file,dec_file)
	with open(file, 'rb') as ifile:
		with open(dec_file, 'rb') as ofile: 
			if ifile.read() == ofile.read():
				print("\tMATCH - Encryption and Decryption\n")
			else:
				print("\tDON'T MATCH - Encryption and Decryption\n")
			
	ifile.close()
	ofile.close()
print("---------------------------------------------------------------------")
print("filesize - 1kb")
cipher = 256
filesize2 = os.path.getsize(file1)
enc_file_rsa(file1,pu_key,filesize2)
dec_file_rsa(file1+'.enc',file1,pr_key, cipher)
dec1_file=file1+'.dec'
verify_enc_dec(file1,dec1_file)

print("---------------------------------------------------------------------")
print("filesize - 1mb")
filesize = os.path.getsize(file2)
enc_file_rsa(file2,pu_key,filesize)
dec_file_rsa(file2+'.enc',file2,pr_key, cipher)
dec2_file=file2+'.dec'
verify_enc_dec(file2,dec2_file)

print("*********************************************************************")
######################### 3072 bit key size

key2_st=time.time()
rsa_key = RSA.generate(3072)
key2_end=time.time()
print("Time taken to generate 3072-bit key", pow(10,6)*(key2_end-key2_st),"micro sec" )
pvt_key = rsa_key.exportKey("PEM")
pub_key = rsa_key.publickey().exportKey("PEM")
#print(pvt_key)
#print(pub_key)
pr_key = RSA.import_key(pvt_key)
pu_key = RSA.import_key(pub_key)
cipher = 384
print("---------------------------------------------------------------------")
print("filesize - 1kb")

filesize2 = os.path.getsize(file1)
enc_file_rsa(file1,pu_key,filesize2)
dec_file_rsa(file1+'.enc',file1,pr_key, cipher)
dec1_file=file1+'.dec'
verify_enc_dec(file1,dec1_file)
print("---------------------------------------------------------------------")

print("filesize - 1mb")
filesize = os.path.getsize(file2)
enc_file_rsa(file2,pu_key,filesize)
dec_file_rsa(file2+'.enc',file2,pr_key, cipher)
dec2_file=file2+'.dec'
verify_enc_dec(file2,dec2_file)


