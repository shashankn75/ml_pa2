from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import hashlib, time, os

print("***************")
print("      DSA")
print("***************")

file = "./1kbfile"
file2 = "./10mbfile"
filesize = os.path.getsize(file)
filesize2 = os.path.getsize(file2)

########    2048bit key DSA , 1kb file     ##############################
print("operations for 2048-bit key")

key_st=time.time()
key = DSA.generate(2048)
key_end=time.time()
print("2048-bit key-gen time  ", pow(10,6)*(key_end-key_st),"micro sec" )

print("---------------------------------------------------------------------")
print("filesize - 1kb")
f = open("public_key1kb.pem", "wb")
f.write(key.publickey().export_key())
f.close()


with open (file, 'rb')as f256:
	hash_1kb=f256.read()
f256.close()

f = open("public_key1kb.pem", "rb")
hash_obj = SHA256.new(hash_1kb)
signer_st = time.time()
signer = DSS.new(key, 'fips-186-3')
signer_end = time.time()
print("\tTime taken to create the signature ", pow(10,6)*(signer_end-signer_st),"micro sec")

sig_st=time.time()
sender_signature = signer.sign(hash_obj)
sig_end=time.time()
#print("\tTime taken to sign 1kb file  ", pow(10,6)*(sig_end-sig_st),"micro sec" )
d =sig_end-sig_st
print("\tPer byte signing speed", pow(10,6)*(d/filesize),"micro sec\n")


pub_key = DSA.import_key(f.read())
f.close()

receiver_signature = DSS.new(pub_key,'fips-186-3' )

try:
	ver_st = time.time()
	receiver_signature.verify(hash_obj, sender_signature)
	ver_end = time.time()
	d = ver_end-ver_st
	print("\tSignature verified for 2048-bit key")
	print("\tTime taken to verify signature for 1kb file ", pow(10,6)*(ver_end-ver_st)," micro sec" )
	print("\tPer byte verifying speed", pow(10,6)*(d/filesize),"micro sec\n")
except ValueError:
	print("\tUnauthentic for 2048-bit key")	


########    2048bit key DSA , 10mb file     ################################

print("---------------------------------------------------------------------")
print("filesize - 10mb")


with open (file2, 'rb')as f256:
	hash_10mb=f256.read()
f256.close()

f = open("public_key1kb.pem", "rb")
hash_obj = SHA256.new(hash_10mb)
signer_st= time.time()
signer = DSS.new(key, 'fips-186-3')
signer_end = time.time()
print("\tTime taken to create the signature ", pow(10,6)*(signer_end-signer_st),"micro sec" )

sig_st=time.time()
sender_signature = signer.sign(hash_obj)
sig_end=time.time()
#print("\tTime taken to sign 10mb file  ", pow(10,6)*(sig_end-sig_st),"micro sec" )
d =sig_end-sig_st
print("\tPer byte signing speed", pow(10,6)*(d/filesize2),"micro sec\n")

pub_key = DSA.import_key(f.read())
f.close()

receiver_signature = DSS.new(pub_key,'fips-186-3' )

try:
	ver_st = time.time()
	receiver_signature.verify(hash_obj, sender_signature)
	ver_end = time.time()
	d = ver_end-ver_st
	print("\tSignature verified for 2048-bit key")
	print("\tTime taken to verify signature for 10mb file ", pow(10,6)*(ver_end-ver_st)," micro sec" )
	print("\tPer byte verifying speed", pow(10,6)*(d/filesize2),"micro sec\n")
except ValueError:
	print("\tUnauthentic for 2048-bit key")	

print("*********************************************************************")

#################################################################

###    3072bit key DSA , 1kb file  ############################

print("operations for 3072-bit key")

key2_st=time.time()
key2 = DSA.generate(3072)
key2_end=time.time()

print("3072-bit key-gen time  ", pow(10,6)*(key2_end-key2_st),"micro sec")
print("---------------------------------------------------------------------")
print("filesize - 1kb")
f = open("public_key2.pem", "wb")
f.write(key2.publickey().export_key())
f.close()

f = open("public_key2.pem", "rb")
hash_obj = SHA256.new(hash_1kb)
signer_st = time.time()
signer = DSS.new(key2, 'fips-186-3')
signer_end = time.time()
print("\tTime taken to create the signature ", pow(10,6)*(signer_end-signer_st),"micro sec" )

sig2_st=time.time()
sender_signature = signer.sign(hash_obj)
sig2_end=time.time()
#print("\tTime taken to sign 1kb file  ", pow(10,6)*(sig2_end-sig2_st),"micro sec" )
d =sig2_end-sig2_st
print("\tPer byte signing speed", pow(10,6)*(d/filesize),"micro sec\n")


pub_key2 = DSA.import_key(f.read())
f.close()

receiver_signature = DSS.new(pub_key2,'fips-186-3' )

try:
	ver2_st=time.time()
	receiver_signature.verify(hash_obj, sender_signature)
	ver2_end = time.time()
	d = ver2_end-ver2_st
	print("\tSignature verified for 3072-bit key")
	print("\tTime taken to verify signature for 1kb file ", pow(10,6)*(ver2_end-ver2_st),"micro sec" )
	print("\tPer byte verifying speed", pow(10,6)*(d/filesize),"micro sec\n")
except ValueError:
	print("\tUnauthentic for 3072-bit key")

###    3072bit key DSA , 10mb file  ############################
print("---------------------------------------------------------------------")
print("filesize - 10mb")

f = open("public_key2.pem", "rb")
hash_obj = SHA256.new(hash_10mb)
signer_st=time.time()
signer = DSS.new(key2, 'fips-186-3')
signer_end = time.time()
print("\tTime taken to create the signature ", pow(10,6)*(signer_end-signer_st),"micro sec" )

sig2_st=time.time()
sender_signature = signer.sign(hash_obj)
sig2_end=time.time()
#print("\tTime taken to sign 10mb file  ", pow(10,6)*(sig2_end-sig2_st),"micro sec" )
d =sig2_end-sig2_st
print("\tPer byte signing speed", pow(10,6)*(d/filesize2),"micro sec\n")


pub_key2 = DSA.import_key(f.read())
f.close()

receiver_signature = DSS.new(pub_key2,'fips-186-3' )

try:
	ver2_st=time.time()
	receiver_signature.verify(hash_obj, sender_signature)
	ver2_end = time.time()
	d = ver2_end-ver2_st
	print("\tSignature verified for 3072-bit key")
	print("\tTime taken to verify signature for 10mb file ", pow(10,6)*(ver2_end-ver2_st),"micro sec" )
	print("\tPer byte verifying speed", pow(10,6)*(d/filesize2),"micro sec\n")
except ValueError:
	print("\tUnauthentic for 3072-bit key")

	

