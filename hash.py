import hashlib
import time, os

print("**************")
print("    Hash")
print("**************")

file = "./1kbfile"
file2 = "./10mbfile"
size =512
filesize = os.path.getsize(file)
filesize2 = os.path.getsize(file2)

####################       1kb hash

d=0 
f256_hash = hashlib.sha256()
with open (file, 'rb')as f256:
	while len(f256.read(size))>0:
		block = f256.read(size)
		hash_1kb_sha256_st = time.time()
		f256_hash.update(block)
		hash_1kb_sha256_end = time.time() 
		d+=hash_1kb_sha256_end-hash_1kb_sha256_st
print("SHA-256 for 1kb file  ",f256_hash.hexdigest())
if d<1:
	print("Time taken to hash 1kb file with SHA-256",1000000*d,"micro sec")
else:
	print("Time taken to hash 1kb file with SHA-256", pow(10,6)*d,"micro sec")
print("Per byte hash speed", pow(10,6)*(d/filesize),"micro sec\n")


d=0
 
f512_hash = hashlib.sha512()
with open (file, 'rb')as f512:
	while len(f512.read(size))>0:
		block = f512.read(size)
		hash_1kb_sha512_st = time.time()
		f512_hash.update(block)
		hash_1kb_sha512_end = time.time()
		d+=hash_1kb_sha512_end-hash_1kb_sha512_st
print("SHA-512 for 1kb file  ",f512_hash.hexdigest())

if d<1:
	print("Time taken to hash 1kb file with SHA-512", 1000000*d,"micro sec")
else:
	print("Time taken to hash 1kb file with SHA-512", pow(10,6)*d,"s")
print("Per byte hash speed", pow(10,6)*(d/filesize),"micro sec\n")



d=0
f3_256_hash = hashlib.sha3_256()
with open (file, 'rb')as f3:
	while len(f3.read(size))>0:
		block=f3.read(size)
		hash_1kb_sha3_256_st = time.time()
		f3_256_hash.update(block)
		hash_1kb_sha3_256_end = time.time()
		d+=hash_1kb_sha3_256_end-hash_1kb_sha3_256_st
print("SHA3-256 for 1kb file  ",f3_256_hash.hexdigest())

if d<1:
	print("Time taken to hash 1kb file with SHA3-256", 1000000*d,"micro sec")
else:
	print("Time taken to hash 1kb file with SHA3-256", pow(10,6)*d,"micro sec")
print("Per byte hash speed", pow(10,6)*(d/filesize),"micro sec\n")


print("*********************************************************************")
#####################    10mb hash

d=0
f256_hash = hashlib.sha256()
with open (file2, 'rb')as f256:
	while len(f256.read(size))>0:
		block=f256.read(size)
		hash_10mb_sha256_st = time.time()
		f256_hash.update(block)
		hash_10mb_sha256_end = time.time()
		d+=hash_10mb_sha256_end-hash_10mb_sha256_st
print("SHA-256 for 10mb file  ",f256_hash.hexdigest())

if d<1:
	print("Time taken to hash 10mb file with SHA-256", pow(10,6)*d,"micro sec")
else:
	print("Time taken to hash 10mb file with SHA-256", pow(10,6)*d,"micro sec")
print("Per byte hash speed", pow(10,6)*(d/filesize2),"micro sec\n")


d=0
f512_hash = hashlib.sha512()
with open (file2, 'rb')as f512:
	while len(f512.read(size))>0:
		block=f512.read(size)
		hash_10mb_sha512_st = time.time()
		f512_hash.update(block)
		hash_10mb_sha512_end = time.time()
		d+=hash_10mb_sha512_end-hash_10mb_sha512_st
print("SHA-512 for 10mb file  ",f512_hash.hexdigest())

if d<1:
	print("Time taken to hash 10mb file with SHA-512", pow(10,6)*d,"micro sec")
else:
	print("Time taken to hash 10mb file with SHA-512", pow(10,6)*d,"micro sec")
print("Per byte hash speed", pow(10,6)*(d/filesize2),"micro sec\n")


d=0
f3_256_hash = hashlib.sha3_256()
with open (file2, 'rb')as f3:
	while len(f3.read(size))>0:
		block=f3.read(size)
		hash_10mb_sha3_256_st = time.time()
		f3_256_hash.update(block)
		hash_10mb_sha3_256_end = time.time()
		d+=hash_10mb_sha3_256_end-hash_10mb_sha3_256_st
print("SHA3-256 for 10mb file  ",f3_256_hash.hexdigest())

if d<1:
	print("Time taken to hash 10mb file with SHA3-256", pow(10,6)*d,"micro sec")
else:
	print("Time taken to hash 10mb file with SHA3-256", pow(10,6)*d,"micro sec")
print("Per byte hash speed", pow(10,6)*(d/filesize2),"micro sec\n")

