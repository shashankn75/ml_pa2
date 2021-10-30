# speed-evaluation-of-Cryptographic-operations-

This project is to simulate and evalute the performance of different cryptographic libraries : AES, DSA, RSA and hash
hash algorithms evaluated : sha256, sha512, sha3_256
AES implemented for CBC and CTR mode for key sizes 128bit and 256bit
DSA implemented for key sizes 2048bit and 3072bit
RSA implemented for key sizes 2048bit and 3072bit

The simulation is run for files of different sizes 1kb, 1mb and 10mb. It can either be generated using string of random characters or 
a pre-existing files of correspoding sizes.

How to run:
-Download all the files in the repo in a linux distro or any linux virtual environment,
-run the script 'crytotools'    ./cryptotools
-Make use of 'makefile' to install libraries if not already existing. 
