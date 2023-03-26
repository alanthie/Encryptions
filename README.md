A C++ program (Linux and Windows) to encrypt/decrypt (without the usual limitations)

Multiple encryption keys for one message to encrypt.
<pre>
[Keys extracted from a puzzle question-answer].
[Keys extracted from local common file shared between 2 parties (like USB keys), 
                     public web files, 
                     public video web files (using youtube-dl), 
                     user/password protected ftp files].
[Embedded random keys automatically generated and protected by public/private RSA or ECC keys].
[Historical hash keys].
</pre>

Multiple encryption algorithms for one message to encrypt.

Deep recursive and cascading encryption [so can use many lower bits key size if needed]

Unlimited encryption keys size!

**Allow perfect secrecy**:
<pre>
Shannon's work on information theory showed that to achieve so-called 'perfect secrecy', 
the key length must be at least as large as the message and only used once
(this algorithm is called the one-time pad). 
</pre>
 

Example, encodes a file into an encrypted file
<pre>
./crypto encode -h
Usage: encode [-h] [--cfg VAR] [--auto VAR] [--input VAR] [--output VAR] [--puzzle VAR] [--qapuzzle VAR] [--fullpuzzle VAR] [--url VAR] [--staging VAR] [--local VAR] [--rsapriv VAR] [--rsapub VAR] [--eccpriv VAR] [--eccpub VAR] [--histopriv VAR] [--histopub VAR] [--keep VAR] [--keyfactor VAR] [--known_ftp_server VAR] [--encryped_ftp_user VAR] [--encryped_ftp_pwd VAR] [--gmp VAR] [--selftest VAR] [--shuffle VAR]

Encodes a file into an encrypted file

Optional arguments:
  -h, --help              	shows help message and exits 
  -v, --version           	prints version information and exits 
  -cfg, --cfg             	specify a config file. [default: ""]
  -a, --auto              	auto export public/status keys with the encrypted data [default: ""]
  -i, --input             	specify the input file. [default: ""]
  -o, --output            	specify the output encrypted file (default to <input path>.encrypted) [default: ""]
  -p, --puzzle            	specify the input (optional) puzzle file. [default: ""]
  -q, --qapuzzle          	specify the output qa puzzle file (default to <puzzle path>.qa) [default: ""]
  -f, --fullpuzzle        	specify the output (optional) full puzzle file. [default: ""]
  -u, --url               	specify the (optional input) url list file. [default: ""]
  -s, --staging           	specify the staging folder. [default: ""]
  -l, --local             	specify the local folder of known contents. [default: ""]
  -rpv, --rsapriv         	specify my private folder for rsa*.db [default: ""]
  -rpu, --rsapub          	specify the other public folder for rsa*.db [default: ""]
  -epv, --eccpriv         	specify my private folder for private ecc*.db [default: ""]
  -epu, --eccpub          	specify the other public folder for public ecc*.db [default: ""]
  -hpv, --histopriv       	specify the private folder for historical hashes [default: ""]
  -hpu, --histopub        	specify the other public folder for historical hashes [default: ""]
  -v, --verbose           	specify the verbose [default: ""]
  -k, --keep              	specify if keeping staging file [default: ""]
  -x, --keyfactor         	specify a key_size_factor, this multiply the key size by the factor [default: "1"]
  -fs, --known_ftp_server 	specify list of ftp protected server [default: ""]
  -fu, --encryped_ftp_user	specify list of ftp username (encrypted with string_encode) [default: ""]
  -fp, --encryped_ftp_pwd 	specify list of ftp password (encrypted with string_encode) [default: ""]
  -g, --gmp               	use gmp [default: ""]
  -t, --selftest          	encryption selftest [default: ""]
  -sh, --shuffle          	specify pre encryption shuffling percentage of data 0-100 [default: "0"]

Output example:
MESSAGE is 117169 bytes
Padding msg with bytes: 15
Encryptor encode() salsa20 32_64             , number of rounds : 1, number of blocks (64 bytes): 1831, number of keys (32 bytes): 1104, shuffling: 0%
Encryptor encode() binAES 16_16 - aes_type: 0, number of rounds : 1, number of blocks (16 bytes): 7404, number of keys (16 bytes): 2208, shuffling: 0%
Encryptor encode() binAES 16_16 - aes_type: 2, number of rounds : 1, number of blocks (16 bytes): 7484, number of keys (16 bytes): 2208, shuffling: 0%
Encryptor encode() twofish 16_16             , number of rounds : 1, number of blocks (16 bytes): 7564, number of keys (16 bytes): 2208, shuffling: 0%
Encryptor encode() salsa20 32_64             , number of rounds : 1, number of blocks (64 bytes): 1933, number of keys (32 bytes): 1104, shuffling: 0%
Encryptor encode() idea 8_16                 , number of rounds : 1, number of blocks (8 bytes): 15808, number of keys (16 bytes): 2208, shuffling: 0%
Encryptor encode() binAES 16_16 - aes_type: 1, number of rounds : 1, number of blocks (16 bytes): 8076, number of keys (16 bytes): 2208, shuffling: 0%
Encryptor encode() binAES 16_16 - aes_type: 0, number of rounds : 1, number of blocks (16 bytes): 8248, number of keys (16 bytes): 2208, shuffling: 0%
Encryptor encode() binAES 16_16 - aes_type: 2, number of rounds : 1, number of blocks (16 bytes): 8340, number of keys (16 bytes): 2208, shuffling: 0%
Encryptor encode() twofish 16_16             , number of rounds : 1, number of blocks (16 bytes): 8756, number of keys (16 bytes): 2208, shuffling: 0%
Encryptor encode() salsa20 32_64             , number of rounds : 1, number of blocks (64 bytes): 2213, number of keys (32 bytes): 4, shuffling: 0%
data encrypted size: 141636
qa_puz_key size:     128
crypto ENCODING SUCCESS
Encrypted file: msg.zip.encrypted
Puzzle file   : (default)
Elapsed time in seconds: 38 sec
</pre>

Example of msg.crypto:
<pre>
// ------------------------------------------------------------------------------------------------------------
// *.crypto file available!
// ------------------------------------------------------------------------------------------------------------
//  crypto encode -p puzzle.txt -i msg.zip -o msg.zip.encrypted -f puzzle.txt.full -q puzzle_qa.txt -u ./urls.txt -v 1 -l ./AL_SAM/
//  crypto pack -q puzzle_qa.txt -i msg.zip.encrypted -o msg.crypto -k alain -ht alain
//
//  crypto unpack -q puzzle_qa.txt -o msg.zip.encrypted -i msg.crypto -k alain
//  crypto decode -i msg.zip.encrypted -o msg.zip -p puzzle_qa.txt -v 1 -l ./AL_SAM/
// ------------------------------------------------------------------------------------------------------------
</pre>

Videos describing the project:
<pre>
https://odysee.com/@C++_alanthier:0/screenshot-from-2023-02-20-22-10-02_qpG2gyJg:c
https://odysee.com/@C++_alanthier:0/screenshot-from-2023-02-09-21-50-13_uIWWm6KM:1
One-Time Pad Cipher (Perfect Security) https://www.youtube.com/watch?v=F5Yrk6LHM2w
</pre>

Current set of encryption algorithms
<pre>
    Binary DES
    Binary AES ecb
    Binary AES cbc
    Binary AES cfb
    TWOFISH
    Salsa20
    IDEA
    RSA (2 primes)
    Shuffling
    Recursive RSA
    Elliptic Curve
    Recursive Elliptic Curve
    Future: Multiple primes (3+) RSA [ the security of Multi-prime RSA is undeniably better than the standard RSA]
    Future: Cascading auto generated embedded key protected by multiple RSA/ECC keys
</pre>

Overview:
![Alt text](/Doc/overview2.png?raw=true "Overview")

Recursive RSA (and Elliptic Curve):
![Alt text](/Doc/RecursiveRSA.png?raw=true "Recursive RSA")

Example of urls.txt:
<pre>
;------------------------------------------------------------------------------------------------------------
; Encoding commands, msg.zip.encrypted file to be send to the recipient (sam):
; crypto encode -u urls.txt -g 1 -v 1 -i msg.zip -l ./sam/local/ -r ./sam/ -x 3 -epu ./sam/ -epv ./me/
; or
; crypto encode -cfg ./cfg.ini -v 1 -a 1
;------------------------------------------------------------------------------------------------------------

;------------------------------------------------------------------------------------------------------------
; Decoding commands for me:
;
; Decoding commands at the recipient site (sam):
; decode -g 1 -i msg.zip.encrypted -l ./al/local/ -r ./me/  -epu ./al/ -epv ./me/ -v 1
; or
; crypto decode -cfg ./cfg.ini -v 1 -a 1
;------------------------------------------------------------------------------------------------------------

;------------------------------------------------------------------------
; URL keys source when encoding:
;------------------------------------------------------------------------
;Web files (also ftp[f] and videos[v])
[w]https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz
[w]https://i.postimg.cc/ZKGMV8SP/Screenshot-from-2023-02-23-19-39-28.png

;Local shared files between me and sam (like shared USB) in ./sam/
[l]binary.dat.71
[l]binary.dat.44

;Historical shared confirmed hashes in ./me/
[h]5

;RSA public keys given by recipient (sam) in ./sam/
[r]MY_RSAKEY_2048_2023-03-25_14:29:11
[r]MY_RSAKEY_2048_2023-03-25_14:29:11;[r]MY_RSAKEY_2048_2023-03-25_14:29:11;
[mode]block;[r]MY_RSAKEY_2048_2023-03-25_14:29:11;[r]MY_RSAKEY_2048_2023-03-25_14:29:11;[r]MY_RSAKEY_2048_2023-03-25_14:29:11;
[r:]last=10,first=6,random=7;[r:]last=1,first=2,random=25;

;ECC publc keys given by recipient (sam) in ./sam/
[e]MY_ECCKEY_360_2023-03-25_14:33:22
[mode]recur;[e]MY_ECCKEY_1024_2023-03-18_12:20:21;[e]MY_ECCKEY_360_2023-03-25_14:33:22
[e:]last=10,first=1,random=15;[r:]last=10,first=26,random=22;
[e:]last=10,first=2,random=35;[r:]last=13,first=16,random=13;
</pre>
 
Example of config file:
<pre>
;
; cfg.ini 
;
; ./crypto encode -cfg ./cfg.ini -i msg.zip
; ./crypto decode -cfg ./cfg.ini -i msg.zip.encrypted
;

[var]
var_folder_me_and_other = /home/server/dev/Encryptions/testcase/test/AL/

[cmdparam]
filename_urls               = urls.txt
filename_msg_data           = msg.zip
filename_puzzle             = 
filename_full_puzzle        = 
filename_encrypted_data     = msg.zip.encrypted
filename_decrypted_data     = 
keeping                     = 0
folder_local                = [var_folder_me_and_other]sam/local/
folder_my_private_rsa       = [var_folder_me_and_other]me/
folder_other_public_rsa     = [var_folder_me_and_other]sam/
folder_my_private_ecc       = [var_folder_me_and_other]me/
folder_other_public_ecc     = [var_folder_me_and_other]sam/
folder_my_private_hh        = [var_folder_me_and_other]me/
folder_other_public_hh      = [var_folder_me_and_other]sam/
encryped_ftp_user           = 
encryped_ftp_pwd            = 
known_ftp_server            = 
auto_flag                   =
use_gmp                     = 1
self_test                   = 0
key_size_factor             = 3
shufflePerc                 = 0
verbose                     = 1

[keymgr]
max_usage1	= keytype:rsa,bits:64,max_usage_count:1
max_usage2	= keytype:rsa,bits:1024,max_usage_count:16

[keygen]
policy1     = keytype:rsa, pool_first:10, pool_random:30, pool_last:10, pool_new:20, pool_max:100
</pre>

Regular upload of Elliptic Curves of increasing number of bits
<pre>
ecgen_ec_curves/ec192_1.txt
ecgen_ec_curves/ec256_1.txt
ecgen_ec_curves/ec256_2.txt
ecgen_ec_curves/ec256_3.txt
ecgen_ec_curves/ec256_4.txt
ecgen_ec_curves/ec256_5.txt
ecgen_ec_curves/ec256_6.txt
ecgen_ec_curves/ec360_1.txt
ecgen_ec_curves/ec512_1.txt
ecgen_ec_curves/ec512_2.txt
ecgen_ec_curves/ec512_3.txt
ecgen_ec_curves/ec1024_1.txt
ecgen_ec_curves/ec1024_2.txt
ecgen_ec_curves/ec1024_3.txt
ecgen_ec_curves/ec1536_1.txt
</pre>

A tool (qa) for various tasks
<pre>
====================================
QA version   : v0.2_2023-03-25
Not using a configuration file
Select a task: 
====================================
0. Quit
*. Last choice
1. Use a configuration file for default parameters
2. Show configuration
3. HEX(file, position, keysize)
4. Puzzle: Make random puzzle from shared binary (like USB keys) data
5. Puzzle: Resolve puzzle
6. Futur usage
7.  RSA Key: View my private RSA key
8.  RSA Key: View my public RSA key (also included in the private db)
81. RSA Key: View other public RSA key
9.  RSA Key: Export my public RSA key
10. RSA Key: Generate RSA key with OPENSSL command line (fastest)
11. RSA Key: Test RSA GMP key generator
12. RSA Key: Generate RSA key with GMP (fast)
13. ECC: Elliptic Curve test with GMP
14. Historical Hashes: View my private encode history hashes
15. Historical Hashes: View my public decode history hashes
16. Historical Hashes: Export public decode history hashes for confirmation
17. Historical Hashes: Confirm other public decode history hashes
18. EC Domain: Import an elliptic curve domain generated from ecgen (output manually saved in a file)
19. EC Domain: Generate an elliptic curve domain with ecgen
20. EC Domain: View my elliptic curve domains
21. EC Domain: Import the elliptic curve domains of other
22. EC Key: Generate an elliptic curve key
23. EC Key: View my private elliptic curve keys
24. EC Key: Export my public elliptic curve keys
25. EC Key: View my public elliptic curve keys (also included in the private db)
26. EC Key: View other public elliptic curve keys
==> 
</pre>

Man-In-The-Middle Attack prevention now implemented
![Alt text](/Doc/ManInTheMiddleAttack.png?raw=true "ManInTheMiddleAttack")

Planned feature:
![Alt text](/Doc/planned1.png?raw=true "planned1")

Auto transmission of public keys now implemented:
![Alt text](/Doc/autokeys.png?raw=true "autokeys")

License
<pre>
Free for personal usage
License required for commercial usage
</pre>
