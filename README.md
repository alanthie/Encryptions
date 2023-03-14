A C++ program (Linux and Windows) to encrypt/decrypt (without the usual limitations)

Multiple encryption keys for one message to encrypt.
<pre>
[Keys extracted from a puzzle question-answer].
[Keys extracted from local common file shared between 2 parties (like USB keys), 
                     public web files, 
                     public video web files (using youtube-dl), 
                     user/password protected ftp files].
[Embedded random keys automatically generated and protected by public/private RSA keys].
[Historical hash keys].
</pre>

Multiple encryption algorithms for one message to encrypt.

Deep recursive encryption

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
Usage: encode [-h] --input VAR [--output VAR] [--puzzle VAR] [--qapuzzle VAR] [--fullpuzzle VAR] [--url VAR] [--staging VAR] [--local VAR] [--rsa VAR] [--keep VAR] [--keyfactor VAR] [--known_ftp_server VAR] [--encryped_ftp_user VAR] [--encryped_ftp_pwd VAR] [--gmp VAR] [--selftest VAR] [--shuffle VAR]

Encodes a file into an encrypted file

Optional arguments:
  -h, --help              	shows help message and exits 
  -v, --version           	prints version information and exits 
  -i, --input             	specify the input file. [required]
  -o, --output            	specify the output encrypted file (default to <input path>.encrypted) [default: ""]
  -p, --puzzle            	specify the input (optional) puzzle file. [default: ""]
  -q, --qapuzzle          	specify the output qa puzzle file (default to <puzzle path>.qa) [default: ""]
  -f, --fullpuzzle        	specify the output (optional) full puzzle file. [default: ""]
  -u, --url               	specify the (optional input) url list file. [default: ""]
  -s, --staging           	specify the staging folder. [default: ""]
  -l, --local             	specify the local folder of known contents. [default: ""]
  -r, --rsa               	specify the local folder for rsa*.db [default: ""]
  -hh, --histo            	specify the local folder for historical hashes crypto_history_encode.db [default: ""]
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
    Future: Multiple primes (3+) RSA
    Future: Elliptic Curve
</pre>

Overview:
![Alt text](/Doc/overview2.png?raw=true "Overview")

Recursive RSA:
![Alt text](/Doc/RecursiveRSA.png?raw=true "Recursive RSA")

Example of urls.txt:
<pre>
;Web files
https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz
https://i.postimg.cc/ZKGMV8SP/Screenshot-from-2023-02-23-19-39-28.png

Local files (like shared USB)
[l]binary.dat.72
[l]binary.dat.73
[l]binary.dat.76
[l]binary.dat.77
[l]binary.dat.78

;RSA keys
[r]MY_RSAKEY_16384_2023-03-06_19:32:02
[r]MY_RSAKEY_512_2023-03-06_19:12:49
[r]MY_RSAKEY_9200_2023-03-06_19:17:31
[r]MY_RSAKEY_1024_2023-03-05_03:43:04
[r]MY_RSAKEY_1024_2023-03-05_12:44:43
[r]MY_RSAKEY_2048_2023-03-06_16:33:58
[r]MY_RSAKEY_3072_2023-03-05_14:07:52
[r]MY_RSAKEY_4096_2023-03-06_19:13:17
[r]MY_RSAKEY_512_2023-03-06_19:12:49
[r]MY_RSAKEY_4096_2023-03-06_19:13:17
[r]MY_RSAKEY_48000_2023-03-08_17:55:21

;RECURSIVE RSA
[r]MY_RSAKEY_2048_2023-03-09_15:28:31;MY_RSAKEY_8100_2023-03-08_11:35:16;MY_RSAKEY_1024_2023-03-05_19:36:04;MY_RSAKEY_512_2023-03-09_12:14:49

;Historical hashes
;Hash index to a historical key [h]4 ==> 889895c4aaabba7566797c4e8c09d417442168b7878ed38bb05ef28606711fee ... 2023-03-13_22:15:07  datasize: 143044
[h]4
</pre>
 
A tool (qa) for various tasks
<pre>
====================================
QA version   : v0.1_2023-03-12
Select a task: 
====================================
0. Quit
*. Last choice
1. Custom secret F(n)
2. Custom secret P(n)
3. HEX(file, position, keysize)
4. Make random puzzle from shared binary (like USB keys) data
5. Resolve puzzle
6. (Futur usage)
7. View my private RSA key
8. View other public RSA key
9. Extract my public RSA key to file
10. Generate RSA key with OPENSSL command line (fastest)
11. Test RSA GMP key generator
12. Generate RSA key with GMP (fast)
13. Elliptic Curve test with GMP
14. View my encode history hashes
15. View my decode history hashes
==> 
</pre>

Man-In-The-Middle Attack prevention now implemented
![Alt text](/Doc/ManInTheMiddleAttack.png?raw=true "ManInTheMiddleAttack")

License
<pre>
Free for personal usage
License required for commercial usage
</pre>
