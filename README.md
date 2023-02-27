A C++ program (Linux and Windows) to encrypt/decrypt (without the usual limitations)

Multiple encryption keys for one message to encrypt.
<pre>
[Keys extracted from a puzzle question-answer].
[Keys extracted from local common file shared between 2 parties (like USB keys), 
                     public web files, 
                     public video web files (using youtube-dl), 
                     user/password protected ftp files].
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
Usage: encode [-h] --input VAR --output VAR --puzzle VAR --qapuzzle VAR --fullpuzzle VAR [--url VAR] 
              [--staging VAR] [--local VAR] [--keep VAR] [--keyfactor VAR] 
              [--known_ftp_server VAR] [--encryped_ftp_user VAR] [--encryped_ftp_pwd VAR]

Encodes a file into an encrypted file

Optional arguments:
  -h, --help              	shows help message and exits 
  -v, --version           	prints version information and exits 
  -i, --input             	specify the input file. [required]
  -o, --output            	specify the output encrypted file. [required]
  -p, --puzzle            	specify the input puzzle file. [required]
  -q, --qapuzzle          	specify the output qa puzzle file. [required]
  -f, --fullpuzzle        	specify the output full puzzle file. [required]
  -u, --url               	specify the (optional input) url list file. [default: ""]
  -s, --staging           	specify the staging folder. [default: ""]
  -l, --local             	specify the local folder of known contents. [default: ""]
  -v, --verbose           	specify the verbose [default: ""]
  -k, --keep              	specify if keeping staging file [default: ""]
  -x, --keyfactor         	specify a key_size_factor, this multiply the key size by the factor [default: "1"]
  -fs, --known_ftp_server 	specify list of ftp protected server [default: ""]
  -fu, --encryped_ftp_user	specify list of ftp username (encrypted with string_encode) [default: ""]
  -fp, --encryped_ftp_pwd 	specify list of ftp password (encrypted with string_encode) [default: ""]
  
Output:
Encryptor encode() binDES - number of blocks (4 bytes): 29584, number of keys (4 bytes): 114400
Encryptor encode() binAES 16_16 - aes_type: 0, number of rounds : 2, number of blocks (16 bytes): 14820, number of keys (16 bytes): 28600
Encryptor encode() binAES 16_16 - aes_type: 2, number of rounds : 2, number of blocks (16 bytes): 14848, number of keys (16 bytes): 28600
Encryptor encode() twofish 16_16             , number of rounds : 2, number of blocks (16 bytes): 14876, number of keys (16 bytes): 28600
Encryptor encode() salsa20 32_64             , number of rounds : 2, number of blocks (64 bytes): 3726, number of keys (32 bytes): 14300
Encryptor encode() idea 8_16                 , number of rounds : 2, number of blocks (8 bytes): 29864, number of keys (16 bytes): 28600
Encryptor encode() binAES 16_16 - aes_type: 1, number of rounds : 2, number of blocks (16 bytes): 14960, number of keys (16 bytes): 28600
Encryptor encode() binAES 16_16 - aes_type: 0, number of rounds : 2, number of blocks (16 bytes): 14988, number of keys (16 bytes): 28600
Encryptor encode() binAES 16_16 - aes_type: 2, number of rounds : 2, number of blocks (16 bytes): 15016, number of keys (16 bytes): 28600
Encryptor encode() twofish 16_16             , number of rounds : 2, number of blocks (16 bytes): 15044, number of keys (16 bytes): 28600
Encryptor encode() salsa20 32_64             , number of rounds : 2, number of blocks (64 bytes): 3768, number of keys (32 bytes): 14300
Encryptor encode() idea 8_16                 , number of rounds : 2, number of blocks (8 bytes): 30200, number of keys (16 bytes): 28600
Encryptor encode() binAES 16_16 - aes_type: 1, number of rounds : 2, number of blocks (16 bytes): 15128, number of keys (16 bytes): 28600
Encryptor encode() binDES - number of blocks (4 bytes): 60640, number of keys (4 bytes): 128
crypto ENCODING SUCCESS
Encrypted file  : /home/server/dev/Encryptions/testcase/manual/encoder_output/test.zip.encrypted
Puzzle qa file  : /home/server/dev/Encryptions/testcase/manual/encoder_output/puzzle_qa.txt
Puzzle full file: /home/server/dev/Encryptions/testcase/manual/encoder_output/puzzle.txt.full
Elapsed time in seconds: 11 sec
</pre>

Help:
<pre>
crypto -h
Usage: crypto [-h] {batch_decode,batch_encode,binary,decode,encode,random,string_decode,string_encode,test}

Optional arguments:
  -h, --help   	shows help message and exits 
  -v, --version	prints version information and exits 

Subcommands:
  batch_decode  Decode from a config file
  batch_encode  Encode from a config file
  binary        Generate a file with binary random data
  decode        Decodes and extracts a file from an encrypted file
  encode        Encodes a file into an encrypted file
  random        Generate a file with random numbers
  string_decode Decode a string
  string_encode Encode a string
  test          Test a case
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
</pre>

Puzzle:
![Alt text](/Doc/puzzle.png?raw=true "puzzle")

Shared private information:
![Alt text](/Doc/keys.png?raw=true "shared info")

