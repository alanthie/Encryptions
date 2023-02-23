A C++ program (Linux and Windows) to encrypt/decrypt

Multiple encryption keys for one message to encrypt.
<pre>
[Keys extracted from a puzzle question-answer].
[Keys extracted from local common file shared between 2 parties, public web files, protected ftp files].
</pre>

Multiple encryption algorithms for one message to encrypt.

Unlimited encryption keys size (soon...).

Example, encodes a file into an encrypted file
<pre>
./crypto encode -h
Usage: encode [-h] --input VAR --output VAR --puzzle VAR --qapuzzle VAR --fullpuzzle VAR [--url VAR] [--staging VAR] [--keep VAR]

Encodes a file into an encrypted file

Optional arguments:
  -h, --help 		shows help message and exits
  -v, --version  	prints version information and exits
  -i, --input		specify the input file. [required]
  -o, --output   	specify the output encrypted file. [required]
  -p, --puzzle   	specify the input puzzle file. [required]
  -q, --qapuzzle 	specify the output qa puzzle file. [required]
  -f, --fullpuzzle  specify the output full puzzle file. [required]
  -u, --url  		specify the (optional input) url list file.
  -s, --staging  	specify the staging folder. [default: ""]
  -v, --verbose  	specify the verbose [default: ""]
  -k, --keep 		specify if keeping staging file [default: ""]
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
