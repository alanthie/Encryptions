A C++ program (Linux and Windows) to encrypt/decrypt

Multiple encryption keys.
<pre>
[Keys extracted from a puzzle question-answer].
[Keys extracted from local common file shared between 2 parties, public web files, protected ftp files].
</pre>

Multiple encryption algorithms for one message to encrypt.

Unlimited encryption keys size (soon...).

<pre>
Example

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
