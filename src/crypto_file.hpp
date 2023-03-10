#ifndef _INCLUDES_crypto_file
#define _INCLUDES_crypto_file

#include <filesystem>
#include <curl/curl.h>
#include "encrypt.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include "DES.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "crypto_const.hpp"
#include "crypto_parsing.hpp"
#include "data.hpp"
#include "puzzle.hpp"
#include "../src/qa/rsa_gen.hpp"

#ifdef _WIN32
//add preprocessor directive NOMINMAX
#pragma warning ( disable : 4146 )
#include "qa/RSA-GMP/RSAGMP.h"
#include "qa/RSA-GMP/RSAGMPUtils.h"
#else
// LINKER: -lgmp -lgmpxx
#include "qa/RSA-GMP/RSAGMP.h"
#include "qa/RSA-GMP/RSAGMPUtils.h"
#endif

namespace cryptoAL
{
	std::string get_summary_hex(const char* buffer, uint32_t buf_len);

	int wget(const char *in, const char *out, bool verbose);

	namespace fs = std::filesystem;
	bool fileexists(const fs::path& p, fs::file_status s = fs::file_status{})
	{
		if(fs::status_known(s) ? fs::exists(s) : fs::exists(p))
			return true;
		else
			return false;
	}

	int32_t filesize(std::string filename)
	{
		int32_t sz = -1;
		std::ifstream ifd(filename.data(), std::ios::binary | std::ios::ate);
		if (ifd)
		{
			sz = (int32_t)ifd.tellg();
		}
		ifd.close();
		return sz;
	}

	int getvideo(std::string url, std::string outfile, std::string options = "", bool verbose=false)
	{
		// youtube-dl 'https://www.bitchute.com/video/JjqRgjv5GJmW/'
#ifdef _WIN32
		std::string cmd = std::string("youtube-dl ") + url + std::string(" -o ") + outfile + options;
#else
		std::string cmd = std::string("youtube-dl ") + std::string("'") + url + std::string("'") + std::string(" -o ") + outfile + options;
#endif
		if (verbose)
		{
			std::cout << "getvideo in:  " << url << std::endl;
			std::cout << "getvideo out: " << outfile << std::endl;
			std::cout << "getvideo cmd: " << cmd << std::endl;
		}
		int r = system(cmd.data());
		return r;
	}

	// rsa_data is base64 a string
	int getrsa( bool to_encode, const std::string& rsa_key_name, const std::string& rsa_data, std::string outfile,
				std::string local_rsa_db, std::string& embedded_rsa_key,
				std::string options = "", bool verbose=false, bool use_gmp = false, bool SELF_TEST = false)
	{
		options = options;
		if (verbose)
		{
			std::cout << "getrsa to_encode: "       << to_encode << std::endl;
			std::cout << "getrsa rsa_key_name: "    << rsa_key_name << std::endl;
			if (to_encode == false)
				std::cout << "getrsa rsa_data: "    << get_summary_hex(rsa_data.data(),rsa_data.size())  << " size:" << rsa_data.size()<< std::endl;
			std::cout << "getrsa outfile: "         << outfile << std::endl;
			std::cout << "getrsa local_rsa_db: "    << local_rsa_db << std::endl;
			std::cout << "use_gmp: " << use_gmp << std::endl;
		}

		int r = 0;

		// Read rsa keys
		std::map< std::string, generate_rsa::rsa_key > map_rsa;

		if (fileexists(local_rsa_db) == true)
		{
			std::ifstream infile;
			infile.open (local_rsa_db, std::ios_base::in);
			infile >> bits(map_rsa);
			infile.close();

			bool found = false;
			bool ok = true;
			for(auto& [user, k] : map_rsa)
			{
				if (user == rsa_key_name)
				{
					found = true;
					cryptodata temp;
					uint32_t key_len_in_bytes = k.key_size_in_bits/8;

					if (to_encode)
					{
#ifdef RSA_IN_DATA_FEATURE
#else
						if (key_len_in_bytes < RSAKEYLEN_MIN_SIZE)
						{
							std::cerr << "ERROR rsa key len too small in URL: " << key_len_in_bytes*8 << std::endl;
							ok = false;
						}
						else if (key_len_in_bytes > RSAKEYLEN_MAX_SIZE)
						{
							std::cerr << "ERROR rsa key len too big in URL: " << key_len_in_bytes*8 << std::endl;
							ok = false;
						}
						else if (key_len_in_bytes > URL_MAX_SIZE - 3)
						{
							std::cerr << "ERROR rsa key len too big in URL:: " << key_len_in_bytes*8 << std::endl;
							ok = false;
						}
#endif
						if (ok)
						{
							embedded_rsa_key = generate_base64_random_string(key_len_in_bytes - 11);
							if (verbose)
							{
								std::cout << "getrsa rsa key_len_in_bytes: " << key_len_in_bytes << std::endl;
								std::cout << "getrsa rsa_data: " << get_summary_hex(embedded_rsa_key.data(),embedded_rsa_key.size()) << " size:" << embedded_rsa_key.size() << std::endl;
							}

							std::string encoded_rsa_key;

							if (use_gmp == true)
							{
								RSAGMP::Utils::mpzBigInteger modulus(k.base64_to_base10(k.s_n) );
								RSAGMP::Utils::mpzBigInteger pub(k.base64_to_base10(k.s_e));
								RSAGMP::Utils::mpzBigInteger message(k.base64_to_base10(embedded_rsa_key));
								RSAGMP::Utils::mpzBigInteger message1 = RSAGMP::Encrypt(message, pub, modulus);
								std::string s_gmp = k.base10_to_base64(message1.get_str());
								encoded_rsa_key = s_gmp;

								if (SELF_TEST)
								{
									RSAGMP::Utils::mpzBigInteger priv(k.base64_to_base10(k.s_d));
									RSAGMP::Utils::mpzBigInteger message2 = RSAGMP::Decrypt(message1, priv, modulus);
									std::string s_gmp2 = k.base10_to_base64(message2.get_str());
									if (s_gmp2 != embedded_rsa_key)
									{
										std::cout << "ERROR encryption decryption" << std::endl;
										std::cout << "s_gmp2:           " << get_summary_hex(s_gmp2.data(),s_gmp2.size()) << " size:" << s_gmp2.size() << std::endl;
										std::cout << "embedded_rsa_key: " << get_summary_hex(embedded_rsa_key.data(),embedded_rsa_key.size()) << " size:" << embedded_rsa_key.size() << std::endl;
										throw "ERROR encryption decryption";
									} 
									else
									{
										std::cout << "SELF TEST OK encryption decryption" << std::endl;
									}
								}
							}
							else
							{
								std::cout << "WARNING not using GMP" << std::endl;
								typeuinteger  e = k.encode(embedded_rsa_key);
								encoded_rsa_key = k.to_base64(e);
							}
#ifdef RSA_IN_DATA_FEATURE
#else
							if (encoded_rsa_key.size() > URL_MAX_SIZE - 3)
							{
								std::cout << "ERROR getrsa data encoded value too big for URL_MAX_SIZE " << encoded_rsa_key.size()  << " > " << URL_MAX_SIZE - 3 << std::endl;
								ok = false;
							}
							else
#endif
							{
								temp.buffer.write(encoded_rsa_key.data(), encoded_rsa_key.size());
								if (verbose)
								{
									std::cout << "getrsa data encoded : " << get_summary_hex(encoded_rsa_key.data(), encoded_rsa_key.size())  << " size:" << encoded_rsa_key.size() << std::endl;
								}
							}
						}
					}
					else
					{
						// decoding from rsa_data
						if (use_gmp == true)
						{
							RSAGMP::Utils::mpzBigInteger modulus(k.base64_to_base10(k.s_n) );
							RSAGMP::Utils::mpzBigInteger priv(k.base64_to_base10(k.s_d));
							RSAGMP::Utils::mpzBigInteger message(k.base64_to_base10(rsa_data));
							RSAGMP::Utils::mpzBigInteger message1 = RSAGMP::Decrypt(message, priv, modulus);
							std::string s_gmp = k.base10_to_base64(message1.get_str());
							embedded_rsa_key = s_gmp;
						}
						else
						{
							std::cout << "WARNING not using GMP" << std::endl;

							typeuinteger  v = k.val(rsa_data);
							embedded_rsa_key = k.decode(v);
						}

						temp.buffer.write(embedded_rsa_key.data(), embedded_rsa_key.size());
						if (verbose)
						{
							std::cout << "getrsa rsa key_len_in_bytes: " << key_len_in_bytes << std::endl;
							if (use_gmp == false)
								std::cout << "getrsa data decoded: " << get_summary_hex(embedded_rsa_key.data(), embedded_rsa_key.size()) << " size:" << embedded_rsa_key.size() << std::endl;
							else
							   std::cout << "getrsa gmp decoded: " << get_summary_hex(embedded_rsa_key.data(), embedded_rsa_key.size()) << " size:" << embedded_rsa_key.size() << std::endl;
						}
					}

					if (ok)
					{
						ok = temp.save_to_file(outfile);
					}
					else
					{
						r = -1;
					}

					break;
				}
			}

			if (found == false)
			{
				std::cerr << "ERROR getrsa rsa_key_name not found: " << rsa_key_name << std::endl;
				r = -1;
			}
		}
		else
		{
			std::cerr << "ERROR getrsa no local_rsa_db: " << local_rsa_db << std::endl;
			r = -1;
		}

		if (verbose)
		{
		}
		return r;
	}

	static std::string s_last_local_file = "";
	static bool s_use_last = false;
	int getlocal(std::string url, cryptodata& dataout, std::string options = "", bool verbose=false)
	{
		options=options;
		if (verbose)
		{
			std::cout << "getlocal input:  " << url << std::endl;
		}

		std::string nfile;
		if (fileexists(url) == false) // MAY CONFLICT with current folder....
		{
			std::string token;
			if (s_use_last == true)
			{
				token = s_last_local_file;
			}
			else if (s_last_local_file.size() > 0)
			{
				std::cout << "Please, enter the path to the local file: [* == always use last path] "  << url << " " << " last path: " << s_last_local_file << std::endl;
				std:: cin >> token;
				if (token == "*")
				{
					s_use_last = true;
					token = s_last_local_file;
				}
			}
			else
			{
				std::cout << "Please, enter the path to the local file: "  << url << std::endl;
				std:: cin >> token;
			}

			nfile = token + url;
			if (fileexists(nfile) == false)
			{
				std::cerr << "Invalid path to the local file: "  << nfile << std::endl;
				return -1;
			}
			s_last_local_file = token;
		}
		else
		{
			//std::cout << "WARNING Using local file in current folder (remove it if want to specify another path)"  << url << std::endl;
			nfile = url;
		}

		bool r = dataout.read_from_file(nfile);
		auto sz = dataout.buffer.size();

		if (verbose)
		{
			std::cout << "reading local file: "  << nfile << " " << sz << std::endl;
		}

		if (r)
		{
			return 0;
		}

		return -1;
	}


	int getftp( std::string url, std::string outfile,
				std::string encryped_ftp_user,
				std::string encryped_ftp_pwd,
				std::string known_ftp_server,
				std::string options = "", bool verbose=false)
	{
		options = options;
		verbose = verbose;
		std::string user;
		std::string pwd;

		static bool s_ftp_use_last_pwd = false;
		static std::string s_ftp_last_pwd = "";

		if (    (encryped_ftp_user.size() == 0) || (encryped_ftp_user == "none") ||
				(encryped_ftp_pwd.size()  == 0) || (encryped_ftp_pwd  == "none")
		   )
		{
			std::cout << "Looking for a protected ftp file that require user and pwd."<< std::endl;
			std::cout << "URL: "<< url << std::endl;
			std::cout << "Enter ftp user:";
			std::cin >> user;
			std::cout << "Enter ftp pwd:";
			std::cin >> pwd;
		}
		else
		{
			int pos = find_string(url, ';', known_ftp_server,verbose);
			if (pos >= 0)
			{
				encryped_ftp_user= get_string_by_index(encryped_ftp_user, ';', pos, verbose);
				encryped_ftp_pwd = get_string_by_index(encryped_ftp_pwd,  ';', pos, verbose);

				if (s_ftp_last_pwd.size() == 0)
				{
					std::cout << "Looking for a protected ftp file that require user and pwd"<< std::endl;
					std::cout << "URL: "<< url << std::endl;
					std::cout << "Enter pwd used to encode ftp user/pwd: ";
					std::cin >> pwd;
					s_ftp_last_pwd = pwd;
				}
				else if (s_ftp_use_last_pwd == true)
				{
					pwd = s_ftp_last_pwd;
				}
				else
				{
					std::cout << "Looking for a protected ftp file that require user and pwd"<< std::endl;
					std::cout << "URL: "<< url << std::endl;
					std::cout << "Enter pwd used to encode ftp user/pwd [* == always use last one]: ";
					std::cin >> pwd;
					if (pwd == "*")
					{
						pwd = s_ftp_last_pwd;
						s_ftp_use_last_pwd = true;
					}
					s_ftp_last_pwd = pwd;
				}
				user = decrypt_simple_string(encryped_ftp_user, pwd);
				pwd  = decrypt_simple_string(encryped_ftp_pwd,  pwd);
			}
			else
			{
				std::cout << "Looking for a protected ftp file that require user and pwd"<< std::endl;
				std::cout << "URL: "<< url << std::endl;
				std::cout << "Enter ftp user:";
				std::cin >> user;
				std::cout << "Enter ftp pwd:";
				std::cin >> pwd;
			}
		}

		if (fileexists(outfile))
			std::remove(outfile.data());

		int pos = (int)user.find('@');
		if (pos > 0)
		{
			user.replace(pos, 1, "%40");
		}

		std::string cmd = "ftp://" + user + ":" + pwd + "@" + url;
		if ( wget(cmd.data(), outfile.data(), false) != 0)
		{
			std::cout << "ERROR with wget ftp://... " << url  << std::endl;
			user= "nonenonenonenonenonenonenonenonenonenone";
			pwd = "nonenonenonenonenonenonenonenonenonenone";
			cmd = "nonenonenonenonenonenonenonenonenonenone";
			return -1;
		}
		else
		{
			std::cout << "OK with wget ftp://..." << std::endl;
			user= "nonenonenonenonenonenonenonenonenonenone";
			pwd = "nonenonenonenonenonenonenonenonenonenone";
			cmd = "nonenonenonenonenonenonenonenonenonenone";
			return 0;
		}
	}

	//https://github.com/patrickjennings/General-Haberdashery/blob/master/wget/wget.c
	size_t write(void *ptr, size_t size, size_t nmemb, FILE *stream)
	{
		return fwrite(ptr, size, nmemb, stream);
	}

	int wget(const char *in, const char *out, bool verbose=false)
	{
		if (verbose)
		{
			std::cout << "wget in:  " << in << std::endl;
			std::cout << "wget out: " << out << std::endl;
		}

		CURL* curl;
		CURLcode res;
		FILE* fp;

		if (!(curl = curl_easy_init()))
		{
			std::cerr << "ERROR curl_easy_init()" << std::endl;
			return -1;
		}

		if(!(fp = fopen(out, "wb")))	// Open in binary
		{
			std::cerr << "ERROR opening file for writing " << out << std::endl;
			return -1;
		}

		// Set the curl easy options
		curl_easy_setopt(curl, CURLOPT_URL, in);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

		res = curl_easy_perform(curl);	// Perform the download and write
		if (res != 0)
		{
			std::cerr << "ERROR CURL return " << res << std::endl;
		}

		curl_easy_cleanup(curl);
		fclose(fp);
		return res;
}

	std::string file_checksum(std::string filename)
	{
		std::string s = "";
		cryptodata temp;
		bool r = temp.read_from_file(filename);
		if (r==true)
		{
			SHA256 sha;
			sha.update(reinterpret_cast<const uint8_t*> (temp.buffer.getdata()), temp.buffer.size() );
			uint8_t* digest = sha.digest();
			s = SHA256::toString(digest);
			delete[] digest;
		}
		else
		{
			std::cerr << "ERROR reading " << filename << ", code: " << r << std::endl;
		}
		return s;
	}

	std::string HEX(std::string sfile, long long pos, long long keysize)
	{
		bool r = true;
		if (fileexists(sfile) == false)
		{
			 std::cerr <<  "ERROR File not found - check the file path " << sfile<< std::endl;
			 return "";
		}
		if (pos < 0)
		{
			 std::cerr <<  "WARNING position less than 0 - reset to 0 " << std::endl;
			 pos = 0;
		}
		if (keysize < 1)
		{
			 std::cerr <<  "WARNING keysize less than one - reset to 1 " << std::endl;
			 keysize = 1;
		}

		cryptodata d;
		r = d.read_from_file(sfile);
		if (r == false)
		{
			 std::cerr <<  "ERROR Unable to read file " + sfile<< std::endl;
			 return "";
		}

		long long len = (long long)d.buffer.size();
		if (pos + keysize >= len)
		{
			std::cerr << "ERROR key pos+len bigger then file size: " << len << std::endl;
			return "";
		}

		Buffer b;
		b.increase_size((uint32_t)keysize);
		b.write(&d.buffer.getdata()[pos], (uint32_t)keysize, 0);

		std::string hex;
		char c;
		for(long long i=0;i<keysize;i++)
		{
			c = b.getdata()[i];
			hex += makehex((char)c, 2);
		}

		return hex;
	}

	void show_summary(const char* buffer, uint32_t buf_len)
	{
		for( uint32_t j = 0; j< buf_len; j++)
		{
			if (j<16) std::cout << (int)(unsigned char)buffer[j] << " ";
			else if (j==16) {std::cout << " ... [" << buf_len << "] ... ";}
			else if (j>buf_len-16) std::cout << (int)(unsigned char)buffer[j] << " ";
		}
		std::cout <<  std::endl;
	}
	std::string get_summary_hex(const char* buffer, uint32_t buf_len)
	{
		std::string s;
		for( uint32_t j = 0; j< buf_len; j++)
		{
			if (j<16) {s+= makehex((char)buffer[j], 2); s+= " ";}
			else if (j==16) {s+= " ... ["; s+= std::to_string(buf_len); s+= "] ... ";}
			else if (j>buf_len-16) { s+=  makehex((char)buffer[j], 2); s+=" ";}
		}
		return s;
	}

	//The following commands will get you the IP address list to find public IP addresses for your machine:
	//
	//    curl ifconfig.me
	//    curl -4/-6 icanhazip.com
	//    curl ipinfo.io/ip
	//    curl api.ipify.org
	//    curl checkip.dyndns.org
	//    dig +short myip.opendns.com @resolver1.opendns.com
	//    host myip.opendns.com resolver1.opendns.com
	//    curl ident.me
	//    curl bot.whatismyipaddress.com
	//    curl ipecho.net/plain

}
#endif

