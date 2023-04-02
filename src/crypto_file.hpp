#ifndef _INCLUDES_crypto_file
#define _INCLUDES_crypto_file

#include "crypto_const.hpp"
#include "crypto_parsing.hpp"
#include <curl/curl.h>
#include "encrypt.h" //decrypt_simple_string

namespace cryptoAL
{
namespace key_file
{
	int wget(const char *in, const char *out, bool verbose);

	int getvideo(std::string url, std::string outfile, std::string options = "", [[maybe_unused]] bool verbose=false)
	{
		// youtube-dl 'https://www.bitchute.com/video/JjqRgjv5GJmW/'
#ifdef _WIN32
		std::string cmd = std::string("youtube-dl ") + url + std::string(" -o ") + outfile + options;
#else
		std::string cmd = std::string("youtube-dl ") + std::string("'") + url + std::string("'") + std::string(" -o ") + outfile + options;
#endif
		if (VERBOSE_DEBUG)
		{
			std::cout << "getvideo in:  " << url << std::endl;
			std::cout << "getvideo out: " << outfile << std::endl;
			std::cout << "getvideo cmd: " << cmd << std::endl;
		}
		int r = system(cmd.data());
		return r;
	}

	static std::string s_last_local_file = "";
	static bool s_use_last = false;
	int getlocal(std::string url, cryptodata& dataout, std::string options = "", [[maybe_unused]] bool verbose=false)
	{
		options=options;
		if (VERBOSE_DEBUG)
		{
			std::cout << "getlocal input:  " << url << std::endl;
		}

		std::string nfile;
		if (file_util::fileexists(url) == false) // folder_local is use
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
			if (file_util::fileexists(nfile) == false)
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

		if (VERBOSE_DEBUG)
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
			int pos = parsing::find_string(url, ';', known_ftp_server,verbose);
			if (pos >= 0)
			{
				encryped_ftp_user= parsing::get_string_by_index(encryped_ftp_user, ';', pos, verbose);
				encryped_ftp_pwd = parsing::get_string_by_index(encryped_ftp_pwd,  ';', pos, verbose);

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

		if (file_util::fileexists(outfile))
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

	size_t write(void *ptr, size_t size, size_t nmemb, FILE *stream)
	{
		return fwrite(ptr, size, nmemb, stream);
	}

	int wget(const char *in, const char *out, [[maybe_unused]] bool verbose=false)
	{
		if (VERBOSE_DEBUG)
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
}
#endif

