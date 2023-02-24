#ifndef _INCLUDES_crypto_file
#define _INCLUDES_crypto_file

#include <filesystem>
#include <curl/curl.h>
#include "encrypt.h"
#include <iostream>
#include <fstream>
#include "DES.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "crypto_const.hpp"
#include "data.hpp"
#include "puzzle.hpp"

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

int getlocal(std::string url, cryptodata& dataout, std::string options = "", bool verbose=false)
{
    options=options;
    if (verbose)
    {
        std::cout << "getlocal in:  " << url << std::endl;
    }

    std::string nfile;
    if (fileexists(url) == false)
    {
        std::cout << "Please, enter the path to the local file: "  << nfile << std::endl;
        std::string token;
        std:: cin >> token;
        nfile = token + url;
        if (fileexists(nfile) == false)
        {
            std::cerr << "Invalid path to the local file: "  << nfile << std::endl;
            return -1;
        }
    }
    else
    {
        nfile = url;
    }

    bool r = dataout.read_from_file(nfile);
    if (r) return 0;

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
            std::cout << "Looking for a protected ftp file that require user and pwd"<< std::endl;
            std::cout << "URL: "<< url << std::endl;
            std::cout << "Enter pwd used to encode ftp user/pwd: ";
            std::cin >> pwd;
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

    int pos = user.find('@');
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

#endif

