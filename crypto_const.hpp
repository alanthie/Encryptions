#ifndef _INCLUDES_crypto_const
#define _INCLUDES_crypto_const

#include <filesystem>
#include <curl/curl.h>
#include "encrypt.h"
//-lcurl

constexpr static uint32_t BASE          = 25000; // BASE*BASE >= FILE_SIZE_LIM
constexpr static int16_t URL_MIN_SIZE   = 10;
constexpr static int16_t URL_MAX_SIZE   = 256;
constexpr static int16_t KEY_SIZE       = 256;
constexpr static int16_t CHKSUM_SIZE    = 64;
constexpr static int16_t URLINFO_SIZE   = 2+URL_MAX_SIZE+4+6+CHKSUM_SIZE+KEY_SIZE+4; // padding 16x
constexpr static int16_t PADDING_MULTIPLE = 8;
constexpr static int16_t NITER_LIM      = 100;
constexpr static int16_t PUZZLE_SIZE_LIM = 10000;
constexpr static uint32_t FILE_SIZE_LIM = 100*1000*1000;

const std::string REM_TOKEN             = "REM";
const std::string CHKSUM_TOKEN          = "CHKSUM";

class urlkey
{
public:
    urlkey() {}

    uint16_t url_size = 0;              // 2
    char url[URL_MAX_SIZE]= {0};        // 256
    char magic[4]= {'a','b','c','d'};   // 4
    uint16_t key_fromH = 0;             // 2 random offset
    uint16_t key_fromL = 0;             // 2
    uint16_t key_size = KEY_SIZE;       // 2
    char key[KEY_SIZE] = {0};           // 256
    char checksum[CHKSUM_SIZE] = {0};   // 64

    char urlinfo_with_padding[URLINFO_SIZE] = {0};
};

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

int find_string(std::string url, char delim, std::string vlist, bool verbose = false)
{
    size_t pos_start = 0;
    size_t pos_end = 0;
    std::string  token;
    int cnt = 0;

    if (verbose)
        std::cout << "searching for match of "<< url << " in list " << vlist << std::endl;

    for(size_t i=0;i<vlist.size();i++)
    {
        if (vlist[i]!=delim) pos_end++;
        else
        {
            token = vlist.substr(pos_start, pos_end-pos_start);
            if (verbose)
                std::cout << "token "<< token << std::endl;
            if (url.find(token, 0) != std::string::npos)
            {
                return cnt;
            }
            pos_start = pos_end+1;
            cnt++;
        }
    }
    return -1;
}

std::string get_string_by_index(std::string vlist, char delim, int idx, bool verbose = false)
{
    size_t pos_start = 0;
    size_t pos_end = 0;
    std::string token;
    int cnt = 0;

    for(size_t i=0;i<vlist.size();i++)
    {
        if (vlist[i]!=delim) pos_end++;
        else
        {
            token = vlist.substr(pos_start, pos_end-pos_start);
            if (verbose)
                std::cout << "token "<< token << std::endl;
            if (idx == cnt)
                return token;

            pos_start = pos_end+1;
            i = pos_start;
            cnt++;
        }
    }
    return "";
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

