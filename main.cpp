#include <iostream>
#include "Encryptions/DES.h"


#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

//https://github.com/patrickjennings/General-Haberdashery/blob/master/wget/wget.c
//-lcurl
size_t write(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	return fwrite(ptr, size, nmemb, stream);
}

int wget(char *in, char *out)
{
	CURL* curl;
	CURLcode res;
	FILE* fp;

	if(!(curl = curl_easy_init()))
		return -1;

	if(!(fp = fopen(out, "wb")))	// Open in binary
		return -1;

	// Set the curl easy options
	curl_easy_setopt(curl, CURLOPT_URL, in);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

	res = curl_easy_perform(curl);	// Perform the download and write

	curl_easy_cleanup(curl);
	fclose(fp);
	return res;
}

int main_wget(int args, char *argc[])
{
	if(args != 3)
	{
		printf("%s url file\n", argc[0]);
		return -1;
	}

	if(wget(argc[1], argc[2]) != 0)
		printf("An error occured!\n");

	return 0;
}


//class DES : public SymAlg{
//    private:
//        uint64_t keys[16];
//        std::string run(const std::string & data);
//
//    public:
//        DES();
//        DES(const std::string & KEY);
//        void setkey(const std::string & KEY);
//        std::string encrypt(const std::string & DATA);
//        std::string decrypt(const std::string & DATA);
//        unsigned int blocksize() const;
//};

int main()
{
    std::string KEY  = "EWTW;RLd"; // 8 bytes l peut exister 2e56 (soit 7.2*10e16) clés différentes !
    std::string data = "65431234"; // 8 bytes

    DES des(KEY);
    std::string data_encr = des.encrypt(data);
    std::string data_back = des.decrypt(data_encr);
    if (data != data_back)
    {
        std::cout << "Error with DES algo"
        << "\nkey " << KEY
        << "\ndata " << data
        << "\ndata_encr " << data_encr
        << "\ndata_back " << data_back
        << std::endl;
    }
    else
    {
        std::cout << "OK with DES algo "
        << "\nkey " << KEY
        << "\ndata " << data
        << "\ndata_encr " << data_encr
        << "\ndata_back " << data_back
        << std::endl;
    }


    std::string url = "https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz";
    std::string filename  = "./Staging/Python-3.8.1.tgz";

    if ( wget(url.data(), filename.data()) != 0)
        printf("An error occured wget !\n");
    else
        std::cout << "OK with wget " << std::endl;

    std::cout << "done " << std::endl;
    int a; std::cin >> a;
    return 0;
}
