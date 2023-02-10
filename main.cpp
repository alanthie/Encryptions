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

class puzzle
{
public:
    struct QA
    {
        std::string Q;
        std::string A;
    };
    //"What is yout name", "AxxxN"

    puzzle(bool isfull) : is_full(isfull) {}
    std::string filename()
    {
        (isfull == true) ? return "puzzle_full.txt" : return "puzzle_partial.txt";
    }

    bool read_from_file();
    bool is_all_answered();
    bool save_to_file();

    std::string make_key(int size_multiple_of_n = 16);
    bool make_partial(puzzle& p);

    bool is_full = true;
    std::vector<QA> vQA;
};

class data
{
public:
    data(std::string file_name) : filename(file_name) {}
    ~data()
    {
    }

    bool read_from_file();
    //bool read_from_buffer(std::string& buffer);
    bool save_to_file();
    void pre_append(std::string& s);

    bool copy_buffer_to(data& dst);
    //void swap_buffer_with(data& dst);
    void clear_data();

    std::string filename;
    std::string buffer_data;
};


class encryptor
{
public:
    int encrypted_urlkey_size = 256+2+64; // padding
    struct urlkey
    {
        std::string url;        // 256
        size_t key_from;        // 2
        size_t key_size = 64;   // 64

        std::string key;
        std::string url_from_size_with_padding;
    };

    encryptor(  std::string filename_urlkey,
                std::string filename_msg_data,
                std::string filename_encrypted_data,
        ) :
        file_urlkey(filename_urlkey),
        msg_data(filename_msg_data),
        puz_full(true),
        puz_partial(false),
        encrypted_data(filename_encrypted_data),
        data_temp("temp.dat");
        data_temp_next("temp_next.dat");
    {
    }

    ~encryptor()
    {
        // remove temp
    }

    bool read_file_urlkey();
    bool make_key(size_t i);
    bool make_url_from_size_with_padding(size_t i, std::string puzzle_key);

    // select algos
    bool encode(data& data_temp, std::string& key, data& data_temp_next);

    bool encrypt()
    {
        if (read_file_urlkey() == false)
        {
            return false;
        }
        if (puz_full.read_from_file() == false)
        {
            return false;
        }
        std::string puz_key = puz_full.make_key();
        for(size_t i=0; i<vurlkey.size(); i++)
        {
        i   f (make_key(i) == false)
            {
                return false;
            }
            if (make_url_from_size_with_padding(i, puz_key) == false)
            {
                return false;
            }
        }

        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (i==0)
            {
                if (msg_data.read() == false)
                {
                    return false;
                }
                if (msg_data.copy_buffer_to(data_temp)== false)
                {
                    return false;
                }
            }

            if (i>0) data_temp.pre_append(vurlkey[i].url_from_size_with_padding);

            data_temp_next.clear_data();
            encode(data_temp, vurlkey[i].key, data_temp_next);

            data_temp_next.copy_buffer_to(data_temp);
            data_temp_next.clear_data();
        }
        // pwd0...
        encrypted_data_temp.copy_buffer_to(encrypted_data);
        encrypted_data.save_to_file();

        // encode(Data,          key1) => Data1             // urlkey1=>key1
        // encode(Data1+urlkey1, key2) => Data2
        // encode(Data2+urlkey2, key3) => Data3
        // ...
        // encode(DataN-1+urlkeyN-1, keyN) => DataN
        // encode(DataN+urlkeyN,     pwd0) => DataFinal
        //
        // decode(DataFinal, pwd0) => DataN+urlkeyN         urlkeyN=>keyN
        // decode(DataN,     keyN) => DataN-1+urlkeyN-1     urlkeyN-1=>keyN-1
        // ...
        // decode(Data2, key2) => Data1+urlkey1             urlkey1=>key1
        // decode(Data1, key1) => Data

        if (puz_full.save_to_file() == false)
        {
            return false;
        }
        if (puz_full.make_partial(puz_partial) == false)
        {
            return false;
        }
        if (puz_partial.save_to_file() == false)
        {
            return false;
        }
    }

    std::string     file_urlkey;
    std::vector<urlkey> vurlkey;
    data            msg_data;
    puzzle          puz_full;

    puzzle          puz_partial;
    data            encrypted_data;

    data            data_temp;
    data            data_temp_next;
};

class decryptor
{
public:
    // pack
    struct encrypted_header
    {
    };
    struct decrypted_header
    {
    };

     encrypted_data(puzzle& p) : puz(p) {}
    ~encrypted_data()
    {
        if (encrypted_data != nullptr)
        {
            delete []encrypted_data;
            encrypted_data = null_ptr;
            encrypted_data_size = 0;
        }
    }

    std::string encrypted_filename() {return "msg_encrypted.dat";}
    std::string decrypted_filename() {return "msg_decrypted.txt";}

    long long encrypted_filesize() {return encrypted_data_size;}

    bool read_encrypted_data();
    std::string make_key(int size_multiple_of_n = 16);

    bool decrypted_header();
    bool is_valid_decrypted_header();
    bool decrypt();

    data        encrypted_data;
    data        decrypted_data;
    puzzle&     puz;
};

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
