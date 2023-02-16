#include <iostream>
#include "Encryptions/DES.h"
#include "Buffer.hpp"
#include "SHA256.h"

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <random>

class random_engine
{
  public:
    std::random_device                      rd;
    std::mt19937                            mt;
    std::uniform_real_distribution<double>  dist;

    random_engine() : rd{}, mt{rd()}, dist{0.0, 1.0}
    {
        seed();
    }

    double get_rand()
    {
      return dist(mt);
    }

    void seed()
    {
        srand ((unsigned int)time(NULL));
        int n = rand() % 100;
        for (int i=0;i<n;i++) get_rand(); // random seed
    }
};

//https://github.com/patrickjennings/General-Haberdashery/blob/master/wget/wget.c
//-lcurl
size_t write(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	return fwrite(ptr, size, nmemb, stream);
}

int wget(char *in, const char *out)
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

constexpr static uint32_t BASE  = 25000; // BASE*BASE >= FILE_SIZE_LIM
constexpr static int16_t URL_MIN_SIZE   = 10;
constexpr static int16_t URL_MAX_SIZE   = 256;
constexpr static int16_t KEY_SIZE       = 256;
constexpr static int16_t CHKSUM_SIZE    = 64;
constexpr static int16_t URLINFO_SIZE   = 2+URL_MAX_SIZE+4+6+CHKSUM_SIZE+KEY_SIZE+4; // padding 16x
constexpr static int16_t PADDING_MULTIPLE = 8;
constexpr static int16_t NITER_LIM      = 100;
constexpr static int16_t PUZZLE_SIZE_LIM = 10000;
constexpr static uint32_t FILE_SIZE_LIM = 100*1000*1000;

class data
{
public:
    data() {}
    ~data() {}

    virtual bool read_from_file(std::string filename, bool allow_realloc = true)
    {
        std::ifstream ifd(filename.data(), std::ios::binary | std::ios::ate);
        if (ifd)
        {
            int32_t sz = ifd.tellg();
            if(sz<=-1)
            {
                std::cerr << "ERROR read_from_file can not read size" << filename << std::endl;
                ifd.close();
                return false;
            }

            if(sz==0)
            {
                //  empty file
                std::cerr << "WARNING read_from_file empty file" << filename << std::endl;
                ifd.close();
                return true;
            }

            uint32_t usz = (uint32_t) sz;

            if (this->allocsize() < usz)
            {
                if (allow_realloc)
                {
                    if (usz < FILE_SIZE_LIM)
                    {
                        realloc(usz);
                    }
                    else
                    {
                        std::cerr << "ERROR read_from_file FILE_SIZE_LIM " << filename << " " << usz << std::endl;
                        ifd.close();
                        return false;
                    }
                }
                else
                {
                    std::cerr << "ERROR read_from_file allow_realloc = false " << filename << " " << usz << std::endl;
                    ifd.close();
                    return false;
                }
            }

            ifd.seekg(0, std::ios::beg);
            int32_t r = buffer.read(ifd, usz, 0);
            if (r <= -1)
            {
                std::cerr << "ERROR read_from_file buffer.read(ifd, sz, 0);" << filename << " " << usz << std::endl;
                ifd.close();
                return false;
            }

            uint32_t ur = (uint32_t) r;
            if (ur != usz)
            {
                std::cerr << "ERROR read_from_file r!=usz" << filename << " " << usz << std::endl;
                ifd.close();
                return false;
            }
            ifd.close();
            return true;
        }
        else
        {
            std::cerr << "ERROR read_from_file OPENING FAILED " << filename << std::endl;
        }
        return false;
    }

    virtual bool save_to_file(std::string filename)
    {
        std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
        if (ofd.bad() == false)
        {
            int32_t r = buffer.write(ofd, buffer.size());
            if (r==-1)
            {
                std::cerr << "ERROR save_to_file" << "Failed for buffer.write(ofd, buffer.size()" << buffer.size() <<  std::endl;
                ofd.close();
                return false;
            }
            if (r!=(int32_t)buffer.size())
            {
                std::cerr << "ERROR save_to_file" << "Failed for buffer.write(ofd, buffer.size() " << r << std::endl;
                ofd.close();
                return false;
            }
            ofd.close();
            return true;
        }
        else
        {
            std::cerr << "ERROR save_to_file" << "Failed  to open file " << filename << std::endl;
        }
        return false;
    }

    void append(char* p, uint32_t n)        {buffer.write(p, n, -1);}
    void append(const char* p, uint32_t n)  {buffer.write(p, n, -1);}

	int32_t get_first(size_t n, Buffer& rout)
	{
        if (buffer.size() < n)
        {
            std::cerr << "WARNING get_first" << "Failed for (buffer.size() < n) " << n << std::endl;
            return -1;
        }
        rout.erase();
        rout.write(buffer.getdata(), n, 0);
        return n;
	}

	int32_t get_last(size_t n, Buffer& rout)
	{
        if (buffer.size() < n)
        {
            std::cerr << "WARNING get_last" << "Failed for (buffer.size() < n) " << n << std::endl;
            return -1;
        }
        rout.erase();
        rout.write(buffer.getdata() + buffer.size() - n, n, 0);
        return n;
	}

    bool copy_buffer_to(data& dst)
    {
        dst.realloc(buffer.size() + 1);
        dst.buffer.write(buffer.getdata(), buffer.size(), 0);
        return true;
    }

    void clear_data()           {buffer.clear();}
    void erase()                {buffer.erase();}
    void realloc(uint32_t sz)   {buffer.realloc(sz);}
    uint32_t allocsize()        {return buffer.allocsize();}

    Buffer buffer;
};

bool is_file_same(std::string filename1, std::string filename2)
{
    data data1;
    data data2;

    if(data1.read_from_file(filename1)==false)
        return false;

    if(data2.read_from_file(filename2)==false)
        return false;

    if(data1.buffer.size() != data2.buffer.size() )
        return false;

    for(size_t i=0;i< data1.buffer.size() ; i++)
    {
        if ( data1.buffer.getdata()[i] != data2.buffer.getdata()[i])
            return false;
    }
    return true;
}

class puzzle
{
public:
    struct QA
    {
        int type = 0; // 0==QA, 1==REM, 2==CHK
        std::string Q;
        std::string A;
    };

    const std::string REM_TOKEN = "REM";
    const std::string CHKSUM_TOKEN = "CHKSUM";

    puzzle() {}

    void remove_partial(std::string& a)
    {
        std::string  s;
        for(size_t i = 0; i < a.size(); i++)
        {
            if (i==0) continue;
            if (i==a.size()-1) continue;
            a[i] = 'x'; //"What is yout name?": "AxxxN"
        }
    }

    bool make_partial()
    {
        for(size_t i = 0; i < vQA.size(); i++)
        {
            if (vQA[i].type == 0)
            {
                remove_partial(vQA[i].A);
            }
        }
        return true;
    }

    bool is_all_answered() {return true;}

    std::string checksum()
    {
        data temp;
        std::string s;
        for(size_t i = 0; i < vQA.size(); i++)
        {
            if (vQA[i].type == 0)
            {
                s = "\"" + vQA[i].Q +"\"" +" : " +  "\"" + vQA[i].A + "\"" + "\n";
                temp.buffer.write(s.data(), s.size(), -1);
            }
            else if (vQA[i].type == 1)
            {
                s = vQA[i].Q + vQA[i].A + "\n";
                temp.buffer.write(s.data(), s.size(), -1);
            }
        }

        SHA256 sha;
        sha.update(reinterpret_cast<const uint8_t*> (temp.buffer.getdata()), temp.buffer.size() );
        uint8_t* digest = sha.digest();
        s = SHA256::toString(digest);
        std::cout << "chksum puzzle " << s << std::endl;
        delete[] digest;

        return s;
    }

    bool read_from_file(std::string filename, bool b)
    {
        if (puz_data.read_from_file(filename, b) == true)
        {
            bool r = parse_puzzle();
            if (r)
            {
                chksum_puzzle = checksum();
            }
            return r;
        }
        return false;
    }

    bool save_to_file(std::string filename)
    {
        data temp;

        std::string s;
        for(size_t i = 0; i < vQA.size(); i++)
        {
            if (vQA[i].type == 0)
            {
                s = "\"" + vQA[i].Q +"\"" +" : " +  "\"" + vQA[i].A + "\"" + "\n";
            }
            else
            {
                s =vQA[i].Q + vQA[i].A + "\n";
            }
            temp.buffer.write(s.data(), s.size(), -1);
        }
        s = CHKSUM_TOKEN + " puzzle : " + chksum_puzzle + "\n";
        temp.buffer.write(s.data(), s.size(), -1);

        return temp.save_to_file(filename);
    }

    void make_key(Buffer& rout)
    {
        size_t r = puz_data.buffer.size() % PADDING_MULTIPLE;
        rout.write(puz_data.buffer.getdata(), puz_data.buffer.size(), 0);

        char c[1] = {'0'};
        for(size_t i = 0; i < PADDING_MULTIPLE - r; i++)
        {
            // padding
            rout.write(c, 1, -1);
        }
    }

    bool parse_puzzle()
    {
        size_t pos = 0;
        char c;
        std::string sqa;

        vQA.clear();
        size_t sz = puz_data.buffer.size();

        while (pos < sz)
        {
            c = puz_data.buffer.getdata()[pos];
            if (c!=0)
            {
                if ((c!= '\n') && (c!= '\r'))
                {
                    sqa+=c;
                }
                else
                {
                    if ((sqa.size() >= REM_TOKEN.size()) && (sqa.substr(0,REM_TOKEN.size()) == REM_TOKEN))
                    {
                        parse_rem(sqa);
                    }
                    else if ((sqa.size() >= CHKSUM_TOKEN.size()) && (sqa.substr(0,CHKSUM_TOKEN.size()) == CHKSUM_TOKEN))
                    {
                        parse_chksum(sqa);
                    }
                    else if (sqa.size() > 7) // "" : ""
                    {
                        if (parse_qa(sqa) == false)
                        {
                            //return false;
                        }
                    }
                    else
                    {
                        // skip (remove)
                    }
                    sqa.clear();
                }
            }
            pos++;
        }

        if (sqa.size() > 7)
        {
            if (parse_qa(sqa) == false)
            {
                //return false;
            }
        }
        return true;
    }

    bool parse_rem(std::string qa)
    {
        if (qa.size() < REM_TOKEN.size())
            return false;

        QA q_a;
        q_a.type = 1;
        q_a.Q = qa;
        q_a.A = "";
        vQA.push_back( q_a );
        return true;
    }

    bool parse_chksum(std::string qa)
    {
        if (qa.size() < CHKSUM_TOKEN.size())
            return false;

        QA q_a;
        q_a.type = 2;
        q_a.Q = qa;
        q_a.A = "";
        vQA.push_back( q_a );
        return true;
    }

    bool parse_qa(std::string qa)
    {
        size_t pos = 0;
        char c;
        std::string q;
        std::string a;
        bool do_q = true;
        bool do_a = false;
        bool do_sep = false;
        bool start_found = false;
        bool end_found = false;

        size_t sz = qa.size();
        while (pos < sz)
        {
            c = qa[pos];
            if (do_sep==false)
            {
                if (start_found==false)
                {
                    if (c!= '"')
                    {
                        //skip
                    }
                    else
                    {
                        start_found = true;
                    }
                }
                else if (end_found==false)
                {
                    if (c!= '"')
                    {
                        if (do_q) q+= c;
                        if (do_a) a+= c;
                    }
                    else
                    {
                        end_found = true;
                        if (do_q) {do_q=false;do_sep=true;}
                        if (do_a) {do_a=false;}
                    }
                }
            }
            else
            {
                if (c!= ':')
                {
                    //skip
                }
                else
                {
                    //separator_found = true;
                    do_sep = false;
                    start_found = false;
                    end_found = false;
                    do_a = true;
                }
            }
            pos++;
        }
        if ((do_q==true) || (do_a==true) || (do_sep==true))
        {
            return false;
        }

        if (q.size()<=0)
            return false;

        QA q_a;
        q_a.type = 0;
        q_a.Q = q;
        q_a.A = a;
        vQA.push_back( q_a );

        return true;
    }

    data puz_data;
    std::vector<QA> vQA;
    std::string chksum_puzzle;
};

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

class encryptor
{
public:

    encryptor(  std::string ifilename_urls,
                std::string ifilename_msg_data,
                std::string ifilename_puzzle,
                std::string ifilename_partial_puzzle,
                std::string ifilename_encrypted_data
        )
    {
        filename_urls = ifilename_urls;
        filename_msg_data = ifilename_msg_data;
        filename_puzzle = ifilename_puzzle;
        filename_partial_puzzle = ifilename_partial_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;
    }

    ~encryptor()
    {
    }

    bool read_file_urls(std::string filename)
    {
        bool r = true;
        r = urls_data.read_from_file(filename);

        std::string s;
        std::string url;
        if (r)
        {
            for(size_t i=0;i<urls_data.buffer.size();i++)
            {
                // parse url
                if (urls_data.buffer.getdata()[i] == '\n')
                {
                    url = s;
                    if ((url.size() >= URL_MIN_SIZE) && (url.size() <= URL_MAX_SIZE))
                    {
                        urlkey uk;
                        for(size_t ii=0;ii<URL_MAX_SIZE;ii++) uk.url[ii] = 0;
                        for(size_t ii=0;ii<url.size();ii++) uk.url[ii] = url[ii];
                        uk.url_size = url.size();
                        vurlkey.push_back(uk);
                    }
                    else
                    {
                        // skip!
                        std::cerr << "WARNING read_file_urls " << "Failed for ((url.size() >= URL_MIN_SIZE) && (url.size() <= URL_MAX_SIZE))" << std::endl;
                    }
                    s.clear();
                }
                else
                {
                    if (urls_data.buffer.getdata()[i]!=0)
                    {
                        s+=urls_data.buffer.getdata()[i];
                    }
                    else
                    {
                        std::cerr << "WARNING read_file_urls " << "Failed for (urls_data.buffer.getdata()[i]!=0) " << std::endl;
                    }
                }
            }
        }
        return r;
    }

    bool make_urlkey_from_url(size_t i)
	{
		bool r = true;
		std::string file = "./Staging/url_file.dat";
		std::remove(file.data());

		// DOWNLOAD URL FILE
		std::cout << "URL " << vurlkey[i].url << std::endl;
		if (wget(&vurlkey[i].url[0], file.data()) != 0)
		{
            std::cerr << "ERROR wget vurlkey[i].url " << vurlkey[i].url << std::endl;
            r = false;
		}

		if (r)
		{
			data d;
			r = d.read_from_file(file);
			if (r)
			{
				if (d.buffer.size() > KEY_SIZE)
				{
					random_engine rd;
					uint32_t t = rd.get_rand() * (d.buffer.size() - KEY_SIZE);
					vurlkey[i].key_fromH = (t / BASE);
					vurlkey[i].key_fromL = t - (vurlkey[i].key_fromH  * BASE);
//					vurlkey[i].key_fromH = 2;
//					vurlkey[i].key_fromL = 3;
//					int32_t t = BASE*vurlkey[i].key_fromH  + vurlkey[i].key_fromL;
					std::cout << "vurlkey[i].key_fromH=" << vurlkey[i].key_fromH << " ";
					std::cout << "vurlkey[i].key_fromL=" << vurlkey[i].key_fromL << " ";
					std::cout << "key_pos=" << t << " ";
					std::cout << "key_pos=" << BASE*vurlkey[i].key_fromH + vurlkey[i].key_fromL  << " ";
					std::cout <<  std::endl;

					for( size_t j = 0; j< KEY_SIZE; j++)
					{
						vurlkey[i].key[j] = d.buffer.getdata()[t+j];
						std::cout << (int)(unsigned char)vurlkey[i].key[j] << " ";
                    }
                    std::cout <<  std::endl;
				}
				else
				{
                    std::cout << "key_pos=" << (int32_t)0 << " ";
					for( size_t j = 0; j< d.buffer.size(); j++)
					{
						vurlkey[i].key[j] = d.buffer.getdata()[j];
						std::cout << (int)(unsigned char)vurlkey[i].key[j] << " ";
                    }
					for( size_t j = d.buffer.size(); j< KEY_SIZE; j++)
					{
						vurlkey[i].key[j] = j % 7;
						std::cout << (int)(unsigned char)vurlkey[i].key[j] << " ";
                    }
                    std::cout <<  std::endl;
				}

				// vurlkey[i].checksum
                {
                    SHA256 sha;
                    sha.update(reinterpret_cast<const
                    uint8_t*> (d.buffer.getdata()), d.buffer.size() );
                    uint8_t* digest = sha.digest();
                    auto s = SHA256::toString(digest);
                    for( size_t j = 0; j< CHKSUM_SIZE; j++)
                        vurlkey[i].checksum[j] = s[j];
                    std::cout << "Encryption checksum " << SHA256::toString(digest) << std::endl;
                    delete[] digest;
                }
            }
            else
            {
                std::cerr << "ERROR reading file " << file << std::endl;
            }

		}

		std::remove(file.data());
		return r;
	}

    bool make_urlinfo_with_padding(size_t i)
	{
		bool r = true;

		Buffer temp(URLINFO_SIZE);
		temp.init(0);
		temp.writeUInt16(vurlkey[i].url_size, -1);
		temp.write(&vurlkey[i].url[0], URL_MAX_SIZE, -1);
		temp.write(&vurlkey[i].magic[0], 4, -1);
		temp.writeUInt16(vurlkey[i].key_fromH, -1);
		temp.writeUInt16(vurlkey[i].key_fromL, -1);
		temp.writeUInt16(vurlkey[i].key_size, -1);
		temp.write(&vurlkey[i].key[0], KEY_SIZE, -1);
		temp.write(&vurlkey[i].checksum[0], CHKSUM_SIZE, -1);

		for( size_t j = 0; j< URLINFO_SIZE; j++)
            vurlkey[i].urlinfo_with_padding[j] = temp.getdata()[j];

		return r;
	}


    // select various encoding algos based on iter, ...
    bool encode(size_t iter, data& data_temp, const char* key, uint32_t key_size, data& data_temp_next)
	{
        iter = iter;
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 4 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encoding file must be multiple of 4 bytes iter: " << iter << std::endl;
		}

        // BINARY DES is multiple of 4
		uint32_t nblock = data_temp.buffer.size() / 4;
		uint32_t nkeys  = key_size / 4;

		char KEY[4];
		char DATA[4];
		std::string data_encr;

		uint32_t key_idx = 0;
		for(size_t blocki = 0; blocki < nblock; blocki++)
		{
            for(size_t j = 0; j < 4; j++)
            {
                c = data_temp.buffer.getdata()[4*blocki + j];
                DATA[j] = c;
            }

            for(size_t j = 0; j < 4; j++)
            {
                c = key[4*key_idx + j];
                KEY[j] = c;
            }
            key_idx++;
            if (key_idx >= nkeys) key_idx=0;

            DES des(KEY);
            data_encr = des.encrypt_bin(DATA, 4);
            data_temp_next.buffer.write(data_encr.data(), data_encr.size(), -1); // 8 bytes!
        }

		return r;
	}

    bool encrypt(bool allow_empty_url = false)
    {
        if (read_file_urls(filename_urls) == false)
        {
            std::cerr << "ERROR " << "read_file_urls" << std::endl;
            return false;
        }
        if (allow_empty_url == false)
        {
            if (vurlkey.size() == 0)
            {
                std::cerr << "ERROR " << "(vurlkey.size() == 0)" << std::endl;
                return false;
            }
        }

        if (puz.read_from_file(filename_puzzle, false) == false)
        {
            std::cerr << "ERROR " << "puz.read_from_file" << std::endl;
            return false;
        }
        if (puz.puz_data.buffer.size() == 0)
        {
            std::cerr << "ERROR " << "(puz.buffer.size() == 0)" << std::endl;
            return false;
        }

        Buffer puz_key(PUZZLE_SIZE_LIM);
        puz.make_key(puz_key);
        if (puz_key.size()== 0)
        {
            std::cerr << "ERROR " << "(puz_key.size()== 0)" << std::endl;
            return false;
        }

		if (puz.is_all_answered() == false)
        {
            std::cerr << "ERROR " << "(puz.is_all_answered() == false)" << std::endl;
            return false;
        }
        if (puz.make_partial() == false)
        {
            std::cerr << "ERROR " << "(puz.make_partial() == false)" << std::endl;
            return false;
        }
        if (puz.save_to_file(filename_partial_puzzle) == false)
        {
            std::cerr << "ERROR " << "puz.save_to_file(filename_partial_puzzle) == false)" << std::endl;
            return false;
        }

        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (make_urlkey_from_url(i) == false)
            {
                std::cerr << "ERROR " << "(make_key_from_url(i) == false) == false)" << std::endl;
                return false;
            }
            if (make_urlinfo_with_padding(i) == false)
            {
                std::cerr << "ERROR " << "(make_urlinfo_with_padding(i, puz_key) == false)" << std::endl;
                return false;
            }
        }

        if (msg_data.read_from_file(filename_msg_data) == false)
        {
            std::cerr << "ERROR " << "(msg_data.read_from_file(filename_msg_data) == false)" << std::endl;
            return false;
        }
        if (msg_data.copy_buffer_to(data_temp)== false)
        {
            std::cerr << "ERROR " << "(msg_data.copy_buffer_to(data_temp)== false)" << std::endl;
            return false;
        }

        auto sz_msg = data_temp.buffer.size();
        if (sz_msg % PADDING_MULTIPLE != 0)
        {
            std::cerr << "ERROR " << "Msg must be multiple of PADDING_MULTIPLE, sz_msg: " << PADDING_MULTIPLE << " " << sz_msg << std::endl;
            return false;

//            int16_t n = PADDING_MULTIPLE - (sz_msg % PADDING_MULTIPLE);
//            char c[1] = {' '};
//            for(int16_t i= 0; i< n; i++)
//                data_temp.buffer.write(&c[0], 1, -1);
        }

		// encode(Data,          key1) => Data1 // urlkey1=>key1
        // encode(Data1+urlkey1, key2) => Data2
        // encode(Data2+urlkey2, key3) => Data3
        // ...
        // encode(DataN-1+urlkeyN-1, keyN) => DataN
        // encode(DataN+urlkeyN+Niter,     pwd0) => DataFinal
        //
        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (i==0)
            {
                // skip msg_data already read into data_temp
            }

            char save_key[KEY_SIZE];
            for(size_t ii=0; ii<KEY_SIZE; ii++)
                save_key[ii] = vurlkey[i].key[ii];

            if (i>0)
            {
                for(size_t ii=0; ii<KEY_SIZE; ii++)
                    vurlkey[i-1].key[ii] = 0;

                data_temp.append(&vurlkey[i-1].urlinfo_with_padding[0], URLINFO_SIZE);
            }

            data_temp_next.clear_data();
            encode(i, data_temp, &save_key[0], KEY_SIZE, data_temp_next);

            data_temp.buffer.swap_with(data_temp_next.buffer);
            data_temp_next.erase();
        }

        if (vurlkey.size()>0)
        {
            for(size_t ii=0; ii<KEY_SIZE; ii++)
                vurlkey[vurlkey.size()-1].key[ii] = 0;

            data_temp.append(&vurlkey[vurlkey.size()-1].urlinfo_with_padding[0], URLINFO_SIZE);
        }
        else
        {
        }

        // Save number of iterations (N web keys + 1 puzzle key) in the last 2 byte! + PADDING_MULTIPLE-2
        Buffer temp(PADDING_MULTIPLE);
		temp.init(0);
		temp.writeUInt16(vurlkey.size() + 1, PADDING_MULTIPLE-2);
        data_temp.append(temp.getdata(), PADDING_MULTIPLE);

        //encode(DataN+urlkeyN+Niter,     pwd0) => DataFinal
        encode(vurlkey.size(), data_temp, puz_key.getdata(), puz_key.size(), data_temp_next);

        data_temp_next.copy_buffer_to(encrypted_data);
        encrypted_data.save_to_file(filename_encrypted_data);

		return true;
    }

    data                urls_data;
    data                msg_data;
    puzzle              puz;
    data                encrypted_data;

    std::vector<urlkey> vurlkey;
    data                data_temp;
    data                data_temp_next;

    std::string filename_urls;
    std::string filename_msg_data;
    std::string filename_puzzle;
    std::string filename_partial_puzzle;
    std::string filename_encrypted_data;
};

class decryptor
{
public:
	decryptor(	std::string ifilename_partial_puzzle,
                std::string ifilename_puzzle,
                std::string ifilename_encrypted_data,
			 	std::string ifilename_decrypted_data)
	{
        filename_partial_puzzle = ifilename_partial_puzzle;
        filename_puzzle = ifilename_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;
        filename_decrypted_data = ifilename_decrypted_data;
	}

    ~decryptor()
    {
    }

    bool read_urlinfo(Buffer& temp, urlkey& out_uk)
	{
		bool r = true;
        uint32_t pos = 0;

		out_uk.url_size = temp.readUInt16(pos); pos+=2;
		std::cout << "read_urlinfo out_uk.url_size " << out_uk.url_size << " "<< std::endl;

		for( int16_t j = 0; j< out_uk.url_size; j++) out_uk.url[j] = temp.getdata()[pos+j];
        for( int16_t j = out_uk.url_size; j< URL_MAX_SIZE; j++) out_uk.url[j] = 0;
        pos += URL_MAX_SIZE;

        for( int16_t j = 0; j< 4; j++)
        {
            out_uk.magic[j] = temp.getdata()[pos+j];
            std::cout << "out_uk.magic[j] " << out_uk.magic[j]<< std::endl;
        }
        pos += 4;

		out_uk.key_fromH = temp.readUInt16(pos); pos+=2;
		out_uk.key_fromL = temp.readUInt16(pos); pos+=2;
		out_uk.key_size = temp.readUInt16(pos);  pos+=2;

		std::cout << "out_uk.key_fromH " << out_uk.key_fromH << " ";
		std::cout << "out_uk.key_fromL " << out_uk.key_fromL << std::endl;
		int32_t v = out_uk.key_fromH * BASE + out_uk.key_fromL;

		std::cout << "out_uk.key_from " << v << " ";
		std::cout << "out_uk.key_size " << out_uk.key_size << std::endl;

		 // zero
        for( int16_t j = 0; j< KEY_SIZE; j++) out_uk.key[j] = 0;
        pos += KEY_SIZE;

		for( int16_t j = 0; j< CHKSUM_SIZE; j++)
		{
            out_uk.checksum[j] = temp.getdata()[pos+j];
            //std::cout << out_uk.checksum[j];
        }
        //std::cout << std::endl;
        pos += CHKSUM_SIZE;

		return r;
	}

	bool get_key(urlkey& uk)
	{
		bool r = true;
		std::string file = "./Staging/url_file.dat";
		std::remove(file.data());

        if ( (uk.url_size < URL_MIN_SIZE) || (uk.url_size > URL_MAX_SIZE))
        {
            std::cerr << "ERROR " << "Invalid web url size" << std::endl;
            r = false;
        }

		// DOWNLOAD URL FILE
		if (r)
		{
            char u[URL_MAX_SIZE+1] = {0};
            for( int16_t j = 0; j< URL_MAX_SIZE; j++)
                u[j] = uk.url[j];

            std::cout << "URL " << u << std::endl;
            if (wget(u, file.data()) != 0)
            {
                std::cerr << "ERROR " << "Unable to read web url contents" << std::endl;
                r = false;
            }
		}

		if (r)
		{
			data d;
			r = d.read_from_file(file);

			if (r)
			{
                uint32_t pos = uk.key_fromH * BASE + uk.key_fromL ;
                size_t  key_size = uk.key_size;

                std::cout << "pos " << pos << " ";
                std::cout << "key_size " << key_size << std::endl;

                if (pos >= d.buffer.size() - key_size)
                {
                    std::cerr << "ERROR " << "Invalid web file size" << std::endl;
                    r = false;
                }

                if (r && (key_size <= KEY_SIZE))
                {
                    for( size_t j = 0; j< key_size; j++)
                    {
                        uk.key[j] = d.buffer.getdata()[pos+j];
                        std::cout << (int)(unsigned char)uk.key[j]<< "  ";
                    }
                    for( size_t j = key_size; j < KEY_SIZE; j++)
                    {
    					uk.key[j] = j % 7;
    					std::cout << (int)(unsigned char)uk.key[j]<< "  ";
                    }
                    std::cout << std::endl;

                    std::string checksum;
                    {
                        SHA256 sha;
                        sha.update(reinterpret_cast<const uint8_t*> (d.buffer.getdata()), d.buffer.size() );
                        uint8_t* digest = sha.digest();
                        checksum = SHA256::toString(digest);
                        std::cout << "Decryption checksum " << checksum << std::endl;
                        delete[] digest;
                    }

                    char c;
//                    for( size_t j = 0; j< CHKSUM_SIZE; j++)
//                    {
//                        c = uk.checksum[j];
//                        //std::cout << c;
//                    }
//                    std::cout << std::endl;

                    for( size_t j = 0; j< CHKSUM_SIZE; j++)
                    {
                        c = checksum.at(j);
                        if (c != uk.checksum[j])
                        {
                            std::cerr << "ERROR " << "Invalid web file checksum " << j << std::endl;
                            r = false;
                            break;
                        }
                    }
                }
                else
                {
                    std::cerr << "ERROR " << "Invalid web key size" << std::endl;
                    r = false;
                }
            }
            else
            {
                std::cerr << "ERROR " << "Unable to read downloaded url contents " << file <<std::endl;
                r = false;
            }
		}

		std::remove(file.data());
		return r;
	}

	bool decode(size_t iter, data& data_encrypted, const char* key, uint32_t key_size, data& data_decrypted)
	{
        iter = iter;
        bool r = true;
		char c;

        // BINARY DES (double file size on encryption, divide in 2 on decryption)
		uint32_t nblock = data_encrypted.buffer.size() / 8;
		uint32_t nkeys  = key_size / 4;

        // BINARY DES
        //      DES(const char KEY[4]);
        //      std::string encrypt_bin(const char* data, int data_size=4);
        //      void decrypt_bin(const std::string& DATA, char* out, int out_size=4);

		char KEY[4];
		std::string DATA;
        char data_decr[4];

		uint32_t key_idx = 0;
		for(size_t blocki = 0; blocki < nblock; blocki++)
		{
            DATA.clear();
            for(size_t j = 0; j < 8; j++)
            {
                c = data_encrypted.buffer.getdata()[8*blocki + j];
                DATA += c;
            }

            for(size_t j = 0; j < 4; j++)
            {
                c = key[4*key_idx + j];
                KEY[j] = c;
            }
            key_idx++;
            if (key_idx >= nkeys) key_idx=0;

            DES des(KEY);
            des.decrypt_bin(DATA, data_decr, 4);
            data_decrypted.buffer.write(&data_decr[0], 4, -1); // 8 bytes to 4 bytes!
        }

        return r;
	}


    bool decrypt()
	{
		bool r = true;
		Buffer puz_key(PUZZLE_SIZE_LIM);

		if (r)
		{
			if (puz.read_from_file(filename_puzzle, false) == false)
			{
                std::cerr << "ERROR " << "(puz.read_from_file(filename_puzzle) == false)" << std::endl;
				r = false;
			}
		}

		if (r)
		{
			if (puz.is_all_answered() == false)
			{
                std::cerr << "ERROR " << "(puz.is_all_answered() == false)" << std::endl;
				r = false;
			}
		}

		if (r)
		{
			puz.make_key(puz_key);
			if (puz_key.size() == 0)
			{
                std::cerr << "ERROR " << "(puz_key.size() == 0)" << std::endl;
				r = false;
			}
		}

		if (r)
		{
            if (encrypted_data.read_from_file(filename_encrypted_data) == false)
			{
                std::cerr << "ERROR " << "encrypted_data.read_from_file(filename_encrypted_data) == false)" << std::endl;
				r = false;
			}
		}

		// decode(DataFinal, pwd0) => DataN+urlkeyN+NITER  urlkeyN=>keyN
        if (r)
		{
            data_temp_next.clear_data();
            if (decode(0, encrypted_data, puz_key.getdata(), puz_key.size(), data_temp_next) == false)
            {
                std::cerr << "ERROR " << "(decode(0, encrypted_data, puz_key.getdata(), puz_key.size(), data_temp_next) == false)" << std::endl;
                r = false;
            }
        }

		// N+1 = Number of iterations in the last 2 byte! +PADDING_MULTIPLE-2
		int16_t NITER = 0;
        if (r)
		{
            size_t file_size = data_temp_next.buffer.size();
            if (file_size >= PADDING_MULTIPLE)
            {
                NITER = data_temp_next.buffer.readUInt16(file_size-2);
                NITER = NITER - 1;
                if (NITER < 0)
                    r = false;
                else if (NITER > NITER_LIM)
                    r = false;

                if (r==false)
                {
                    std::cerr << "ERROR " << "encrypted_data can not be decoded - invalid iteration value" << std::endl;
                }
            }
            else
            {
                std::cerr << "ERROR " << "encrypted_data can not be decoded  - invalid file size" << std::endl;
                r = false;
            }
		}

		if (NITER == 0)
        {
            // remove last PADDING_MULTIPLE char
            data_temp_next.buffer.remove_last_n_char(PADDING_MULTIPLE);

            data_temp.buffer.swap_with(data_temp_next.buffer);
            data_temp_next.erase();
        }
        else
        {
            urlkey uk;
            if (r)
            {
                if (NITER > 0)
                {
                    size_t buffer_size = data_temp_next.buffer.size();

                    // Get urlkeyN
                    if (buffer_size >= URLINFO_SIZE + PADDING_MULTIPLE) // last PADDING_MULTIPLE is NITER+1
                    {
                        // Inverse of data_temp.append(&vurlkey[vurlkey.size()-1].urlinfo_with_padding[0], URLINFO_SIZE);
                        Buffer temp(URLINFO_SIZE + PADDING_MULTIPLE);
                        data_temp_next.get_last(URLINFO_SIZE + PADDING_MULTIPLE, temp);

                        if (read_urlinfo(temp, uk) == false)
                        {
                            std::cerr << "ERROR " << "encrypted_data can not be decoded  - invalid urlinfo" << std::endl;
                            r = false;
                        }

                        if (r)
                        {
                            data_temp_next.buffer.remove_last_n_char(URLINFO_SIZE + PADDING_MULTIPLE);
                        }
                    }
                    else
                    {
                        std::cerr << "ERROR " << "encrypted_data can not be decoded  - invalid urlinfo size" << std::endl;
                        r = false;
                    }
                }
            }

            if (r)
            {
                data_temp.buffer.swap_with(data_temp_next.buffer);
                data_temp_next.erase();

                // decode(DataFinal, pwd0) => DataN+urlkeyN         urlkeyN=>keyN
                // decode(DataN,     keyN) => DataN-1+urlkeyN-1     urlkeyN-1=>keyN-1
                // ...
                // decode(Data2, key2) => Data1+urlkey1             urlkey1=>key1
                // decode(Data1, key1) => Data
                for(int16_t iter=0; iter<NITER; iter++)
                {
                    // Get KeyN from uk info read from the web
                    r = get_key(uk);
                    if (r==false)
                    {
                        break;
                    }

                    // decode(DataN, keyN) => DataN-1+urlkeyN-1     urlkeyN-1=>keyN-1
                    if (decode(iter, data_temp, &uk.key[0], KEY_SIZE, data_temp_next) == false)
                    {
                        r = false;
                        std::cerr << "ERROR " << "encrypted_data can not be decoded" << std::endl;
                        break;
                    }

                    size_t buffer_size = data_temp_next.buffer.size();

                    // Get urlkeyN
                    if (iter < NITER - 1)
                    {
                        if (buffer_size >= URLINFO_SIZE)
                        {
                            // Inverse of data_temp.append(&vurlkey[vurlkey.size()-1].urlinfo_with_padding[0], URLINFO_SIZE);
                            Buffer temp(URLINFO_SIZE);
                            data_temp_next.get_last(URLINFO_SIZE, temp);

                            if (read_urlinfo(temp, uk) == false)
                            {
                                r = false;
                                std::cerr << "ERROR " << "encrypted_data can not be decoded - can not read urlinfo" << std::endl;
                                break;
                            }

                            if (r)
                            {
                                data_temp_next.buffer.remove_last_n_char(URLINFO_SIZE);
                            }
                        }
                        else
                        {
                            r = false;
                            std::cerr << "ERROR " << "encrypted_data can not be decoded - invalid urlinfo size" << std::endl;
                            break;
                        }
                    }

                    data_temp.buffer.swap_with(data_temp_next.buffer);
                    data_temp_next.erase();
                }
            }
		}

		if (r)
		{
            // data_temp_next => decrypted_data
            r = data_temp.copy_buffer_to(decrypted_data);
            if (r)
            {
                r = decrypted_data.save_to_file(filename_decrypted_data);
                if(r==false)
                {
                    std::cerr << "ERROR " << "FAILED in decrypted_data.save_to_file(filename_decrypted_data);" << std::endl;
                }
            }
            else
            {
                std::cerr << "ERROR " << "FAILED in data_temp.copy_buffer_to(decrypted_data);" << std::endl;
            }
		}

		return r;
	}

	puzzle      puz;
    data        encrypted_data;
    data        decrypted_data;

	std::string filename_partial_puzzle;
	std::string filename_puzzle;
    std::string filename_encrypted_data;
	std::string filename_decrypted_data;

    data        data_temp;
    data        data_temp_next;
};

void DOTESTCASE(std::string TEST, bool disable_netw = false, std::string file_msg = "/msg.txt")
{
    std::string TESTCASE = "testcase";
    std::string file_url            = "/urls.txt";
    std::string file_partial_puzzle = "/partial_puzzle.txt";
    std::string file_msg_encrypted  = "/msg_encrypted.dat";
    std::string file_puzzle         = "/puzzle.txt";
    std::string file_msg_decrypted  = "/msg_decrypted.dat";

    {
        std::string file = "./"+TESTCASE+"/"+TEST+file_partial_puzzle;
		std::remove(file.data());

		file = "./"+TESTCASE+"/"+TEST+file_msg_encrypted;
		std::remove(file.data());

        encryptor encr("./"+TESTCASE+"/"+TEST+file_url,
                       "./"+TESTCASE+"/"+TEST+file_msg,
                       "./"+TESTCASE+"/"+TEST+file_puzzle,
                       "./"+TESTCASE+"/"+TEST+file_partial_puzzle,
                       "./"+TESTCASE+"/"+TEST+file_msg_encrypted);

        if (encr.encrypt(disable_netw) == true)
        {
            decryptor decr( encr.filename_partial_puzzle,
                            encr.filename_puzzle,
                            encr.filename_encrypted_data,
                            "./"+TESTCASE+"/"+TEST+file_msg_decrypted
                          );

            if (decr.decrypt() == true)
            {
                if( is_file_same(encr.filename_msg_data, decr.filename_decrypted_data) == false)
                {
                    std::cout << ""+TESTCASE+" "+TEST+" - ERROR encrypt/decrypt failed " << std::endl;
                }
                else
                {
                    std::cout << "SUCCESS "+TESTCASE+" "+TEST+"" << std::endl;
                }
            }
            else
            {
                std::cout << ""+TESTCASE+" "+TEST+" - ERROR decrypt() " << std::endl;
            }
        }
        else
        {
            std::cout << ""+TESTCASE+" "+TEST+" - ERROR encrypt() " << std::endl;
        }
    }
    std::cout << std::endl;
}

int main()
{
    // TEST makehex() <=> hextobin()
    if (false)
    {
        std::cout << "bin 255 to hex2 " << makehex((char)255, 2) << std::endl;
        std::cout << "bin 128 to hex2 " << makehex((char)128, 2) << std::endl;
        std::cout << "bin 0 to hex2 "   << makehex((char)0  , 2) << std::endl;
        std::cout << "bin 256*10+5 to hex4 "   << makehex((uint32_t)2565  , 4) << std::endl;

        std::cout << "hex2 " << makehex((char)255, 2) << " to uint8_t " << (int)hextobin(makehex((char)255, 2), uint8_t(0)) << std::endl;
        std::cout << "hex4 " << makehex((uint32_t)2565  , 4) << " to uint32_t " << (int)hextobin(makehex((uint32_t)2565  , 4), uint32_t(0)) << std::endl;
    }

    // TEST CLASSIC STRING DES
    if (false)
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
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
        else
        {
            std::cout << "OK with DES algo "
            << "\nkey " << KEY
            << "\ndata " << data
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
    }

    // TEST BINARYE DES
    if (false)
    {
        char bin[4] = {12, 0, 34, 0}; // bin 4 => string 8
        char dat[4] = {33, 5, 12, 0}; // bin 4 => string 8
        char out_dat[4];

        DES des(bin);
        std::string data_encr = des.encrypt_bin(dat, 4);
        des.decrypt_bin(data_encr, out_dat, 4);

        std::string data_back  = "{";
        for(size_t i=0;i<4;i++)
        {
            data_back+=std::to_string((int)out_dat[i]);
            data_back+=",";
        }
        data_back += "}";

        bool ok = true;
        for(size_t i=0;i<4;i++)
        {
            if (dat[i] != out_dat[i])
            {
                std::cout << "Error with DES binary algo"
                //<< "\nkey " << KEY
                << "\ndata {33, 5, 12, 0}"
                //<< "\ndata_encr " << data_encr
                << "\ndata_back " << data_back
                << std::endl;
                ok = false;
                break;
            }
        }
        if (ok)
        {
            std::cout << "OK with DES binary algo "
            //<< "\nkey " << KEY
            << "\ndata {33, 5, 12, 0}"
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
    }

    // TEST wget
    if (false)
    {
        std::string url = "https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz";
        std::string filename  = "./Staging/Python-3.8.1.tgz";

        if ( wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            std::cout << "OK with wget " << std::endl;
        }
    }
    //https://ln5.sync.com/dl/7259131b0/twwrxp25-j6j6viw3-5a99vmwn-rv43m9e6
    if (false)
    {
        //Sync public TerrePlane (Flat earth) img.pgn
        //std::string url = "https://ln5.sync.com/dl/7259131b0/twwrxp25-j6j6viw3-5a99vmwn-rv43m9e6";
        //std::string url = "https://cp.sync.com/9a4886a8-b1b3-4a2c-a3c7-4b0c01d76486";
        //std::string url = "https://cp.sync.com/file/1342219113/view/image";
        //std::string url = "https://u.pcloud.link/publink/show?code=XZH2QgVZC4KuzbwhtBmqrvCrpMQhTzAkOd2V";
        //"downloadlink": " // EXPIRED
        std::string url = "https://c326.pcloud.com/dHZTgqwh1ZJ8HkagZZZQaV0o7Z2ZZLH4ZkZH2QgVZ91trCtkdpvFP5vxOxY8VcyStULb7/Screenshot%20from%202021-06-16%2014-28-40.png";
        //"https:\/\/c326.pcloud.com\/dHZTgqwh1ZJ8HkagZZZQaV0o7Z2ZZLH4ZkZH2QgVZ91trCtkdpvFP5vxOxY8VcyStULb7\/Screenshot%20from%202021-06-16%2014-28-40.png"
        std::string filename  = "./Staging/img.png";

        if ( wget(url.data(), filename.data()) != 0)
        {
            std::cout << "An error occured wget " << std::endl;
        }
        else
        {
            std::cout << "OK with wget " << std::endl;
        }
    }

    // TESTCASE nowebkey
    if (false)
    {
        DOTESTCASE("nowebkey", true);
    }

    // TESTCASE onewebkey
    if (false)
    {
        DOTESTCASE("onewebkey", false);
    }

    // TESTCASE manywebkey
    if (false)
    {
        DOTESTCASE("manywebkey", false);
    }

    //int a; std::cin >> a;

    // TESTCASE
    if (true)
    {
        DOTESTCASE("zipcontent", false, "/test.zip");
    }

//    std::cout << "done enter a number to exit " << std::endl;
//    int a; std::cin >> a;
    return 0;
}
