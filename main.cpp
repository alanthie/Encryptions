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

constexpr static int KEY_SIZE       = 64;
constexpr static int CHKSUM_SIZE    = 64;
constexpr static int URLINFO_SIZE   = 256+CHKSUM_SIZE+KEY_SIZE+4+2+2+8; // padding 16x
constexpr static size_t PADDING_MULTIPLE = 16;
constexpr static int16_t NITER_LIM = 100;

class data
{
public:
    data() {}
    ~data() {}

    virtual bool read_from_file(std::string filename)
    {
        std::ifstream ifd(filename.data(), std::ios::binary | std::ios::ate);
        if (ifd)
        {
            uint32_t sz = ifd.tellg();
            if (this->allocsize() < sz) realloc(sz+1);

            ifd.seekg(0, std::ios::beg);
            int32_t r = buffer.read(ifd, sz, 0);
            if (r==-1)
            {
                ifd.close();
                return false;
            }
            if (r!=(int32_t)sz)
            {
                ifd.close();
                return false;
            }
            ifd.close();
            return true;
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
                ofd.close();
                return false;
            }
            if (r!=(int32_t)buffer.size())
            {
                ofd.close();
                return false;
            }
            ofd.close();
            return true;
        }
        return false;
    }

    void append(char* p, uint32_t n) {buffer.write(p, n, -1);}
    void append(const char* p, uint32_t n) {buffer.write(p, n, -1);}

	uint32_t get_first(size_t n, Buffer& rout)
	{
        if (buffer.size() < n) return -1;
        rout.erase();
        rout.write(buffer.getdata(), n, 0);
        return n;
	}
	uint32_t get_last(size_t n, Buffer& rout)
	{
        if (buffer.size() < n) return -1;
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

    void clear_data() {buffer.clear();}
    void erase() {buffer.erase();}
    void realloc(uint32_t sz){buffer.realloc(sz);}
    uint32_t allocsize() {return buffer.allocsize();}

    Buffer buffer;
};


class puzzle : public data
{
public:
    struct QA
    {
        std::string Q;
        std::string A;
    };

    puzzle() {}

    bool make_partial() {return true;}
    bool is_all_answered() {return true;}

    bool read_from_file(std::string filename) override
    {
        return data::read_from_file(filename);
    }
    bool save_to_file(std::string filename) override
    {
        return data::save_to_file(filename);
    }
    //"What is yout name?": "AxxxN"
    //"What is Q(23)?": "3xxxxxxx8"

    void make_key(Buffer& rout)
    {
        size_t r = buffer.size() % PADDING_MULTIPLE;
        //rout.realloc(buffer.size() + r);
        rout.write(buffer.getdata(), buffer.size(), 0);

        char c[1] = {'0'};
        for(size_t i = 0; i < PADDING_MULTIPLE - r; i++)
        {
            // padding
            rout.write(c, 1, -1);
        }

    }

    std::vector<QA> vQA;
};

class urlkey
{
public:
    urlkey() {}

    int16_t url_size = 0;           // 2
    std::string url;                // 256
    int32_t key_from = 0;           // 2 random offset
    int16_t key_size = KEY_SIZE;    // 2
    std::string checksum;           // 64
    char key[KEY_SIZE] = {0};       // 64

    char urlinfo_with_padding[URLINFO_SIZE] = {0};
};

class encryptor
{
public:

    encryptor(  std::string ifilename_urls,
                std::string ifilename_msg_data,
                std::string ifilename_puzzle,
                std::string ifilename_encrypted_data
        )
    {
        filename_urls = ifilename_urls;
        filename_msg_data = ifilename_msg_data;
        filename_puzzle = ifilename_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;
    }

    ~encryptor()
    {
        // remove temp
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
                    if ((url.size() > 0) && (url.size() < 256))
                    {
                        urlkey uk;
                        uk.url = url;
                        uk.url_size = url.size();
                        vurlkey.push_back(uk);
                    }
                    else
                    {
                    }
                    s.clear();
                }
                else
                {
                    if (urls_data.buffer.getdata()[i]!=0) s+=urls_data.buffer.getdata()[i];
                    else {}
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
		if (wget(vurlkey[i].url.data(), file.data()) != 0)
		{
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
					int32_t pos = rd.get_rand() * (d.buffer.size() - KEY_SIZE);
					vurlkey[i].key_from = pos;
					for( size_t j = 0; j< KEY_SIZE; j++)
						vurlkey[i].key[j] = d.buffer.getdata()[pos+j];
				}
				else
				{
					for( size_t j = 0; j< d.buffer.size(); j++)
						vurlkey[i].key[j] = d.buffer.getdata()[j];
					for( size_t j = d.buffer.size(); j< KEY_SIZE; j++)
						vurlkey[i].key[j] = j % 7;
				}

				// vurlkey[i].checksum
                {
                    SHA256 sha;
                    sha.update(reinterpret_cast<const uint8_t*> (d.buffer.getdata()), d.buffer.size() );
                    uint8_t* digest = sha.digest();
                    vurlkey[i].checksum = SHA256::toString(digest);
                    std::cout << SHA256::toString(digest) << " " << vurlkey[i].checksum.size() << std::endl;
                    delete[] digest;
                }
            }
		}

		std::remove(file.data());
		return r;
	}

    bool make_urlinfo_with_padding(size_t i, Buffer& puzzle_key)
	{
		bool r = true;

		Buffer temp(URLINFO_SIZE+1);
		temp.init(0);
		temp.writeInt16(vurlkey[i].url_size, -1);
		temp.write(vurlkey[i].url.data(), vurlkey[i].url.size(), -1);
		temp.writeInt32(vurlkey[i].key_from, -1);
		temp.writeInt16(vurlkey[i].key_size, -1);
		temp.write(vurlkey[i].checksum.data(), vurlkey[i].checksum.size(), -1);
		temp.write(vurlkey[i].key, KEY_SIZE, -1);

		for( size_t j = 0; j< URLINFO_SIZE; j++)
            vurlkey[i].urlinfo_with_padding[j] = temp.getdata()[j];

		return r;
	}


    // select various encoding algos
    bool encode(size_t iter, data& data_temp, const char* key, uint32_t key_size, data& data_temp_next)
	{
		bool r = true;
		char c;

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

    bool encrypt()
    {
        if (read_file_urls(filename_urls) == false)
        {
            std::cerr << "ERROR " << "read_file_urls" << std::endl;
            return false;
        }
        if (vurlkey.size() == 0)
        {
            std::cerr << "ERROR " << "(vurlkey.size() == 0)" << std::endl;
            return false;
        }

        if (puz.read_from_file(filename_puzzle) == false)
        {
            std::cerr << "ERROR " << "puz.read_from_file" << std::endl;
            return false;
        }
        if (puz.buffer.size() == 0)
        {
            std::cerr << "ERROR " << "(puz.buffer.size() == 0)" << std::endl;
            return false;
        }

        Buffer puz_key(10000);
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
        if (puz.save_to_file("./Staging/puz_partial.txt") == false)
        {
            std::cerr << "ERROR " << "puz.save_to_file(Staging/puz_partial.txt) == false)" << std::endl;
            return false;
        }

        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (make_urlkey_from_url(i) == false)
            {
                std::cerr << "ERROR " << "(make_key_from_url(i) == false) == false)" << std::endl;
                return false;
            }
            if (make_urlinfo_with_padding(i, puz_key) == false)
            {
                std::cerr << "ERROR " << "(make_urlinfo_with_padding(i, puz_key) == false)" << std::endl;
                return false;
            }
        }

		// encode(Data,          key1) => Data1             // urlkey1=>key1
        // encode(Data1+urlkey1, key2) => Data2
        // encode(Data2+urlkey2, key3) => Data3
        // ...
        // encode(DataN-1+urlkeyN-1, keyN) => DataN
        // encode(DataN+urlkeyN,     pwd0) => DataFinal
        //
        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (i==0)
            {
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

        // Number of iterations in the last 2 byte!
        Buffer temp(2+1);
		temp.init(0);
		temp.writeInt16(vurlkey.size() + 1, -1);
        data_temp.append(temp.getdata(), 2);

        // encode(DataN+urlkeyN, pwd0) => DataFinal
        encode(vurlkey.size(), data_temp, puz_key.getdata(), puz_key.size(), data_temp_next);

        data_temp_next.copy_buffer_to(encrypted_data);
        encrypted_data.save_to_file(filename_encrypted_data);

		return true;
    }

    std::vector<urlkey> vurlkey;
    data                urls_data;
    data                msg_data;
    puzzle              puz;
    data                encrypted_data;

    data                data_temp;
    data                data_temp_next;

    std::string filename_urls;
    std::string filename_msg_data;
    std::string filename_puzzle;
    std::string filename_encrypted_data;
};

class decryptor
{
public:
	decryptor(	std::string ifilename_puzzle,
                std::string ifilename_encrypted_data,
			 	std::string ifilename_decrypted_data)
	{
	}

    ~decryptor()
    {
    }

    bool read_urlinfo(Buffer& temp, urlkey& out_uk)
	{
		bool r = true;
        uint32_t pos = 0;

		out_uk.url_size = temp.readInt16(pos); pos+=2;

		out_uk.url.clear();
		for( size_t j = 0; j< out_uk.url_size; j++)
            out_uk.url += temp.getdata()[pos+j];
        pos += out_uk.url_size;

		out_uk.key_from = temp.readInt32(pos); pos+=4;
		out_uk.key_size = temp.readInt16(pos); pos+=2;

		for( size_t j = 0; j< CHKSUM_SIZE; j++)
            out_uk.checksum[j] = temp.getdata()[pos+j];
        pos += CHKSUM_SIZE;

        // zero
        for( size_t j = 0; j< KEY_SIZE; j++)
            out_uk.key[j] = 0;
        pos += KEY_SIZE;

		return r;
	}

	bool get_key(urlkey& uk)
	{
		bool r = true;
		std::string file = "./Staging/url_file.dat";

		std::remove(file.data());

		// DOWNLOAD URL FILE
		if (wget(uk.url.data(), file.data()) != 0)
		{
            std::cerr << "ERROR " << "Invalid web url" << std::endl;
            r = false;
		}

		if (r)
		{
			data d;
			r = d.read_from_file(file);
			if (r)
			{
                uint32_t pos = uk.key_from;
                size_t   key_size = uk.key_size;

                if (pos >= d.buffer.size() - key_size)
                {
                    std::cerr << "ERROR " << "Invalid web file size" << std::endl;
                    r = false;
                }

                if (r && (key_size <= KEY_SIZE))
                {
                    for( size_t j = 0; j< key_size; j++)
                        uk.key[j] = d.buffer.getdata()[pos+j];
                    for( size_t j = key_size; j < KEY_SIZE; j++)
    					uk.key[j] = j % 7;

                    std::string checksum;
                    {
                        SHA256 sha;
                        sha.update(reinterpret_cast<const uint8_t*> (d.buffer.getdata()), d.buffer.size() );
                        uint8_t* digest = sha.digest();
                        checksum = SHA256::toString(digest);
                        std::cout << checksum << " " << checksum.size() << std::endl;
                        delete[] digest;
                    }

                    if (checksum != uk.checksum)
                    {
                        std::cerr << "ERROR " << "Invalid web file checksum" << std::endl;
                        r = false;
                    }
                }
                else
                {
                    std::cerr << "ERROR " << "Invalid web key size" << std::endl;
                    r = false;
                }
            }
		}

		std::remove(file.data());
		return r;
	}

	bool decode(size_t iter, data& data_encrypted, const char* key, uint32_t key_size, data& data_decrypted)
	{
        bool r = true;

        return r;
	}


    bool decrypt()
	{
		bool r = true;
		Buffer puz_key(10000);

		if (r)
		{
			if (puz.read_from_file(filename_puzzle) == false)
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

		// decode(DataFinal, pwd0) => DataN+urlkeyN  urlkeyN=>keyN
        if (r)
		{
            data_temp_next.clear_data();
            decode(0, encrypted_data, puz_key.getdata(), puz_key.size(), data_temp_next);
        }

		// N+1 = Number of iterations in the last 2 byte!
		int16_t NITER = 0;
        if (r)
		{
            size_t file_size = data_temp_next.buffer.size();
            if (file_size >= 2)
            {
                NITER = data_temp_next.buffer.readInt16(file_size-2);
                NITER = NITER - 1;
                if (NITER < 0) r = false;
                else if (NITER > NITER_LIM) r = false;

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

		urlkey uk;
		if (r)
        {
            size_t buffer_size = data_temp_next.buffer.size();

            // Get urlkeyN
            if (buffer_size >= URLINFO_SIZE + 2) // last 2 is NITER+1
            {
                // Inverse of data_temp.append(&vurlkey[vurlkey.size()-1].urlinfo_with_padding[0], URLINFO_SIZE);
                Buffer temp(URLINFO_SIZE + 2);
                data_temp_next.get_last(URLINFO_SIZE + 2, temp);

                if (read_urlinfo(temp, uk) == false)
                {
                    std::cerr << "ERROR " << "encrypted_data can not be decoded  - invalid urlinfo" << std::endl;
                    r = false;
                }
            }
            else
            {
                std::cerr << "ERROR " << "encrypted_data can not be decoded  - invalid urlinfo size" << std::endl;
                r = false;
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
                // Get KeyN from uk info in the web
                r = get_key(uk);
                if (r==false)
                {
                    break;
                }

                // decode(DataN, keyN) => DataN-1+urlkeyN-1     urlkeyN-1=>keyN-1
                if (decode(iter, encrypted_data, &uk.key[0], KEY_SIZE, data_temp_next) == false)
                {
                    r = false;
                    std::cerr << "ERROR " << "encrypted_data can not be decoded" << std::endl;
                    break;
                }

                size_t buffer_size = data_temp_next.buffer.size();

                // Get urlkeyN
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
                }
                else
                {
                    r = false;
                    std::cerr << "ERROR " << "encrypted_data can not be decoded - invalid urlinfo size" << std::endl;
                    break;
                }

                data_temp.buffer.swap_with(data_temp_next.buffer);
                data_temp_next.erase();
            }
		}
		return r;
	}

	puzzle      puz;
    data        encrypted_data;
    data        decrypted_data;

	std::string filename_puzzle;
    std::string filename_encrypted_data;
	std::string filename_decrypted_data;

    data        data_temp;
    data        data_temp_next;
};


int main()
{
    std::cout << "bin 255 to hex2 " << makehex((char)255, 2) << std::endl;
    std::cout << "bin 128 to hex2 " << makehex((char)128, 2) << std::endl;
    std::cout << "bin 0 to hex2 "   << makehex((char)0  , 2) << std::endl;
    std::cout << "bin 256*10+5 to hex4 "   << makehex((uint32_t)2565  , 4) << std::endl;

    std::cout << "hex2 " << makehex((char)255, 2) << " to uint8_t " << (int)hextobin(makehex((char)255, 2), uint8_t(0)) << std::endl;
    std::cout << "hex4 " << makehex((uint32_t)2565  , 4) << " to uint32_t " << (int)hextobin(makehex((uint32_t)2565  , 4), uint32_t(0)) << std::endl;


    std::string KEY  = "EWTW;RLd"; // 8 bytes l peut exister 2e56 (soit 7.2*10e16) clés différentes !
    std::string data = "65431234"; // 8 bytes

    {
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


    // BINARYE DES
    {
        char bin[4] = {12, 0, 34, 0}; // bin 4 => string 8
        char dat[4] = {33, 5, 12, 0}; // bin 4 => string 8
        char out_dat[4];
//        KEY.clear();  for(size_t i=0;i<4;i++) KEY +=makehex(bin[i], 2);
//        data.clear(); for(size_t i=0;i<4;i++) data+=makehex(dat[i], 2);

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
                << "\nkey " << KEY
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
            << "\nkey " << KEY
            << "\ndata {33, 5, 12, 0}"
            //<< "\ndata_encr " << data_encr
            << "\ndata_back " << data_back
            << std::endl;
        }
    }
    //return 0;

    std::string url = "https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz";
    std::string filename  = "./Staging/Python-3.8.1.tgz";

    if ( wget(url.data(), filename.data()) != 0)
    {
        printf("An error occured wget !\n");
    }
    else
    {
        std::cout << "OK with wget " << std::endl;
    }


	encryptor test("./Staging/urls.txt",
				   "./Staging/msg.txt",
				   "./Staging/puzzle.txt",
				   "./Staging/msg_encrypted.dat");
	test.encrypt();

    std::cout << "done " << std::endl;
    int a; std::cin >> a;
    return 0;
}
