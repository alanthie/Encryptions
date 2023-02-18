#ifndef _INCLUDES_encryptor
#define _INCLUDES_encryptor

#include <iostream>
#include <fstream>
#include "Encryptions/DES.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "crypto_const.hpp"
#include "data.hpp"
#include "puzzle.hpp"

class encryptor
{
public:

    encryptor(  std::string ifilename_urls,
                std::string ifilename_msg_data,
                std::string ifilename_puzzle,
                std::string ifilename_partial_puzzle,
                std::string ifilename_encrypted_data,
                bool verb = false
        )
    {
        filename_urls = ifilename_urls;
        filename_msg_data = ifilename_msg_data;
        filename_puzzle = ifilename_puzzle;
        filename_partial_puzzle = ifilename_partial_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;
        verbose = verb;
    }

    ~encryptor()
    {
    }

    bool read_file_urls(std::string filename)
    {
        char c;
        bool r = true;
        r = urls_data.read_from_file(filename);

        std::string s;
        char url[URL_MAX_SIZE+1] = { 0 };
        int pos = -1;

        if (r)
        {
            for(size_t i=0;i<urls_data.buffer.size();i++)
            {
                // parse url
                c = urls_data.buffer.getdata()[i];
                //std::cout << (int)(unsigned char)c << " ";
                pos++;

                if (c == '\n')
                {
                    //std::cout << std::endl;
#ifdef _WIN32
                    int len = pos - 1; // rn
#else
                    int16_t len = pos;   // n
#endif
                    if ((len >= URL_MIN_SIZE) && (len <= URL_MAX_SIZE))
                    {
                        urlkey uk;
                        for(int16_t ii=0;ii<URL_MAX_SIZE;ii++) uk.url[ii] = 0;
                        for (int16_t ii = 0; ii < len; ii++)
                        {
                            uk.url[ii] = url[ii];
                        }

                        uk.url_size = len;
                        vurlkey.push_back(uk);
                    }
                    else
                    {
                        // skip!
                        //std::string s(url);
                        if (len > 0)
                        {
                            std::cerr << "WARNING url skipped, " << "(url.size() >= URL_MIN_SIZE) && (url.size() <= URL_MAX_SIZE)) " << len <<std::endl;
                        }
                    }
                    s.clear();
                    pos = -1;
                    //std::cout << std::endl;
                }
                else
                {
                    if ((c!=0) && (c!='\r') && (c!='\n'))
                    {
                        url[pos] = c;
                    }
                }
            }
        }
        return r;
    }

    bool make_urlkey_from_url(size_t i)
	{
		bool r = true;

        std::string file = "./staging_url_file.dat";
        if (fileexists(file))
		    std::remove(file.data());

		// DOWNLOAD URL FILE
		bool is_video = false;
		if (vurlkey[i].url[0]=='[')
		{
            if (vurlkey[i].url[1]=='v')
            {
                is_video = true;
            }
		}

		int pos_url = 0;
		if (is_video) pos_url = 3;
        int rc = 0;

        std::string s(&vurlkey[i].url[pos_url]);
        if (is_video)
        {
            rc = getvideo(s.data(), file.data(), "", verbose);
            if (rc!= 0)
            {
                std::cerr << "ERROR with getvideo using youtube-dl, error code: " << rc << " url: " << s <<  " file: " << file << std::endl;
                r = false;
            }
        }
        else
        {
            rc = wget(s.data(), file.data(), verbose);
            if (rc!= 0)
            {
                std::cerr << "ERROR with wget, error code: " << rc << " url: " << s <<  " file: " << file << std::endl;
                r = false;
            }
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
                    if (verbose)
                    {
                        std::cout << "vurlkey[i].key_fromH=" << vurlkey[i].key_fromH << " ";
                        std::cout << "vurlkey[i].key_fromL=" << vurlkey[i].key_fromL << " ";
                        std::cout << "key_pos=" << t << " ";
                        //std::cout << "key_pos=" << BASE*vurlkey[i].key_fromH + vurlkey[i].key_fromL  << " ";
                        std::cout <<  std::endl;
					}

					for( size_t j = 0; j< KEY_SIZE; j++)
					{
						vurlkey[i].key[j] = d.buffer.getdata()[t+j];
						if (verbose)
                            std::cout << (int)(unsigned char)vurlkey[i].key[j] << " ";
                    }
                    if (verbose)
                        std::cout <<  std::endl;
				}
				else
				{
                    if (verbose)
                        std::cout << "key_pos=" << (int32_t)0 << " ";
					for( size_t j = 0; j< d.buffer.size(); j++)
					{
						vurlkey[i].key[j] = d.buffer.getdata()[j];
						if (verbose)
                            std::cout << (int)(unsigned char)vurlkey[i].key[j] << " ";
                    }
					for( size_t j = d.buffer.size(); j< KEY_SIZE; j++)
					{
						vurlkey[i].key[j] = j % 7;
						if (verbose)
                            std::cout << (int)(unsigned char)vurlkey[i].key[j] << " ";
                    }
                    if (verbose)
                        std::cout <<  std::endl;
				}

                {
                    SHA256 sha;
                    sha.update(reinterpret_cast<const
                    uint8_t*> (d.buffer.getdata()), d.buffer.size() );
                    uint8_t* digest = sha.digest();
                    auto s = SHA256::toString(digest);
                    for( size_t j = 0; j< CHKSUM_SIZE; j++)
                        vurlkey[i].checksum[j] = s[j];
                    if (verbose)
                        std::cout << "Encryption checksum " << SHA256::toString(digest) << std::endl;
                    delete[] digest;
                }
            }
            else
            {
                std::cerr << "ERROR reading file " << file << std::endl;
            }

		}

        if (fileexists(file))
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
            std::cerr << "ERROR " << "encoding file must be multiple of 4 bytes, iter: " << iter << std::endl;
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
        if (filename_puzzle.size() ==  0)
        {
            std::cerr << "ERROR empty puzzle filename " <<  std::endl;
            return false;
        }
        filename_full_puzzle = filename_puzzle + ".full";

        if (filename_msg_data.size() ==  0)
        {
            std::cerr << "ERROR empty msg_data filename " <<  std::endl;
            return false;
        }

        if (fileexists(filename_puzzle) == false)
        {
            std::cerr << "ERROR missing puzzle file " << filename_puzzle <<  std::endl;
            return false;
        }
        if (fileexists(filename_msg_data) == false)
        {
            std::cerr << "ERROR missing msg file " << filename_msg_data <<  std::endl;
            return false;
        }

        if (filename_urls.size() > 0)
        {
            if (fileexists(filename_urls))
            {
                if (read_file_urls(filename_urls) == false)
                {
                    std::cerr << "ERROR " << "reading urls " << filename_urls << std::endl;
                    return false;
                }

                if (allow_empty_url == false)
                {
                    if (vurlkey.size() == 0)
                    {
                        std::cerr << "ERROR " << "url empty in file " << filename_urls << std::endl;
                        return false;
                    }
                }
            }
            else
            {
            }
        }

        if (puz.read_from_file(filename_puzzle, false) == false)
        {
            std::cerr << "ERROR " << " reading puzzle file " << filename_puzzle << std::endl;
            return false;
        }
        if (puz.puz_data.buffer.size() == 0)
        {
            std::cerr << "ERROR " << "puzzle file empty " << filename_puzzle << std::endl;
            return false;
        }

		if (puz.is_all_answered() == false)
        {
            std::cerr << "ERROR " << "puzzle not fully answered " << std::endl;
            return false;
        }

        // before removal of answer
        if (puz.save_to_file(filename_full_puzzle) == false)
        {
            std::cerr << "ERROR " << "saving puzzle " << filename_full_puzzle << std::endl;
            return false;
        }

        // before removal of answer
        Buffer puz_key(PUZZLE_SIZE_LIM);
        puz.make_key(puz_key);
        if (puz_key.size()== 0)
        {
            std::cerr << "ERROR " << "reading puzzle key in file " << filename_full_puzzle << std::endl;
            return false;
        }

        // removal of answer
        if (puz.make_partial() == false)
        {
            std::cerr << "ERROR " << "making partial puzzle" << std::endl;
            return false;
        }

        // after removal of answer
        if (puz.save_to_file(filename_partial_puzzle) == false)
        {
            std::cerr << "ERROR " << "saving puzzle " << filename_partial_puzzle << std::endl;
            return false;
        }

        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (make_urlkey_from_url(i) == false)
            {
                std::cerr << "ERROR " << "extracting url info, url index: " << i << std::endl;
                return false;
            }
            if (make_urlinfo_with_padding(i) == false)
            {
                std::cerr << "ERROR " << "making url info, url index: " << i <<std::endl;
                return false;
            }
        }

        if (msg_data.read_from_file(filename_msg_data) == false)
        {
            std::cerr << "ERROR " << "reading msg file" << filename_msg_data <<std::endl;
            return false;
        }
        if (msg_data.copy_buffer_to(data_temp)== false)
        {
            std::cerr << "ERROR " << "reading copying msg file" << filename_msg_data <<std::endl;
            return false;
        }

        int16_t PADDING = 0;
        auto sz_msg = data_temp.buffer.size();
        if (sz_msg % PADDING_MULTIPLE != 0)
        {
            //std::cout << "WARNING " << "Padding msg to multiple of " << PADDING_MULTIPLE << " " << sz_msg << std::endl;

            int16_t n = PADDING_MULTIPLE - (sz_msg % PADDING_MULTIPLE);
            PADDING = n;
            char c[1] = {' '};
            for(int16_t i= 0; i< n; i++)
                data_temp.buffer.write(&c[0], 1, -1);
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
        temp.writeUInt16(PADDING, PADDING_MULTIPLE - 4);
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
    std::string filename_full_puzzle;
    bool verbose;
};


#endif
