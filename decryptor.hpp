#ifndef _INCLUDES_decryptor
#define _INCLUDES_decryptor

#include <iostream>
#include <fstream>
#include "Encryptions/DES.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "crypto_const.hpp"
#include "data.hpp"
#include "puzzle.hpp"


class decryptor
{
public:
	decryptor(  std::string ifilename_puzzle,
                std::string ifilename_encrypted_data,
			 	std::string ifilename_decrypted_data,
			 	bool verb = false)
	{
        filename_puzzle = ifilename_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;
        filename_decrypted_data = ifilename_decrypted_data;
        verbose = verb;
	}

    ~decryptor()
    {
    }

    bool read_urlinfo(Buffer& temp, urlkey& out_uk)
	{
		bool r = true;
        uint32_t pos = 0;

		out_uk.url_size = temp.readUInt16(pos); pos+=2;
		if (verbose)
            std::cout << "read_urlinfo out_uk.url_size " << out_uk.url_size << " "<< std::endl;

		for( int16_t j = 0; j< out_uk.url_size; j++) out_uk.url[j] = temp.getdata()[pos+j];
        for( int16_t j = out_uk.url_size; j< URL_MAX_SIZE; j++) out_uk.url[j] = 0;
        pos += URL_MAX_SIZE;

        for( int16_t j = 0; j< 4; j++)
        {
            out_uk.magic[j] = temp.getdata()[pos+j];
            //std::cout << "out_uk.magic[j] " << out_uk.magic[j]<< std::endl;
        }
        pos += 4;

		out_uk.key_fromH = temp.readUInt16(pos); pos+=2;
		out_uk.key_fromL = temp.readUInt16(pos); pos+=2;
		out_uk.key_size = temp.readUInt16(pos);  pos+=2;

        if (verbose)
        {
            std::cout << "out_uk.key_fromH " << out_uk.key_fromH << " ";
            std::cout << "out_uk.key_fromL " << out_uk.key_fromL << std::endl;
		}
		int32_t v = out_uk.key_fromH * BASE + out_uk.key_fromL;

		if (verbose)
		{
            std::cout << "out_uk.key_from " << v << " ";
            std::cout << "out_uk.key_size " << out_uk.key_size << std::endl;
        }

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
		std::string file = "./staging_url_file.dat";
        if (fileexists(file))
		    std::remove(file.data());

        if ( (uk.url_size < URL_MIN_SIZE) || (uk.url_size > URL_MAX_SIZE))
        {
            std::cerr << "ERROR " << "invalid web url size " << uk.url_size << std::endl;
            r = false;
        }

		// DOWNLOAD URL FILE
		char u[URL_MAX_SIZE+1] = {0};
		if (r)
		{
            for( int16_t j = 0; j< URL_MAX_SIZE; j++)
                u[j] = uk.url[j];

            bool is_video=  false;
            if (u[0]=='[')
            {
                if (u[1]=='v')
                {
                    is_video = true;
                }
            }

            int pos_url = 0;
            if (is_video) pos_url = 3;
            int rc = 0;

            if (is_video)
            {
                std::string s(&u[pos_url]);
                rc = getvideo(s, file.data(), "", verbose);
            }
            else
            {
                rc = wget(u, file.data(), verbose);
            }

            if (rc != 0)
            {
                std::cerr << "ERROR " << "unable to read web url contents " << "URL " << u << std::endl;
                r = false;
            }
		}

		if (r)
		{
			data d;
			r = d.read_from_file(file);

			if (r)
			{
                uint32_t pos = (uk.key_fromH * BASE) + uk.key_fromL ;
                size_t  key_size = uk.key_size;

//                std::cout << "pos " << pos << " ";
//                std::cout << "key_size " << key_size << std::endl;

                if (pos >= d.buffer.size() - key_size)
                {
                    std::string su(u);
                    std::cerr << "ERROR " << "invalid web file key position: " << pos << " url: " << su << std::endl;
                    r = false;
                }

                if (r && (key_size <= KEY_SIZE))
                {
                    for( size_t j = 0; j< key_size; j++)
                    {
                        uk.key[j] = d.buffer.getdata()[pos+j];
                        if (verbose)
                            std::cout << (int)(unsigned char)uk.key[j]<< " ";
                    }
                    for( size_t j = key_size; j < KEY_SIZE; j++)
                    {
    					uk.key[j] = j % 7;
    					if (verbose)
                            std::cout << (int)(unsigned char)uk.key[j]<< " ";
                    }
                    if (verbose)
                        std::cout << std::endl;

                    std::string checksum;
                    {
                        SHA256 sha;
                        sha.update(reinterpret_cast<const uint8_t*> (d.buffer.getdata()), d.buffer.size() );
                        uint8_t* digest = sha.digest();
                        checksum = SHA256::toString(digest);
                        if (verbose)
                            std::cout << "Decryption checksum " << checksum << std::endl;
                        delete[] digest;
                    }

                    char c;
                    for( size_t j = 0; j< CHKSUM_SIZE; j++)
                    {
                        c = checksum.at(j);
                        if (c != uk.checksum[j])
                        {
                            std::cerr << "ERROR " << "invalid web file checksum at " << j << std::endl;
                            if (verbose)
                            {
                                std::string su(u);
                                for( size_t j = 0; j< CHKSUM_SIZE; j++)
                                {
                                    std::cout << (int)(unsigned char)uk.checksum[j] << " ";
                                }
                                std::cout << "url: " << su << std::endl;
                            }
                            r = false;
                            break;
                        }
                    }
                }
                else
                {
                    std::cerr << "ERROR " << "invalid web key size: " << key_size << std::endl;
                    r = false;
                }
            }
            else
            {
                std::cerr << "ERROR " << "unable to read downloaded url contents " << file <<std::endl;
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
        if (filename_puzzle.size() ==  0)
        {
            std::cout << "ERROR empty puzzle filename " <<  std::endl;
            return false;
        }
        if (filename_encrypted_data.size() ==  0)
        {
            std::cout << "ERROR empty encrypted_data filename " <<  std::endl;
            return false;
        }

        if (fileexists(filename_puzzle) == false)
        {
            std::cout << "ERROR missing puzzle file " << filename_puzzle <<  std::endl;
            return false;
        }
        if (fileexists(filename_encrypted_data) == false)
        {
            std::cout << "ERROR missing encrypted_data file " << filename_encrypted_data <<  std::endl;
            return false;
        }

		bool r = true;
		Buffer puz_key(PUZZLE_SIZE_LIM);

		if (r)
		{
			if (puz.read_from_file(filename_puzzle, false) == false)
			{
                std::cerr << "ERROR " << "reading puzzle file" << std::endl;
				r = false;
			}
		}

		if (r)
		{
			if (puz.is_all_answered() == false)
			{
                std::cerr << "ERROR " << "puzzle not fully answered" << std::endl;
				r = false;
			}
		}

		if (r)
		{
			if (puz.is_valid_checksum() == false)
			{
                std::cerr << "ERROR " << "invalid puzzle answers or checksum" << std::endl;
				r = false;
			}
		}

		if (r)
		{
			puz.make_key(puz_key);
			if (puz_key.size() == 0)
			{
                std::cerr << "ERROR " << "puzzle empty" << std::endl;
				r = false;
			}
		}

		if (r)
		{
            if (encrypted_data.read_from_file(filename_encrypted_data) == false)
			{
                std::cerr << "ERROR " << "reading encrypted file " << filename_encrypted_data <<  std::endl;
				r = false;
			}
		}

		// decode(DataFinal, pwd0) => DataN+urlkeyN+NITER  urlkeyN=>keyN
        if (r)
		{
            data_temp_next.clear_data();
            if (decode(0, encrypted_data, puz_key.getdata(), puz_key.size(), data_temp_next) == false)
            {
                std::cerr << "ERROR " << "decoding with next key" << std::endl;
                r = false;
            }
        }

		// N+1 = Number of iterations in the last 2 byte! + PADDING + PADDING_MULTIPLE-2
		int16_t NITER = 0;
        int16_t PADDING = 0;
        if (r)
		{
            size_t file_size = data_temp_next.buffer.size();
            if (file_size >= PADDING_MULTIPLE)
            {
                PADDING = data_temp_next.buffer.readUInt16(file_size - 4);
                NITER   = data_temp_next.buffer.readUInt16(file_size-2);
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
                std::cerr << "ERROR " << "encrypted_data can not be decoded - invalid file size" << std::endl;
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

        // Unpadding
        if (r)
        {
            if (PADDING > 0)
            {
                //std::cerr << "WARNING Unpadding of " << PADDING << " " << data_temp.buffer.size() << std::endl;
                data_temp.buffer.remove_last_n_char(PADDING);
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
                    std::cerr << "ERROR " << "saving " << filename_decrypted_data << std::endl;
                }
            }
            else
            {
                std::cerr << "ERROR " << "copying " << filename_decrypted_data  <<std::endl;
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
    bool        verbose;
};


#endif
