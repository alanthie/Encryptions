#ifndef _INCLUDES_encryptor
#define _INCLUDES_encryptor

#include <iostream>
#include <fstream>
#include "DES.h"
#include "AESa.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "crypto_const.hpp"
#include "data.hpp"
#include "puzzle.hpp"
#include "twofish.h"
#include "Salsa20.h"
#include "IDEA.hpp"

static bool s_Twofish_initialise = false;

class encryptor
{
friend class crypto_package;
private:
    encryptor() {}

public:

    encryptor(  std::string ifilename_urls,
                std::string ifilename_msg_data,
                std::string ifilename_puzzle,
                std::string ifilename_partial_puzzle,
                std::string ifilename_full_puzzle,
                std::string ifilename_encrypted_data,
                std::string istaging,
                std::string ifolder_local,
                bool verb = false,
                bool keep = false,
                std::string iencryped_ftp_user = "",
                std::string iencryped_ftp_pwd  = "",
                std::string iknown_ftp_server  = "",
                long ikey_size_factor = 1)
    {
        filename_urls = ifilename_urls;
        filename_msg_data = ifilename_msg_data;
        filename_puzzle = ifilename_puzzle;
        filename_partial_puzzle = ifilename_partial_puzzle;
        filename_full_puzzle = ifilename_full_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;
        staging = istaging;
        folder_local = ifolder_local;
        verbose = verb;
        keeping = keep;
        encryped_ftp_user = iencryped_ftp_user;
        encryped_ftp_pwd  = iencryped_ftp_pwd;
        known_ftp_server  = iknown_ftp_server;
        key_size_factor = ikey_size_factor;
        if (key_size_factor < 1) key_size_factor = 1;

        if (staging.size()==0)
        {
            staging ="./";
        }

        puz.verbose = verb;

//        std::cout << "known_ftp_serve   " << known_ftp_server << std::endl;
//        std::cout << "encryped_ftp_user " << encryped_ftp_user << std::endl;
//        std::cout << "encryped_ftp_pwd  " << encryped_ftp_pwd << std::endl;
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
                pos++;

                if (c == '\n')
                {
#ifdef _WIN32
                    int len = pos - 1; // rn
#else
                    int16_t len = pos;   // n
#endif
                    if ( ((len >= URL_MIN_SIZE) && (len <= URL_MAX_SIZE)) &&
                        (url[0]!=';') )
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
                        if (len > 0)
                        {
                            if (url[0]!=';')
                                std::cerr << "WARNING url skipped, " << "(url.size() >= URL_MIN_SIZE) && (url.size() <= URL_MAX_SIZE))  url=" << url <<std::endl;
                        }
                    }
                    s.clear();
                    pos = -1;
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

        if(fs::is_directory(staging)==false)
        {
            std::cerr << "ERROR staging is not a folder " << staging << std::endl;
            return false;
        }

        std::string file = staging + "encode_staging_url_file_" + std::to_string(staging_cnt) + ".dat";
        staging_cnt++;

        if (fileexists(file))
		    std::remove(file.data());

		// DOWNLOAD URL FILE
		bool is_video = false;
		bool is_ftp = false;
		bool is_local = false;
		if (vurlkey[i].url[0]=='[')
		{
            if (vurlkey[i].url[1]=='v')
            {
                is_video = true;
            }
		}
        if (vurlkey[i].url[0]=='[')
		{
            if (vurlkey[i].url[1]=='f')
            {
                is_ftp = true;
            }
		}
        if (vurlkey[i].url[0]=='[')
		{
            if (vurlkey[i].url[1]=='l')
            {
                is_local = true;
            }
		}

		int pos_url = 0;
		if      (is_video) pos_url = 3;
		else if (is_ftp)   pos_url = 3;
		else if (is_local) pos_url = 3;
        int rc = 0;
        cryptodata dataout_local;
        cryptodata dataout_other;

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
        else if (is_local)
        {
            std::string local_url = folder_local + s;
            rc = getlocal(local_url.data(), dataout_local, "", verbose);
            if (rc!= 0)
            {
                std::cerr << "ERROR with get local file, error code: " << rc << " url: " << local_url <<  " file: " << file << std::endl;
                r = false;
            }
        }
        else if (is_ftp)
        {
            rc = getftp(s.data(), file.data(),
                        encryped_ftp_user,
                        encryped_ftp_pwd,
                        known_ftp_server,
                        "", verbose);
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
			cryptodata* pointer_datafile;
			if (is_local == false)
			{
                r = dataout_other.read_from_file(file);
                pointer_datafile = &dataout_other;
            }
            else
            {
                pointer_datafile = &dataout_local;
            }
            cryptodata& d = *pointer_datafile;

			if (r)
			{
                int32_t databuffer_size = (int32_t)d.buffer.size();
                vurlkey[i].key_size = perfect_key_size;

				if (databuffer_size >= perfect_key_size)
				{
					random_engine rd;
					if (verbose)
                    {
                        std::cout << "get a random position in " << databuffer_size << " bytes of url file" <<  std::endl;
                    }

					uint32_t t = (uint32_t) (rd.get_rand() * (databuffer_size - perfect_key_size));
					vurlkey[i].key_fromH = (t / BASE);
					vurlkey[i].key_fromL = t - (vurlkey[i].key_fromH  * BASE);

                    if (verbose)
                    {
                        std::cout << "key_fromH=" << vurlkey[i].key_fromH << " ";
                        std::cout << "key_fromL=" << vurlkey[i].key_fromL << " ";
                        std::cout << "key_pos="   << t << " ";
                        std::cout << "key_size="  << vurlkey[i].key_size << " ";
                        std::cout <<  std::endl;
					}

                    Buffer* b = vurlkey[i].get_buffer(); // allocate
                    b->increase_size(perfect_key_size);
                    b->write(&d.buffer.getdata()[t], perfect_key_size, -1);

                    if (verbose)
                    {
                        for( int32_t j = 0; j< perfect_key_size; j++)
                        {
                            if (j<32) std::cout << (int)(unsigned char)d.buffer.getdata()[t+j] << " ";
                            else if (j==32) {std::cout << " ... [" << perfect_key_size << "] ... ";}
                            else if (j>perfect_key_size-32) std::cout << (int)(unsigned char)d.buffer.getdata()[t+j] << " ";
                        }
                        std::cout <<  std::endl;
                    }
				}
				else
				{
                    if (verbose)
                    {
                        std::cout << "WARNING URL file size less than key size (padding remaining) "  << "key_pos=" << (int32_t)0 <<  std::endl;
                        std::cout << "WARNING Increase number of URL (or use bigger URL file size) for perfect security" <<  std::endl;
                    }

                    Buffer* b = vurlkey[i].get_buffer(); // allocate
                    b->increase_size(perfect_key_size);
                    b->write(&d.buffer.getdata()[0], databuffer_size, -1);

                    char c[1];
					for( int32_t j = databuffer_size; j< perfect_key_size; j++)
					{
						c[0] = (char) ( (unsigned char)(j % 127) );
                        b->write(&c[0], 1, -1);
                    }
				}

				if      (i%6==0)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc;
				else if (i%6==1)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_ecb;
				else if (i%6==2)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb;
				else if (i%6==3)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH;
				else if (i%6==4)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_Salsa20;
				else              vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_IDEA;

				if (verbose)
                    std::cout << "crypto_algo=" << vurlkey[i].crypto_algo << std::endl;

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

		if (keeping == false)
		{
            if (fileexists(file))
                std::remove(file.data());
        }
		return r;
	}

    bool make_urlinfo_with_padding(size_t i)
	{
		bool r = true;

		Buffer temp(URLINFO_SIZE);
		temp.init(0);
		temp.writeUInt16(vurlkey[i].crypto_algo, -1);
		temp.writeUInt16(vurlkey[i].url_size, -1);
		temp.write(&vurlkey[i].url[0], URL_MAX_SIZE, -1);
		temp.write(&vurlkey[i].magic[0], 4, -1);
		temp.writeUInt16(vurlkey[i].key_fromH, -1);
		temp.writeUInt16(vurlkey[i].key_fromL, -1);
		temp.writeUInt32(vurlkey[i].key_size, -1);
		temp.write(&vurlkey[i].key[0], MIN_KEY_SIZE, -1);
		temp.write(&vurlkey[i].checksum[0], CHKSUM_SIZE, -1);

		for( size_t j = 0; j< URLINFO_SIZE; j++)
            vurlkey[i].urlinfo_with_padding[j] = temp.getdata()[j];

		return r;
	}

    bool encode_idea(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 8 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_idea data file must be multiple of 8 bytes idea" << data_temp.buffer.size() << std::endl;
            return r;
		}

		if (key_size % 16 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_idea key must be multiple of 16 bytes " <<  key_size << std::endl;
            return r;
		}

		uint32_t nround = 1;
		uint32_t nblock = data_temp.buffer.size() / 8;
		uint32_t nkeys  = key_size / 16;

		if (data_temp.buffer.size() > 0)
		{
            if (key_size > data_temp.buffer.size() )
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() idea 8_16                 " <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (8 bytes): " << nblock <<
                            ", number of keys (16 bytes): "  << nkeys  << std::endl;
        }

		uint8_t KEY[16+1];
		uint8_t DATA[8+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 8; j++)
                    {
                        c = data_temp.buffer.getdata()[8*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8] = 0; // Data must be 128 bits long
                }
                else
                {
                    for(size_t j = 0; j < 8; j++)
                    {
                        c = data_temp_next.buffer.getdata()[8*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8] = 0; // Data must be 128 bits long
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                idea algo;
                algo.IDEA(DATA, KEY, true);

                data_temp_next.buffer.write((char*)&DATA[0], (uint32_t)8, -1);
            }
        }

		return r;
	}


    bool encode_salsa20(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 64 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_salsa20 data file must be multiple of 64 bytes salsa20" << data_temp.buffer.size() << std::endl;
            return r;
		}

		if (key_size % 32 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_salsa20 key must be multiple of 32 bytes " <<  key_size << std::endl;
            return r;
		}

		uint32_t nround = 1;
		uint32_t nblock = data_temp.buffer.size() / 64;
		uint32_t nkeys  = key_size / 32;

		if (data_temp.buffer.size() > 0)
		{
            if (key_size > data_temp.buffer.size() )
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() salsa20 32_64             " <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (64 bytes): " << nblock <<
                            ", number of keys (32 bytes): "   << nkeys  << std::endl;
        }

		uint8_t KEY[32+1];
		uint8_t DATA[64+1];
		uint8_t enc[64+1];
		uint32_t key_idx = 0;
		uint8_t iv[8]  = {0x12, 0x01, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde};

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 64; j++)
                    {
                        c = data_temp.buffer.getdata()[64*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[64] = 0; // Data must be 128 bits long
                }
                else
                {
                    for(size_t j = 0; j < 64; j++)
                    {
                        c = data_temp_next.buffer.getdata()[64*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[64] = 0; // Data must be 128 bits long
                }

                for(size_t j = 0; j < 32; j++)
                {
                    c = key[32*key_idx + j];
                    KEY[j] = c;
                }
                KEY[32] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                ucstk::Salsa20 s20(KEY);
                s20.setIv(iv);
                s20.processBlocks(DATA, enc, 1);

                data_temp_next.buffer.write((char*)&enc[0], (uint32_t)64, -1);
            }
        }

		return r;
	}

    bool encode_twofish(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 16 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_twofish encoding file must be multiple of 16 bytes" <<  std::endl;
		}
		if (key_size == 0)
		{
            std::cerr << "ERROR encode_twofish - key_size = 0 " <<  "" << std::endl;
            return false;
        }
        if (key_size % 16 != 0)
		{
            std::cerr << "ERROR encode_twofish - key_size must be 16x " <<  key_size << std::endl;
            return false;
        }
        if (data_temp.buffer.size() == 0)
		{
            std::cerr << "ERROR encode_twofish - data size is 0 " << std::endl;
            return false;
        }


		uint32_t nround = 1;
		uint32_t nblock = data_temp.buffer.size() / 16;
		uint32_t nkeys  = key_size / 16;

		if (data_temp.buffer.size() > 0)
		{
            if (key_size > data_temp.buffer.size() )
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
		}

		int rr = 0;
		if (s_Twofish_initialise == false)
		{
            rr = Twofish_initialise();
            if (rr < 0)
            {
                std::cout << "Error with Twofish_initialise " << rr << std::endl;
                r = false;
                return r;
            }
            s_Twofish_initialise = true;
        }

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() twofish 16_16             " <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (16 bytes): " << nblock <<
                            ", number of keys (16 bytes): "   << nkeys  << std::endl;
        }

		Twofish_Byte KEY[16+1];
		Twofish_Byte DATA[16+1];
		Twofish_Byte out[16+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_temp.buffer.getdata()[16*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[16] = 0; // Data must be 128 bits long
                }
                else
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_temp_next.buffer.getdata()[16*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[16] = 0; // Data must be 128 bits long
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;


                Twofish_key xkey;
                rr = Twofish_prepare_key( KEY, 16, &xkey );
                if (rr < 0)
                {
                    std::cerr << "ERROR Twofish_prepare_key " << rr << std::endl;
                    r = false;
                    break;
                }

                Twofish_encrypt(&xkey, DATA, out);
                data_temp_next.buffer.write((char*)&out[0], (uint32_t)16, -1);
            }
        }

		return r;
	}

	bool encode_binaes16_16(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next,
                            CRYPTO_ALGO_AES aes_type)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 16 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encoding file must be multiple of 16 bytes aes16_16" <<  std::endl;
		}

		uint32_t nround = 1;
		uint32_t nblock = data_temp.buffer.size() / 16;
		uint32_t nkeys  = key_size / 16;

		if (data_temp.buffer.size() > 0)
		{
            if (key_size > data_temp.buffer.size() )
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() binAES 16_16 - aes_type: " << (int)aes_type <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (16 bytes): " << nblock <<
                            ", number of keys (16 bytes): "   << nkeys  << std::endl;
        }

		unsigned char KEY[16+1];
		unsigned char DATA[16+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_temp.buffer.getdata()[16*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[16] = 0; // Data must be 128 bits long
                }
                else
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_temp_next.buffer.getdata()[16*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[16] = 0; // Data must be 128 bits long
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                unsigned int plainLen = 16 * sizeof(unsigned char);

                if (aes_type == CRYPTO_ALGO_AES::ECB)
                {
                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto e = aes.EncryptECB(DATA, plainLen, KEY);

                    data_temp_next.buffer.write((char*)&e[0], (uint32_t)16, -1);
                    delete []e;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CBC)
                {
                    const unsigned char iv[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto e = aes.EncryptCBC(DATA, plainLen, KEY, iv);

                    data_temp_next.buffer.write((char*)&e[0], (uint32_t)16, -1);
                    delete []e;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CFB)
                {
                    const unsigned char iv[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto e = aes.EncryptCFB(DATA, plainLen, KEY, iv);

                    data_temp_next.buffer.write((char*)&e[0], (uint32_t)16, -1);
                    delete []e;
                }
                else
                {
                    std::cerr << "ERROR unsupportes AES type " << (int)aes_type << std::endl;
                    r = false;
                    break;
                }
            }
        }

		return r;
	}

	bool encode_binDES(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 4 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encoding file must be multiple of 4 bytes, binDES" << std::endl;
		}

        // BINARY DES is multiple of 4
		uint32_t nblock = data_temp.buffer.size() / 4;
		uint32_t nkeys  = key_size / 4;

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() binDES - " <<
                            "number of blocks (4 bytes): " << nblock <<
                            ", number of keys (4 bytes): " << nkeys  << std::endl;
        }

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
            data_temp_next.buffer.write(data_encr.data(), (uint32_t)data_encr.size(), -1); // 8 bytes!
        }

		return r;
	}

    // select various encoding algos based on iter, ...
    bool encode(size_t iter, size_t NITER, uint16_t crypto_algo,
                cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		if ((iter==0) || (iter==NITER))
            return encode_binDES(data_temp, key, key_size, data_temp_next);
		else
		{
            //vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16
            if (iter-1 >= vurlkey.size())
            {
                std::cerr << "WARNING mismatch iter out of range " <<  iter-1 << std::endl;
            }
            else if ((crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_ecb) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_Salsa20) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_IDEA)
                     )
            {
                std::cerr << "WARNING mismatch algo at iter " <<  iter-1 << std::endl;
            }

            if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH)
            {
                return encode_twofish(data_temp, key, key_size, data_temp_next);
            }
            else if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_Salsa20)
            {
                return encode_salsa20(data_temp, key, key_size, data_temp_next);
            }
            else if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_IDEA)
            {
                return encode_idea(data_temp, key, key_size, data_temp_next);
            }
            else
            {
                CRYPTO_ALGO_AES aes_type = CRYPTO_ALGO_AES::ECB;
                if (crypto_algo      == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) aes_type = CRYPTO_ALGO_AES::CBC;
                else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) aes_type = CRYPTO_ALGO_AES::CFB;

                return encode_binaes16_16(data_temp, key, key_size, data_temp_next, aes_type);
            }
        }
	}

    bool encrypt(bool allow_empty_url = false)
    {
        if (filename_puzzle.size() ==  0)
        {
            std::cerr << "ERROR empty puzzle filename " <<  std::endl;
            return false;
        }

        if (filename_full_puzzle.size() ==  0)
        {
            std::cerr << "ERROR empty filename_full_puzzle filename " <<  std::endl;
            return false;
        }

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
//        else
//        {
//            if (verbose)
//            {
//                std::cout << "Initial draft puzzle size " << puz.puz_data.buffer.size() << std::endl;
//                std::cout << "Initial draft_puzzle " << filename_puzzle << std::endl;
//            }
//        }

		if (puz.is_all_answered() == false)
        {
            std::cerr << "ERROR " << "puzzle not fully answered " << std::endl;
            return false;
        }

        // before removal of answer
        // call internally puz.make_puzzle_before_checksum(temp);
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

        if (msg_data.read_from_file(filename_msg_data) == false)
        {
            std::cerr << "ERROR " << "reading msg file" << filename_msg_data <<std::endl;
            return false;
        }

        msg_input_size = msg_data.buffer.size();
        NURL_ITERATIONS = (int32_t)vurlkey.size();
		if (NURL_ITERATIONS >= 1)
		{
            perfect_key_size = ((int32_t)msg_input_size) / NURL_ITERATIONS; // ignore extra and ignore first encoding
            if (perfect_key_size % MIN_KEY_SIZE != 0)
            {
                perfect_key_size += MIN_KEY_SIZE - (perfect_key_size % MIN_KEY_SIZE);
            }
		}
		if (perfect_key_size < MIN_KEY_SIZE) perfect_key_size = MIN_KEY_SIZE;
		perfect_key_size = perfect_key_size * key_size_factor;
        if (verbose)
        {
            std::cout << "msg_input_size = " << msg_input_size << " ";
            std::cout << "number of URL keys = " << NURL_ITERATIONS << " ";
            std::cout << "perfect_key_size (* key_size_factor) = " << perfect_key_size <<  std::endl;
        }

        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (verbose)
            {
                std::cout.flush();
                std::cout << "\nEncryptor reading keys - iteration: " << i << std::endl;
            }

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

        if (msg_data.copy_buffer_to(data_temp)== false)
        {
            std::cerr << "ERROR " << "reading copying msg file" << filename_msg_data <<std::endl;
            return false;
        }

        int16_t PADDING = 0;
        auto sz_msg = data_temp.buffer.size();
        if (verbose)
        {
            std::cout << "MESSAGE is " << sz_msg  << " bytes"<< std::endl;
        }

        if (sz_msg % PADDING_MULTIPLE != 0)
        {
            int16_t n = PADDING_MULTIPLE - (sz_msg % PADDING_MULTIPLE);
            if (verbose)
            {
                if (n > 0)
                    std::cout << "Padding msg with bytes: " << n  << std::endl;
            }

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

            if (i>0)
            {
                for(size_t ii=0; ii<MIN_KEY_SIZE; ii++)
                    vurlkey[i-1].key[ii] = 0;

                data_temp.append(&vurlkey[i-1].urlinfo_with_padding[0], URLINFO_SIZE);
            }

            data_temp_next.clear_data();
            encode( i, vurlkey.size(), vurlkey[i].crypto_algo, data_temp,
                    &vurlkey[i].get_buffer()->getdata()[0], vurlkey[i].key_size,
                    data_temp_next);

            data_temp.buffer.swap_with(data_temp_next.buffer);
            data_temp_next.erase();
        }

        if (vurlkey.size()>0)
        {
            for(size_t ii=0; ii<MIN_KEY_SIZE; ii++)
                vurlkey[vurlkey.size()-1].key[ii] = 0;

            data_temp.append(&vurlkey[vurlkey.size()-1].urlinfo_with_padding[0], URLINFO_SIZE);
        }

        // Save number of iterations (N web keys + 1 puzzle key) in the last 2 byte! + PADDING_MULTIPLE-2
        Buffer temp(PADDING_MULTIPLE);
		temp.init(0);
        temp.writeUInt16(PADDING, PADDING_MULTIPLE - 4);
		temp.writeUInt16((uint16_t)vurlkey.size() + 1, PADDING_MULTIPLE - 2);
        data_temp.append(temp.getdata(), PADDING_MULTIPLE);

        //encode(DataN+urlkeyN+Niter,     pwd0) => DataFinal
        encode( vurlkey.size(), vurlkey.size(), (uint16_t)CRYPTO_ALGO::ALGO_BIN_DES,
                data_temp, puz_key.getdata(), puz_key.size(), data_temp_next);

        data_temp_next.copy_buffer_to(encrypted_data);
        encrypted_data.save_to_file(filename_encrypted_data);

		return true;
    }

    cryptodata          urls_data;
    cryptodata          msg_data;
    puzzle              puz;
    cryptodata          encrypted_data;

    std::vector<urlkey> vurlkey;
    cryptodata          data_temp;
    cryptodata          data_temp_next;

    std::string filename_urls;
    std::string filename_msg_data;
    std::string filename_puzzle;
    std::string filename_partial_puzzle;
    std::string filename_full_puzzle;
    std::string filename_encrypted_data;
    std::string staging;
    std::string folder_local;
    bool verbose;
    bool keeping;
    std::string encryped_ftp_user;
    std::string encryped_ftp_pwd;
    std::string known_ftp_server;
    int staging_cnt=0;

    size_t msg_input_size = 0;
    int32_t NURL_ITERATIONS = 0;
	int32_t perfect_key_size = 0;
	long    key_size_factor = 1;
};


#endif
