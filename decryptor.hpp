#ifndef _INCLUDES_decryptor
#define _INCLUDES_decryptor

#include <iostream>
#include <fstream>
#include "DES.h"
#include "AESa.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "crypto_const.hpp"
#include "crypto_file.hpp"
#include "data.hpp"
#include "puzzle.hpp"

class decryptor
{
public:
	decryptor(  std::string ifilename_puzzle,
                std::string ifilename_encrypted_data,
			 	std::string ifilename_decrypted_data,
			 	std::string istaging,
			 	std::string ifolder_local,
			 	bool verb = false,
			 	bool keep = false,
                std::string iencryped_ftp_user = "",
                std::string iencryped_ftp_pwd  = "",
                std::string iknown_ftp_server  = "")
	{
        filename_puzzle = ifilename_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;
        filename_decrypted_data = ifilename_decrypted_data;
        staging =istaging;
        folder_local = ifolder_local;
        verbose = verb;
        keeping = keep;
        encryped_ftp_user = iencryped_ftp_user;
        encryped_ftp_pwd  = iencryped_ftp_pwd;
        known_ftp_server  = iknown_ftp_server;

        if (staging.size()==0)
        {
            staging ="./";
        }
	}

    ~decryptor()
    {
    }

    bool read_urlinfo(Buffer& temp, urlkey& out_uk)
	{
		bool r = true;
        uint32_t pos = 0;

        if (verbose)
		{
            std::cout << "Reading next URL info " << std::endl;
        }

        out_uk.crypto_algo = temp.readUInt16(pos); pos+=2;
		out_uk.url_size    = temp.readUInt16(pos); pos+=2;
		if (verbose)
		{
            std::cout << "crypto_algo " << out_uk.crypto_algo << " "<< std::endl;
            std::cout << "url_size "    << out_uk.url_size << " "<< std::endl;
        }

		for( int16_t j = 0; j< out_uk.url_size; j++) out_uk.url[j] = temp.getdata()[pos+j];
        for( int16_t j = out_uk.url_size; j< URL_MAX_SIZE; j++) out_uk.url[j] = 0;
        pos += URL_MAX_SIZE;

        for( int16_t j = 0; j< 4; j++)
        {
            out_uk.magic[j] = temp.getdata()[pos+j];
        }
        pos += 4;

		out_uk.key_fromH = temp.readUInt16(pos); pos+=2;
		out_uk.key_fromL = temp.readUInt16(pos); pos+=2;
		out_uk.key_size  = temp.readUInt32(pos); pos+=4;

        if (verbose)
        {
            std::cout << "key_fromH " << out_uk.key_fromH << " ";
            std::cout << "key_fromL " << out_uk.key_fromL << std::endl;
		}
		int32_t v = out_uk.key_fromH * BASE + out_uk.key_fromL;

		if (verbose)
		{
            std::cout << "key_from " << v << " ";
            std::cout << "key_size " << out_uk.key_size << std::endl;
        }

        // zero
        for( int16_t j = 0; j< MIN_KEY_SIZE; j++) out_uk.key[j] = 0;
        pos += MIN_KEY_SIZE;

		for( int16_t j = 0; j< CHKSUM_SIZE; j++)
		{
            out_uk.checksum[j] = temp.getdata()[pos+j];
        }
        pos += CHKSUM_SIZE;

		return r;
	}

	bool get_key(urlkey& uk)
	{
		bool r = true;

        if(fs::is_directory(staging)==false)
        {
            std::cerr << "ERROR staging is not a folder " << staging << std::endl;
            return false;
        }

        std::string file = staging + "decode_staging_url_file_" + std::to_string(staging_cnt) + ".dat";
        staging_cnt++;

        if (fileexists(file))
		    std::remove(file.data());

        if ( (uk.url_size < URL_MIN_SIZE) || (uk.url_size > URL_MAX_SIZE))
        {
            std::cerr << "ERROR " << "invalid web url size " << uk.url_size << std::endl;
            r = false;
        }

		// DOWNLOAD URL FILE
		cryptodata dataout_local;
        cryptodata dataout_other;
		char u[URL_MAX_SIZE+1] = {0};

        bool is_video =  false;
        bool is_ftp   =  false;
        bool is_local =  false;

		if (r)
		{
            for( int16_t j = 0; j< URL_MAX_SIZE; j++)
                u[j] = uk.url[j];

            if (u[0]=='[')
            {
                if (u[1]=='v')
                {
                    is_video = true;
                }
                if (u[1]=='f')
                {
                    is_ftp = true;
                }
                if (u[1]=='l')
                {
                    is_local = true;
                }
            }

            int pos_url = 0;
            if      (is_video)   pos_url = 3;
            else if (is_ftp)     pos_url = 3;
            else if (is_local)   pos_url = 3;
            int rc = 0;

            if (is_video)
            {
                std::string s(&u[pos_url]);
                rc = getvideo(s, file.data(), "", verbose);
            }
            else if (is_local)
            {
                std::string s(&u[pos_url]);
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
                std::string s(&u[pos_url]);
                rc = getftp(s.data(), file.data(),
                            encryped_ftp_user,
                            encryped_ftp_pwd,
                            known_ftp_server,
                            "", verbose);
                if (rc!= 0)
                {
                    std::cerr << "ERROR with getftp, error code: " << rc << " url: " << s <<  " file: " << file << std::endl;
                    r = false;
                }
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
                uint32_t pos = (uk.key_fromH * BASE) + uk.key_fromL ;
                int32_t  key_size = uk.key_size;

                if (pos >= d.buffer.size() - key_size)
                {
                    std::string su(u);
                    std::cerr << "ERROR " << "invalid web file key position: " << pos << " url: " << su << std::endl;
                    r = false;
                }

                if (r)
                {
                    Buffer* b = uk.get_buffer(); // allocate
                    b->increase_size(key_size);

                    int32_t databuffer_size = (int32_t)d.buffer.size();
                    if (databuffer_size < key_size)
                    {
                        b->write(&d.buffer.getdata()[0], databuffer_size, -1);

                        // PADDING...
                        char c[1];
                        for( int32_t j = databuffer_size; j< key_size; j++)
                        {
                            c[0] = (char) ( (unsigned char)(j % 127) );
                            b->write(&c[0], 1, -1);
                        }
                    }
                    else
                    {
                        b->write(&d.buffer.getdata()[pos], key_size, -1);
                    }

                    if (verbose)
                    {
                        for( int32_t j = 0; j< key_size; j++)
                        {
                            if (j<32) std::cout << (int)(unsigned char)b->getdata()[j] << " ";
                            else if (j==32) {std::cout << " ... [" << key_size << "] ... ";}
                            else if (j>key_size-32) std::cout << (int)(unsigned char)b->getdata()[j] << " ";
                        }
                        std::cout <<  std::endl;
                    }

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
            }
            else
            {
                std::cerr << "ERROR " << "unable to read downloaded url contents " << file <<std::endl;
                r = false;
            }
		}

		if (keeping == false)
		{
            if (fileexists(file))
                std::remove(file.data());
        }
		return r;
	}

	bool decode_binDES(cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptodata& data_decrypted)
	{
        bool r = true;
		char c;

        // BINARY DES (double file size on encryption, divide in 2 on decryption)
		uint32_t nblock = data_encrypted.buffer.size() / 8;
		uint32_t nkeys  = key_size / 4;

		if (verbose)
		{
            std::cout <<    "\nDecryptor decode() binDES - " <<
                            "number of blocks (8 bytes): " << nblock <<
                            ", number of keys (4 bytes): " << nkeys  << std::endl;
        }

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


	bool decode_salsa20(    cryptodata& data_encrypted,
                            const char* key, uint32_t key_size,
                            cryptodata& data_decrypted)
	{
        bool r = true;
		char c;

		if (key_size % 32 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "decode_salsa20 key must be multiple of 32 bytes " <<  key_size << std::endl;
            return r;
		}
		if (data_encrypted.buffer.size() % 64 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "decode_salsa20 data must be multiple of 64 bytes " <<  data_encrypted.buffer.size() << std::endl;
            return r;
		}

		uint32_t nround = 1;
		uint32_t nblock = data_encrypted.buffer.size() / 64;
		uint32_t nkeys  = key_size / 32;

		uint8_t iv[8]  = {0x12, 0x01, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde};

		if (data_encrypted.buffer.size() > 0)
		{
            if (key_size > data_encrypted.buffer.size() )
            {
                nround = key_size / data_encrypted.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
            std::cout <<    "\nDecryptor decode() salsa20 32_64           " <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (64 bytes): " << nblock <<
                            ", number of keys (32 bytes): "   << nkeys  << std::endl;
        }

		uint8_t KEY[32+1];
        uint8_t encrypted[64+1];
        uint8_t out[64+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) *  nblock) % nkeys;
            }
            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            if (r == false)
                break;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 64; j++)
                    {
                        c = data_encrypted.buffer.getdata()[64*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[64]=0;
                }
                else
                {
                    for(size_t j = 0; j < 64; j++)
                    {
                        c = data_decrypted.buffer.getdata()[64*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[64]=0;
                }

                for(size_t j = 0; j < 32; j++)
                {
                    c = key[32*key_idx + j];
                    KEY[j] = c;
                }
                KEY[32]=0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                ucstk::Salsa20 s20(KEY);
                s20.setIv(iv);
                s20.processBlocks(encrypted, out, 1);

                data_decrypted.buffer.write((char*)&out[0], 64, -1);
            }
        }

        return r;
	}

	bool decode_twofish(cryptodata& data_encrypted,
                            const char* key, uint32_t key_size,
                            cryptodata& data_decrypted)
	{
        bool r = true;
		char c;

		uint32_t nround = 1;
		uint32_t nblock = data_encrypted.buffer.size() / 16;
		uint32_t nkeys  = key_size / 16;

		if (data_encrypted.buffer.size() > 0)
		{
            if (key_size > data_encrypted.buffer.size() )
            {
                nround = key_size / data_encrypted.buffer.size();
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
            std::cout <<    "\nDecryptor decode() twofish                 " <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (16 bytes): " << nblock <<
                            ", number of keys (16 bytes): "   << nkeys  << std::endl;
        }

		Twofish_Byte KEY[16+1];
        Twofish_Byte encrypted[16+1];
        Twofish_Byte out[16+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) *  nblock) % nkeys;
            }
            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            if (r == false)
                break;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_encrypted.buffer.getdata()[16*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[16]=0;
                }
                else
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_decrypted.buffer.getdata()[16*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[16]=0;
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16]=0;

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
                Twofish_decrypt(&xkey, encrypted, out);
                data_decrypted.buffer.write((char*)&out[0], 16, -1);
            }
        }

        return r;
	}

	bool decode_binaes16_16(cryptodata& data_encrypted,
                            const char* key, uint32_t key_size,
                            cryptodata& data_decrypted,
                            CRYPTO_ALGO_AES aes_type)
	{
        bool r = true;
		char c;

		uint32_t nround = 1;
		uint32_t nblock = data_encrypted.buffer.size() / 16;
		uint32_t nkeys  = key_size / 16;

		if (data_encrypted.buffer.size() > 0)
		{
            if (key_size > data_encrypted.buffer.size() )
            {
                nround = key_size / data_encrypted.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
            std::cout <<    "\nDecryptor decode() binAES 16_16 - aes_type: " << (int)aes_type <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (16 bytes): " << nblock <<
                            ", number of keys (16 bytes): "   << nkeys  << std::endl;
        }

		unsigned char KEY[16+1];
        unsigned char encrypted[16+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) *  nblock) % nkeys;
            }
            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            if (r == false)
                break;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_encrypted.buffer.getdata()[16*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[16]=0;
                }
                else
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_decrypted.buffer.getdata()[16*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[16]=0;
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16]=0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext

                if (aes_type == CRYPTO_ALGO_AES::ECB)
                {
                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto p = aes.DecryptECB(encrypted, plainLen, KEY);

                    data_decrypted.buffer.write((char*)&p[0], 16, -1);
                    delete []p;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CBC)
                {
                    const unsigned char iv[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto p = aes.DecryptCBC(encrypted, plainLen, KEY, iv);

                    data_decrypted.buffer.write((char*)&p[0], 16, -1);
                    delete []p;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CFB)
                {
                    const unsigned char iv[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto p = aes.DecryptCFB(encrypted, plainLen, KEY, iv);

                    data_decrypted.buffer.write((char*)&p[0], 16, -1);
                    delete []p;
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

	bool decode(size_t iter, size_t NITER, uint16_t crypto_algo,
                cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptodata& data_decrypted)
	{
        if ((iter==0) || (iter==NITER-1))
        {
            return decode_binDES(data_encrypted, key, key_size, data_decrypted);
        }
        else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_TWOFISH)
        {
            return decode_twofish(data_encrypted, key, key_size, data_decrypted);
        }
        else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_Salsa20)
        {
            return decode_salsa20(data_encrypted, key, key_size, data_decrypted);
        }
		else
		{
            CRYPTO_ALGO_AES aes_type = CRYPTO_ALGO_AES::ECB;
            if      (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) aes_type = CRYPTO_ALGO_AES::CBC;
            else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) aes_type = CRYPTO_ALGO_AES::CFB;

            return decode_binaes16_16(data_encrypted, key, key_size, data_decrypted, aes_type);
        }
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
            if (decode( 0, 1, (uint16_t)CRYPTO_ALGO::ALGO_BIN_DES,
                        encrypted_data, puz_key.getdata(), puz_key.size(), data_temp_next) == false)
            {
                std::cerr << "ERROR " << "decoding with next key" << std::endl;
                r = false;
            }
        }

		// N(urls keys)+1(puzzle key) = Number of iterations in the last 2 byte! + PADDING + PADDING_MULTIPLE-2
		int16_t NITER = 0;
        int16_t PADDING = 0;
        if (r)
		{
            uint32_t file_size = (uint32_t)data_temp_next.buffer.size();
            if (file_size >= PADDING_MULTIPLE)
            {
                if (PADDING_LEN_ENCODESIZE == 2) // will skip padding
                {
                    PADDING = data_temp_next.buffer.readUInt16(file_size - 4);
                }
                else if (PADDING_LEN_ENCODESIZE > 2)
                {
                    std::cerr << "WARNING " << "unmanaged padding encoding size " << PADDING_LEN_ENCODESIZE  <<std::endl;
                }

                NITER   = data_temp_next.buffer.readUInt16(file_size - 2);
                NITER = NITER - 1;

                if (NITER < 0)
                {
                    std::cerr << "ERROR " << "encrypted_data can not be decoded - iteration value less than zero " << NITER << std::endl;
                    r = false;
                }
                else if (NITER > NITER_LIM)
                {
                    std::cerr << "ERROR " << "encrypted_data can not be decoded - iteration value bigger than limit " << NITER << std::endl;
                    r = false;
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
                    uk.erase_buffer();

                    r = get_key(uk);
                    if (r == false)
                    {
                        break;
                    }

                    // uk.crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16
                    if ((uk.crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_ecb) &&
                        (uk.crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) &&
                        (uk.crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) &&
                        (uk.crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH) &&
                        (uk.crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_Salsa20)
                       )
                    {
                        std::cerr << "WARNING mismatch algo at url iter: " <<  iter << std::endl;
                    }

                    // decode(DataN, keyN) => DataN-1+urlkeyN-1     urlkeyN-1=>keyN-1
                    if (decode( iter+1, NITER+1, uk.crypto_algo, data_temp,
                                &uk.get_buffer()->getdata()[0], uk.key_size,
                                data_temp_next) == false)
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
    cryptodata  encrypted_data;
    cryptodata  decrypted_data;

	std::string filename_puzzle;
    std::string filename_encrypted_data;
	std::string filename_decrypted_data;
	std::string staging;
	std::string folder_local;

    cryptodata  data_temp;
    cryptodata  data_temp_next;
    bool        verbose;
    bool        keeping;
    std::string encryped_ftp_user;
    std::string encryped_ftp_pwd;
    std::string known_ftp_server;
    int         staging_cnt=0;
};


#endif
