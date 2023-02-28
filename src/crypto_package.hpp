#ifndef CRYPTO_PACKAGE_H
#define CRYPTO_PACKAGE_H

#include <map>
#include <string>
#include <vector>
#include <utility>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include "crypto_const.hpp"
#include "crc32a.hpp"

class crypto_package
{
public:

    crypto_package(bool v = true) {verbose = v;}

    bool unpack(std::string input_crypto_file, std::string output_qa_puzzle_file, std::string output_enc_data_file,
                std::string input_puzzle_enc_key)
    {
        bool r = true;

        if (fileexists(input_crypto_file) == false)
        {
            std::cerr << "ERROR missing crypto file " << input_crypto_file <<  std::endl;
            return false;
        }

        cryptodata input_crypto;
        cryptodata input_enc_qa_puzzle;

        if (input_crypto.read_from_file(input_crypto_file) == false)
        {
            std::cerr << "ERROR " << "reading crypto file " << input_crypto_file <<std::endl;
            return false;
        }

        std::uint32_t sz_input_crypto = input_crypto.buffer.size();
        if (sz_input_crypto < 128)
        {
            std::cerr << "ERROR " << "invalid crypto file size " << sz_input_crypto <<std::endl;
            return false;
        }

        CRYPTO_HEADER header;

        if (input_crypto.buffer.getdata()[0] != 'C') r = false;
        if (input_crypto.buffer.getdata()[1] != 'R') r = false;
        if (input_crypto.buffer.getdata()[2] != 'Y') r = false;
        if (input_crypto.buffer.getdata()[3] != 'P') r = false;
        if (input_crypto.buffer.getdata()[4] != 'T') r = false;
        if (input_crypto.buffer.getdata()[5] != 'O') r = false;

        if (r== false)
        {
            std::cerr << "ERROR " << "invalid crypto file signature" << input_crypto_file <<std::endl;
            return false;
        }

        std::uint32_t pos = 6;
        header.version                  = input_crypto.buffer.readUInt16(pos);pos+=2;
        header.enc_puzzle_size          = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.enc_puzzle_padding_size  = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.enc_data_size            = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.enc_data_padding_size    = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.crc_enc_data_hash        = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.crc_enc_puzzle_hash      = input_crypto.buffer.readUInt32(pos);pos+=4;

        for(size_t i=0;i<32+64;i++) header.enc_puzzle_key_hint[i]=0;
        for(size_t i=0;i<32+64;i++)
        {
            header.enc_puzzle_key_hint[i] = input_crypto.buffer.getdata()[pos+i];
        }
        pos+=32+64;

        if (verbose)
        {
            std::cout << "INFO " << "header read - sz_input_crypto :" << sz_input_crypto << " pos " << pos << std::endl;
            std::cout << "INFO " << "enc_puzzle_size :" << header.enc_puzzle_size <<std::endl;
            std::cout << "INFO " << "enc_puzzle_padding_size :" << header.enc_puzzle_padding_size <<std::endl;
            std::cout << "INFO " << "enc_data_size :" << header.enc_data_size <<std::endl;
            std::cout << "INFO " << "enc_data_padding_size :" << header.enc_data_padding_size <<std::endl;
            std::cout << "INFO " << "crc_enc_data_hash :" << header.crc_enc_data_hash <<std::endl;
            std::cout << "INFO " << "crc_enc_puzzle_hash :" << header.crc_enc_puzzle_hash <<std::endl;
        }

        std::uint32_t sz_file_in_header = 128 +
                        header.enc_puzzle_size + header.enc_puzzle_padding_size +
                        header.enc_data_size   + header.enc_data_padding_size;

        if (sz_input_crypto != sz_file_in_header)
        {
            std::cerr << "ERROR " << "invalid crypto header content, total file size mismatch " << sz_file_in_header << std::endl;
            return false;
        }

        input_enc_qa_puzzle.buffer.write(&input_crypto.buffer.getdata()[pos], header.enc_puzzle_size, -1);
        pos += header.enc_puzzle_size;
        pos += header.enc_puzzle_padding_size;
        if (verbose)
            std::cout << "INFO " << "input_enc_qa_puzzle read " << " pos " << pos << std::endl;

        cryptodata output_enc_data;

        output_enc_data.buffer.write(&input_crypto.buffer.getdata()[pos], header.enc_data_size, -1);
        pos += header.enc_data_size;
        pos += header.enc_data_padding_size;
        if (verbose)
            std::cout << "INFO " << "output_enc_data read " << " pos " << pos << std::endl;

        if (input_puzzle_enc_key.size() == 0)
        {
            // warning...
            if (verbose)
                std::cout << "INFO " << "(input_puzzle_enc_key.size() == 0)" << " pos " << pos << std::endl;

            r = input_enc_qa_puzzle.save_to_file(output_qa_puzzle_file);
            if (r == false)
            {
                std::cerr << "ERROR " << "writing output qa puzzle file " << output_qa_puzzle_file <<std::endl;
                return false;
            }

            if (r)
            {
                r = output_enc_data.save_to_file(output_enc_data_file);
                if (r == false)
                {
                    std::cerr << "ERROR " << "writing output enc_data_file " << output_enc_data_file << std::endl;
                    return false;
                }
            }
        }
        else
        {
            if (verbose)
                std::cout << "INFO " << "input_puzzle_enc_key.size() " << input_puzzle_enc_key.size() << " pos " << pos << std::endl;

            cryptodata data_temp_next;
            int16_t crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH;

            r = decode(crypto_algo, input_enc_qa_puzzle, input_puzzle_enc_key.data(), input_puzzle_enc_key.size(), data_temp_next);
            if (r)
            {
                r = data_temp_next.save_to_file(output_qa_puzzle_file);
                if (r == false)
                {
                    std::cerr << "ERROR " << "writing output qa puzzle file " << output_qa_puzzle_file <<std::endl;
                    return false;
                }
            }
            else
            {
                std::cerr << "ERROR " << "decoding ALGO_TWOFISH" << std::endl;
            }

            if (r)
            {
                r = output_enc_data.save_to_file(output_enc_data_file);
                if (r == false)
                {
                    std::cerr << "ERROR " << "writing output enc_data_file " << output_enc_data_file << std::endl;
                    return false;
                }
            }
        }

        return r;
    }

    bool pack(  std::string qa_puzzle_file, std::string enc_data_file, char* puzzle_enc_key, std::uint32_t puzzle_enc_key_size,
                std::string output_crypto_file, std::string puzzle_hint = "")
    {
        bool r = true;

        if (fileexists(qa_puzzle_file) == false)
        {
            std::cerr << "ERROR missing qa puzzle file " << qa_puzzle_file <<  std::endl;
            return false;
        }
        if (fileexists(enc_data_file) == false)
        {
            std::cerr << "ERROR missing encrypted data file " << enc_data_file <<  std::endl;
            return false;
        }

        cryptodata enc_puzzle_data;

        if (enc_puzzle_data.read_from_file(qa_puzzle_file) == false)
        {
            std::cerr << "ERROR " << "reading qa puzzle file " << qa_puzzle_file <<std::endl;
            return false;
        }

        if (puzzle_enc_key_size == 0)
        {
            // warning...
            r = pack_internal(enc_puzzle_data, enc_data_file, output_crypto_file, puzzle_hint);
        }
        else
        {
            std::uint32_t sz = enc_puzzle_data.buffer.size();
            std::uint32_t sz_padding = 0;
            if (sz % PADDING_MULTIPLE != 0)
            {
                sz_padding = PADDING_MULTIPLE - (sz % PADDING_MULTIPLE );
                char c[1] = {0};
                for(std::uint32_t i=0;i<sz_padding;i++)
                {
                    enc_puzzle_data.buffer.write(&c[0], 1, -1);
                }
            }

            cryptodata data_temp_next;
            int16_t crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH;
            r = encode(crypto_algo, enc_puzzle_data, puzzle_enc_key, puzzle_enc_key_size, data_temp_next, sz_padding);
            if (r)
            {
                r = pack_internal(data_temp_next, enc_data_file, output_crypto_file, puzzle_hint, sz_padding);
            }
        }

        return r;
    }

    bool pack_internal( cryptodata& input_enc_puzzle, std::string enc_data_file, std::string output_crypto_file, std::string hint = "",
                        std::uint32_t sz_padding_puzzle = 0)
    {
        bool r = true;

        CRYPTO_HEADER header;
        header.sig[0]= 'C';
        header.sig[1]= 'R';
        header.sig[2]= 'Y';
        header.sig[3]= 'P';
        header.sig[4]= 'T';
        header.sig[5]= 'O';
        header.version = 1;

        if (fileexists(enc_data_file) == false)
        {
            std::cerr << "ERROR missing encrypted data file " << enc_data_file <<  std::endl;
            return false;
        }

        cryptodata          input_enc_data;
        cryptodata          output_data;

        if (input_enc_data.read_from_file(enc_data_file) == false)
        {
            std::cerr << "ERROR " << "reading encrypted data file " << enc_data_file <<std::endl;
            return false;
        }

        std::uint32_t sz_input_enc_puzzle = input_enc_puzzle.buffer.size();
        std::uint32_t sz_input_enc_data   = input_enc_data.buffer.size();
        header.enc_puzzle_size = sz_input_enc_puzzle;
        header.enc_data_size= sz_input_enc_data;

        std::uint32_t sz_padding_input_enc_puzzle  = 0;;
        std::uint32_t sz_padding_input_enc_data = 0;
        if (sz_input_enc_puzzle % PADDING_MULTIPLE != 0)
        {
            sz_padding_input_enc_puzzle = PADDING_MULTIPLE - (sz_input_enc_puzzle % PADDING_MULTIPLE );
        }
        if (sz_padding_input_enc_data % PADDING_MULTIPLE != 0)
        {
            sz_padding_input_enc_data = PADDING_MULTIPLE - (sz_padding_input_enc_data % PADDING_MULTIPLE );
        }
        header.enc_puzzle_padding_size = sz_padding_input_enc_puzzle; // + sz_padding_puzzle;
        header.enc_data_padding_size = sz_padding_input_enc_data;

        std::uint32_t crc_input_enc_puzzle= 0;
        std::uint32_t crc_input_enc_data = 0;

        {
            CRC32 crc;
            crc.update(&input_enc_puzzle.buffer.getdata()[0], sz_input_enc_puzzle);
            crc_input_enc_puzzle = crc.get_hash();
            header.crc_enc_data_hash = crc_input_enc_puzzle;
        }
        {
            CRC32 crc;
            crc.update(&input_enc_data.buffer.getdata()[0], sz_input_enc_data);
            crc_input_enc_data = crc.get_hash();
            header.crc_enc_data_hash = crc_input_enc_data;
        }

        for(size_t i=0;i<32+64;i++) header.enc_puzzle_key_hint[i]=0;
        for(size_t i=0;i<32+64;i++)
        {
            if (i < hint.size())
                header.enc_puzzle_key_hint[i] = hint[i];
        }

        output_data.buffer.write(&header.sig[0], 6, -1);
        output_data.buffer.writeUInt16(header.version, -1);
        output_data.buffer.writeUInt32(header.enc_puzzle_size, -1);
        output_data.buffer.writeUInt32(header.enc_puzzle_padding_size, -1);
        output_data.buffer.writeUInt32(header.enc_data_size, -1);
        output_data.buffer.writeUInt32(header.enc_data_padding_size, -1);
        output_data.buffer.writeUInt32(header.crc_enc_data_hash, -1);
        output_data.buffer.writeUInt32(header.crc_enc_puzzle_hash, -1);
        output_data.buffer.write(&header.enc_puzzle_key_hint[0], 32+64, -1);

        output_data.buffer.write(&input_enc_puzzle.buffer.getdata()[0], sz_input_enc_puzzle, -1);
        char c[1] = {0};
        for(std::uint32_t i=0;i<sz_padding_input_enc_puzzle;i++)
        {
            output_data.buffer.write(&c[0], 1, -1);
        }

        output_data.buffer.write(&input_enc_data.buffer.getdata()[0], sz_input_enc_data, -1);
        for(std::uint32_t i=0;i<sz_padding_input_enc_data;i++)
        {
            output_data.buffer.write(&c[0], 1, -1);
        }

        r = output_data.save_to_file(output_crypto_file);
        if (r== false)
        {
            std::cerr << "ERROR " << "writing output crypto file " << output_crypto_file <<std::endl;
            return false;
        }

        return r;
    }


    bool encode(uint16_t crypto_algo, cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next,
                std::uint32_t sz_padding_puzzle)
	{
        encryptor e;

        if (     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_ecb) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_Salsa20) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_IDEA)
           )
        {
            std::cerr << "WARNING unknown algo " <<  crypto_algo << std::endl;
        }

        if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH)
        {
            return e.encode_twofish(data_temp, key, key_size, data_temp_next);
        }
        else if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_Salsa20)
        {
            return e.encode_salsa20(data_temp, key, key_size, data_temp_next);
        }
        else if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_IDEA)
        {
            return e.encode_idea(data_temp, key, key_size, data_temp_next);
        }
        else
        {
            CRYPTO_ALGO_AES aes_type = CRYPTO_ALGO_AES::ECB;
            if (crypto_algo      == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) aes_type = CRYPTO_ALGO_AES::CBC;
            else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) aes_type = CRYPTO_ALGO_AES::CFB;

            return e.encode_binaes16_16(data_temp, key, key_size, data_temp_next, aes_type);
        }
        return false;
	}

	bool decode(uint16_t crypto_algo, cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptodata& data_decrypted)
	{
        decryptor e;

        if (     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_ecb) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_Salsa20) &&
                 (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_IDEA)
           )
        {
            std::cerr << "WARNING unknown algo - reset to ALGO_TWOFISH " <<  crypto_algo << std::endl;
            crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH;
        }

        if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_TWOFISH)
        {
            return e.decode_twofish(data_encrypted, key, key_size, data_decrypted);
        }
        else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_IDEA)
        {
            return e.decode_idea(data_encrypted, key, key_size, data_decrypted);
        }
        else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_Salsa20)
        {
            return e.decode_salsa20(data_encrypted, key, key_size, data_decrypted);
        }
		else
		{
            CRYPTO_ALGO_AES aes_type = CRYPTO_ALGO_AES::ECB;
            if      (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) aes_type = CRYPTO_ALGO_AES::CBC;
            else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) aes_type = CRYPTO_ALGO_AES::CFB;

            return e.decode_binaes16_16(data_encrypted, key, key_size, data_decrypted, aes_type);
        }

        return false;
	}

	bool verbose = false;
};

#endif
