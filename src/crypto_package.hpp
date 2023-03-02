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
#include "puzzle.hpp"

class crypto_package
{
public:

    crypto_package(bool v = false) {verbose = v;}

    bool unpack(std::string input_crypto_file, std::string output_qa_puzzle_file, std::string output_enc_data_file,
                std::string input_puzzle_enc_key)
    {
        bool empty_puzzle_output = false;
        if (output_qa_puzzle_file.size() == 0)
            empty_puzzle_output = true;

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
        if (sz_input_crypto < CRYPTO_HEADER_SIZE)
        {
            std::cerr << "ERROR " << "invalid crypto file size (too small) " << sz_input_crypto <<std::endl;
            return false;
        }

        CRYPTO_HEADER header;

        if (input_crypto.buffer.getdata()[0] != 'C') r = false;
        if (input_crypto.buffer.getdata()[1] != 'R') r = false;
        if (input_crypto.buffer.getdata()[2] != 'Y') r = false;
        if (input_crypto.buffer.getdata()[3] != 'P') r = false;
        if (input_crypto.buffer.getdata()[4] != 'T') r = false;
        if (input_crypto.buffer.getdata()[5] != 'O') r = false;

        if (r == false)
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
        header.crc_enc_puzzle_key_hash  = input_crypto.buffer.readUInt32(pos);pos+=4;

        // TODO header values range check...

        for(size_t i=0;i<HINT_SIZE;i++) header.enc_puzzle_key_hint[i]=0;
        for(size_t i=0;i<HINT_SIZE;i++)
        {
            header.enc_puzzle_key_hint[i] = input_crypto.buffer.getdata()[pos+i];
        }
        header.enc_puzzle_key_hint[HINT_SIZE-1] = 0;
        pos+=HINT_SIZE;

        if (verbose)
        {
            std::cout << "INFO " << "header read - sz_input_crypto :" << sz_input_crypto << " pos " << pos << std::endl;
            std::cout << "INFO " << "enc_puzzle_size :" << header.enc_puzzle_size <<std::endl;
            std::cout << "INFO " << "enc_puzzle_padding_size :" << header.enc_puzzle_padding_size <<std::endl;
            std::cout << "INFO " << "enc_data_size :" << header.enc_data_size <<std::endl;
            std::cout << "INFO " << "enc_data_padding_size :" << header.enc_data_padding_size <<std::endl;
            std::cout << "INFO " << "crc_enc_data_hash :" << header.crc_enc_data_hash <<std::endl;
            std::cout << "INFO " << "crc_enc_puzzle_hash :" << header.crc_enc_puzzle_hash <<std::endl;
            std::cout << "INFO " << "crc_enc_puzzle_key_hash :" << header.crc_enc_puzzle_key_hash <<std::endl;
        }

        std::uint32_t sz_file_in_header = CRYPTO_HEADER_SIZE +
                        header.enc_puzzle_size + header.enc_puzzle_padding_size +
                        header.enc_data_size   + header.enc_data_padding_size;

        if (sz_input_crypto != sz_file_in_header)
        {
            std::cerr << "ERROR " << "invalid crypto header content, total file size mismatch " << sz_file_in_header << std::endl;
            return false;
        }

        // TODO crc check...
        // TODO size limit check...


        if (header.crc_enc_puzzle_key_hash != 0)
        {
            if (empty_puzzle_output == false)
            {
                if (input_puzzle_enc_key.size() == 0)
                {
                    std::cerr << "ERROR " << "The puzzle was encrypted with a key, a key is needed to unpack the puzzle "<< std::endl;
                    return false;
                    //std::cerr << "This may be ok if no initial puzzle was provided for encoding" << std::endl;
                }
                else
                {
                    CRC32 crc;
                    crc.update(input_puzzle_enc_key.data(), input_puzzle_enc_key.size());
                    auto c = crc.get_hash();
                    if (c != header.crc_enc_puzzle_key_hash )
                    {
                        std::cerr << "ERROR " << "Invalid key provided to unpack, header crc: "<< header.crc_enc_puzzle_key_hash << ", crc key: " << c << std::endl;
                        std::string h(header.enc_puzzle_key_hint);
                        std::cerr << "Hint for the key is " << h << std::endl;
                        return false;
                    }
                }
            }
            else
            {
                std::cerr << "ERROR " << "The puzzle was encrypted with a key, you are unpacking without extracting the unencrypted qa puzzle "<< std::endl;
                return false;
                //std::cerr << "This may be ok if no initial puzzle was provided for encoding" << std::endl;
            }
        }

        input_enc_qa_puzzle.buffer.write(&input_crypto.buffer.getdata()[pos], header.enc_puzzle_size, -1);
        pos += header.enc_puzzle_size;
        pos += header.enc_puzzle_padding_size;

        cryptodata output_enc_data;

        output_enc_data.buffer.write(&input_crypto.buffer.getdata()[pos], header.enc_data_size, -1);
        pos += header.enc_data_size;
        pos += header.enc_data_padding_size;

        if (input_puzzle_enc_key.size() == 0)
        {
            if (empty_puzzle_output == false)
            {
                // with token
                puzzle puz;
                if (puz.read_from_data(input_enc_qa_puzzle) == false)
                {
                    std::cerr << "ERROR " << "reading puzzle" <<std::endl;
                    return false;
                }

                r = puz.save_to_file(output_qa_puzzle_file);
                if (r == false)
                {
                    std::cerr << "ERROR " << "writing output qa puzzle file " << output_qa_puzzle_file <<std::endl;
                    return false;
                }
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
            cryptodata data_temp_next;
            int16_t crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH;

            if (input_enc_qa_puzzle.buffer.size() > 0)
            {
                r = decode(crypto_algo, input_enc_qa_puzzle, input_puzzle_enc_key.data(), (uint32_t)input_puzzle_enc_key.size(), data_temp_next);
                if (r == false)
                {
                    std::cerr << "ERROR " << "decoding encrypted puzzle " << std::endl;
                }
            }

            if (r)
            {
                if (empty_puzzle_output == false)
                {
                    // with token
                    if (data_temp_next.buffer.size() > 0)
                    {
                        puzzle puz;
                        if (puz.read_from_data(data_temp_next) == false)
                        {
                            std::cerr << "ERROR " << "reading puzzle" <<std::endl;
                            return false;
                        }

                        r = puz.save_to_file(output_qa_puzzle_file);
                        if (r == false)
                        {
                            std::cerr << "ERROR " << "writing output qa puzzle file " << output_qa_puzzle_file <<std::endl;
                            return false;
                        }
                    }
                    else
                    {
                        // ?
                        std::cerr << "ERROR " << "no puzzle to unpack" << std::endl;
                        return false;
                    }
                }
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
        bool empty_puzzle = false;
        bool r = true;

        if (fileexists(qa_puzzle_file) == false)
        {
            std::cerr << "WARNING missing qa puzzle file (using default puzzle)" <<  std::endl;
            empty_puzzle = true;
        }

        if (fileexists(enc_data_file) == false)
        {
            std::cerr << "ERROR missing encrypted data file " << enc_data_file <<  std::endl;
            return false;
        }

        puzzle puz;
        if (empty_puzzle == false)
        {
            if (puz.read_from_file(qa_puzzle_file, true) == false)
            {
                std::cerr << "ERROR " << "reading qa puzzle file " << qa_puzzle_file <<std::endl;
                return false;
            }
        }
        else
        {
            if (puz.read_from_empty_puzzle(true) == false)
            {
                std::cerr << "ERROR " << "reading default puzzle" <<std::endl;
                return false;
            }
        }

        Buffer puz_key;
        puz.make_key(puz_key);

        cryptodata enc_puzzle_data;
        enc_puzzle_data.buffer.write(&puz_key.getdata()[0], puz_key.size());

        CRC32 crc;
        crc.update(&enc_puzzle_data.buffer.getdata()[0], enc_puzzle_data.buffer.size());
        uint32_t crc_puz_key = crc.get_hash();

        if (puzzle_enc_key_size == 0)
        {
            r = pack_internal(enc_puzzle_data, enc_data_file, output_crypto_file, puzzle_enc_key, puzzle_enc_key_size, crc_puz_key, puzzle_hint );
        }
        else
        {
            std::uint32_t sz = enc_puzzle_data.buffer.size();

            cryptodata data_temp_next;
            int16_t crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH;

            if (sz == 0)
            {
                std::cerr << "ERROR " << "Default puzzle should not be empty " <<std::endl;
            }
            else
            {
                r = encode(crypto_algo, enc_puzzle_data, puzzle_enc_key, puzzle_enc_key_size, data_temp_next);
            }

            if (r)
            {
                r = pack_internal(data_temp_next, enc_data_file, output_crypto_file, puzzle_enc_key, puzzle_enc_key_size, crc_puz_key, puzzle_hint);
            }
        }

        return r;
    }

    bool pack_internal( cryptodata& input_enc_puzzle, std::string enc_data_file, std::string output_crypto_file,
                        char* puzzle_enc_key, std::uint32_t puzzle_enc_key_size, uint32_t crc_puz_key,
                        std::string hint = "")
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


        // Read from input_enc_data
        uint32_t crc_puz_key_in_data = 0;
        uint32_t file_size = (uint32_t)input_enc_data.buffer.size();
        if (file_size >= 4)
        {
            crc_puz_key_in_data = input_enc_data.buffer.readUInt32(file_size - 4);
        }

        if (crc_puz_key != crc_puz_key_in_data)
        {
            std::cerr << "ERROR " << "Invalid puzzle"  << std::endl;
            std::cout << "data size                           "  << file_size << std::endl;
            std::cerr << "CRC32 of puzzle key provided is     "  << crc_puz_key << std::endl;
            std::cerr << "CRC32 of puzzle key when encoded is "  << crc_puz_key_in_data << std::endl;
            return false;
        }
        else if (verbose)
        {
            std::cout << "data size                           "  << file_size << std::endl;
            std::cout << "CRC32 of puzzle key provided is     "  << crc_puz_key << std::endl;
            std::cout << "CRC32 of puzzle key when encoded is "  << crc_puz_key_in_data << std::endl;
        }

        std::uint32_t sz_input_enc_puzzle = input_enc_puzzle.buffer.size();
        std::uint32_t sz_input_enc_data   = input_enc_data.buffer.size();
        header.enc_puzzle_size = sz_input_enc_puzzle;
        header.enc_data_size   = sz_input_enc_data;

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
        header.enc_puzzle_padding_size = sz_padding_input_enc_puzzle;
        header.enc_data_padding_size = sz_padding_input_enc_data;

        // TODO size limit check...
        // TODO sz_padding_puzzle == 0 check...

        std::uint32_t crc_input_enc_puzzle= 0;
        std::uint32_t crc_input_enc_data = 0;

        if (sz_input_enc_puzzle > 0)
        {
            CRC32 crc;
            crc.update(&input_enc_puzzle.buffer.getdata()[0], sz_input_enc_puzzle);
            crc_input_enc_puzzle = crc.get_hash();
            header.crc_enc_puzzle_hash = crc_input_enc_puzzle;
        }
        else
        {
            header.crc_enc_puzzle_hash = 0;
        }

        if (sz_input_enc_data > 0)
        {
            CRC32 crc;
            crc.update(&input_enc_data.buffer.getdata()[0], sz_input_enc_data);
            crc_input_enc_data = crc.get_hash();
            header.crc_enc_data_hash = crc_input_enc_data;
        }
        else
        {
            header.crc_enc_data_hash = 0;
        }

        if (puzzle_enc_key_size > 0)
        {
            CRC32 crc;
            crc.update(puzzle_enc_key, puzzle_enc_key_size);
            auto n = crc.get_hash();
            header.crc_enc_puzzle_key_hash = n;
            //std::cerr << "Writing " << "crc_enc_puzzle_key_hash " << header.crc_enc_puzzle_key_hash <<std::endl;
        }
        else
        {
            header.crc_enc_puzzle_key_hash = 0;
        }

        for(size_t i=0;i<HINT_SIZE;i++) header.enc_puzzle_key_hint[i]=0;
        for(size_t i=0;i<HINT_SIZE;i++)
        {
            if (i < hint.size())
                header.enc_puzzle_key_hint[i] = hint[i];
        }
        header.enc_puzzle_key_hint[HINT_SIZE-1] = 0;// a string

        output_data.buffer.write(&header.sig[0], 6, -1);
        output_data.buffer.writeUInt16(header.version, -1);
        output_data.buffer.writeUInt32(header.enc_puzzle_size, -1);
        output_data.buffer.writeUInt32(header.enc_puzzle_padding_size, -1);
        output_data.buffer.writeUInt32(header.enc_data_size, -1);
        output_data.buffer.writeUInt32(header.enc_data_padding_size, -1);
        output_data.buffer.writeUInt32(header.crc_enc_data_hash, -1);
        output_data.buffer.writeUInt32(header.crc_enc_puzzle_hash, -1);
        output_data.buffer.writeUInt32(header.crc_enc_puzzle_key_hash, -1);
        output_data.buffer.write(&header.enc_puzzle_key_hint[0], HINT_SIZE, -1);

        output_data.buffer.write(&input_enc_puzzle.buffer.getdata()[0], sz_input_enc_puzzle, -1); // if (sz_input_enc_puzzle==0) nothing written
        char c[1] = {0};
        for(std::uint32_t i=0;i<sz_padding_input_enc_puzzle;i++)
        {
            output_data.buffer.write(&c[0], 1, -1);
        }

        output_data.buffer.write(&input_enc_data.buffer.getdata()[0], sz_input_enc_data, -1); // if (sz_input_enc_data==0) nothing written
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


    bool encode(uint16_t crypto_algo, cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
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

	std::string DUMPheader(std::string input_crypto_file)
	{
        bool r = true;
        std::string s;

        if (fileexists(input_crypto_file) == false)
        {
            std::cerr << "ERROR missing crypto file " << input_crypto_file <<  std::endl;
            return "";
        }

        cryptodata input_crypto;
        cryptodata input_enc_qa_puzzle;

        if (input_crypto.read_from_file(input_crypto_file) == false)
        {
            std::cerr << "ERROR " << "reading crypto file " << input_crypto_file <<std::endl;
            return s;
        }

        std::uint32_t sz_input_crypto = input_crypto.buffer.size();
        if (sz_input_crypto < CRYPTO_HEADER_SIZE)
        {
            std::cerr << "ERROR " << "invalid crypto file size (too small) " << sz_input_crypto <<std::endl;
            return s;
        }

        CRYPTO_HEADER header;

        if (input_crypto.buffer.getdata()[0] != 'C') r = false;
        if (input_crypto.buffer.getdata()[1] != 'R') r = false;
        if (input_crypto.buffer.getdata()[2] != 'Y') r = false;
        if (input_crypto.buffer.getdata()[3] != 'P') r = false;
        if (input_crypto.buffer.getdata()[4] != 'T') r = false;
        if (input_crypto.buffer.getdata()[5] != 'O') r = false;

        if (r == false)
        {
            std::cerr << "ERROR " << "invalid crypto file signature " << input_crypto_file <<std::endl;
            return s;
        }

        std::uint32_t pos = 6;
        header.version                  = input_crypto.buffer.readUInt16(pos);pos+=2;
        header.enc_puzzle_size          = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.enc_puzzle_padding_size  = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.enc_data_size            = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.enc_data_padding_size    = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.crc_enc_data_hash        = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.crc_enc_puzzle_hash      = input_crypto.buffer.readUInt32(pos);pos+=4;
        header.crc_enc_puzzle_key_hash  = input_crypto.buffer.readUInt32(pos);pos+=4;

        // TODO header values range check...

        for(size_t i=0;i<HINT_SIZE;i++) header.enc_puzzle_key_hint[i]=0;
        for(size_t i=0;i<HINT_SIZE;i++)
        {
            header.enc_puzzle_key_hint[i] = input_crypto.buffer.getdata()[pos+i];
        }
        header.enc_puzzle_key_hint[HINT_SIZE-1]=0;
        pos+=HINT_SIZE;

        std::stringstream ss;
        if (verbose)
        {
            ss << "size of file : " << sz_input_crypto << std::endl;
            ss << "header.version : " << header.version <<std::endl;
            ss << "header.enc_puzzle_size : " << header.enc_puzzle_size <<std::endl;
            ss << "header.enc_puzzle_padding_size : " << header.enc_puzzle_padding_size <<std::endl;
            ss << "header.enc_data_size : " << header.enc_data_size <<std::endl;
            ss << "header.enc_data_padding_size : " << header.enc_data_padding_size <<std::endl;
            ss << "header.crc_enc_data_hash : " << header.crc_enc_data_hash <<std::endl;
            ss << "header.crc_enc_puzzle_hash : " << header.crc_enc_puzzle_hash <<std::endl;
            ss << "header.crc_enc_puzzle_key_hash : " << header.crc_enc_puzzle_key_hash <<std::endl;
            ss << "header.enc_puzzle_key_hint : " << std::string(header.enc_puzzle_key_hint) <<std::endl;
        }
        s = ss.str();

        std::uint32_t sz_file_in_header = CRYPTO_HEADER_SIZE +
                        header.enc_puzzle_size + header.enc_puzzle_padding_size +
                        header.enc_data_size   + header.enc_data_padding_size;

        if (sz_input_crypto != sz_file_in_header)
        {
            std::cerr << "ERROR " << "invalid crypto header content, total file size mismatch " << sz_file_in_header << std::endl;
            return s;
        }
        return s;
	}

	bool verbose = false;
};

#endif
