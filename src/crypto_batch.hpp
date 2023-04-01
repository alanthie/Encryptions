#ifndef _INCLUDES_crypto_batch
#define _INCLUDES_crypto_batch

#include <iostream>
#include <fstream>
#include <chrono>

#include "crypto_const.hpp"
#include "DES.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "argparse.hpp"
#include "ini_parser.hpp"
#include "random_engine.hpp"
#include "data.hpp"
#include "puzzle.hpp"
#include "encryptor.hpp"
#include "decryptor.hpp"
#include "crypto_test.hpp"

namespace cryptoAL
{

bool batch(std::string mode, std::string inifile, bool verbose)
{
    if (fileexists(inifile) == false)
    {
        std::cout << "ERROR config file not found:" << inifile << std::endl;
        return false;
    }

    ini_parser ini(inifile);
    std::map<std::string, std::map<std::string, std::string>>& map_sections = ini.get_sections();

    if (verbose)
    {
        std::cout << "Crypto batch, config file content " << inifile << std::endl;
        for(auto& [s, m] : map_sections)
        {
            std::cout << "[" << s << "]" << std::endl;
            for(auto& [p, v] : m)
            {
                std::cout  << p << "=" << v << std::endl;
            }
        }
        std::cout << std::endl;
    }

    const std::string Config    = "Config";
    const std::string Encoding  = "Encoding";
    const std::string Decoding  = "Decoding";

    std::string folder_encoder_input;
    std::string folder_encoder_output;
    std::string folder_decoder_input;
    std::string folder_decoder_output;
    std::string folder_staging;
    std::string folder_local;
    std::string keep_staging;
    std::string encryped_ftp_user;
    std::string encryped_ftp_pwd;
    std::string known_ftp_server;
    std::string key_factor;

    std::string encoding_input_puzzle;
    std::string encoding_input_msg;
    std::string encoding_input_urls;
    std::string encoding_output_qa_puzzle;
    std::string encoding_output_full_puzzle;
    std::string encoding_output_file_encrypted;

    std::string decoding_input_qa_puzzle;
    std::string decoding_input_msg_encrypted;
    std::string decoding_output_msg_unencrypted;

    if (map_sections.find(Config) == map_sections.end())
    {
        std::cout << "ERROR no Config section in config file: " << inifile << std::endl;
        return false;
    }
    else
    {
        folder_encoder_input    = ini.get_string("folder_encoder_input", Config);
        folder_encoder_output   = ini.get_string("folder_encoder_output", Config);
        folder_decoder_input    = ini.get_string("folder_decoder_input", Config);
        folder_decoder_output   = ini.get_string("folder_decoder_output", Config);
        folder_staging          = ini.get_string("folder_staging", Config);
        keep_staging            = ini.get_string("keep_stage_file", Config);
        folder_local            = ini.get_string("folder_local", Config);
        encryped_ftp_user = ini.get_string("encryped_ftp_user", Config);
        encryped_ftp_pwd  = ini.get_string("encryped_ftp_pwd", Config);
        known_ftp_server  = ini.get_string("known_ftp_server", Config);
        key_factor        = ini.get_string("key_factor", Config);

        if(std::filesystem::exists(folder_staging)==false)
        {
            std::filesystem::create_directories(folder_staging);
        }
    }

    if (map_sections.find(Decoding) == map_sections.end())
    {
        std::cout << "ERROR no Encoding section in config file: " << inifile << std::endl;
        return false;
    }
    else
    {
        decoding_input_qa_puzzle        = ini.get_string("decoding_input_qa_puzzle", Decoding);
        decoding_input_msg_encrypted    = ini.get_string("decoding_input_msg_encrypted", Decoding);
        decoding_output_msg_unencrypted = ini.get_string("decoding_output_msg_unencrypted", Decoding);
    }

    if (map_sections.find(Encoding) == map_sections.end())
    {
        std::cout << "ERROR no Encoding section in config file: " << inifile << std::endl;
        return false;
    }
    else
    {
        encoding_input_puzzle       = ini.get_string("encoding_input_puzzle", Encoding);
        encoding_input_msg          = ini.get_string("encoding_input_msg", Encoding);
        encoding_input_urls         = ini.get_string("encoding_input_urls", Encoding);
        encoding_output_qa_puzzle   = ini.get_string("encoding_output_qa_puzzle", Encoding);
        encoding_output_full_puzzle = ini.get_string("encoding_output_full_puzzle", Encoding);
        encoding_output_file_encrypted= ini.get_string("encoding_output_file_encrypted", Encoding);
    }

    if (mode == "encode")
    {
        std::cout << "crypto ENCODING..." << std::endl;

        if(std::filesystem::is_directory(folder_encoder_input)==false)
        {
            std::cerr << "ERROR folder_encoder_input is not a folder " << folder_encoder_input << std::endl;
            return false;
        }
        if(std::filesystem::is_directory(folder_encoder_input)==false)
        {
            std::cerr << "ERROR folder_encoder_output is not a folder " << folder_encoder_output << std::endl;
            return false;
        }

        if(std::filesystem::is_regular_file(folder_encoder_input + encoding_input_urls) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_encoder_input + encoding_input_urls << std::endl;
            return false;
        }
        if(std::filesystem::is_regular_file(folder_encoder_input + encoding_input_msg) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_encoder_input + encoding_input_msg<< std::endl;
            return false;
        }
        if(std::filesystem::is_regular_file(folder_encoder_input + encoding_input_puzzle) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_encoder_input + encoding_input_puzzle<< std::endl;
            return false;
        }

        if(std::filesystem::exists(folder_encoder_output)==false)
        {
            std::filesystem::create_directories(folder_encoder_output);
        }
        if(std::filesystem::is_directory(folder_encoder_output)==false)
        {
            std::cerr << "ERROR folder_encoder_output is not a folder " << folder_encoder_output << std::endl;
            return false;
        }

        size_t sz = 0;
        long ikeyfactor = 1;
        try
        {
            if (key_factor.size()==0)
            {
                ikeyfactor = 1;
            }
            else
            {
                ikeyfactor = std::stol (key_factor, &sz);
            }
        }
        catch(...)
        {
            std::cout << "Warning invalid keyfactor format, keyfactor reset to 1" << std::endl;
            ikeyfactor = 1;
        }

        encryptor encr("",
                       folder_encoder_input + encoding_input_urls,
                       folder_encoder_input + encoding_input_msg,
                       folder_encoder_input + encoding_input_puzzle,
                       folder_encoder_output + encoding_output_qa_puzzle,
                       folder_encoder_output + encoding_output_full_puzzle,
                       folder_encoder_output + encoding_output_file_encrypted,
                       folder_staging,
                       folder_local,
                       "","", "","","","","", "",
                       verbose,
                       (keep_staging == "true") ? true:false,
                       encryped_ftp_user,
                       encryped_ftp_pwd,
                       known_ftp_server,
                       ikeyfactor,
                       false,
                       false);

        if (encr.encrypt(true) == true)
        {
            std::cout << "crypto ENCODING SUCCESS" << std::endl;
            std::cout << "Encrypted file  : "     << folder_encoder_output + encoding_output_file_encrypted << std::endl;
            std::cout << "Puzzle qa file  : "     << folder_encoder_output + encoding_output_qa_puzzle << std::endl;
            std::cout << "Puzzle full file: "     << folder_encoder_output + encoding_output_full_puzzle << std::endl;
            return true;
        }
        else
        {
            std::cerr << "ENCODING FAILED" << std::endl;
            return false;
        }
    }


    if (mode == "decode")
    {
        std::cout << "crypto DECODING..." << std::endl;

        if(std::filesystem::is_directory(folder_decoder_input)==false)
        {
            std::cerr << "ERROR folder_decoder_input is not a folder " << folder_decoder_input << std::endl;
            return false;
        }
        if(std::filesystem::is_regular_file(folder_decoder_input + decoding_input_qa_puzzle) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_decoder_input + decoding_input_qa_puzzle << std::endl;
            return false;
        }
        if(std::filesystem::is_regular_file(folder_decoder_input + decoding_input_msg_encrypted) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_decoder_input + decoding_input_msg_encrypted << std::endl;
            return false;
        }

        if(std::filesystem::exists(folder_decoder_output)==false)
        {
            std::filesystem::create_directories(folder_decoder_output);
        }
        if(std::filesystem::is_directory(folder_decoder_output)==false)
        {
            std::cerr << "ERROR folder_decoder_output is not a folder " << folder_decoder_output << std::endl;
            return false;
        }

        decryptor decr("",folder_decoder_input + decoding_input_qa_puzzle,
                       folder_decoder_input + decoding_input_msg_encrypted,
                       folder_decoder_output + decoding_output_msg_unencrypted,
                       folder_staging,
                       folder_local,
                       "","","","","","","", "",
                       verbose,
                       (keep_staging == "true") ? true:false,
                       encryped_ftp_user,
                       encryped_ftp_pwd,
                       known_ftp_server);

        if (decr.decrypt() == true)
        {
            std::cout << "crypto DECODING SUCCESS" << std::endl;
            std::cout << "Decrypted file: " << folder_decoder_output + decoding_output_msg_unencrypted << std::endl;
            return true;
        }
        else
        {
            std::cerr << "DECODING FAILED" << std::endl;
            return false;
        }
    }

	return true;
}

}
#endif
