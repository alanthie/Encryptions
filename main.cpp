#include <iostream>
#include <fstream>
#include <chrono>

#include "Encryptions/DES.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "argparse.hpp"
#include "ini_parser.hpp"
#include "random_engine.hpp"
#include "crypto_const.hpp"
#include "data.hpp"
#include "puzzle.hpp"
#include "encryptor.hpp"
#include "decryptor.hpp"
#include "crypto_test.hpp"

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
    std::string keep_staging;
    std::string encryped_ftp_user;
    std::string encryped_ftp_pwd;

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
        encryped_ftp_user       = ini.get_string("encryped_ftp_user", Config);
        encryped_ftp_pwd        = ini.get_string("encryped_ftp_pwd", Config);

        if(fs::exists(folder_staging)==false)
        {
            fs::create_directories(folder_staging);
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

    // ./crypto encode  -i ./test.zip -o ./test.zip.encrypted -p ./puzzle.txt -q ./partial_puzzle.txt -u ./urls.txt -v 1
    // ./crypto decode  -i ./test.zip.encrypted -p ./puzzle.txt.full -o ./test.zip.unencrypted -v 1

    if (mode == "encode")
    {
        std::cout << "crypto ENCODING..." << std::endl;

        if(fs::is_directory(folder_encoder_input)==false)
        {
            std::cerr << "ERROR folder_encoder_input is not a folder " << folder_encoder_input << std::endl;
            return false;
        }
        if(fs::is_directory(folder_encoder_input)==false)
        {
            std::cerr << "ERROR folder_encoder_output is not a folder " << folder_encoder_output << std::endl;
            return false;
        }

        if(fs::is_regular_file(folder_encoder_input + encoding_input_urls) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_encoder_input + encoding_input_urls << std::endl;
            return false;
        }
        if(fs::is_regular_file(folder_encoder_input + encoding_input_msg) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_encoder_input + encoding_input_msg<< std::endl;
            return false;
        }
        if(fs::is_regular_file(folder_encoder_input + encoding_input_puzzle) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_encoder_input + encoding_input_puzzle<< std::endl;
            return false;
        }

        if(fs::exists(folder_encoder_output)==false)
        {
            fs::create_directories(folder_encoder_output);
        }
        if(fs::is_directory(folder_encoder_output)==false)
        {
            std::cerr << "ERROR folder_encoder_output is not a folder " << folder_encoder_output << std::endl;
            return false;
        }

        encryptor encr(folder_encoder_input + encoding_input_urls,
                       folder_encoder_input + encoding_input_msg,
                       folder_encoder_input + encoding_input_puzzle,
                       folder_encoder_output + encoding_output_qa_puzzle,
                       folder_encoder_output + encoding_output_full_puzzle,
                       folder_encoder_output + encoding_output_file_encrypted,
                       folder_staging,
                       verbose,
                       (keep_staging == "true") ? true:false,
                       encryped_ftp_user,
                       encryped_ftp_pwd);

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

        if(fs::is_directory(folder_decoder_input)==false)
        {
            std::cerr << "ERROR folder_decoder_input is not a folder " << folder_decoder_input << std::endl;
            return false;
        }
        if(fs::is_regular_file(folder_decoder_input + decoding_input_qa_puzzle) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_decoder_input + decoding_input_qa_puzzle << std::endl;
            return false;
        }
        if(fs::is_regular_file(folder_decoder_input + decoding_input_msg_encrypted) == false)
        {
            std::cerr << "ERROR not a regular file " << folder_decoder_input + decoding_input_msg_encrypted << std::endl;
            return false;
        }

        if(fs::exists(folder_decoder_output)==false)
        {
            fs::create_directories(folder_decoder_output);
        }
        if(fs::is_directory(folder_decoder_output)==false)
        {
            std::cerr << "ERROR folder_decoder_output is not a folder " << folder_decoder_output << std::endl;
            return false;
        }

//        if(fs::is_regular_file(folder_decoder_output + decoding_output_msg_unencrypted) == false)
//        {
//            std::cerr << "ERROR not a regular file " << folder_decoder_output + decoding_output_msg_unencrypted<< std::endl;
//            return false;
//        }

        decryptor decr(folder_decoder_input + decoding_input_qa_puzzle,
                       folder_decoder_input + decoding_input_msg_encrypted,
                       folder_decoder_output + decoding_output_msg_unencrypted,
                       folder_staging,
                       verbose,
                       (keep_staging == "true") ? true:false,
                       encryped_ftp_user,
                       encryped_ftp_pwd);

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

int main_crypto(int argc, char **argv)
{
    // Main parser
    argparse::ArgumentParser program("crypto");

    // ./crypto batch_encode -i ./crypto_batch.ini
    // ./crypto batch_decode -i ./crypto_batch.ini
    argparse::ArgumentParser batchencode_command("batch_encode");
    {
        batchencode_command.add_description("Encode from a config file");

        batchencode_command.add_argument("-i", "--input")
            .required()
            .help("specify the config file (*.ini)");

        batchencode_command.add_argument("-v", "--verbose")
            .default_value(std::string(""))
            .help("specify the verbose");
    }
    argparse::ArgumentParser batchdecode_command("batch_decode");
    {
        batchdecode_command.add_description("Decode from a config file");

        batchdecode_command.add_argument("-i", "--input")
            .required()
            .help("specify the config file (*.ini)");

        batchdecode_command.add_argument("-v", "--verbose")
            .default_value(std::string(""))
            .help("specify the verbose");
    }

    // Test subcommand
    argparse::ArgumentParser test_command("test");
    {
        test_command.add_description("Test a case");

        test_command.add_argument("-i", "--input")
            .required()
            .help("specify the testcase name.");

        test_command.add_argument("-f", "--folder")
            .default_value(std::string(""))
            .help("specify the root folder of test");

        test_command.add_argument("-v", "--verbose")
            .default_value(std::string(""))
            .help("specify the verbose");
    }

    // Encode subcommand
    argparse::ArgumentParser encode_command("encode");
    {
        encode_command.add_description("Encodes a file into an encrypted file");

        encode_command.add_argument("-i", "--input")
            .required()
            .help("specify the input file.");

        encode_command.add_argument("-o", "--output")
            .required()
            .help("specify the output encrypted file.");

        encode_command.add_argument("-p", "--puzzle")
            .required()
            .help("specify the input puzzle file.");

        encode_command.add_argument("-q", "--qapuzzle")
            .required()
            .help("specify the output qa puzzle file.");

        encode_command.add_argument("-f", "--fullpuzzle")
            .required()
            .help("specify the output full puzzle file.");

        encode_command.add_argument("-u", "--url")
            .help("specify the (optional input) url list file.");

        encode_command.add_argument("-s", "--staging")
            .default_value(std::string(""))
            .help("specify the staging folder.");

        encode_command.add_argument("-v", "--verbose")
            .default_value(std::string(""))
            .help("specify the verbose");

        encode_command.add_argument("-k", "--keep")
            .default_value(std::string(""))
            .help("specify if keeping staging file");
    }

    // Decode subcommand
    argparse::ArgumentParser decode_command("decode");
    {
        decode_command.add_description("Decodes and extracts a file from an encrypted file");

        decode_command.add_argument("-i", "--input")
            .required()
            .help("specify the input encrypted file.");

        decode_command.add_argument("-o", "--output")
            .required()
            .default_value(std::string(""))
            .help("specify the output decrypted file.");

        decode_command.add_argument("-p", "--puzzle")
            .required()
            .help("specify the input puzzle file.");

        decode_command.add_argument("-s", "--staging")
            .default_value(std::string(""))
            .help("specify the staging folder.");

        decode_command.add_argument("-v", "--verbose")
            .default_value(std::string(""))
            .help("specify the verbose");

        decode_command.add_argument("-k", "--keep")
            .default_value(std::string(""))
            .help("specify if keeping staging file");
    }

    // Add the subcommands to the main parser
    program.add_subparser(encode_command);
    program.add_subparser(decode_command);
    program.add_subparser(test_command);
    program.add_subparser(batchencode_command);
    program.add_subparser(batchdecode_command);

    // Parse the arguments
    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return -1;
    }

    if (program.is_subcommand_used("test"))
    {
        auto& cmd = test_command;
        auto testname = cmd.get<std::string>("--input");
        auto folder = cmd.get<std::string>("--folder");
        auto verb = cmd.get<std::string>("--verbose");

        bool verbose = verb.size()>0 ? true : false;

        if (testname == "core")
        {
            test_core(verbose);
        }
        else
        {
            if      (testname == "nowebkey")   DOTESTCASE(testname, folder, true, verbose);
            else if (testname == "zipcontent") DOTESTCASE(testname, folder, false, verbose, "/test.zip");
            else DOTESTCASE(testname, folder, false, verbose);
        }
        return 0;
    }

    if (program.is_subcommand_used("batch_encode"))
    {
        auto& cmd = batchencode_command;
        auto inifile    = cmd.get<std::string>("--input");
        auto verb       = cmd.get<std::string>("--verbose");
        bool verbose = verb.size()>0 ? true : false;

        batch("encode", inifile, verbose);
        return 0;
    }

    if (program.is_subcommand_used("batch_decode"))
    {
        auto& cmd = batchdecode_command;
        auto inifile    = cmd.get<std::string>("--input");
        auto verb       = cmd.get<std::string>("--verbose");
        bool verbose = verb.size()>0 ? true : false;

        batch("decode", inifile, verbose);
        return 0;
    }

    // Encode command
    if (program.is_subcommand_used("encode"))
    {
        auto& cmd = encode_command;
        auto input_path  = cmd.get<std::string>("--input");
        auto output_path = cmd.get<std::string>("--output");
        auto puzzle_path  = cmd.get<std::string>("--puzzle");
        auto qa_puzzle_path  = cmd.get<std::string>("--qapuzzle");
        auto full_puzzle_path  = cmd.get<std::string>("--fullpuzzle");
        auto url_path  = cmd.get<std::string>("--url");
        auto staging_path  = cmd.get<std::string>("--staging");
        auto verb  = cmd.get<std::string>("--verbose");
        auto keep = cmd.get<std::string>("--keep");

        bool verbose = verb.size()>0 ? true : false;
        bool keeping = keep.size()>0 ? true : false;

        // ./crypto encode  -i ./test.zip -o ./test.zip.encrypted -p ./puzzle.txt -q ./partial_puzzle.txt -u ./urls.txt
        std::cout << "crypto ENCODING..." << std::endl;
        encryptor encr(url_path,
                       input_path,
                       puzzle_path,
                       qa_puzzle_path,
                       full_puzzle_path,
                       output_path,
                       staging_path,
                       verbose,
                       keeping);

        if (encr.encrypt(false) == true)
        {
            std::cerr << "crypto ENCODING SUCCESS" << std::endl;
            std::cout << "Encrypted file: " << output_path << std::endl;
            std::cout << "Puzzle file   : "    << qa_puzzle_path << std::endl;
            return 0;
        }
        else
        {
            std::cerr << "ENCODING FAILED" << std::endl;
            return -1;
        }
    }

    // Decode command
    else if (program.is_subcommand_used("decode"))
    {
        auto& cmd = decode_command;
        auto input_path  = cmd.get<std::string>("--input");
        auto output_path = cmd.get<std::string>("--output");
        auto puzzle_path  = cmd.get<std::string>("--puzzle");
        auto staging_path  = cmd.get<std::string>("--staging");
        auto verb  = cmd.get<std::string>("--verbose");
        auto keep = cmd.get<std::string>("--keep");

        bool verbose = verb.size()>0 ? true : false;
        bool keeping = keep.size()>0 ? true : false;

        // ./crypto decode  -i ./test.zip.encrypted -o ./test.zip.unencrypted -p ./puzzle.txt
        std::cout << "crypto DECODING..." << std::endl;
        decryptor decr(puzzle_path,
                       input_path,
                       output_path,
                       staging_path,
                       verbose,
                       keeping);

        if (decr.decrypt() == true)
        {
            std::cout << "crypto DECODING SUCCESS" << std::endl;
            std::cout << "Decrypted file: " << output_path << std::endl;
            return 0;
        }
        else
        {
            std::cerr << "DECODING FAILED" << std::endl;
            return -1;
        }
    }

    // No subcommands were given
    else
    {
        std::cerr << program << std::endl;
    }

    return 0;
}

int main(int argc, char **argv)
{
//    batch("encode", "/home/server/dev/Encryptions/crypto_batch.ini", true);
//    batch("decode", "/home/server/dev/Encryptions/crypto_batch.ini", true);
//    return 0;

    std::chrono::time_point<std::chrono::steady_clock> tstart ;
    std::chrono::time_point<std::chrono::steady_clock> tend ;

    tstart = std::chrono::steady_clock::now();

    int r = main_crypto(argc, argv);

    tend = std::chrono::steady_clock::now();
    std::cout   << "Elapsed time in seconds: "
                << std::chrono::duration_cast<std::chrono::seconds>(tend - tstart).count()<< " sec"
                << std::endl;
    return r;
}
