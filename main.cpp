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
#include "crypto_batch.hpp"
#include "encrypt.h"
#include "data.hpp"

bool generate_random_file(std::string filename, long long N=10000)
{
    cryptodata data;
    std::string s;
    std::string si;
    std::string sn;
    const double LIM = 1000*1000*1000;
    srand ((unsigned int)time(NULL));
    srand ((unsigned int)time(NULL));
    long long n;
    long long t;
    random_engine rd;

    for(long long i=0;i<N;i++)
    {
        n = (long long)(rd.get_rand() * LIM);
        si = std::to_string(i);
        sn = std::to_string(n);
        if (i%10 == 0) s = si + ":" + sn + " \n";
        else s = si + ":" + sn + " ";
        data.buffer.write(s.data(), s.size(), -1);

        t = (long long)(rd.get_rand() * 100);
        for(long long j=0;j<t;j++)
            rd.get_rand();
    }
    s = "\n";
    data.buffer.write(s.data(), s.size(), -1);

    bool r = data.save_to_file(filename);
    return r;
}

int main_crypto(int argc, char **argv)
{
    // Argument parser
    try
    {
        argparse::ArgumentParser program("crypto");

        argparse::ArgumentParser random_file_command("random");
        {
            random_file_command.add_description("Generate a file with random numbers");

            random_file_command.add_argument("-o", "--output")
                .default_value(std::string("random.txt"))
                .help("specify the output file");
        }

        argparse::ArgumentParser string_encode_command("string_encode");
        {
            string_encode_command.add_description("Encode a string");

            string_encode_command.add_argument("-i", "--input")
                .required()
                .help("specify the input string.");

            string_encode_command.add_argument("-k", "--key")
                .required()
                .help("specify the key.");
        }

        argparse::ArgumentParser string_decode_command("string_decode");
        {
            string_decode_command.add_description("Decode a string");

            string_decode_command.add_argument("-i", "--input")
                .required()
                .help("specify the input string to decode.");

            string_decode_command.add_argument("-k", "--key")
                .required()
                .help("specify the key.");
        }

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
        program.add_subparser(string_encode_command);
        program.add_subparser(string_decode_command);
        program.add_subparser(random_file_command);

        // Parse the arguments
        try {
            program.parse_args(argc, argv);
        }
        catch (const std::runtime_error& err)
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

            bool verbose = verb.size() > 0 ? true : false;

            if (testname == "core")
            {
                test_core(verbose);
            }
            else
            {
                if (testname == "nowebkey")   DOTESTCASE(testname, folder, true, verbose);
                else if (testname == "zipcontent") DOTESTCASE(testname, folder, false, verbose, "/test.zip");
                else DOTESTCASE(testname, folder, false, verbose);
            }
            return 0;
        }

        if (program.is_subcommand_used("random"))
        {
            auto& cmd = random_file_command;
            auto filename = cmd.get<std::string>("--output");
            generate_random_file(filename);
            return 0;
        }

        if (program.is_subcommand_used("batch_encode"))
        {
            auto& cmd = batchencode_command;
            auto inifile = cmd.get<std::string>("--input");
            auto verb = cmd.get<std::string>("--verbose");
            bool verbose = verb.size() > 0 ? true : false;

            batch("encode", inifile, verbose);
            return 0;
        }

        if (program.is_subcommand_used("batch_decode"))
        {
            auto& cmd = batchdecode_command;
            auto inifile = cmd.get<std::string>("--input");
            auto verb = cmd.get<std::string>("--verbose");
            bool verbose = verb.size() > 0 ? true : false;

            batch("decode", inifile, verbose);
            return 0;
        }

        if (program.is_subcommand_used("string_encode"))
        {
            auto& cmd = string_encode_command;
            auto s = cmd.get<std::string>("--input");
            auto k = cmd.get<std::string>("--key");

            auto se = encrypt_simple_string(s, k);
            bool ok = is_valid_string(se);
            if (ok == false)
            {
                std::cout << "The encrypted string is not a printable string, please use another key " << std::endl;
            }
            else
            {
                std::cout << "The encrypted string is : " << se << std::endl;
            }
            return 0;
        }

        if (program.is_subcommand_used("string_decode"))
        {
            auto& cmd = string_decode_command;
            auto s = cmd.get<std::string>("--input");
            auto k = cmd.get<std::string>("--key");

            auto se = decrypt_simple_string(s, k);
            bool ok = is_valid_string(se);
            if (ok == false)
            {
                std::cout << "The decrypted string is not a printable string, please use another key " << std::endl;
            }
            std::cout << "The decrypted string is : " << decrypt_simple_string(s, k) << std::endl;
            return 0;
        }

        // Encode command
        if (program.is_subcommand_used("encode"))
        {
            auto& cmd = encode_command;
            auto input_path = cmd.get<std::string>("--input");
            auto output_path = cmd.get<std::string>("--output");
            auto puzzle_path = cmd.get<std::string>("--puzzle");
            auto qa_puzzle_path = cmd.get<std::string>("--qapuzzle");
            auto full_puzzle_path = cmd.get<std::string>("--fullpuzzle");
            auto url_path = cmd.get<std::string>("--url");
            auto staging_path = cmd.get<std::string>("--staging");
            auto verb = cmd.get<std::string>("--verbose");
            auto keep = cmd.get<std::string>("--keep");

            bool verbose = verb.size() > 0 ? true : false;
            bool keeping = keep.size() > 0 ? true : false;

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
                std::cout << "Puzzle file   : " << qa_puzzle_path << std::endl;
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
            auto input_path = cmd.get<std::string>("--input");
            auto output_path = cmd.get<std::string>("--output");
            auto puzzle_path = cmd.get<std::string>("--puzzle");
            auto staging_path = cmd.get<std::string>("--staging");
            auto verb = cmd.get<std::string>("--verbose");
            auto keep = cmd.get<std::string>("--keep");

            bool verbose = verb.size() > 0 ? true : false;
            bool keeping = keep.size() > 0 ? true : false;

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
    }
    catch (...)
    {
        std::cerr << "CRYPTO FAILED - exception thrown" << std::endl;
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
