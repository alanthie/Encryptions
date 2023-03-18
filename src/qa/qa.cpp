#include "mathcommon.h"

//#define USE_EMPTY 1
#ifdef USE_EMPTY
    #define qaclass qa_internal_empty
    #include "qa_internal_empty.hpp"
#else
    #define qaclass qa_internal
    #include "qa_internal.hpp" // NOT SHARED ON GITHUB
#endif
#include <thread>
#include "../c_plus_plus_serializer.h"

#ifdef _WIN32
//add preprocessor directive NOMINMAX
#pragma warning ( disable : 4146 )
#include "RSA-GMP/RSAGMPTest.h"
#else
//LINKER LIB: -lgmp -lgmpxx
#include "RSA-GMP/RSAGMPTest.h"
#endif

#include "../../src/crypto_const.hpp"
#include "../../src/crypto_history.hpp"
#include "../../src/crypto_key_util.hpp"
#include "../../src/crypto_ecckey.hpp"
using namespace cryptoAL;

#include "ec_gmp/ec_gmp_p_mul.hpp"

//#define TEST_ENCRYPT_DECRYPT true
#include "SimpleECC/src/test_simple_ecc.hpp"

#include "ecc_point/ecc_curve.hpp"

std::string VERSION = "v0.2";
std::string FULLVERSION = VERSION + "_" + cryptoAL::get_current_date();

long long keybits8x(long long bits)
{
	if (bits % 8 != 0)
	{
		bits += ( 8 - (bits % 8) );
	}
	return bits;
}

void  menu()
{
    long long choice = 1;
    long long last_choice = 1;
    long long n;

    std::string schoice;
    while(choice != 0)
    {
        std::cout << "====================================" << std::endl;
        std::cout << "QA version   : " << FULLVERSION   << std::endl;
        std::cout << "Select a task: " << std::endl;
        std::cout << "====================================" << std::endl;
        std::cout << "0. Quit" << std::endl;
        std::cout << "*. Last choice" << std::endl;
        std::cout << "1. Custom secret F(n)" << std::endl;
        std::cout << "2. Custom secret P(n)" << std::endl;
        std::cout << "3. HEX(file, position, keysize)" << std::endl;
        std::cout << "4. Puzzle: Make random puzzle from shared binary (like USB keys) data" << std::endl;
        std::cout << "5. Puzzle: Resolve puzzle" << std::endl;
        std::cout << "6. <Futur usage>" << std::endl;
        std::cout << "7.  RSA Key: View my private RSA key" << std::endl;
        std::cout << "8.  RSA Key: View public RSA key" << std::endl;
        std::cout << "9.  RSA Key: Export my public RSA key" << std::endl;
        std::cout << "10. RSA Key: Generate RSA key with OPENSSL command line (fastest)" << std::endl;
        std::cout << "11. RSA Key: Test RSA GMP key generator" << std::endl;
        std::cout << "12. RSA Key: Generate RSA key with GMP (fast)" << std::endl;
        std::cout << "13. ECC: Elliptic Curve test with GMP" << std::endl;
		std::cout << "14. Historical Hashes: View my private encode history hashes" << std::endl;
		std::cout << "15. Historical Hashes: View my public decode history hashes" << std::endl;
		std::cout << "16. Historical Hashes: Export public decode history hashes for confirmation" << std::endl;
		std::cout << "17. Historical Hashes: Confirm other public decode history hashes" << std::endl;
		std::cout << "18. EC Domain: Import an elliptic curve domain generated from ecgen (output manually saved in a file)" << std::endl;
		std::cout << "19. EC Domain: Generate an elliptic curve domain with ecgen" << std::endl;
		std::cout << "20. EC Domain: View my elliptic curve domains" << std::endl;
        std::cout << "21. EC Domain: Import the elliptic curve domains of other" << std::endl;
		std::cout << "22. EC Key: Generate an elliptic curve key" << std::endl;
		std::cout << "23. EC Key: View my private elliptic curve keys" << std::endl;
		std::cout << "24. EC Key: Export my public elliptic curve keys" << std::endl;
		std::cout << "25. EC Key: View public elliptic curve keys" << std::endl;
        std::cout << "==> ";
        std::cin >> schoice;

        if (schoice == "*") choice = last_choice;
        else choice = cryptoAL::str_to_ll(schoice);
        std::cout << std::endl;

        if (choice == -1) continue;
        last_choice = choice;

        if (choice == 0) return;
        else if (choice == 1)
        {
            ecc_curve c;
//            c.test_msg("232FFTT325");
//            c.test_msg("2");
//            c.test_msg("232FF232FFTT325TT325");

            bool r;
            r = c.test_encode_decode("232FFTT325"); if (r) {std::cout << "OK " << std::endl;} else {std::cout << "FAILED " << std::endl;}
            r = c.test_encode_decode("2");          if (r) {std::cout << "OK " << std::endl;} else {std::cout << "FAILED " << std::endl;}
            r = c.test_encode_decode("232FF232FFTT325TT325");if (r) {std::cout << "OK " << std::endl;} else {std::cout << "FAILED " << std::endl;}

            std::cout << "F(n)" << std::endl;
            std::cout << "Enter a number: ";
            std::string snum;
            std::cin >> snum;
            n = cryptoAL::str_to_ll(snum);
            if (n==-1) continue;

            qaclass qa;
            auto rr = qa.F(n);
            std::cout << "F(" << n << ") = " << rr << std::endl;
            std::cout << std::endl;
        }

        else if (choice == 2)
        {
            std::cout << "P(n)" << std::endl;
            std::cout << "Enter a number: ";
            std::string snum;
            std::cin >> snum;
            n = cryptoAL::str_to_ll(snum);
            if (n==-1) continue;

            qaclass qa;
            auto r = qa.P(n);
            std::cout << "P(" << n << ") = " << r << std::endl;
            std::cout << std::endl;
        }

        else if (choice == 3)
        {
            std::cout << "HEX(file, position, keysize)" << std::endl;
            std::cout << "Enter filename: ";
            std::string sfile;
            std::cin >> sfile;

            std::cout << "Enter position: ";
            std::string spos;
            std::cin >> spos;
            long long pos = cryptoAL::str_to_ll(spos);

            std::cout << "Enter keysize: ";
            std::string skeysize;
            std::cin >> skeysize;
            long long keysize = cryptoAL::str_to_ll(skeysize);

            qaclass qa;
            auto r = qa.HEX(sfile, pos, keysize);
            std::cout << "HEX(" << sfile << "," << pos << "," << keysize << ") = " << r << std::endl;
            std::cout << std::endl;
        }

        else if (choice == 4)
      	{
             qaclass qa;
             std::cout << "Enter folder of qa binary random data: ";
             std::string sf;
             std::cin >> sf;

            std::cout << "Enter puzzle filename (0 = defaut): ";
            std::string pf;
            std::cin >> pf;
            if (pf == "0") pf = "";

            std::cout << "Enter data short filename (0 = defaut): ";
            std::string dsf;
            std::cin >> dsf;
            if (dsf == "0") dsf = "";

            std::cout << "Enter N_bin_files (0 = defaut): ";
            std::string snf;
            std::cin >> snf;
            long long nf = cryptoAL::str_to_ll(snf);

            std::cout << "Enter N_qa (0 = defaut): ";
            std::string snqa;
            std::cin >> snqa;
            long long nqa = cryptoAL::str_to_ll(snqa);

            qa.make_puzzle(pf, sf, dsf, nf, nqa);
        }

        else if (choice == 5)
        {
            qaclass qa;
            std::cout << "Enter folder of qa binary random data: ";
            std::string sf;
            std::cin >> sf;

            std::cout << "Enter puzzle filename (0 = defaut): ";
            std::string pf;
            std::cin >> pf;
            if (pf == "0") pf = "";

            std::cout << "Enter output resolved puzzle filename (0 = defaut): ";
            std::string opf;
            std::cin >> opf;
            if (opf == "0") opf = "";

            qa.resolve_puzzle(pf, opf, sf);
         }

   		else if (choice == 6)
        {
        }

		else if (choice == 7)
        {
			std::cout << "Enter path for rsa database " << RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileRSADB = pathdb + RSA_MY_PRIVATE_DB;

			std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_private;

			// View
			if (cryptoAL::fileexists(fileRSADB) == true)
			{
				std::ifstream infile;
				infile.open (fileRSADB, std::ios_base::in);
				infile >> bits(map_rsa_private);
				infile.close();

                if (onlysummary == false)
                {
                    for(auto& [user, k] : map_rsa_private)
                    {
                        std::cout << "key name: " << user << std:: endl;
                        std::cout << "key size: " << k.key_size_in_bits << std:: endl;
                        std::cout << "key public  n (base 10): " << k.get_n()<< std:: endl;
                        std::cout << "key public  e (base 10): " << k.get_e() << std:: endl;
                        std::cout << "key private d (base 10): " << k.get_d() << std:: endl;
                        std::cout << std:: endl;
                    }
				}
			}
			else
			{
				std::cerr << "no file: "  << fileRSADB << std:: endl;
				continue;
			}

			std::cout << "---------------------------" << std::endl;
          	std::cout << "Summary of " << fileRSADB << std::endl;
         	std::cout << "---------------------------" << std::endl;
          	for(auto& [user, k] : map_rsa_private)
          	{
              	std::cout << "[r]" << user << std:: endl;
          	}
          	std::cout << std:: endl;
		}

	  	else if (choice == 8)
     	{
			std::cout << "Enter path for rsa public database " << RSA_OTHER_PUBLIC_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileRSADB = pathdb + RSA_OTHER_PUBLIC_DB;

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_private;

			// View
          	if (cryptoAL::fileexists(fileRSADB) == true)
      		{
 				std::ifstream infile;
              	infile.open (fileRSADB, std::ios_base::in);
          		infile >> bits(map_rsa_private);
             	infile.close();

             	if (onlysummary == false)
                {
                    for(auto& [user, k] : map_rsa_private)
                    {
                        std::cout << "key name: " << user << std:: endl;
                        std::cout << "key size: " << k.key_size_in_bits << std:: endl;
                        std::cout << "key public  n (base 10): " << k.get_n()<< std:: endl;
                        std::cout << "key public  e (base 10): " << k.get_e() << std:: endl;
                        std::cout << "key private d (base 10): <should be zero> " << k.get_d() << std:: endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "Public keys are in file: " << fileRSADB << std::endl;
					std::cout << "Links to copy paste into url file when encoding message with RSA" << std::endl;
					std::cout << "------------------------------------------------------" << std::endl;
					for(auto& [user, k] : map_rsa_private)
					{
					  std::cout << "[r]" << user << std:: endl;
					}
					std::cout << std:: endl;
          		}
      		}
            else
            {
                std::cerr << "no file: "  << fileRSADB << std:: endl;
				continue;
            }
		}

      	else if (choice == 9)
      	{
			std::cout << "Enter path for rsa database " << RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileRSADB = pathdb + RSA_MY_PRIVATE_DB;

			std::cout << "Enter file to export to (0 = ./" + RSA_OTHER_PUBLIC_DB + "): ";
			std::string outfile;
			std::cin >> outfile;
			if (outfile == "0") outfile = "./" + RSA_OTHER_PUBLIC_DB;

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_private;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_public;

			if (cryptoAL::fileexists(fileRSADB) == true)
			{
				std::ifstream infile;
				infile.open (fileRSADB, std::ios_base::in);
				infile >> bits(map_rsa_private);
				infile.close();

				for(auto& [keyname, k] : map_rsa_private)
				{
                    generate_rsa::rsa_key key_public;
                    key_public.key_size_in_bits = k.key_size_in_bits ;
                    key_public.s_n = k.s_n ;
                    key_public.s_e = k.s_e ;
                    key_public.s_d = "" ;

                    map_rsa_public.insert(std::make_pair(keyname,  key_public));
				}

				std::cout << "---------------------------" << std::endl;
				std::cout << "Summary of " << outfile << std::endl;
				std::cout << "---------------------------" << std::endl;
				for(auto& [keyname, k] : map_rsa_public)
				{
				  std::cout << keyname << std:: endl;
				}
				std::cout << std:: endl;

				{
					std::ofstream out;
					out.open(outfile, std::ios_base::out);
					out << bits(map_rsa_public);
					out.close();
				}
			}
			else
			{
			  	std::cerr << "no file: " << fileRSADB << std:: endl;
				continue;
			}
		}

		else if (choice == 10)
      	{
			qaclass qa;
			generate_rsa::PRIVATE_KEY key;

			std::cout << "Enter rsa key length in bits (0 = defaut = 16384): ";
			std::string snum;
			std::cin >> snum;
			long long klen = cryptoAL::str_to_ll(snum);
			if (klen==-1) continue;
			if (klen == 0) klen = 16384;
			klen = keybits8x(klen);

			std::cout << "Enter path for rsa database " << RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileRSADB = pathdb + RSA_MY_PRIVATE_DB;

			std::cout << "Enter path for OPENSSL "<< " (0 = not needed, 1 = D:\\000DEV\\Encryptions\\Exec_Windows\\binOpenSSL\\ for openssl.exe) : ";
			std::string pathopenssl;
			std::cin >> pathopenssl;
			if (pathopenssl == "0") pathopenssl = "";
			if (pathopenssl == "1") pathopenssl = "D:\\000DEV\\Encryptions\\Exec_Windows\\binOpenSSL\\";

			typeuinteger n;
			typeuinteger e;
			typeuinteger d;

			std::cout << "generating/testing key with gmp..." << std::endl;
            auto start = std::chrono::high_resolution_clock::now();

			int result = qa.generate_rsa_with_openssl(n, e, d, (uint32_t)klen, pathopenssl);

			auto finish = std::chrono::high_resolution_clock::now();
            std::cout << "generation elapsed time: " <<  std::chrono::duration_cast<std::chrono::seconds>(finish - start).count() << " seconds"<< std:: endl;


			if (result == 0)
			{
				generate_rsa::rsa_key rkey;
				key.to_rsa_key(rkey, n, e, d, (uint32_t)klen);

				std::map< std::string, generate_rsa::rsa_key > map_rsa_private;
				if (cryptoAL::fileexists(fileRSADB) == true)
				{
					std::ifstream infile;
					infile.open (fileRSADB, std::ios_base::in);
					infile >> bits(map_rsa_private);
					infile.close();
				}

				bool test_with_gmp = true;
				bool ok = true;
				auto start1 = std::chrono::high_resolution_clock::now();

				int r = RSAGMP::rsa_gmp_test_key(   cryptoAL::key_util::base64_to_base10(rkey.s_n) , cryptoAL::key_util::base64_to_base10(rkey.s_e),
                                                    cryptoAL::key_util::base64_to_base10(rkey.s_d), (uint32_t)klen);
				if (r!=0)
				{
					ok = false;
				}

				auto finish1 = std::chrono::high_resolution_clock::now();

				std::cout << "generation elapsed time: " <<  std::chrono::duration_cast<std::chrono::seconds>(finish - start).count() << " seconds"<< std:: endl;
				std::cout << "testing elapsed time:    " <<  std::chrono::duration_cast<std::chrono::milliseconds>(finish1 - start1).count() << " milliseconds"<< std:: endl;

				if (test_with_gmp == false)
				{
					auto start1 = std::chrono::high_resolution_clock::now();
					std::cout << "Testing key..." << std:: endl;
					std::string rsa_msg = "A10";
					typeuinteger encoded;
					std::string s;
					try
					{
						encoded = rkey.encode(rsa_msg);
						s = rkey.decode(e);

						auto finish1 = std::chrono::high_resolution_clock::now();
						std::chrono::duration<double, std::milli> elapsed1 = finish1 - start1;
						std::cout << "Testing elapsed time: " << elapsed1.count() / 1000 << " sec" << std:: endl;
					}
					catch(...)
					{
						ok = false;
						std::cerr << "ERROR encoding/decoding - exception thrown" << std:: endl;
					}

					if (ok)
					{
						if (rsa_msg != s)
						{
						 	 std::cerr << "ERROR encoding/decoding with key" << std:: endl;
						}
					}
				}

				if (ok)
				{
 					// backup
             		{
						std::ofstream outfile;
						outfile.open(fileRSADB + ".bck", std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
       				 }

                	std::string keyname = std::string("MY_RSAKEY_") + std::to_string(klen) + std::string("_") + get_current_time_and_date();
                  	map_rsa_private.insert(std::make_pair(keyname,  rkey));

					{
						std::ofstream outfile;
						outfile.open(fileRSADB, std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
         			}
                  	std::cout << "key saved as: "  << keyname << " in " << fileRSADB << std:: endl;
					continue;
				}
			}
          	else
			{
			  	std::cerr << "FAILED to generate key - retry" << std:: endl;
				continue;
			}
		}

   		else if (choice == 11)
		{
			int nt = std::thread::hardware_concurrency();
			std::cout << "using " << nt << " threads - test keys 1024 to 16384" << std::endl;
			RSAGMP::Utils::TestGenerator generator;
			RSAGMP::CustomTest(1024, &generator, nt);
			RSAGMP::CustomTest(2048, &generator, nt);
			RSAGMP::CustomTest(4096, &generator, nt);
			RSAGMP::CustomTest(4096*2, &generator, nt);
			RSAGMP::CustomTest(4096*4, &generator, nt);
		}

		else if (choice == 12)
      	{
			qaclass qa;
			generate_rsa::PRIVATE_KEY key;

			std::cout << "Enter rsa key length in bits (0 = defaut = 2048): ";
			std::string snum;
			std::cin >> snum;
			long long klen = cryptoAL::str_to_ll(snum);
			if (klen==-1) continue;
			if (klen == 0) klen = 2048;
			klen = keybits8x(klen);

			std::cout << "Enter path for rsa database " << RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileRSADB = pathdb + RSA_MY_PRIVATE_DB;

			int nt = std::thread::hardware_concurrency();
			std::cout << "using " << nt << " threads" << std::endl;

			RSAGMP::Utils::TestGenerator generator;

			RSAGMP::Utils::mpzBigInteger pub;
			RSAGMP::Utils::mpzBigInteger priv;
			RSAGMP::Utils::mpzBigInteger modulus;
			bool r = RSAGMP::get_keys((unsigned int)klen, &generator, nt, 20, pub, priv, modulus);
			if (r)
			{
				std::string s_n(modulus.get_str());
				std::string s_e(pub.get_str());
				std::string s_d(priv.get_str());

				generate_rsa::rsa_key k;
				generate_rsa::rsa_key rkey( (int)klen,
										  cryptoAL::key_util::base10_to_base64(s_n),
										  cryptoAL::key_util::base10_to_base64(s_e),
										  cryptoAL::key_util::base10_to_base64(s_d));

				// READ
				std::map< std::string, generate_rsa::rsa_key > map_rsa_private;

				if (cryptoAL::fileexists(fileRSADB) == false)
				{
					std::ofstream outfile;
					outfile.open(fileRSADB, std::ios_base::out);
					outfile.close();
				}

				if (cryptoAL::fileexists(fileRSADB) == true)
				{
					std::ifstream infile;
					infile.open (fileRSADB, std::ios_base::in);
					infile >> bits(map_rsa_private);
					infile.close();
				}
				else
				{
					std::cerr << "no file: "  << fileRSADB << std:: endl;
					continue;
				}

				// backup
				{
					std::ofstream outfile;
					outfile.open(fileRSADB + ".bck", std::ios_base::out);
					outfile << bits(map_rsa_private);
					outfile.close();
				}

				std::string keyname = std::string("MY_RSAKEY_") + std::to_string(klen) + std::string("_") + cryptoAL::get_current_time_and_date();
				map_rsa_private.insert(std::make_pair(keyname,  rkey));

				{
					std::ofstream outfile;
					outfile.open(fileRSADB, std::ios_base::out);
					outfile << bits(map_rsa_private);
					outfile.close();
				}
				std::cout << "key saved as: "  << keyname << " in " << fileRSADB << std:: endl;
			}
        }

        else if (choice == 13)
      	{
			qaclass qa;

			cryptoECC::test_ecc(0);
            cryptoECC::test_ecc(1);
            std::cout << std:: endl;

            //#define TEST_ENCRYPT_DECRYPT true
            cryptoSimpleECC::test_simple_ecc();
        }

        else if (choice == 14)
      	{
			std::cout << "Enter path for encode history database " << CRYPTO_HISTORY_ENCODE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileHistoDB = pathdb + CRYPTO_HISTORY_ENCODE_DB;

			if (cryptoAL::fileexists(fileHistoDB) == true)
			{
				cryptoAL::show_history_key(fileHistoDB);
			}
			else
			{
				std::cerr << "no file: " << fileHistoDB << std:: endl;
				continue;
			}
        }

        else if (choice == 15)
      	{
			std::cout << "Enter path for decode history database " << CRYPTO_HISTORY_DECODE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileHistoDB = pathdb + CRYPTO_HISTORY_DECODE_DB;

			if (cryptoAL::fileexists(fileHistoDB) == true)
			{
				cryptoAL::show_history_key(fileHistoDB);
			}
			else
			{
				std::cerr << "no file: " << fileHistoDB << std:: endl;
				continue;
			}
        }

		else if (choice == 16)
      	{
		//std::cout << "16. Histo: Export public decode history hashes" << std::endl;
		//std::cout << "17. Histo: Confirm public history hashes" << std::endl;

			std::cout << "Enter path for local decode history database " << CRYPTO_HISTORY_DECODE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileHistoDB = pathdb + CRYPTO_HISTORY_DECODE_DB;

			if (cryptoAL::fileexists(fileHistoDB) == true)
			{
				bool r = cryptoAL::export_public_history_key(fileHistoDB);
				if (r==false)
				{
                    std::cerr << "export FAILED" << std:: endl;
				}
				else
				{
                    std::cout << "export OK " << fileHistoDB + ".public" <<  std:: endl;
				}
			}
			else
			{
				std::cerr << "no file: " << fileHistoDB << std:: endl;
				continue;
			}
        }
		else if (choice == 17)
      	{
			std::cout << "Enter path of encode history database " << CRYPTO_HISTORY_ENCODE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileHistoDB = pathdb + CRYPTO_HISTORY_ENCODE_DB;

			std::cout << "Enter path to read (" + CRYPTO_HISTORY_DECODE_DB + ".public" + ")" +  " from " << " (0 = current directory) : ";
			std::string pathreaddb;
			std::cin >> pathreaddb;
			if (pathreaddb == "0") pathreaddb = "./";
			std::string importfile = pathreaddb + CRYPTO_HISTORY_DECODE_DB + ".public";

			if (cryptoAL::fileexists(fileHistoDB) == true)
			{
				if (cryptoAL::fileexists(importfile) == true)
				{
					uint32_t cnt;
					uint32_t n;
					bool r = confirm_history_key(fileHistoDB, importfile, cnt, n);
					if (r==false)
					{
						std::cerr << "confirm FAILED" << std:: endl;
					}
					else
					{
						std::cerr << "number of new confirm: " << cnt << ", number of hashes: " << n << std:: endl;
					}
				}
				else
				{
					std::cerr << "no file: " << importfile << std:: endl;

				}
            }
			else
			{
				std::cerr << "no file: " << fileHistoDB << std:: endl;
				continue;
			}
        }

		else if (choice == 18)
      	{
            qaclass qa;

			std::cout << "Enter ecc text file (ecgen output) to parse: ";
			std::string eccfile;
			std::cin >> eccfile;

			std::cout << "Enter path for ecc domain database " << ECC_DOMAIN_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileECCDOMDB = pathdb + ECC_DOMAIN_DB;

			if (cryptoAL::fileexists(eccfile) == true)
			{
                int klen = 0;
				typeuinteger a; typeuinteger b; typeuinteger p;
				typeuinteger n; typeuinteger gx; typeuinteger gy;
				typeuinteger h;

				bool r = cryptoAL::key_util::parse_ecc_domain(eccfile, klen, a, b, p, n, gx, gy, h);
				if (r)
				{
                    cryptoAL::ecc_domain dom;
                    cryptoAL::ecc_domain::to_ecc_domain(dom, klen, a, b, p, n, gx, gy, h);

					// READ
					std::map< std::string, cryptoAL::ecc_domain > map_ecc_domain;

					if (cryptoAL::fileexists(fileECCDOMDB) == false)
					{
						std::ofstream outfile;
						outfile.open(fileECCDOMDB, std::ios_base::out);
						outfile.close();
					}

					if (cryptoAL::fileexists(fileECCDOMDB) == true)
					{
						std::ifstream infile;
						infile.open (fileECCDOMDB, std::ios_base::in);
						infile >> bits(map_ecc_domain);
						infile.close();
					}
					else
					{
						std::cerr << "no file: "  << fileECCDOMDB << std:: endl;
						continue;
					}

					// backup
					{
						std::ofstream outfile;
						outfile.open(fileECCDOMDB + ".bck", std::ios_base::out);
						outfile << bits(map_ecc_domain);
						outfile.close();
					}

					//std::string keyname = std::string("MY_RSAKEY_") + std::to_string(klen) + std::string("_") + cryptoAL::get_current_time_and_date();
					map_ecc_domain.insert(std::make_pair(dom.name(), dom) );

					{
						std::ofstream outfile;
						outfile.open(fileECCDOMDB, std::ios_base::out);
						outfile << bits(map_ecc_domain);
						outfile.close();
					}

					std::cout << "elliptic curve domain save as: " << dom.name() << std:: endl;
				}
				else
                {
                    std::cerr << "parse error" << std:: endl;
                    continue;
                }
			}
			else
			{
				std::cerr << "no file: " << eccfile << std:: endl;
				continue;
			}
        }

        else if (choice == 19)
        {
            std::cout << "Example: launch this command in Linux for  512 ECC bits key: ./ecgen --fp -v -m 2g -u -p -r 512" << std::endl;
            std::cout << "Example: launch this command in Linux for 1024 ECC bits key: ./ecgen --fp -v -m 8g -u -p -r 1024" << std::endl;
            std::cout << "Example: launch this command in Linux for 2048 ECC bits key: ./ecgen --fp -v -m 32g -u -p -r 2048" << std::endl;
            std::cout << "Save the output in a text file then do [Import an elliptic curve domain from text file]" << std::endl;
            std::cout << "Enter 0 to continue" << std::endl;
            std::string pathdb;
            std::cin >> pathdb;
            if (pathdb == "0") pathdb = "./";
            std::string fileECCDOMDB = pathdb + ECC_DOMAIN_DB;
        }

        else if (choice == 20)
        {
			std::cout << "Enter path for ecc domain database " << ECC_DOMAIN_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileECCDOMDB = pathdb + ECC_DOMAIN_DB;

			std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, cryptoAL::ecc_domain > map_ecc_domain;

			// View
			if (cryptoAL::fileexists(fileECCDOMDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCDOMDB, std::ios_base::in);
				infile >> bits(map_ecc_domain);
				infile.close();

                if (onlysummary == false)
                {
                    for(auto& [eccname, k] : map_ecc_domain)
                    {
                        std::cout << "ecc name: " << eccname << std:: endl;
                        std::cout << "ecc size: " << k.key_size_bits << std:: endl;
                        std::cout << "ecc a : " << k.s_a << std:: endl;
                        std::cout << "ecc b : " << k.s_b << std:: endl;
                        std::cout << "ecc p : " << k.s_p << std:: endl;
                        std::cout << "ecc n : " << k.s_n<< std:: endl;
                        std::cout << "ecc gx : " << k.s_gx << std:: endl;
                        std::cout << "ecc gy : " << k.s_gy << std:: endl;
                        std::cout << "ecc h : " << k.s_h << std:: endl;
                        std::cout << std:: endl;
                    }
				}
			}
			else
			{
				std::cerr << "no file: "  << fileECCDOMDB << std:: endl;
				continue;
			}

			std::cout << "---------------------------" << std::endl;
          	std::cout << "Summary of " << fileECCDOMDB << std::endl;
         	std::cout << "---------------------------" << std::endl;
          	for(auto& [eccname, k] : map_ecc_domain)
          	{
              	std::cout << eccname << std:: endl;
          	}
          	std::cout << std:: endl;
		}

		else if (choice == 22)
        {
			std::cout << "Enter path for ecc domain database " << ECC_DOMAIN_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileECCDOMDB = pathdb + ECC_DOMAIN_DB;

			qaclass qa;
			std::map< std::string, cryptoAL::ecc_domain > map_ecc_domain;

			// View
			if (cryptoAL::fileexists(fileECCDOMDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCDOMDB, std::ios_base::in);
				infile >> bits(map_ecc_domain);
				infile.close();

				std::cout << "---------------------------" << std::endl;
				std::cout << "Domains summary in " << fileECCDOMDB << std::endl;
				std::cout << "---------------------------" << std::endl;
				std::vector<std::string> vdomname;
				int cnt=0;
				for(auto& [eccname, k] : map_ecc_domain)
				{
					std::cout << "[" << cnt+1 << "]" << eccname << std::endl;
					cnt++;
					vdomname.push_back(eccname);
				}
				std::cout << std:: endl;

				if (cnt == 0)
				{
                    std::cout << "Add ecc domain first" << std::endl;
                    continue;
				}

				std::cout << "Select a ecc domain " << 1 << "-" << std::to_string(cnt) << " (0 = largest key ) : ";
				std::string dom;
				std::cin >> dom;

				long long idom = cryptoAL::str_to_ll(dom);
				if (idom <   1) idom = 1;
				if (idom > cnt) idom = cnt;

				std::string dom_name = vdomname[idom-1];
				auto& domain = map_ecc_domain[dom_name];

				ecc_key ek;
				ek.set_domain(domain);
				bool r = ek.generate_private_public_key(true);

				if (r)
				{
                    std::cout << "Enter path for ecc private keys database " << ECCKEY_MY_PRIVATE_DB << " (0 = same as domain) : ";
                    std::string pathecckeydb;
                    std::cin >> pathecckeydb;
                    if (pathecckeydb == "0") pathecckeydb = pathdb;
                    std::string fileECCKEYDB = pathecckeydb + ECCKEY_MY_PRIVATE_DB;

                    // READ
                    std::map< std::string, ecc_key > map_ecckey_private;

                    if (cryptoAL::fileexists(fileECCKEYDB) == false)
                    {
                        std::ofstream outfile;
                        outfile.open(fileECCKEYDB, std::ios_base::out);
                        outfile.close();
                    }

                    if (cryptoAL::fileexists(fileECCKEYDB) == true)
                    {
                        std::ifstream infile;
                        infile.open (fileECCKEYDB, std::ios_base::in);
                        infile >> bits(map_ecckey_private);
                        infile.close();
                    }
                    else
                    {
                        std::cerr << "no file: "  << fileECCKEYDB << std:: endl;
                        continue;
                    }

                    // backup
                    {
                        std::ofstream outfile;
                        outfile.open(fileECCKEYDB + ".bck", std::ios_base::out);
                        outfile << bits(map_ecckey_private);
                        outfile.close();
                    }

                    std::string keyname = std::string("MY_ECCKEY_") + std::to_string(domain.key_size_bits) + std::string("_") + cryptoAL::get_current_time_and_date();
                    map_ecckey_private.insert(std::make_pair(keyname, ek));

                    {
                        std::ofstream outfile;
                        outfile.open(fileECCKEYDB, std::ios_base::out);
                        outfile << bits(map_ecckey_private);
                        outfile.close();
                    }
                    std::cout << "key saved as: "  << keyname << " in " << fileECCKEYDB << std:: endl;
                }
                else
                {
                    std::cerr << "Error generating key " << std:: endl;
                    continue;
                }
			}
			else
			{
				std::cerr << "no file: "  << fileECCDOMDB << std:: endl;
				continue;
			}
		}

        else if (choice == 23)
        {
			std::cout << "Enter path for ecc db " << ECCKEY_MY_PRIVATE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileECCKEYDB = pathdb + ECCKEY_MY_PRIVATE_DB;

			std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, ecc_key > map_ecckey_private;

			// View
			if (cryptoAL::fileexists(fileECCKEYDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCKEYDB, std::ios_base::in);
				infile >> bits(map_ecckey_private);
				infile.close();

                if (onlysummary == false)
                {
                    for(auto& [kname, k] : map_ecckey_private)
                    {
                        std::cout << "key name: " << kname << std::endl;
                        std::cout << "domain:   " << k.dom.name() << std::endl;
                        std::cout << "key size: " << k.dom.key_size_bits << std::endl;
                        std::cout << "key public  kG_x: " << k.s_kg_x<< std::endl;
                        std::cout << "key public  kG_y: " << k.s_kg_y<< std::endl;
                        std::cout << "key private k   : " << k.s_k << std::endl;
                        std::cout << std:: endl;
                    }
				}
			}
			else
			{
				std::cerr << "no file: "  << fileECCKEYDB << std:: endl;
				continue;
			}

			std::cout << "---------------------------" << std::endl;
          	std::cout << "Summary of " << fileECCKEYDB << std::endl;
         	std::cout << "---------------------------" << std::endl;
          	for(auto& [kname, k] : map_ecckey_private)
          	{
              	std::cout << "[e]" << kname << std:: endl;
          	}
          	std::cout << std:: endl;
		}

		else if (choice == 24)
      	{
			std::cout << "Enter path for ecc database " << ECCKEY_MY_PRIVATE_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileECCKEYDB = pathdb + ECCKEY_MY_PRIVATE_DB;

			std::cout << "Enter file to export to (0 = ./" + ECCKEY_OTHER_PUBLIC_DB + "): ";
			std::string outfile;
			std::cin >> outfile;
			if (outfile == "0") outfile = "./" + ECCKEY_OTHER_PUBLIC_DB;

			qaclass qa;
			std::map< std::string, ecc_key > map_ecc_private;
			std::map< std::string, ecc_key > map_ecc_public;

			if (cryptoAL::fileexists(fileECCKEYDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCKEYDB, std::ios_base::in);
				infile >> bits(map_ecc_private);
				infile.close();

				for(auto& [keyname, k] : map_ecc_private)
				{
                    ecc_key key_public(k.dom, k.s_kg_x, k.s_kg_y, "");
                    map_ecc_public.insert(std::make_pair(keyname,  key_public) );
				}

				std::cout << "---------------------------" << std::endl;
				std::cout << "Summary of " << outfile << std::endl;
				std::cout << "---------------------------" << std::endl;
				for(auto& [keyname, k] : map_ecc_public)
				{
				  std::cout << keyname << std:: endl;
				}
				std::cout << std:: endl;

				{
					std::ofstream out;
					out.open(outfile, std::ios_base::out);
					out << bits(map_ecc_public);
					out.close();
				}
			}
			else
			{
			  	std::cerr << "no file: " << fileECCKEYDB << std:: endl;
				continue;
			}
		}

	  	else if (choice == 25)
     	{
			std::cout << "Enter path for ecc public database " << ECCKEY_OTHER_PUBLIC_DB << " (0 = current directory) : ";
			std::string pathdb;
			std::cin >> pathdb;
			if (pathdb == "0") pathdb = "./";
			std::string fileECCKEYDB = pathdb + ECCKEY_OTHER_PUBLIC_DB;

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, ecc_key > map_ecc_public;

			// View
          	if (cryptoAL::fileexists(fileECCKEYDB) == true)
      		{
 				std::ifstream infile;
              	infile.open (fileECCKEYDB, std::ios_base::in);
          		infile >> bits(map_ecc_public);
             	infile.close();

             	if (onlysummary == false)
                {
                    for(auto& [kname, k] : map_ecc_public)
                    {
                        std::cout << "key name: " << kname << std::endl;
                        std::cout << "domain:   " << k.dom.name() << std::endl;
                        std::cout << "key size: " << k.dom.key_size_bits << std::endl;
                        std::cout << "key public  kG_x: " << k.s_kg_x<< std::endl;
                        std::cout << "key public  kG_y: " << k.s_kg_y<< std::endl;
                        std::cout << "key private k <should be empty> : " << k.s_k << std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "Public keys are in file: " << fileECCKEYDB << std::endl;
					std::cout << "Links to copy paste into url file when encoding message with ECC" << std::endl;
					std::cout << "------------------------------------------------------" << std::endl;
					for(auto& [kname, k] : map_ecc_public)
					{
					  std::cout << "[e]" << kname << std:: endl;
					}
					std::cout << std:: endl;
          		}
      		}
            else
            {
                std::cerr << "no file: "  << fileECCKEYDB << std:: endl;
				continue;
            }
		}


    }

}


int main()
{
    menu();
    return 0;
}
