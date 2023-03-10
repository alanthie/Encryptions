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
using namespace cryptoAL;

std::string VERSION = "v0.1";
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
        std::cout << "4. Make random puzzle from shared binary (like USB keys) data" << std::endl;
        std::cout << "5. Resolve puzzle" << std::endl;
        std::cout << "6. <Futur usage>" << std::endl;
        std::cout << "7. View my private RSA key" << std::endl;
        std::cout << "8. View other public RSA key" << std::endl;
        std::cout << "9. Extract my public RSA key to file" << std::endl;
        std::cout << "10. Generate RSA key with OPENSSL command line (fastest)" << std::endl;
        std::cout << "11. Test RSA GMP key generator" << std::endl;
        std::cout << "12. Generate RSA key with GMP (fast)" << std::endl;
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
            std::cout << "F(n)" << std::endl;
            std::cout << "Enter a number: ";
            std::string snum;
            std::cin >> snum;
            n = cryptoAL::str_to_ll(snum);
            if (n==-1) continue;

            qaclass qa;
            auto r = qa.F(n);
            std::cout << "F(" << n << ") = " << r << std::endl;
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

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_private;

			// View
			if (cryptoAL::fileexists(fileRSADB) == true)
			{
				std::ifstream infile;
				infile.open (fileRSADB, std::ios_base::in);
				infile >> bits(map_rsa_private);
				infile.close();

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

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_private;

			// View
          	if (cryptoAL::fileexists(fileRSADB) == true)
      		{
 				std::ifstream infile;
              	infile.open (fileRSADB, std::ios_base::in);
          		infile >> bits(map_rsa_private);
             	infile.close();

                for(auto& [user, k] : map_rsa_private)
             	{
					std::cout << "key name: " << user << std:: endl;
					std::cout << "key size: " << k.key_size_in_bits << std:: endl;
					std::cout << "key public  n (base 10): " << k.get_n()<< std:: endl;
					std::cout << "key public  e (base 10): " << k.get_e() << std:: endl;
					std::cout << "key private d (base 10): <should be zero> " << k.get_d() << std:: endl;
					std::cout << std:: endl;
          		}


 				if (cryptoAL::fileexists(fileRSADB) == true)
				{
					std::ifstream infile;
					infile.open (fileRSADB, std::ios_base::in);
					infile >> bits(map_rsa_private);
					infile.close();

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

			int result = qa.generate_rsa_with_openssl(n, e, d, klen, pathopenssl);

			auto finish = std::chrono::high_resolution_clock::now();
            std::cout << "generation elapsed time: " <<  std::chrono::duration_cast<std::chrono::seconds>(finish - start).count() << " seconds"<< std:: endl;


			if (result == 0)
			{
				generate_rsa::rsa_key rkey;
				key.to_rsa_key(rkey, n, e, d, klen);

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

				int r = RSAGMP::rsa_gmp_test_key(rkey.base64_to_base10(rkey.s_n) , rkey.base64_to_base10(rkey.s_e), rkey.base64_to_base10(rkey.s_d), klen);
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
			bool r = RSAGMP::get_keys(klen, &generator, nt, 20, pub, priv, modulus);
			if (r)
			{
				std::string s_n(modulus.get_str());
				std::string s_e(pub.get_str());
				std::string s_d(priv.get_str());

				generate_rsa::rsa_key k;
				generate_rsa::rsa_key rkey( klen,
										  k.base10_to_base64(s_n),
										  k.base10_to_base64(s_e),
										  k.base10_to_base64(s_d));

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

    }
}


int main()
{
    menu();
    return 0;
}
