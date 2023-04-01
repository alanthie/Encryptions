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
#include "../../src/crypto_cfg.hpp"
//using namespace cryptoAL;

#include "ec_gmp/ec_gmp_p_mul.hpp"
#include "SimpleECC/src/test_simple_ecc.hpp"
#include "ecc_point/ecc_curve.hpp"
#include "aes-whitebox/aes_whitebox.hpp"
#include "aes-whitebox/aes_whitebox_compiler.hpp"

#include "menu/menu.h"

std::string VERSION = "v0.3";
std::string FULLVERSION = VERSION + "_" + cryptoAL::get_current_date();

long long keybits8x(long long bits)
{
	if (bits % 8 != 0)
	{
		bits += ( 8 - (bits % 8) );
	}
	return bits;
}

	struct qakeyutil
    {
        static int pos64(char c)
        {
            for(size_t  i=0;i<cryptoAL::BASEDIGIT64.size();i++)
            {
                if (c == cryptoAL::BASEDIGIT64[i])
                {
                    return (int)i;
                }
            }
            std::cerr << "ERROR pos64v invalid base 64 char " << (int)(unsigned char)c << std::endl;
            throw std::string("ERROR pos64() invalid base 64 char ");
            return 0;
        }

        static int pos10(char c)
        {
            for(size_t i=0;i<cryptoAL::BASEDIGIT10.size();i++)
            {
                if (c == cryptoAL::BASEDIGIT10[i])
                {
                    return (int)i;
                }
            }
            std::cerr << "ERROR invalid base 10 char " << (int)c << std::endl;
            throw "ERROR invalid base 10 char ";
            return 0;
        }

        static typeuinteger val(const std::string& s)
        {
            typeuinteger r = 0;
            long long n = (long long)s.size();
            for(long long i=0;i<n;i++)
            {
                r *= 64;
                r += pos64(s[i]);
            }
            return r;
        }
        static typeuinteger val10(const std::string& s)
        {
            typeuinteger r = 0;
            long long n = (long long)s.size();
            for(long long i=0;i<n;i++)
            {
                r *= 10;
                r += pos10(s[i]);
            }
            return r;
        }

        static typeuinteger mod_pow(typeuinteger base, typeuinteger exp, const typeuinteger& mod)
        {
            typeuinteger resoult = 1;

            while (exp > 0)
            {
                if (typeuinteger(exp & 1) == 1)
                    resoult = (base * resoult) % mod;
                base = (base * base) % mod;
                exp >>= 1;
            }

            return resoult;
        }

        static typeuinteger power_modulo(const typeuinteger& a, const typeuinteger& power, const typeuinteger& mod)
        {
            try
            {
                // windows stack overflow....
                // Visual Studio uses 4KB for the stack but reserved 1MB by default. You can change this in "Configuration Properties"->Linker->System->"Stack Reserve Size" to 10MB for example.
                // (a ⋅ b) mod m = [(a mod m) ⋅ (b mod m)] mod m
                if (power == 0) return 1;
                if (power % 2 == 1)
                {
                    return ((a % mod) * power_modulo(a, power - 1, mod)) % mod;
                }

                typeuinteger b = power_modulo(a, power / 2, mod) % mod;
                return (b * b) % mod;
            }
            catch (const std::exception& e)
            {
                std::cerr << "ERROR exception thrown in power_modulo " << e.what() << std::endl;
                throw e;
            }
            catch (...)
            {
                std::cerr << "ERROR exception thrown in power_modulo " << std::endl;
                throw std::string("ERROR exception thrown in power_modulo ");
            }
        }

        static std::string base10_to_base64(const std::string& s)
        {
            typeuinteger m = val10(s);
            return to_base64(m);
        }
        static std::string base64_to_base10(const std::string& s)
        {
            typeuinteger m = val(s);
            return to_base10(m);
        }

        static std::string to_base64(const typeuinteger& v)
        {
            typeuinteger r = v;
            typeuinteger b64 = 64;
            typeuinteger t;
            int digit;
            std::string s;
            while(r > 0)
            {
                t = (r % b64);
                digit = t.toInt();
                if (digit< 0) throw std::string("to base64 bad digit < 0");
                if (digit>63) throw std::string("to base64 bad digit > 63");
                s += cryptoAL::BASEDIGIT64[digit];
                r = r - digit;
                r = r / 64;
            }
            std::reverse(s.begin(), s.end());
            return s;
        }

        static std::string to_base10(const typeuinteger& v)
        {
            typeuinteger r = v;
            int digit;
            std::string s;
            typeuinteger t;
            typeuinteger b10 = 10;
            while(r > 0)
            {
                t = (r % b10);
                digit = t.toInt();
                if (digit<0) throw std::string("to base10 bad digit < 0");
                if (digit>9) throw std::string("to base10 bad digit > 9");
                s += cryptoAL::BASEDIGIT10[digit];
                r = r - digit;
                r = r / 10;
            }
            std::reverse(s.begin(), s.end());
            return s;
        }

		static void TEST()
        {
            std::string serr;

            if (to_base10(1234) != "1234")
            {
                serr = "Error with to_base10 1234";
                std::cerr << serr << std::endl;
                throw serr;
            }

            if (val10("456")  != 456)
            {
                serr = "Error with val10 456";
                std::cerr << serr << std::endl;
                throw serr;
            }

            if (val10("0456") != 456)
            {
                serr = "Error with val10 0456";
                std::cerr << serr << std::endl;
                throw serr;
            }

            typeuinteger m = val10("456");
            std::string m64 = to_base64(m);
            if (val(m64) != m)
            {
                serr = "Error with to_base64/val";
                std::cerr << serr << std::endl;
                throw serr;
            }

            m64 = base10_to_base64("456");
            if (val(m64) != 456)
            {
                serr = "Error with to_base10_to_base64";
                std::cerr << serr << std::endl;
                throw serr;
            }
        }

        static typeuinteger hex_to_uinteger(std::string s)
        {
            typeuinteger r = 0;
            long long n = (long long)s.size();
            for(long long i=0;i<n;i++)
            {
                r *= 16;
                if ((s[i]>= '0') && (s[i]<= '9') )
                    r += (s[i] - '0');
                else if ((s[i]>= 'a') && (s[i]<= 'f') )
                    r += 10 + (s[i] - 'a');
                else if ((s[i]>= 'A') && (s[i]<= 'F') )
                    r +=  10 + (s[i] - 'A');
                else
                   throw "invalid hex";
            }
            return r;
        }

        static bool eccfileexists(const std::filesystem::path& p, std::filesystem::file_status s = std::filesystem::file_status{})
        {
            if(std::filesystem::status_known(s) ? std::filesystem::exists(s) : std::filesystem::exists(p))
                return true;
            else
                return false;
        }

		static bool parse_ecc_domain(	const std::string& FILE, int& klen_inbits,
                                        typeuinteger& a, typeuinteger& b, typeuinteger& p,
                                        typeuinteger& n, typeuinteger& gx, typeuinteger& gy,
                                        typeuinteger& h)
     	{
			if (eccfileexists(FILE) == false)
			{
				std::cerr << "no file: " << FILE << std::endl;
				return false;
			}

			std::string s;

			s = cryptoAL::get_block_infile(FILE, "\"p\":" , "},");
			if (s.size() == 0) return false;
			{
                //std::cout << "s = " << s << std::endl;
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                p = hex_to_uinteger(t);
			}
			std::cout << "p = " << p << " bits: " << p.bitLength() << std::endl;

			klen_inbits = p.bitLength();

			s = cryptoAL::get_block_infile(FILE, "\"a\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                a = hex_to_uinteger(t);
			}
			std::cout << "a = " << a << " bits: " << a.bitLength() << std::endl;

			s = cryptoAL::get_block_infile(FILE, "\"b\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                b = hex_to_uinteger(t);
			}
			std::cout << "b = " << b << " bits: " << b.bitLength() << std::endl;

			s = cryptoAL::get_block_infile(FILE, "\"order\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                n = hex_to_uinteger(t);
			}
			std::cout << "n = " << n << " bits: " <<n.bitLength() << std::endl;

			s = cryptoAL::get_block_infile(FILE, "\"x\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                gx = hex_to_uinteger(t);
			}
			std::cout << "gx = " << gx << " bits: " << gx.bitLength() << std::endl;

			s = cryptoAL::get_block_infile(FILE, "\"y\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                gy = hex_to_uinteger(t);
			}
			std::cout << "gy = " << gy << " bits: " << gy.bitLength() << std::endl;

			h = 1;
			return true;
		 }

    };

using namespace ns_menu;;

void  menu()
{

    long long choice = 1;
    long long last_choice = 1;
    //long long n;

	bool first_time = true;
	bool cfg_parse_result = false;
	std::string cfg_file;
	cryptoAL::crypto_cfg cfg("", false);

// NEW MENU....
//ns_menu::main_menu mm(cfg, FULLVERSION, cfg_file);
//mm.run();

    std::string schoice;
    while(choice != 0)
    {
        std::cout << "====================================" << std::endl;
        std::cout << "QA version   : " << FULLVERSION   << std::endl;

		if (cfg_parse_result == false)
			std::cout << "Not using a configuration file" <<std::endl;
		else
			std::cout << "Current configuration file: [" << cfg_file << "]" << std::endl;

        std::cout << "Select a task: " << std::endl;
        std::cout << "====================================" << std::endl;
        std::cout << "0. Quit" << std::endl;
        std::cout << "*. Last choice" << std::endl;
        std::cout << "1. Use a configuration file for default parameters" << std::endl;
        std::cout << "2. Show configuration" << std::endl;
        std::cout << "3. HEX(file, position, keysize)" << std::endl;
        std::cout << "4. Puzzle: Make random puzzle from shared binary (like USB keys) data" << std::endl;
        std::cout << "5. Puzzle: Resolve puzzle" << std::endl;
        std::cout << "6. WhiteBox keys AES 512-32768 bits - create new key tables" << std::endl;
        std::cout << "7.  RSA Key: View my private RSA key" << std::endl;
        std::cout << "8.  RSA Key: View my public RSA key (also included in the private db)" << std::endl;
		std::cout << "81. RSA Key: View other public RSA key" << std::endl;
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
		std::cout << "25. EC Key: View my public elliptic curve keys (also included in the private db)" << std::endl;
		std::cout << "26. EC Key: View other public elliptic curve keys" << std::endl;
        std::cout << "==> ";

		if (first_time)
		{
			schoice = "1";
		}
		else
		{
        	std::cin >> schoice;
		}

        if (schoice == "*") choice = last_choice;
        else choice = cryptoAL::str_to_ll(schoice);
        std::cout << std::endl;

        if (choice == -1) continue;
        last_choice = choice;

        if (choice == 0) return;
        else if (choice == 1)
        {
			// "1. Use a config file"
			first_time = false;

			std::cout << "Enter full path of the config file (0 = ./cfg.ini, 1 = skip): ";
			std::string sfile;
			std::cin >> sfile;
			if (sfile.size() == 0)
			{
			}
			else
			{
				if (sfile == "1")
				{
					continue;
				}

				if (sfile == "0") sfile = "./cfg.ini";
				if (cryptoAL::fileexists(sfile) == true)
				{
					cfg_file = sfile;
					cfg.reset_cfg(cfg_file);
					cfg_parse_result = cfg.parse();

					if (cfg_parse_result)
					{
					}
					else
					{
					}
				}
			}

/*
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
*/
        }

        else if (choice == 2)
        {
			// 2. Show configuration"
			if (cfg_parse_result)
			{
				cfg.show();
			}
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
			if (true)
			{
			    std::cout << "Select one 1=AES512, 2=AES1024, 3=AES2048, 4=AES4096, 5=AES8192, 6=AES16384, 7=AES32768 ";
				std::string spos;
				std::cin >> spos;
				long long pos = cryptoAL::str_to_ll(spos);
				if (pos<1) pos = 1;
				if (pos>7) pos = 6;

				std::string aes;
				if (pos==1) aes = "aes512";
				else if (pos==2) aes = "aes1024";
				else if (pos==3) aes = "aes2048";
				else if (pos==4) aes = "aes4096";
				else if (pos==5) aes = "aes8192";
				else if (pos==6) aes = "aes16384";
				else if (pos==7) aes = "aes32768";

				std::cout << "Enter key name (4 *.tbl files are generated in current directory, you can move them): ";
				std::string kn;
				std::cin >> kn;
				if (kn.size()==0) continue;

				kn = kn + std::string("_") + cryptoAL::get_current_time_and_date_short();
				std::cerr << "key name is: " << kn << std::endl;

				std::string file_for_key;
				std::string file_for_xor;

				std::cout << "Enter file to use to generate the key (0 = ./binary.dat.1) : ";
				std::cin >> file_for_key;
				if (file_for_key.size()==0) continue;
				if (file_for_key == "0") file_for_key = "./binary.dat.1";

				std::cout << "Enter file to use to generate the xor (0 = ./binary.dat.2) : ";
				std::cin >> file_for_xor;
				if (file_for_xor.size()==0) continue;
				if (file_for_xor == "0") file_for_xor = "./binary.dat.2";

				std::string pos_for_key;
				std::string pos_for_xor;
				long long pos1;
				long long pos2;

				std::cout << "Enter file position for key (0 = first byte) : ";
				std::cin >> pos_for_key;
				if (pos_for_key.size()==0) continue;
				if (pos_for_key == "0") pos1 = 0;
				pos1 = cryptoAL::str_to_ll(pos_for_key);
				if (pos1 < 0) pos1 = 0;

				std::cout << "Enter file position for xor (0 = first byte) : ";
				std::cin >> pos_for_xor;
				if (pos_for_xor.size()==0) continue;
				if (pos_for_xor == "0") pos2 = 0;
				pos2 = cryptoAL::str_to_ll(pos_for_xor);
				if (pos2 < 0) pos2 = 0;

				int r = WBAES::generate_aes(file_for_key, (uint32_t)pos1, file_for_xor, (uint32_t)pos2, aes, "./", kn, true);		// CREATE
				if (r!=0)
				{
					std::cerr << "ERROR creating aes" << std::endl;
					continue;
				}
				WBAES::wbaes_instance_mgr aes_instance_mgr(aes, "./", kn, true, true);	// LOAD
				WBAES::wbaes_vbase* paes = aes_instance_mgr.get_aes();
				if (paes == nullptr) continue;
				int N = 2 * paes->key_length(); // 2x test

				std::string splain 		= cryptoAL::generate_base16_random_string(2*N); // 2 * for base16
				std::string splaincopy 	= splain;
				size_t plainLen = splain.size();

				//uint8_t eout[plainLen] = {0};
				//uint8_t dout[plainLen] = {0};
				std::vector<uint8_t> eout(plainLen, 0);
				std::vector<uint8_t> dout(plainLen, 0);

				//NO KEY!!!!!!!!!!!!!!!!!! but BIG *.tbl
				const unsigned char iv[16] = {0x60, 0x61, 0x82, 0x93, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

				// aes
				std::cout << "AES test message: ";
				for(size_t i=0;i<plainLen;i++) std::cout << (int)splain[i];
				std::cout <<std::endl;

				paes->aes_whitebox_encrypt_cfb(iv, (uint8_t*)splaincopy.data(), plainLen, eout.data());
				std::cout << "AES encrypt: ";
				for(size_t i=0;i<plainLen;i++) std::cout << (int)eout[i];
				std::cout <<std::endl;

				paes->aes_whitebox_decrypt_cfb(iv, eout.data(), plainLen, dout.data());
				std::cout << "AES decrypt: ";
				for(size_t i=0;i<plainLen;i++) std::cout << (int)dout[i];
				std::cout <<std::endl;

				for(size_t i=0;i<plainLen;i++)
				{
					if (dout[i] != splain[i])
					{
						std::cout << "Error with binary AES cfb algo "<< i <<std::endl;
						std::cout << (int)dout[i]<<std::endl;
						std::cout << (int)splain[i]<<std::endl;
						break;
					}
				}
				std::cout << "TEST OK with binary AES cfb algo "<<std::endl;

			}
        }

		else if (choice == 7)
        {
			// 7.  RSA Key: View my private RSA key"
			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path for my private rsa database " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				std::cin >> pathdb;
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

			std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_RSA_private;

			// View
			if (cryptoAL::fileexists(fileRSADB) == true)
			{
				std::ifstream infile;
				infile.open (fileRSADB, std::ios_base::in);
				infile >> bits(map_RSA_private);
				infile.close();

                if (onlysummary == false)
                {
                    for(auto& [user, k] : map_RSA_private)
                    {
                        std::cout << "key name: " << user << std:: endl;
                        std::cout << "key size: " << k.key_size_in_bits << std:: endl;
                        std::cout << "key public  n (base 10): " << k.get_n()<< std:: endl;
                        std::cout << "key public  e (base 10): " << k.get_e() << std:: endl;
                        std::cout << "key private d (base 10): " << k.get_d() << std:: endl;
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
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
          	for(auto& [user, k] : map_RSA_private)
          	{
              	std::cout << "[r]" << user << std:: endl;
          	}
          	std::cout << std:: endl;
		}

	  	else if (choice == 8)
     	{
			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PUBLIC_DB;
			}
			else
			{
				std::cout << "Enter path for my rsa public database " << cryptoAL::RSA_MY_PUBLIC_DB << " (0 = current directory) : ";
				std::string pathdb;
				std::cin >> pathdb;
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PUBLIC_DB;
			}

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_RSA_private;

			// View
          	if (cryptoAL::fileexists(fileRSADB) == true)
      		{
 				std::ifstream infile;
              	infile.open (fileRSADB, std::ios_base::in);
          		infile >> bits(map_RSA_private);
             	infile.close();

             	if (onlysummary == false)
                {
                    for(auto& [user, k] : map_RSA_private)
                    {
                        std::cout << "key name: " << user << std:: endl;
                        std::cout << "key size: " << k.key_size_in_bits << std:: endl;
                        std::cout << "key public  n (base 10): " << k.get_n()<< std:: endl;
                        std::cout << "key public  e (base 10): " << k.get_e() << std:: endl;
                        std::cout << "key private d (base 10): <should be zero> " << k.get_d() << std:: endl;
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "My public keys are in file: " << fileRSADB << std::endl;
					std::cout << "------------------------------------------------------" << std::endl;
					for(auto& [user, k] : map_RSA_private)
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

		else if (choice == 81)
     	{
			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_other_public_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_other_public_rsa + cryptoAL::RSA_OTHER_PUBLIC_DB;
			}
			else
			{
				std::cout << "Enter path of other rsa public database " << cryptoAL::RSA_OTHER_PUBLIC_DB << " (0 = current directory) : ";
				std::string pathdb;
				std::cin >> pathdb;
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_OTHER_PUBLIC_DB;
			}

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_RSA_private;

			// View
          	if (cryptoAL::fileexists(fileRSADB) == true)
      		{
 				std::ifstream infile;
              	infile.open (fileRSADB, std::ios_base::in);
          		infile >> bits(map_RSA_private);
             	infile.close();

             	if (onlysummary == false)
                {
                    for(auto& [user, k] : map_RSA_private)
                    {
                        std::cout << "key name: " << user << std:: endl;
                        std::cout << "key size: " << k.key_size_in_bits << std:: endl;
                        std::cout << "key public  n (base 10): " << k.get_n()<< std:: endl;
                        std::cout << "key public  e (base 10): " << k.get_e() << std:: endl;
                        std::cout << "key private d (base 10): <should be zero> " << k.get_d() << std:: endl;
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "Other public keys are in file: " << fileRSADB << std::endl;
					std::cout << "Links to copy paste into url file when encoding message with RSA" << std::endl;
					std::cout << "------------------------------------------------------" << std::endl;
					for(auto& [user, k] : map_RSA_private)
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
            //std::cout << "9.  RSA Key: Export my public RSA key" << std::endl;
			std::string fileRSADB;
			std::string pathdb;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
                pathdb = cfg.cmdparam.folder_my_private_rsa;
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path of my private rsa database to read: " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				std::cin >> pathdb;
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

			std::string outfile = pathdb + cryptoAL::RSA_MY_PUBLIC_DB;
			std::cout << "Public rsa keys would be saved in: " << outfile << std::endl;

			//std::cout << "Enter file to export to (0 = ./" + cryptoAL::RSA_OTHER_PUBLIC_DB + "): ";
			//std::cin >> outfile;
			//if (outfile == "0") outfile = "./" + cryptoAL::RSA_OTHER_PUBLIC_DB;

			qaclass qa;
			std::map< std::string, generate_rsa::rsa_key > map_RSA_private;
			std::map< std::string, generate_rsa::rsa_key > map_RSA_public;

			if (cryptoAL::fileexists(fileRSADB) == true)
			{
				std::ifstream infile;
				infile.open (fileRSADB, std::ios_base::in);
				infile >> bits(map_RSA_private);
				infile.close();

				for(auto& [keyname, k] : map_RSA_private)
				{
                    generate_rsa::rsa_key key_public;
                    key_public.key_size_in_bits = k.key_size_in_bits ;
                    key_public.s_n = k.s_n ;
                    key_public.s_e = k.s_e ;
                    key_public.s_d = "" ;

                    map_RSA_public.insert(std::make_pair(keyname,  key_public));
				}

				std::cout << "---------------------------" << std::endl;
				std::cout << "Summary of " << outfile << std::endl;
				std::cout << "---------------------------" << std::endl;
				for(auto& [keyname, k] : map_RSA_public)
				{
				  std::cout << keyname << std:: endl;
				}
				std::cout << std:: endl;

				{
					std::ofstream out;
					out.open(outfile, std::ios_base::out);
					out << bits(map_RSA_public);
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

			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path for rsa database " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				std::cin >> pathdb;
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

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

				std::map< std::string, generate_rsa::rsa_key > map_RSA_private;
				if (cryptoAL::fileexists(fileRSADB) == true)
				{
					std::ifstream infile;
					infile.open (fileRSADB, std::ios_base::in);
					infile >> bits(map_RSA_private);
					infile.close();
				}

				bool test_with_gmp = true;
				bool ok = true;
				auto start1 = std::chrono::high_resolution_clock::now();

				int r = RSAGMP::rsa_gmp_test_key(   qakeyutil::base64_to_base10(rkey.s_n) , qakeyutil::base64_to_base10(rkey.s_e),
                                                    qakeyutil::base64_to_base10(rkey.s_d), (uint32_t)klen);
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
						outfile << bits(map_RSA_private);
						outfile.close();
       				 }

                	std::string keyname = std::string("MY_RSAKEY_") + std::to_string(klen) + std::string("_") + cryptoAL::get_current_time_and_date();
                  	map_RSA_private.insert(std::make_pair(keyname,  rkey));

					{
						std::ofstream outfile;
						outfile.open(fileRSADB, std::ios_base::out);
						outfile << bits(map_RSA_private);
						outfile.close();
         			}
                  	std::cout << "key saved as: "  << keyname << " in " << fileRSADB << std:: endl;
					continue;
				}
			}
          	else
			{
			  	std::cerr << "ERROR FAILED to generate key - retry" << std:: endl;
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

			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path for rsa database " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				std::cin >> pathdb;
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

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
										  qakeyutil::base10_to_base64(s_n),
										  qakeyutil::base10_to_base64(s_e),
										  qakeyutil::base10_to_base64(s_d));

				// READ
				std::map< std::string, generate_rsa::rsa_key> map_rsa_private;

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
					std::cerr << "ERROR no file: "  << fileRSADB << std:: endl;
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
      		std::string fileHistoDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_hh.size()>0))
			{
				fileHistoDB = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PRIVATE_ENCODE_DB;
			}
			else
			{
                std::cout << "Enter path of encode history database " << cryptoAL::HHKEY_MY_PRIVATE_ENCODE_DB << " (0 = current directory) : ";
                std::string pathdb;
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileHistoDB = pathdb + cryptoAL::HHKEY_MY_PRIVATE_ENCODE_DB;
			}

			if (cryptoAL::fileexists(fileHistoDB) == true)
			{
				cryptoAL::show_history_key(fileHistoDB);
			}
			else
			{
				std::cerr << "ERROR no file: " << fileHistoDB << std:: endl;
				continue;
			}
        }

        else if (choice == 15)
      	{
            std::string fileHistoDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_hh.size()>0))
			{
				fileHistoDB = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
			}
			else
			{
                std::cout << "Enter path of decode history database " << cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB << " (0 = current directory) : ";
                std::string pathdb;
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileHistoDB = pathdb + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
			}

			if (cryptoAL::fileexists(fileHistoDB) == true)
			{
				cryptoAL::show_history_key(fileHistoDB);
			}
			else
			{
				std::cerr << "ERROR no file: " << fileHistoDB << std:: endl;
				continue;
			}
        }

		else if (choice == 16)
      	{
            //std::cout << "16. Histo: Export public decode history hashes" << std::endl;
            std::string fileHistoPrivateDB;
            std::string fileHistoPublicDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_hh.size()>0))
			{
				fileHistoPrivateDB = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
				fileHistoPublicDB  = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PUBLIC_DECODE_DB;
			}
			else
			{
                std::cout << "Enter path of private decode history database " << cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB << " (0 = current directory) : ";
                std::string pathdb;
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileHistoPrivateDB = pathdb + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
                fileHistoPublicDB  = pathdb + cryptoAL::HHKEY_MY_PUBLIC_DECODE_DB;
            }

			if (cryptoAL::fileexists(fileHistoPrivateDB) == true)
			{
				bool r = cryptoAL::export_public_history_key(fileHistoPrivateDB, fileHistoPublicDB);
				if (r==false)
				{
                    std::cerr << "ERROR export FAILED" << std:: endl;
				}
				else
				{
                    std::cout << "export OK " << fileHistoPublicDB <<  std:: endl;
				}
			}
			else
			{
				std::cerr << "ERROR no file: " << fileHistoPrivateDB << std:: endl;
				continue;
			}
        }
		else if (choice == 17)
      	{
			// Conirming:
			// 	Received HHKEY_OTHER_PUBLIC_DECODE_DB
			// 	Update HHKEY_MY_PRIVATE_ENCODE_DB
			std::string fileHistoPrivateEncodeDB;
            std::string importfile;

			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_hh.size()>0))
			{
				fileHistoPrivateEncodeDB = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
			}
			else
			{
                std::cout << "Enter path of encode history database " << cryptoAL::HHKEY_MY_PRIVATE_ENCODE_DB << " (0 = current directory) : ";
                std::string pathdb;
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileHistoPrivateEncodeDB = pathdb + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
            }

            if ((cfg_parse_result) && (cfg.cmdparam.folder_other_public_hh.size()>0))
			{
				importfile = cfg.cmdparam.folder_other_public_hh + cryptoAL::HHKEY_OTHER_PUBLIC_DECODE_DB;
			}
			else
			{
                std::cout << "Enter path to read received hh (" + cryptoAL::HHKEY_OTHER_PUBLIC_DECODE_DB + ")" << " (0 = current directory) : ";
                std::string pathreaddb;
                std::cin >> pathreaddb;
                if (pathreaddb == "0") pathreaddb = "./";
                importfile = pathreaddb + cryptoAL::HHKEY_OTHER_PUBLIC_DECODE_DB;
            }

			if (cryptoAL::fileexists(fileHistoPrivateEncodeDB) == true)
			{
				if (cryptoAL::fileexists(importfile) == true)
				{
					uint32_t cnt;
					uint32_t n;
					bool r = cryptoAL::confirm_history_key(fileHistoPrivateEncodeDB, importfile, cnt, n);
					if (r==false)
					{
						std::cerr << "ERROR confirm FAILED" << std:: endl;
					}
					else
					{
						std::cerr << "number of new confirm: " << cnt << ", number of hashes: " << n << std:: endl;
					}
				}
				else
				{
					std::cerr << "ERROR no file: " << importfile << std:: endl;

				}
            }
			else
			{
				std::cerr << "ERROR no file: " << fileHistoPrivateEncodeDB << std:: endl;
				continue;
			}
        }

		else if (choice == 18)
      	{
            qaclass qa;

			std::cout << "Enter ecc text file (ecgen output) to parse: ";
			std::string eccfile;
			std::cin >> eccfile;

			std::string fileECCDOMDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
			}
			else
			{
                std::cout << "Enter path for ecc domain database " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
                std::string pathdb;
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileECCDOMDB = pathdb + cryptoAL::ECC_DOMAIN_DB;
			}

			if (cryptoAL::fileexists(eccfile) == true)
			{
                int klen = 0;
				typeuinteger a; typeuinteger b; typeuinteger p;
				typeuinteger n; typeuinteger gx; typeuinteger gy;
				typeuinteger h;

				bool r = qakeyutil::parse_ecc_domain(eccfile, klen, a, b, p, n, gx, gy, h);
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
						std::cerr << "ERROR no file: "  << fileECCDOMDB << std:: endl;
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
                    std::cerr << "ERROR parse error" << std:: endl;
                    continue;
                }
			}
			else
			{
				std::cerr << "ERROR no file: " << eccfile << std:: endl;
				continue;
			}
        }

        else if (choice == 19)
        {
            std::cout << "Example: launch this command in Linux for  512 ECC bits key: ./ecgen --fp -v -m 2g  -u -p -r 512" << std::endl;
            std::cout << "Example: launch this command in Linux for 1024 ECC bits key: ./ecgen --fp -v -m 16g -u -p -r 1024" << std::endl;
            std::cout << "Example: launch this command in Linux for 2048 ECC bits key: ./ecgen --fp -v -m 32g -u -p -r 2048" << std::endl;
            std::cout << "Save the output in a text file then do [Import an elliptic curve domain from text file]" << std::endl;
            std::cout << "Enter 0 to continue" << std::endl;

            std::string fileECCDOMDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
			}
			else
			{
                std::string pathdb;
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileECCDOMDB = pathdb + cryptoAL::ECC_DOMAIN_DB;
            }
        }

        else if (choice == 20)
        {
            std::string fileECCDOMDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
			}
			else
			{
                std::cout << "Enter path for ecc domain database " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
                std::string pathdb;
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileECCDOMDB = pathdb + cryptoAL::ECC_DOMAIN_DB;
			}

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
                        std::cout << "ecc confirmed : " << k.confirmed << std::endl;
                        std::cout << "ecc marked for delete : " << k.deleted << std::endl;
                        std::cout << "ecc usage count: " << k.usage_count<< std::endl;
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

		else if (choice == 21)
        {
            std::string fileECCDOMDB;
            std::string pathdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path of your ecc domain database " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileECCDOMDB = pathdb + cryptoAL::ECC_DOMAIN_DB;
			}

            std::cout << "Enter path of other ecc domain database to import " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
			std::string pathotherdb;
			std::cin >> pathotherdb;
			if (pathotherdb == "0") pathotherdb = "./";
			std::string fileECCDOMOTHERDB = pathotherdb + cryptoAL::ECC_DOMAIN_DB;

            if (fileECCDOMDB == fileECCDOMOTHERDB)
            {
                std::cerr << "ERROR paths should be different" << std::endl;
                continue;
            }
            if (cryptoAL::fileexists(fileECCDOMDB) == false)
			{
                std::cerr << "ERROR no file: " << fileECCDOMDB << std::endl;
                continue;
			}
            if (cryptoAL::fileexists(fileECCDOMOTHERDB) == false)
			{
                std::cerr << "ERROR no file: " << fileECCDOMOTHERDB << std::endl;
                continue;
			}

			qaclass qa;
			std::map< std::string, cryptoAL::ecc_domain > map_ecc_my_domain;
			std::map< std::string, cryptoAL::ecc_domain > map_ecc_other_domain;

			{
                std::ifstream infile;
				infile.open (fileECCDOMDB, std::ios_base::in);
				infile >> bits(map_ecc_my_domain);
				infile.close();
			}

			{
                std::ifstream infile;
				infile.open (fileECCDOMOTHERDB, std::ios_base::in);
				infile >> bits(map_ecc_other_domain);
				infile.close();
			}

            // backup
            {
                std::ofstream outfile;
                outfile.open(fileECCDOMDB + ".bck", std::ios_base::out);
                outfile << bits(map_ecc_my_domain);
                outfile.close();
            }

			int cnt = 0;
			for(auto& [eccname, k] : map_ecc_other_domain)
            {
                if (map_ecc_my_domain.find(eccname) == map_ecc_my_domain.end())
                {
                    map_ecc_my_domain.insert(std::make_pair(eccname, k) );

                    cnt++;
                    std::cout << "---------------" << eccname << std:: endl;
                    std::cout << "adding domain: " << eccname << std:: endl;
                    std::cout << "       prime : " << k.s_p << std:: endl;
                    std::cout << "---------------" << eccname << std:: endl;
                }
            }

            if (cnt == 0)
            {
                std::cout << "no new domain to import" << std:: endl;
                continue;
            }

            {
                std::ofstream outfile;
                outfile.open(fileECCDOMDB, std::ios_base::out);
                outfile << bits(map_ecc_my_domain);
                outfile.close();
            }
        }

		else if (choice == 22)
        {
            std::string fileECCDOMDB;
            std::string pathDOMdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
				pathDOMdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path for ecc domain database " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
                std::cin >> pathDOMdb;
                if (pathDOMdb == "0") pathDOMdb = "./";
                fileECCDOMDB = pathDOMdb + cryptoAL::ECC_DOMAIN_DB;
			}

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

				cryptoAL::ecc_key ek;
				ek.set_domain(domain);
				bool r = ek.generate_private_public_key(true);

				if (r)
				{
                    std::string fileECCKEYDB;
                    if (cfg_parse_result)
                    {
                        fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PRIVATE_DB;
                    }
                    else
                    {
                        std::cout << "Enter path for ecc private keys database " << cryptoAL::ECCKEY_MY_PRIVATE_DB << " (0 = same as domain) : ";
                        std::string pathecckeydb;
                        std::cin >> pathecckeydb;
                        if (pathecckeydb == "0") pathecckeydb = pathDOMdb;
                        fileECCKEYDB = pathecckeydb + cryptoAL::ECCKEY_MY_PRIVATE_DB;
                    }

                    // READ
                    std::map< std::string, cryptoAL::ecc_key > map_ecckey_private;

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
                        std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
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
                    std::cerr << "ERROR generating key " << std:: endl;
                    continue;
                }
			}
			else
			{
				std::cerr << "ERROR no file: "  << fileECCDOMDB << std:: endl;
				continue;
			}
		}

        else if (choice == 23)
        {
            std::string fileECCKEYDB;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PRIVATE_DB;
			}
			else
			{
                std::cout << "Enter path for my private ecc keys db " << cryptoAL::ECCKEY_MY_PRIVATE_DB << " (0 = current directory) : ";
                std::string pathdb;
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileECCKEYDB = pathdb + cryptoAL::ECCKEY_MY_PRIVATE_DB;
			}

			std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, cryptoAL::ecc_key > map_ecckey_private;

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
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
				}
			}
			else
			{
				std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
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
            // 24. EC Key: Export my public elliptic curve keys
            std::string fileECCKEYDB;
            std::string pathdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PRIVATE_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path for my private ecc keys db " << cryptoAL::ECCKEY_MY_PRIVATE_DB << " (0 = current directory) : ";
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileECCKEYDB = pathdb + cryptoAL::ECCKEY_MY_PRIVATE_DB;
			}

			std::string outfile = pathdb + cryptoAL::ECCKEY_MY_PUBLIC_DB;
			std::cout << "Public ecc keys would be saved in: " << outfile << std::endl;;

			qaclass qa;
			std::map< std::string, cryptoAL::ecc_key > map_ecc_private;
			std::map< std::string, cryptoAL::ecc_key > map_ecc_public;

			if (cryptoAL::fileexists(fileECCKEYDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCKEYDB, std::ios_base::in);
				infile >> bits(map_ecc_private);
				infile.close();

				for(auto& [keyname, k] : map_ecc_private)
				{
                    cryptoAL::ecc_key key_public(k.dom, k.s_kg_x, k.s_kg_y, "");
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
			  	std::cerr << "ERROR no file: " << fileECCKEYDB << std:: endl;
				continue;
			}
		}

	  	else if (choice == 25)
     	{
            std::string fileECCKEYDB;
            std::string pathdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PUBLIC_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path for my ecc public database " << cryptoAL::ECCKEY_MY_PUBLIC_DB << " (0 = current directory) : ";
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileECCKEYDB = pathdb + cryptoAL::ECCKEY_MY_PUBLIC_DB;
			}

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, cryptoAL::ecc_key > map_ecc_public;

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
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "My public keys are in file: " << fileECCKEYDB << std::endl;
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
                std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
				continue;
            }
		}

		else if (choice == 26)
     	{
            std::string fileECCKEYDB;
            std::string pathdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_other_public_ecc.size()>0))
			{
				fileECCKEYDB = cfg.cmdparam.folder_other_public_ecc + cryptoAL::ECCKEY_OTHER_PUBLIC_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path of other ecc public database " << cryptoAL::ECCKEY_OTHER_PUBLIC_DB << " (0 = current directory) : ";
                std::cin >> pathdb;
                if (pathdb == "0") pathdb = "./";
                fileECCKEYDB = pathdb + cryptoAL::ECCKEY_OTHER_PUBLIC_DB;
			}

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            std::cin >> osummary;
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			qaclass qa;
			std::map< std::string, cryptoAL::ecc_key > map_ecc_public;

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
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "Other public keys are in file: " << fileECCKEYDB << std::endl;
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
                std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
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
