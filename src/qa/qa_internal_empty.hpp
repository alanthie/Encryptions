#ifndef qa_internal_empty_INCLUDED
#define qa_internal_empty_INCLUDED

#include "mathcommon.h"
#include "prime.h"

#include "../../src/data.hpp"
#include "../../src/crypto_file.hpp"
#include "../../src/Buffer.hpp"
#include "../../src/crypto_const.hpp"
#include "../../src/crypto_parsing.hpp"
#include "../../src/puzzle.hpp"

class qa_internal_empty
{
public:
    virtual uinteger_t F(long long n )
    {
        std::cout << "IMPLEMENTS YOUR PRIVATE VERSION" << std::endl;
        n = n;
        uinteger_t r = 1;
        return r;
    }

    virtual uinteger_t P(long long n )
    {
        std::cout << "IMPLEMENTS YOUR PRIVATE VERSION" << std::endl;
        n = n;
        uinteger_t r = 1;
        return r;
    }

    virtual std::string HEX(std::string sfile, long long pos, long long keysize)
    {
        bool r = true;
        if (cryptoAL::fileexists(sfile) == false)
        {
             std::cerr <<  "ERROR File not found - check path " << sfile<< std::endl;
             return "";
        }
        if (pos < 0) pos = 0;
        if (keysize < 1) keysize = 1;

        cryptoAL::cryptodata d;
        r = d.read_from_file(sfile);
        if (r == false)
        {
             std::cerr <<  "ERROR Unable to read file " + sfile<< std::endl;
             return "";
        }

        long long len = (long long)d.buffer.size();
        if (pos + keysize >= len)
        {
            std::cerr << "ERROR key pos+len bigger then file size: " << len << std::endl;
            return "";
        }

        Buffer b;
        b.increase_size(keysize);
        b.write(&d.buffer.getdata()[pos], keysize, -1);

        std::string hex;
        char c;
        for(long long i=0;i<keysize;i++)
        {
            c = b.getdata()[i];
            hex += makehex((char)c, 2);
        }

        return hex;
    }

    int system_cmd(std::string cmd)
    {
        return system(cmd.data());
    }

    typeuinteger hex_to_uinteger(std::string s)
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

	virtual int generate_rsa_with_openssl(typeuinteger& n, typeuinteger& e, typeuinteger& d, uint32_t klen_inbits, std::string pathopenssl)
     {
        // TODO more check
        std::string FILE = "staging_tmp_openssl_out.txt";
        std::string p = pathopenssl;
        std::string cmd1;
        std::string cmd2;
        if (p.size() > 0)
        {
            cmd1 = p + std::string("openssl.exe") + std::string(" genrsa -verbose -out key.pem ") + std::to_string(klen_inbits);
            cmd2 = p + std::string("openssl.exe") + std::string(" rsa -in key.pem -text -out ") + FILE;
        }
        else
        {
            cmd1 = std::string("openssl genrsa -out key.pem ") + std::to_string(klen_inbits);
            cmd2 = std::string("openssl rsa -in key.pem -text -out ") + FILE;
        }

        std::cout << "Will run these 2 commands on your OS, then parse and test the result keys: "<< std::endl;
        std::cout << cmd1 << std::endl;
        std::cout << cmd2 << std::endl;

		if (cryptoAL::fileexists(FILE))
            std::remove(FILE.data());

        int r;
       	r = system_cmd(cmd1);
        r = system_cmd(cmd2);

		std::string s = cryptoAL::get_block_infile(FILE, "modulus:" , "publicExponent:");
		s = cryptoAL::remove_hex_delim(s);
		n = hex_to_uinteger(s);
		std::cout << "n = " << n << " bits: " << n.bitLength() << std::endl;

 		e = 65537;
		std::cout << "e = " << e << std::endl;

		s = cryptoAL::get_block_infile(FILE, "privateExponent:" , "prime1:");
		s = cryptoAL::remove_hex_delim(s);
		d = hex_to_uinteger(s);
        std::cout << "d = " << d << " bits: " << d.bitLength() << std::endl;

        if (cryptoAL::fileexists(FILE))
            std::remove(FILE.data());

         return 0;
     }

/*
	virtual bool generate_rsa(generate_rsa::PRIVATE_KEY& key, uint32_t klen_inbits)
	{
        int r = generate_rsa::mainGenRSA(key, klen_inbits);
       	std::cerr << "generate_rsa " << r << std::endl;
        if (r == 0) return true;
         	return true;
	}
*/

	virtual bool make_puzzle(std::string puz_filename, std::string folderpathdata, std::string datashortfile, long long N_bin_files, long long N_qa)
     {
         bool r = true;

        cryptoAL::puzzle puz;
        PRIME::random_engine rd;

        long long fileno;
        long long keypos;
        long long keysize;
        int32_t fs;
        std::string fullfile;

        if (folderpathdata.size() == 0) folderpathdata  = "./";
        if (puz_filename.size() == 0)   puz_filename    = "puzzle.txt";
        if (datashortfile.size() == 0)  datashortfile   = "binary.dat";
        if (N_bin_files <= 0)           N_bin_files     = 100;
        if (N_qa <= 0)                  N_qa            = 10;

        std::string qa_line;
        for(long long fidx= 0; fidx < N_bin_files; fidx++)
        {
            fileno = 1 + (long long)(rd.get_rand() * N_bin_files);
            std::string f = datashortfile + "." + std::to_string(fileno);
            fullfile = folderpathdata + f;
            if (cryptoAL::fileexists(fullfile) == true)
            {
                fs = cryptoAL::filesize(fullfile);

                for(long long i = 0; i < N_qa; i++)
                {
                    // QA "HEX;binary.dat.1;12;10" : "aabbaabbaabbaabbaabb"
                    {
                        keypos =  (long long)(rd.get_rand() * (fs - 80));
                        keysize = 40 + (long long)(rd.get_rand() * 40);
                        if (keypos + keysize < fs)
                        {
                            qa_line =   std::string("QA ") +
                                        std::string("\"") +
                                        std::string("HEX;") + f + ";" + std::to_string(keypos) + ";" + std::to_string(keysize) + std::string(";") +
                                        std::string("\"") ;

                            qa_line +=  std::string(" : ");

                            qa_line += std::string("\"");
                            qa_line += HEX(fullfile, keypos, keysize);
                            qa_line += std::string("\"");
                            r = puz.parse_qa(qa_line);
                      }
                    }
                }
            }
            else
            {
                std::cerr << "ERROR no file (skipping) " << fullfile << std::endl;
            }
        }

        r = puz.save_to_file(puz_filename);

        cryptoAL::puzzle pp;
        r = pp.read_from_file(puz_filename , true);
        r = pp.save_to_file(puz_filename + ".full");
        r = pp.make_partial();
        r = pp.save_to_file(puz_filename + ".qa");

        std::cout << "puzzle draft : " << puz_filename << std::endl;
        std::cout << "puzzle full  : " << puz_filename + ".full" << std::endl;
        std::cout << "puzzle qa    : " << puz_filename + ".qa"   << std::endl;
        return r;
    }

    bool resolve_puzzle(std::string puz_filename, std::string out_puz_filename, std::string folderpathdata)
    {
        bool r = true;

        if (folderpathdata.size() == 0)     folderpathdata      = "./";
        if (puz_filename.size() == 0)       puz_filename        = "puzzle.txt.qa";
        if (out_puz_filename.size() == 0)   out_puz_filename    = "puzzle.txt.qa.resolved";

        cryptoAL::puzzle puz;
        if (puz.read_from_file(puz_filename, true) == false)
        {
            std::cerr << "ERROR " << "reading puzzle " << puz_filename<<std::endl;
            return false;
        }

        std::string s;
        std::string chk = puz.read_checksum();
        std::cout << "chk " << chk << std::endl;

        for(size_t i = 0; i < puz.vQA.size(); i++)
        {
            if (puz.vQA[i].type == 0) // QA_
            {
                std::vector<std::string> v = split(puz.vQA[i].Q, ";");
                if(v.size() >= 4)
                {
                    //see make_puzzle()
                    //QA "HEX;binary.dat.1;12;10" : "aabbaabbaabbaabbaabb"
                    if (v[0] == "HEX")
                    {
                        std::string f = folderpathdata + v[1];
                        if (cryptoAL::fileexists(f) == true)
                        {
                            auto fs = cryptoAL::filesize(f);

                            long long pos = str_to_ll(v[2]);
                            long long sz  = str_to_ll(v[3]);
                            if ((pos >= 0) && (sz>=1) && (pos+sz <= fs))
                            {
                                std::string s = HEX(f, pos, sz);
                                puz.vQA[i].A = s;
                            }
                            else
                            {
                                std::cerr << "ERROR UNRECOGNIZED qa line (skipping) " << puz.vQA[i].Q << std::endl;
                            }
                        }
                        else
                        {
                            std::cerr << "ERROR no file (skipping) " << f << std::endl;
                        }
                  }
                    else
                   {
                        std::cerr << "ERROR UNRECOGNIZED qa line (skipping) " << puz.vQA[i].Q << std::endl;
                    }
                }
            }
            else if (puz.vQA[i].type == 1) // REM
            {
            }
            else if (puz.vQA[i].type == 3) //BLOCK
            {
            }
            else if (puz.vQA[i].type == 2) //chksum
            {
            }
            else
            {
            }
        }
        puz.set_checksum(chk); //??
        puz.save_to_file(out_puz_filename);

        std::cout << "Puzzle full : " << out_puz_filename << std::endl;
        return r;
     }


    std::vector<std::string> split(std::string s, std::string delimiter)
    {
        size_t pos_start = 0, pos_end, delim_len = delimiter.length();
        std::string token;
        std::vector<std::string> res;

        while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos)
        {
            token = s.substr (pos_start, pos_end - pos_start);
            pos_start = pos_end + delim_len;
            res.push_back (token);
        }

        res.push_back (s.substr (pos_start));
        return res;
    }

    long long str_to_ll(const std::string& snum)
    {
        long long r = -1;
        try
        {
            r = std::stoll(snum);
        }
        catch (...)
        {
            r = -1;
        }
        return r;
    }

};
#endif
