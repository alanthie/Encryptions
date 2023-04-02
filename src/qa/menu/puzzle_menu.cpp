#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../../../src/puzzle.hpp"
#include "../../../src/qa/prime.h"
#include "menu.h"

namespace ns_menu
{
	bool make_puzzle(std::string puz_filename, std::string folderpathdata, std::string datashortfile, long long N_bin_files, long long N_qa)
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
            if (file_util::fileexists(fullfile) == true)
            {
                fs = file_util::filesize(fullfile);

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
                            qa_line += file_util::HEX(fullfile, keypos, keysize);
                            qa_line += std::string("\"");
                            r = puz.parse_qa(qa_line);
                      }
                    }
                }
            }
            else
            {
                std::cerr << "ERROR no file (skipping) " << fullfile << std::endl;
				r = false;
            }
        }

		if (r)
		{
			r = puz.save_to_file(puz_filename);

			cryptoAL::puzzle pp;
			r = pp.read_from_file(puz_filename , true);
			r = pp.save_to_file(puz_filename + ".full");
			r = pp.make_partial();
			r = pp.save_to_file(puz_filename + ".qa");

			std::cout << "puzzle draft : " << puz_filename << std::endl;
			std::cout << "puzzle full  : " << puz_filename + ".full" << std::endl;
			std::cout << "puzzle qa    : " << puz_filename + ".qa"   << std::endl;
		}
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
            r = false;
        }

		if (r)
		{
			std::string s;
			std::string chk = puz.read_checksum();
			std::cout << "chk " << chk << std::endl;

			for(size_t i = 0; i < puz.vQA.size(); i++)
			{
				if (puz.vQA[i].type == 0) // QA_
				{
					std::vector<std::string> v = cryptoAL::parsing::split(puz.vQA[i].Q, ";");
					if(v.size() >= 4)
					{
						//see make_puzzle()
						//QA "HEX;binary.dat.1;12;10" : "aabbaabbaabbaabbaabb"
						if (v[0] == "HEX")
						{
							std::string f = folderpathdata + v[1];
							if (file_util::fileexists(f) == true)
							{
								auto fs = file_util::filesize(f);

								long long pos = cryptoAL::parsing::str_to_ll(v[2]);
								long long sz  = cryptoAL::parsing::str_to_ll(v[3]);
								if ((pos >= 0) && (sz>=1) && (pos+sz <= fs))
								{
									std::string s = file_util::HEX(f, pos, sz);
									puz.vQA[i].A = s;
								}
								else
								{
									std::cerr << "ERROR UNRECOGNIZED qa line (skipping) " << puz.vQA[i].Q << std::endl;
									r = false;
								}
							}
							else
							{
								std::cerr << "ERROR no file (skipping) " << f << std::endl;
								r = false;
							}
					}
					else
					{
						std::cerr << "ERROR UNRECOGNIZED qa line (skipping) " << puz.vQA[i].Q << std::endl;
						r = false;
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
		}
        return r;
     }

	int main_menu::fPuzzle(int choice)
   	{
		int r = 0;

     	if (choice == 1)
      	{
			std::string sf;
		 	if ((cfg_parse_result) && (cfg.cmdparam.folder_local.size()>0))
			{
				sf = cfg.cmdparam.folder_local;
			}
			else
			{
				std::cout << "Enter folder of qa binary random data: ";
				std::string sf;
				std::cin >> sf;
			}

            std::cout << "Enter puzzle filename (0 = defaut): ";
            std::string pf;
            std::cin >> pf;
            if (pf == "0") pf = "";

            std::cout << "Enter data short filename (0 = defaut): ";
            std::string dsf;
            std::cin >> dsf;
            if (dsf == "0") dsf = "";

            std::cout << "Enter number of files to use (0 = defaut): ";
            std::string snf;
            std::cin >> snf;
            long long nf = cryptoAL::parsing::str_to_ll(snf);

            std::cout << "Enter number of questions to generate per file read  (0 = defaut): ";
            std::string snqa;
            std::cin >> snqa;
            long long nqa = cryptoAL::parsing::str_to_ll(snqa);

            make_puzzle(pf, sf, dsf, nf, nqa);
        }

        else if (choice == 2)
        {
			std::string sf;
		 	if ((cfg_parse_result) && (cfg.cmdparam.folder_local.size()>0))
			{
				sf = cfg.cmdparam.folder_local;
			}
			else
			{
				std::cout << "Enter folder of qa binary random data: ";
				std::string sf;
				std::cin >> sf;
			}

            std::cout << "Enter puzzle filename (0 = defaut): ";
            std::string pf;
            std::cin >> pf;
            if (pf == "0") pf = "";

            std::cout << "Enter output resolved puzzle filename (0 = defaut): ";
            std::string opf;
            std::cin >> opf;
            if (opf == "0") opf = "";

            resolve_puzzle(pf, opf, sf);
  		}
        return r;
    }
}

