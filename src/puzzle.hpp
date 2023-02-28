#ifndef _INCLUDES_puzzle
#define _INCLUDES_puzzle

#include <iostream>
#include <fstream>
#include "DES.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "random_engine.hpp"
#include "crypto_const.hpp"
#include "crypto_file.hpp"
#include "data.hpp"


class puzzle
{
public:
    struct QA
    {
        int type = 0; // 0==QA, 1==REM, 2==CHK, 3==BLOCK
        std::string Q;
        std::string A;
        std::string sblockstart;
        std::string sblockend;
    };


    puzzle(bool verb = false) {verbose = verb;}

    void remove_partial(std::string& a)
    {
        std::string  s;
        for(size_t i = 0; i < a.size(); i++)
        {
            if (i==0) continue;
            if (i==a.size()-1) continue;
            if ((a[i] != '\r') && (a[i] != '\n'))
                a[i] = 'x';
        }
    }

    bool make_partial()
    {
        replace_checksum();
        for(size_t i = 0; i < vQA.size(); i++)
        {
            if (vQA[i].type == 0)
            {
                remove_partial(vQA[i].A);
            }
            else if (vQA[i].type == 3)
            {
                remove_partial(vQA[i].Q);
            }
        }
        return true;
    }

    bool is_all_answered() {return true;}

    std::string parse_checksum(std::string s)
    {
        //CHKSUM puzzle : a1531f26f3744f83ee3bf97dba969a1cd7a4b9ed18a6b8f13da16a6f45c726ff
        for(size_t i = 0; i < s.size(); i++)
        {
            if (s[i] == ':')
            {
                for(size_t j = i+1; j < s.size(); j++)
                {
                    if (s[j] != ' ')
                        return s.substr(j);
                }
            }
        }
        return "";
    }

    std::string read_checksum()
    {
        for(size_t i = 0; i < vQA.size(); i++)
        {
            if (vQA[i].type == 2)
            {
                return parse_checksum(vQA[i].Q);
            }
        }
        return "";
    }

    bool is_valid_checksum()
    {
        std::string s1 = checksum();
        std::string s2 = read_checksum();
        if (s1!=s2)
        {
            return false;
        }
        return true;
    }

    void replace_checksum()
    {
        if (chksum_puzzle.size()==0)
        {
            chksum_puzzle = checksum();
        }
    }

    void make_puzzle_before_checksum(cryptodata& temp)
    {
        std::string s;
        for(size_t i = 0; i < vQA.size(); i++)
        {
            if (vQA[i].type == 0) // QA_
            {
                s = QA_TOKEN + " " + "\"" + vQA[i].Q +"\"" +" : " +  "\"" + vQA[i].A + "\"" + "\n";
                temp.buffer.write(s.data(), (uint32_t)s.size(), -1);
            }
            else if (vQA[i].type == 1) // REM
            {
                s = REM_TOKEN + " " + vQA[i].Q + vQA[i].A + "\n";
                temp.buffer.write(s.data(), (uint32_t)s.size(), -1);
            }
             else if (vQA[i].type == 3) //BLOCK
            {
                s = BLOCK_START_TOKEN + vQA[i].sblockstart + "\n"
                    + vQA[i].Q + vQA[i].A
                    + BLOCK_END_TOKEN + vQA[i].sblockend + "\n";
                temp.buffer.write(s.data(), (uint32_t)s.size(), -1);
            }
        }

        std::string sc = CHKSUM_TOKEN + " puzzle :  ";
        auto sz =  temp.buffer.size() + sc.size();
        std::uint32_t sz_padding = 0;
        if (sz % PADDING_MULTIPLE != 0)
        {
            sz_padding = PADDING_MULTIPLE - (sz % PADDING_MULTIPLE );
            char c[1] = {' '};
            for(std::uint32_t i=0;i<sz_padding;i++)
            {
                if (i==sz_padding - 1) c[0] = '\n';
                temp.buffer.write(&c[0], 1, -1);
            }
            std::cout << "padding puzzle " << sz_padding << " total " << sz+sz_padding << std::endl;
        }
    }

    std::string checksum()
    {
        cryptodata temp;
        make_puzzle_before_checksum(temp);

        SHA256 sha;
        sha.update(reinterpret_cast<const uint8_t*> (temp.buffer.getdata()), temp.buffer.size() );
        uint8_t* digest = sha.digest();
        std::string s = SHA256::toString(digest);
        if (verbose)
        {
            std::cout << "chksum puzzle " << temp.buffer.size() << " " << s << std::endl;
        }
        delete[] digest;

        return s;
    }

    bool read_from_file(std::string filename, bool b)
    {
        if (puz_data.read_from_file(filename, b) == true)
        {
            bool r = parse_puzzle();
            if (r)
            {
                chksum_puzzle = checksum();
            }
            return r;
        }
        return false;
    }

    bool save_to_file(std::string filename)
    {
        cryptodata temp;
        make_puzzle_before_checksum(temp);

        std::string s = CHKSUM_TOKEN + " puzzle : " + chksum_puzzle + "\n";
        temp.buffer.write(s.data(), (uint32_t)s.size(), -1);

        bool r = temp.save_to_file(filename);
        return r;
    }

    void make_key(Buffer& rout)
    {
        cryptodata temp;
        make_puzzle_before_checksum(temp);

        size_t r = temp.buffer.size() % PADDING_MULTIPLE;
        rout.write(temp.buffer.getdata(), temp.buffer.size(), 0);

        char c[1] = {'0'};
        for(size_t i = 0; i < PADDING_MULTIPLE - r; i++)
        {
            // padding
            rout.write(c, 1, -1);
        }
    }

    bool parse_block(std::string sblock, std::string sblockstart, std::string sblockend)
    {
        QA q_a;
        q_a.type = 3;
        q_a.Q = sblock;
        q_a.A = "";
        q_a.sblockstart = sblockstart;
        q_a.sblockend = sblockend;
        vQA.push_back( q_a );
        return true;
    }

    bool parse_puzzle()
    {
        size_t pos = 0;
        char c;
        bool in_block = false;
        std::string sline;

        vQA.clear();
        size_t sz = puz_data.buffer.size();

        while (pos < sz)
        {
            c = puz_data.buffer.getdata()[pos];
            if (c!=0)
            {
                if ((c!= '\n') && (c!= '\r'))
                {
                    sline += c;
                }
                else
                {
                    if ((sline.size() >= REM_TOKEN.size()) && (sline.substr(0,REM_TOKEN.size()) == REM_TOKEN))
                    {
                        parse_rem(sline);
                    }
                    else if ((sline.size() >= CHKSUM_TOKEN.size()) && (sline.substr(0,CHKSUM_TOKEN.size()) == CHKSUM_TOKEN))
                    {
                        parse_chksum(sline);
                    }
                    else if ((sline.size() >= QA_TOKEN.size()) && (sline.substr(0,QA_TOKEN.size()) == QA_TOKEN))
                    {
                        parse_qa(sline);
                    }
                    else if ((sline.size() >= BLOCK_START_TOKEN.size()) && (sline.substr(0,BLOCK_START_TOKEN.size()) == BLOCK_START_TOKEN))
                    {
                        in_block = true;
                        std::string sblock = "";
                        std::string sblockstart = "";
                        if (sline.size() > BLOCK_START_TOKEN.size()) sblockstart= sline.substr(BLOCK_START_TOKEN.size());
                        std::string sblockend   = "";
                        sline.clear();

                        while ((pos < sz) && (in_block==true))
                        {
                            c = puz_data.buffer.getdata()[pos];
                            if (c!=0)
                            {
                                if ((c != '\n') && (c != '\r'))
                                {
                                    sline += c;
                                }
                                else
                                {
                                    if ((sline.size() >= BLOCK_END_TOKEN.size()) && (sline.substr(0,BLOCK_END_TOKEN.size()) == BLOCK_END_TOKEN))
                                    {
                                        in_block = false;
                                        if (sline.size() > BLOCK_START_TOKEN.size()) sblockend = sline.substr(BLOCK_START_TOKEN.size());
                                        sline.clear();
                                        parse_block(sblock, sblockstart, sblockend);
                                        break;
                                    }
                                    else
                                    {
                                        if (sline.size() > 0) // "\r\n"; 2lines
                                        {
#ifdef _WIN32
                                            sblock += sline + "\n";
#else
                                            sblock += sline + "\n";
#endif
                                        }
                                        sline.clear();
                                    }
                                }
                            }
                            pos++;
                        }
                    }
                    else
                    {
                        // skip (remove)
                    }
                    sline.clear();
                }
            }
            pos++;
        }

        // Last line
        if ((sline.size() >= QA_TOKEN.size()) && (sline.substr(0,QA_TOKEN.size()) == QA_TOKEN))
        {
            parse_qa(sline);
        }
        else if ((sline.size() >= REM_TOKEN.size()) && (sline.substr(0,REM_TOKEN.size()) == REM_TOKEN))
        {
            parse_rem(sline);
        }
        else if ((sline.size() >= CHKSUM_TOKEN.size()) && (sline.substr(0,CHKSUM_TOKEN.size()) == CHKSUM_TOKEN))
        {
            parse_chksum(sline);
        }
        else
        {
            // skip
        }

        return true;
    }

    bool parse_rem(std::string s)
    {
        if (s.size() < REM_TOKEN.size())
            return false;

        QA q_a;
        q_a.type = 1;
        q_a.Q = "";
        if (s.size() > REM_TOKEN.size()+1)
            q_a.Q = s.substr(REM_TOKEN.size()+1);
        q_a.A = "";
        vQA.push_back( q_a );
        return true;
    }

    bool parse_chksum(std::string s)
    {
        if (s.size() < CHKSUM_TOKEN.size())
            return false;

        QA q_a;
        q_a.type = 2;
        q_a.Q = s;
        q_a.A = "";
        vQA.push_back( q_a );
        return true;
    }

    bool parse_qa(std::string qa)
    {
        size_t pos = 0;
        char c;
        std::string q;
        std::string a;
        bool do_q = true;
        bool do_a = false;
        bool do_sep = false;
        bool start_found = false;
        bool end_found = false;

        size_t sz = qa.size();
        while (pos < sz)
        {
            c = qa[pos];
            if (do_sep==false)
            {
                if (start_found==false)
                {
                    if (c!= '"')
                    {
                        //skip
                    }
                    else
                    {
                        start_found = true;
                    }
                }
                else if (end_found==false)
                {
                    if (c!= '"')
                    {
                        if (do_q) q+= c;
                        if (do_a) a+= c;
                    }
                    else
                    {
                        end_found = true;
                        if (do_q) {do_q=false;do_sep=true;}
                        if (do_a) {do_a=false;}
                    }
                }
            }
            else
            {
                if (c!= ':')
                {
                    //skip
                }
                else
                {
                    //separator_found = true;
                    do_sep = false;
                    start_found = false;
                    end_found = false;
                    do_a = true;
                }
            }
            pos++;
        }
        if ((do_q==true) || (do_a==true) || (do_sep==true))
        {
            return false;
        }

        if (q.size()<=0)
            return false;

        QA q_a;
        q_a.type = 0;
        q_a.Q = q;
        q_a.A = a;
        vQA.push_back( q_a );

        return true;
    }

    cryptodata puz_data;
    std::vector<QA> vQA;
    std::string chksum_puzzle;
    bool verbose;
};



#endif
