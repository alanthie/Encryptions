#ifndef qa_internal_empty_INCLUDED
#define qa_internal_empty_INCLUDED

#include "mathcommon.h"
#include "prime.h"

#include "../../src/data.hpp"
#include "../../src/crypto_file.hpp"
#include "../../src/Buffer.hpp"
#include "../../src/crypto_const.hpp"

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
        if (fileexists(sfile) == false)
        {
             std::cerr <<  "ERROR File not found - check path " << sfile<< std::endl;
             return "";
        }
        if (pos < 0) pos = 0;
        if (keysize < 1) keysize = 1;

        cryptodata d;
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
};
#endif
