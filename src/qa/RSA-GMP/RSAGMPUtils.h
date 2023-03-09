
#ifndef __RSA__Utils__
#define __RSA__Utils__
#include <gmpxx.h>
#include <stdlib.h>
#include <random>

namespace RSAGMP
{
   namespace Utils
   {
       typedef mpz_class mpzBigInteger;
       mpzBigInteger pow(mpzBigInteger base, mpzBigInteger exp);
       mpzBigInteger mod_pow(mpzBigInteger base, mpzBigInteger exp, const mpzBigInteger &mod);
       mpzBigInteger inverse(const mpzBigInteger &number, const mpzBigInteger &modulus, unsigned int size);
       bool coprime (mpzBigInteger a, mpzBigInteger b);
       mpzBigInteger byte2biginteger(uint8_t *byte, unsigned int size);
       unsigned bitSize(const mpzBigInteger &number);


       class Generator
       {
       public:
           virtual mpzBigInteger getBig(unsigned int size)=0;//return a positive BigInteger of size bit
       };

       class TestGenerator: public Generator
       {
       private:
           gmp_randstate_t rstate;
           mpz_t rand;
           unsigned long long seed;
       public:
           TestGenerator();
           TestGenerator(unsigned long long seed);
           ~TestGenerator();
           mpzBigInteger getBig(unsigned int size);
           unsigned long long getInt();//return a positive BigInteger of size bit
       };
   }
}

#endif /* defined(__RSA__Utils__) */