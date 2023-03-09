#include "RSAGMPUtils.h"

using namespace RSAGMP;
using namespace Utils;

//random number generator, only for test
Utils::TestGenerator::TestGenerator()
{
   mpz_init(rand);
   std::random_device rd;
   seed = rd();
   gmp_randinit_mt(rstate);
   gmp_randseed_ui(rstate, seed);
}

//random number generator, only for test
Utils::TestGenerator::TestGenerator(unsigned long long seed)
{
   mpz_init(rand);
   this->seed = seed;
   gmp_randinit_mt(rstate);
   gmp_randseed_ui(rstate, this->seed);
}

Utils::TestGenerator::~TestGenerator()
{
   mpz_clear(rand);
   gmp_randclear(rstate);
}

mpzBigInteger Utils::TestGenerator::getBig(unsigned int size)
{
   mpz_urandomb(rand, rstate, size);
   return mpzBigInteger(rand);
};

unsigned long long Utils::TestGenerator::getInt()
{
   mpzBigInteger temp = this->getBig(64);
   return temp.get_si();
}


mpzBigInteger Utils::pow(mpzBigInteger base, mpzBigInteger exp)
{
   mpzBigInteger resoult = 1;

   while(exp > 0)
   {
       if(mpzBigInteger(exp & 1) == 1)
           resoult *= base;
       base *= base;
       exp >>=1;
   }

   return resoult;
}

mpzBigInteger Utils::mod_pow(mpzBigInteger base, mpzBigInteger exp, const mpzBigInteger &mod)
{
   mpzBigInteger resoult = 1;

   while(exp > 0)
   {
       if(mpzBigInteger(exp & 1) == 1)
           resoult = (base * resoult) % mod;
       base = (base * base) % mod;
       exp >>=1;
   }

   return resoult;
}

mpzBigInteger Utils::inverse(const mpzBigInteger &number, const mpzBigInteger &modulus, unsigned int size)
{
   if (modulus == 0)
   {
       return 0;
   }

   int j = 1;
   mpzBigInteger result, temp, intermediate;
   mpzBigInteger *buffer = new mpzBigInteger[size+3];

   buffer[0] = number;
   buffer[1] = modulus;

   while(buffer[j] != 0) //find intermediate values of greatest common divisor
   {
       j++;
       buffer[j] = buffer[j-2] % buffer[j-1];
   }

   result = 1;
   intermediate = 1;
   temp = 0;

   while(j > 1) //inverse calculation from intermediates values
   {

       j--;
       result = temp;
       temp = intermediate - ((buffer[j-1] / buffer[j]) * temp);
       intermediate = result;
   }

   delete [] buffer;

   if(result > 0)
       return result;
   else
        return modulus + result; // ?
}

bool Utils::coprime (mpzBigInteger a, mpzBigInteger b)
{
   if (b == 0)
       return false;
   mpzBigInteger temp;
   long i = 0;

   while(b > 0) //find greatest common divisor
   {
       i++;
       temp = b;
       b = a % b;
       a = temp;
   }

   return a == 1;
}

mpzBigInteger Utils::byte2biginteger(uint8_t *byte, unsigned int size)
{
   mpz_t z;
   mpz_init(z);
   mpz_import(z, size, 1, sizeof(byte[0]), 0, 0, byte);
   mpzBigInteger r = mpzBigInteger(z);
   mpz_clear(z);
   return r;
}

unsigned Utils::bitSize(const mpzBigInteger &number)
{
   return static_cast<unsigned int>(mpz_sizeinbase(number.get_mpz_t(), 2));
}
