
#include "RSAGMPTest.h"

namespace RSAGMP
{
   int main_rsa_gmp_test(unsigned int sz = 1024)
   {
       RSAGMP::DefaultTest(sz);
       return 0;
   }
   
   int main_rsa_gmp_test_mt(unsigned int sz = 1024)
   {
       RSAGMP::Utils::TestGenerator generator;
       RSAGMP::CustomTest(sz, &generator, 8, 20);
       return 0;
   }
}
