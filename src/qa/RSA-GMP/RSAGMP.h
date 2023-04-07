#ifndef __RSA__RSA__
#define __RSA__RSA__

#include "RSAGMPPrime.h"
#include <thread>

namespace RSAGMP
{
  //using namespace Utils;
  //using namespace Prime;
  using Utils::mpzBigInteger;

  // Keygen initializes keys and modulus, return true for success, false for error
  // size = number of bit of keys
  // gen = your subclass of RSA::Utils::Generator, for random number generation
  // precision = precision of Miller-Rabin primality test, error corrispond to 1/2^2*precision
    bool Keygen( mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus, Utils::Generator *gen, unsigned int size, unsigned int precision = 20);
    bool Keygen3(mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus, Utils::Generator *gen, unsigned int size, unsigned int precision = 20);


  // Parallel version of Keygen, initializes keys and modulus, return true for success, false for error
  // size = number of bit of keys
  // gen = your subclass of RSA::Utils::Generator, for random number generation
  // precision = precision of Miller-Rabin primality test, error corrispond to 1/2^2*precision
  // threads = number of threads to use
    bool ParallelKeygen( mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus, Utils::Generator *gen, unsigned int size, int threads=4, unsigned int precision = 20);
    bool ParallelKeygen3(mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus, Utils::Generator *gen, unsigned int size, int threads=6, unsigned int precision = 20);

  //return message encrypted or 0 for input error
  mpzBigInteger Encrypt(const mpzBigInteger &message, const mpzBigInteger &pubkey, const mpzBigInteger &modulus);

  //return message decrypted or 0 for input error
  mpzBigInteger Decrypt(const mpzBigInteger &message, const mpzBigInteger &privkey, const mpzBigInteger &modulus);
}

#endif /* defined(__RSA__RSA__) */
