#ifndef __RSA__Prime__
#define __RSA__Prime__
#include <gmpxx.h>
#include "RSAGMPUtils.h"
#include <thread>
#include <atomic>
#include <condition_variable>

namespace RSAGMP
{
  namespace Prime
  {
      using namespace Utils;

      //gen = random number generator
      //size = number of  bit of namber tested
      //precision = error of MIller-Rabin test = 1/2^(2* precision)
      //seed = seed for random number generator
      bool IsPrime(const mpzBigInteger &number, unsigned int size, unsigned int precision = 20);

      //gen = random number generator
      //size = number of  bit of prime generated
      //precision = error of Miller-Rabin test = 1/2^(2* precision)
      //seed = seed for random number generator
      mpzBigInteger NextPrime(mpzBigInteger current, unsigned int size, unsigned int precision = 20);

      //to use with threads
      //gen = random number generator
      //size = number of  bit of prime generated
      //precision = error of Miller-Rabin test = 1/2^(2* precision)
      //seed = seed for random number generator
      //current contains the next prime
      void ThreadsNextPrime(mpzBigInteger *current, unsigned int size, unsigned int precision = 20);

      //multithread version of ThreadsNextPrime
      //gen = random number generator
      //size = number of  bit of prime generated
      //precision = error of Miller-Rabin test = 1/2^(2* precision)
      //seed = seed for random number generator
      //threads = number of threads to use
      //current contains the next prime
      void ParallelNextPrime(mpzBigInteger *current, unsigned int size, unsigned int precision = 20, int threads = 2);
  }
}

#endif /* defined(__RSA__Prime__) */
