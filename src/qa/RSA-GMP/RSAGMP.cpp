#include "RSAGMP.h"

using namespace RSAGMP;
using namespace Prime;

#define PRIME_SIZE size/2

mpzBigInteger RSAGMP::Encrypt(const mpzBigInteger &message, const mpzBigInteger &pubkey, const mpzBigInteger &modulus)
{
  if(modulus > 1 && pubkey > 1)
  {
      mpzBigInteger result = Utils::mod_pow(message, pubkey, modulus);
      return result;
  }
  return 0;
}

mpzBigInteger RSAGMP::Decrypt(const mpzBigInteger &message, const mpzBigInteger &privkey, const mpzBigInteger &modulus)
{
  if(modulus > 1 && privkey > 1)
  {
      mpzBigInteger result = Utils::mod_pow(message, privkey, modulus);
      return result;
  }
  return 0;
}


//check the compliance with security standard
inline bool E_check(const mpzBigInteger &E, const mpzBigInteger &Phi)
{
  mpzBigInteger quarter = Phi>>2;
  mpzBigInteger half = Phi>>1;
  mpzBigInteger prec = E-1;
  return coprime(E,Phi) && (prec!=quarter) && (prec!=half) && E > 1;
}

//check the compliance with security standard
inline bool Q_check(mpzBigInteger Q, mpzBigInteger P, unsigned long size)
{
  mpzBigInteger dif = abs(P-Q);
  P=(P-1)>>1;
  Q=(Q-1)>>1;

  return (bitSize(dif) > size/2) && coprime(P,Q);
}

//creates the keys from 2 prime numbers
inline bool KeygenRoutine(mpzBigInteger &primeP, mpzBigInteger &primeQ, mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus, RSAGMP::Utils::Generator *gen, unsigned int size)
{
  mpzBigInteger Phi = (primeP-1) * (primeQ-1);
  modulus = primeP * primeQ; //Mod of key

  pubkey = gen->getBig(size);
  pubkey = pubkey % modulus;//public key

  while (!E_check(pubkey, Phi)) //make sure it is appropriate for security standards
  {
      pubkey++;
  }

  privkey = Utils::inverse(pubkey, Phi, size); //private key

  return true;
}

//prime extraction routine for 2 threads
inline void DualRoutine(mpzBigInteger &primeP, mpzBigInteger &primeQ, RSAGMP::Utils::Generator *gen, unsigned int size, unsigned int precision)
{
  primeP = gen->getBig(PRIME_SIZE);
  auto worker = std::thread(ThreadsNextPrime, &primeP, PRIME_SIZE, precision);
  primeQ = Prime::NextPrime(gen->getBig(PRIME_SIZE), PRIME_SIZE, precision);
  worker.join();


  while(!Q_check(primeP, primeQ, PRIME_SIZE))
  {
      primeQ = gen->getBig(PRIME_SIZE);
      Prime::ParallelNextPrime(&primeQ, PRIME_SIZE, precision);
  }
}

//multithread prime extraction routine
inline void ParallelRoutine(mpzBigInteger &primeP, mpzBigInteger &primeQ, RSAGMP::Utils::Generator *gen, unsigned int size, unsigned int precision, int threads)
{
  primeP = gen->getBig(PRIME_SIZE);
  auto worker = std::thread(ParallelNextPrime, &primeP, PRIME_SIZE, precision, threads/2);
  primeQ = gen->getBig(PRIME_SIZE);
  Prime::ParallelNextPrime(&primeQ, PRIME_SIZE, precision, (threads-threads/2));
  worker.join();


  while(!Q_check(primeP, primeQ, PRIME_SIZE))
  {
      primeQ = gen->getBig(PRIME_SIZE);
      Prime::ParallelNextPrime(&primeQ, PRIME_SIZE, precision, threads);
  }
}

bool RSAGMP::Keygen(mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus, RSAGMP::Utils::Generator *gen, unsigned int size, unsigned int precision)
{
  if(size < 64 || precision < 2)
      return false;

  mpzBigInteger primeP = Prime::NextPrime(gen->getBig(PRIME_SIZE), PRIME_SIZE, precision);
  mpzBigInteger primeQ = Prime::NextPrime(gen->getBig(PRIME_SIZE), PRIME_SIZE, precision);


  while(!Q_check(primeP, primeQ, PRIME_SIZE))
  {
      primeQ = Prime::NextPrime(gen->getBig(PRIME_SIZE), PRIME_SIZE, precision);
  }

  return KeygenRoutine(primeP, primeQ, pubkey, privkey, modulus, gen, size);
}

bool RSAGMP::ParallelKeygen(mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus, RSAGMP::Utils::Generator *gen, unsigned int size, int threads, unsigned int precision)
{
  if(threads < 2)
      return Keygen(pubkey, privkey, modulus, gen, size, precision);
  if(size < 64 || precision < 2)
      return false;

  mpzBigInteger primeP, primeQ;

  if(threads < 4)
      DualRoutine(primeP, primeQ, gen, size, precision);
  else ParallelRoutine(primeP, primeQ, gen, size, precision, threads);


  return KeygenRoutine(primeP, primeQ, pubkey, privkey, modulus, gen, size);
}
