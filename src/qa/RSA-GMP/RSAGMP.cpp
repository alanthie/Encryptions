#include "RSAGMP.h"
#include <iostream>

using namespace RSAGMP;
using namespace Prime;

#define PRIME_SIZE size/2
// 3 PRIMES
#define PRIME3_SIZE size/3

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

// check the compliance with security standard
inline bool E_check(const mpzBigInteger &E, const mpzBigInteger &Phi)
{
  mpzBigInteger quarter = Phi>>2;
  mpzBigInteger half = Phi>>1;
  mpzBigInteger prec = E-1;
  return coprime(E,Phi) && (prec!=quarter) && (prec!=half) && E > 1;
}
// 3 PRIMES ??
inline bool E_check3(const mpzBigInteger &E, const mpzBigInteger &Phi)
{
  mpzBigInteger quarter = Phi>>2;
  mpzBigInteger half = Phi>>1;
  mpzBigInteger prec = E-1;
  return coprime(E,Phi) && (prec!=quarter) && (prec!=half) && E > 1;
}

// check the compliance with security standard
inline bool Q_check(mpzBigInteger Q, mpzBigInteger P, unsigned long size)
{
  mpzBigInteger dif = abs(P-Q);
  P=(P-1)>>1;
  Q=(Q-1)>>1;
  return (bitSize(dif) > size/2) && coprime(P,Q); //size/2 is 1/4 now
}

// 3 PRIMES
// check the compliance with security standard
inline bool Q_check3(mpzBigInteger Q, mpzBigInteger P, unsigned long size) //??unsigned long vs unsigned int
{
	bool r = true;
	{
	  	mpzBigInteger dif = abs(P-Q);
	  	P=(P-1) >>1; // (p-1)/2 and (q-1)/2 are coprimes
	  	Q=(Q-1) >>1;
	  	r = (bitSize(dif) > size/3) && coprime(P,Q); //size/2 is 1/6 now
	}
	return r;
}

// creates the keys from 2 prime numbers
inline bool KeygenRoutine(	mpzBigInteger &primeP, mpzBigInteger &primeQ,
							mpzBigInteger &pubkey, mpzBigInteger &privkey,
							mpzBigInteger &modulus,
							RSAGMP::Utils::Generator *gen, unsigned int size)
{
  mpzBigInteger Phi = (primeP-1) * (primeQ-1);
  modulus = primeP * primeQ; 	// Mod of key

  pubkey = gen->getBig(size);
  pubkey = pubkey % modulus;	// public key

  while (!E_check(pubkey, Phi)) // make sure it is appropriate for security standards
  {
      pubkey++;
  }
  privkey = Utils::inverse(pubkey, Phi, size); // private key
  return true;
}

// 3 PRIMES
inline bool KeygenRoutine3(	mpzBigInteger &primeP, mpzBigInteger &primeQ, mpzBigInteger &primeR,
							mpzBigInteger &pubkey, mpzBigInteger &privkey,
							mpzBigInteger &modulus,
							RSAGMP::Utils::Generator *gen, unsigned int size)
{
  mpzBigInteger Phi = (primeP-1) * (primeQ-1) * (primeR-1);
  modulus = primeP * primeQ * primeR;  	// modulus of key

  pubkey = gen->getBig(size);
  pubkey = pubkey % modulus;	// public key

  while (!E_check3(pubkey, Phi)) // make sure it is appropriate for security standards
  {
      pubkey++;
  }
  privkey = Utils::inverse(pubkey, Phi, size); // private key

  //std::cout << "primeP:" << primeP << std::endl;
  //std::cout << "primeQ:" << primeQ << std::endl;
  //std::cout << "primeR:" << primeR << std::endl;
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

// 3 PRIMES
inline void DualRoutine3(mpzBigInteger &primeP, mpzBigInteger &primeQ, mpzBigInteger &primeR,
						 RSAGMP::Utils::Generator *gen, unsigned int size, unsigned int precision)
{
 	primeP = gen->getBig(PRIME3_SIZE);
	auto workerP = std::thread(ThreadsNextPrime, &primeP, PRIME3_SIZE, precision);
	primeR = gen->getBig(PRIME3_SIZE);
	auto workerR = std::thread(ThreadsNextPrime, &primeR, PRIME3_SIZE, precision);
  	primeQ = Prime::NextPrime(gen->getBig(PRIME3_SIZE), PRIME3_SIZE, precision);
  	workerP.join();
	workerR.join();

	while(true)
	{
		while(!Q_check3(primeP, primeQ, PRIME3_SIZE))
		{
			primeQ = gen->getBig(PRIME3_SIZE);
			Prime::ParallelNextPrime(&primeQ, PRIME3_SIZE, precision);
		}
		while(!Q_check3(primeP, primeR, PRIME3_SIZE))
		{
			primeR = gen->getBig(PRIME3_SIZE);
			Prime::ParallelNextPrime(&primeR, PRIME3_SIZE, precision);
		}

		if(Q_check3(primeQ, primeR, PRIME3_SIZE))
		{
			break;
		}
	}
}

// multithread prime extraction routine
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

// 3 PRIMES
inline void ParallelRoutine3(	mpzBigInteger &primeP, mpzBigInteger &primeQ, mpzBigInteger &primeR,
								RSAGMP::Utils::Generator *gen, unsigned int size, unsigned int precision, int threads, bool verbose = true)
{
	primeP = gen->getBig(PRIME3_SIZE);
	auto aworkerP = std::thread(ParallelNextPrime, &primeP, PRIME3_SIZE, precision, threads/3);

	primeR = gen->getBig(PRIME3_SIZE);
	auto aworkerR = std::thread(ParallelNextPrime, &primeR, PRIME3_SIZE, precision, threads/3);

	primeQ = gen->getBig(PRIME3_SIZE);
	Prime::ParallelNextPrime(&primeQ, PRIME3_SIZE, precision, threads/3);

	if (aworkerP.joinable()) aworkerP.join();
	if (aworkerR.joinable()) aworkerR.join();

	bool pqOK;
	bool prOK;
	bool qrOK;
	pqOK = Q_check3(primeP, primeQ, PRIME3_SIZE);
    prOK = Q_check3(primeP, primeR, PRIME3_SIZE);
    qrOK = Q_check3(primeQ, primeR, PRIME3_SIZE);

	uint32_t cnt=0;
    while( (!pqOK) || (!prOK) || (!qrOK) )
    {
		cnt++;
		if (cnt > 2)
		{
            // Redo P
            primeP = gen->getBig(PRIME3_SIZE);
            Prime::ParallelNextPrime(&primeP, PRIME3_SIZE, precision, threads);

            cnt = 0;
            pqOK = Q_check3(primeP, primeQ, PRIME3_SIZE);
            prOK = Q_check3(primeP, primeR, PRIME3_SIZE);
            qrOK = Q_check3(primeQ, primeR, PRIME3_SIZE);
		}

        if ((!pqOK) && (!prOK))
        {
            primeQ = gen->getBig(PRIME3_SIZE);
            auto workerQ = std::thread(ParallelNextPrime, &primeQ, PRIME3_SIZE, precision, threads/2);

            primeR = gen->getBig(PRIME3_SIZE);
            auto workerR = std::thread(ParallelNextPrime, &primeR, PRIME3_SIZE, precision, threads/2);

            if (workerQ.joinable()) workerQ.join();
            if (workerR.joinable()) workerR.join();
        }
        else if (!pqOK)
        {
			primeQ = gen->getBig(PRIME3_SIZE);
			Prime::ParallelNextPrime(&primeQ, PRIME3_SIZE, precision, threads);
        }
        else if (!prOK)
        {
            primeR = gen->getBig(PRIME3_SIZE);
			Prime::ParallelNextPrime(&primeR, PRIME3_SIZE, precision, threads);
        }

        pqOK = Q_check3(primeP, primeQ, PRIME3_SIZE);
        prOK = Q_check3(primeP, primeR, PRIME3_SIZE);
        qrOK = Q_check3(primeQ, primeR, PRIME3_SIZE);
    }
}

bool RSAGMP::Keygen(mpzBigInteger &pubkey,
					mpzBigInteger &privkey,
					mpzBigInteger &modulus,
					RSAGMP::Utils::Generator *gen,
					unsigned int size,
					unsigned int precision)
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

// 3 PRIMES
bool RSAGMP::Keygen3(mpzBigInteger &pubkey,
					 mpzBigInteger &privkey,
					 mpzBigInteger &modulus,
					 RSAGMP::Utils::Generator *gen,
					 unsigned int size,
					 unsigned int precision)
{
	if(size < 32*3 || precision < 2)
	  return false;

	mpzBigInteger primeP = Prime::NextPrime(gen->getBig(PRIME3_SIZE), PRIME3_SIZE, precision);
	mpzBigInteger primeQ = Prime::NextPrime(gen->getBig(PRIME3_SIZE), PRIME3_SIZE, precision);
	mpzBigInteger primeR = Prime::NextPrime(gen->getBig(PRIME3_SIZE), PRIME3_SIZE, precision);

	while(true)
	{
		while(!Q_check3(primeP, primeQ, PRIME3_SIZE))
		{
		  primeQ = Prime::NextPrime(gen->getBig(PRIME3_SIZE), PRIME3_SIZE, precision);
		}
		while(!Q_check3(primeP, primeR, PRIME3_SIZE))
		{
		  primeR = Prime::NextPrime(gen->getBig(PRIME3_SIZE), PRIME3_SIZE, precision);
		}
		if(Q_check3(primeQ, primeR, PRIME3_SIZE))
		{
			break;
		}
	}
	return KeygenRoutine3(primeP, primeQ, primeR, pubkey, privkey, modulus, gen, size);
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

// 3 PRIMES
bool RSAGMP::ParallelKeygen3(mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus,
							 RSAGMP::Utils::Generator *gen, unsigned int size, int threads, unsigned int precision)
{
	if(threads < 3)
	  return Keygen3(pubkey, privkey, modulus, gen, size, precision);

	if(size < 3*32|| precision < 2)
	  return false;

	mpzBigInteger primeP, primeQ, primeR;

	if(threads < 6)
        DualRoutine3(primeP, primeQ, primeR, gen, size, precision);
	else
        ParallelRoutine3(primeP, primeQ, primeR, gen, size, precision, threads);

	return KeygenRoutine3(primeP, primeQ, primeR, pubkey, privkey, modulus, gen, size);
}
