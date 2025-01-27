#include "RSAGMP.h"
#include <iostream>
#include <algorithm>

using namespace RSAGMP;
using namespace Prime;

#define PRIME_SIZE size/2

// N PRIMES
unsigned int PRIME_NSIZE(unsigned long asize, unsigned int N) {return asize/N;}

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

// check the compliance with security standard
inline bool Q_check(mpzBigInteger Q, mpzBigInteger P, unsigned long sizeOnePrime)
{
  mpzBigInteger dif = abs(P-Q);
  P=(P-1)>>1;
  Q=(Q-1)>>1;
  return (bitSize(dif) >= sizeOnePrime/2) && coprime(P,Q); //size/2 is 1/4 now
}

// 3 PRIMES
// check the compliance with security standard
inline bool Q_checkN(mpzBigInteger Q, mpzBigInteger P, unsigned long sizeOnePrime, unsigned int NPRIMES) //??unsigned long vs unsigned int
{
	bool r = true;
	unsigned int szDiffBit = sizeOnePrime/NPRIMES; // this is Nth root so very small difference
	{
	  	mpzBigInteger dif = abs(P-Q);
	  	P=(P-1) >>1; // (p-1)/2 and (q-1)/2 are coprimes
	  	Q=(Q-1) >>1;
	  	r = (bitSize(dif) >= szDiffBit) && coprime(P,Q); //size/2 is 1/2N now
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

  while (!E_check(pubkey, Phi)) // make sure it is appropriate for security standards
  {
      pubkey++;
  }
  privkey = Utils::inverse(pubkey, Phi, size); // private key
  return true;
}

// N PRIMES
inline bool KeygenRoutineN(	std::vector<mpzBigInteger>& vPrime,
							mpzBigInteger &pubkey, mpzBigInteger &privkey,
							mpzBigInteger &modulus,
							RSAGMP::Utils::Generator *gen,
							unsigned int size,
							unsigned int NPRIMES)
{
    mpzBigInteger Phi = 1;
    for(size_t i=0;i<vPrime.size();i++) Phi *= (vPrime[i] - 1);

    modulus = 1;
    for(size_t i=0;i<vPrime.size();i++) modulus *= vPrime[i];

    pubkey = gen->getBig(size);
    pubkey = pubkey % modulus;	// public key

    while (!E_check(pubkey, Phi))
    {
        pubkey++;
    }
    privkey = Utils::inverse(pubkey, Phi, size);
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
 	primeP = gen->getBig(PRIME_NSIZE(size, 3));
	auto workerP = std::thread(ThreadsNextPrime, &primeP, PRIME_NSIZE(size, 3), precision);
	primeR = gen->getBig(PRIME_NSIZE(size, 3));
	auto workerR = std::thread(ThreadsNextPrime, &primeR, PRIME_NSIZE(size, 3), precision);
  	primeQ = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, 3)), PRIME_NSIZE(size, 3), precision);
  	workerP.join();
	workerR.join();

	while(true)
	{
		while(!Q_checkN(primeP, primeQ, PRIME_NSIZE(size, 3), 3))
		{
			primeQ = gen->getBig(PRIME_NSIZE(size, 3));
			Prime::ParallelNextPrime(&primeQ, PRIME_NSIZE(size, 3), precision);
		}
		while(!Q_checkN(primeP, primeR, PRIME_NSIZE(size, 3), 3))
		{
			primeR = gen->getBig(PRIME_NSIZE(size, 3));
			Prime::ParallelNextPrime(&primeR, PRIME_NSIZE(size, 3), precision);
		}

		if(Q_checkN(primeQ, primeR, PRIME_NSIZE(size, 3), 3))
		{
			break;
		}
	}
}

// N PRIMES
inline void DualRoutineN(std::vector<mpzBigInteger>& vPrime,
						 RSAGMP::Utils::Generator *gen,
						 unsigned int size,
						 unsigned int precision,
						 unsigned int NPRIMES)
{
    std::vector<std::thread> vThreads;

    vPrime[0] = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, NPRIMES)), PRIME_NSIZE(size, NPRIMES), precision);
    for(size_t i=1;i<vPrime.size();i++)
    {
        vPrime[i] = gen->getBig(PRIME_NSIZE(size, NPRIMES));
        vThreads.push_back( std::thread(ThreadsNextPrime, &vPrime[i], PRIME_NSIZE(size, NPRIMES), precision) );
    }

	for(size_t i=0;i<vThreads.size();i++)
        vThreads[i].join();

    bool ok;
	while(true)
	{
        for(size_t i=1;i<vPrime.size();i++)
        {
            while(!Q_checkN(vPrime[0], vPrime[i], PRIME_NSIZE(size, NPRIMES), NPRIMES))
            {
                vPrime[i] = gen->getBig(PRIME_NSIZE(size, NPRIMES));
                Prime::ParallelNextPrime(&vPrime[i], PRIME_NSIZE(size, NPRIMES), precision);
            }
		}

        ok = true;
		for(size_t i=0;i<vPrime.size();i++)
        {
            for(size_t j=i+1;j<vPrime.size();j++)
            {
                if(!Q_checkN(vPrime[i], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES))
                {
                    ok = false;
                    break;
                }
            }
        }

        if (ok)
        {
            break;
        }
	}
}

// multithread prime extraction routine
inline void ParallelRoutine(mpzBigInteger &primeP, mpzBigInteger &primeQ, RSAGMP::Utils::Generator *gen, unsigned int size,
                            unsigned int precision, int threads)
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
								RSAGMP::Utils::Generator *gen, unsigned int size, unsigned int precision, int threads,
								bool verbose = true)
{
	bool P = false;
	bool Q = false;
	bool R = false;
	bool pqOK = false;
	bool prOK = false;
	bool qrOK = false;

	std::cout << "...";std::cout.flush();
	primeP = gen->getBig(PRIME_NSIZE(size, 3));
	Prime::ParallelNextPrime(&primeP, PRIME_NSIZE(size, 3), precision, threads);
	P = true;
	std::cout << "P";std::cout.flush();

    while(pqOK==false)
    {
        primeQ = gen->getBig(PRIME_NSIZE(size, 3));
        Prime::ParallelNextPrime(&primeQ, PRIME_NSIZE(size, 3), precision, threads);
        Q = true;
        pqOK = Q_checkN(primeP, primeQ, PRIME_NSIZE(size, 3), 3);
    }
    std::cout << "Q";std::cout.flush();

    if (pqOK)
    {
        while(prOK==false)
        {
            primeR = gen->getBig(PRIME_NSIZE(size, 3));
            Prime::ParallelNextPrime(&primeR, PRIME_NSIZE(size, 3), precision, threads);
            R = true;
            prOK = Q_checkN(primeP, primeR, PRIME_NSIZE(size, 3), 3);
        }
        std::cout << "R";std::cout.flush();

        if (prOK && Q && R)
            qrOK = Q_checkN(primeQ, primeR, PRIME_NSIZE(size, 3), 3);
        else
            qrOK = false;
    }

	uint32_t cnt=0;
	std::cout << "...";
    while( (!pqOK) || (!prOK) || (!qrOK) )
    {
		cnt++;
		if (cnt > 2)
		{
            // Redo P
            std::cout << "...";std::cout.flush();
            P = false;
            Q = false;
            R = false;
            pqOK = false;
            prOK = false;
            qrOK = false;

            primeP = gen->getBig(PRIME_NSIZE(size, 3));
            Prime::ParallelNextPrime(&primeP, PRIME_NSIZE(size, 3), precision, threads);
            P = true;
            std::cout << "P";std::cout.flush();

            cnt = 0;

            while(pqOK==false)
            {
                primeQ = gen->getBig(PRIME_NSIZE(size, 3));
                Prime::ParallelNextPrime(&primeQ, PRIME_NSIZE(size, 3), precision, threads);
                Q = true;
                pqOK = Q_checkN(primeP, primeQ, PRIME_NSIZE(size, 3), 3);
            }
            std::cout << "Q";std::cout.flush();

            if (pqOK)
            {
                while(prOK==false)
                {
                    primeR = gen->getBig(PRIME_NSIZE(size, 3));
                    Prime::ParallelNextPrime(&primeR, PRIME_NSIZE(size, 3), precision, threads);
                    R = true;
                    prOK = Q_checkN(primeP, primeR, PRIME_NSIZE(size, 3), 3);
                }
                std::cout << "R";std::cout.flush();

                if (prOK && Q && R)
                    qrOK = Q_checkN(primeQ, primeR, PRIME_NSIZE(size, 3), 3);
                else
                    qrOK = false;
            }
		}

        if ((!pqOK) && (!prOK))
        {
            while(pqOK==false)
            {
                Q = false;
                primeQ = gen->getBig(PRIME_NSIZE(size, 3));
                Prime::ParallelNextPrime(&primeQ, PRIME_NSIZE(size, 3), precision, threads);
                Q = true;
                pqOK = Q_checkN(primeP, primeQ, PRIME_NSIZE(size, 3), 3);
            }
            std::cout << "Q";std::cout.flush();

			if (pqOK)
			{
                while(prOK==false)
                {
                    R = false;
                    primeR = gen->getBig(PRIME_NSIZE(size, 3));
                    Prime::ParallelNextPrime(&primeR, PRIME_NSIZE(size, 3), precision, threads);
                    R = true;
                    prOK = Q_checkN(primeP, primeR, PRIME_NSIZE(size, 3), 3);
                }
                std::cout << "R";std::cout.flush();

				if (prOK && Q && R)
                    qrOK = Q_checkN(primeQ, primeR, PRIME_NSIZE(size, 3), 3);
                else
                    qrOK = false;
            }
        }
        else if (!pqOK)
        {
            while(pqOK==false)
            {
                Q = false;
                primeQ = gen->getBig(PRIME_NSIZE(size, 3));
                Prime::ParallelNextPrime(&primeQ, PRIME_NSIZE(size, 3), precision, threads);
                Q = true;
                pqOK = Q_checkN(primeP, primeQ, PRIME_NSIZE(size, 3), 3);
            }
            std::cout << "Q";std::cout.flush();

			if (pqOK && Q && R)
                qrOK = Q_checkN(primeQ, primeR, PRIME_NSIZE(size, 3), 3);
            else
                qrOK = false;
        }
        else if (!prOK)
        {
            while(prOK==false)
            {
                R = false;
                primeR = gen->getBig(PRIME_NSIZE(size, 3));
                Prime::ParallelNextPrime(&primeR, PRIME_NSIZE(size, 3), precision, threads);
                R = true;
                prOK = Q_checkN(primeP, primeR, PRIME_NSIZE(size, 3), 3);
            }
            std::cout << "R";std::cout.flush();

			if (prOK && Q && R)
                qrOK = Q_checkN(primeQ, primeR, PRIME_NSIZE(size, 3), 3);
            else
                qrOK = false;
        }
    }
    std::cout << std::endl;
}

// N PRIMES
// ParallelRoutineN(vPrime, gen, size, precision, threads, NPRIMES);
inline void ParallelRoutineN(	std::vector<mpzBigInteger>& vPrime,
								RSAGMP::Utils::Generator *gen,
                                unsigned int size,
                                unsigned int precision,
								int threads,
								unsigned int NPRIMES,
								bool verbose = true)
{
    std::vector<std::thread> vThreads;

    vPrime[0] = gen->getBig(PRIME_NSIZE(size, NPRIMES));
    Prime::ParallelNextPrime(   &vPrime[0], PRIME_NSIZE(size, NPRIMES), precision, std::max(int(1),
                                (int)(threads/vPrime.size())) );

    for(size_t i=1;i<vPrime.size();i++)
    {
        vPrime[i] = gen->getBig(PRIME_NSIZE(size, NPRIMES));
        vThreads.push_back( std::thread(ParallelNextPrime,  &vPrime[i], PRIME_NSIZE(size, NPRIMES), precision,
                                                            std::max(int(1), (int) (threads/vPrime.size()) )));
    }
	for(size_t i=0;i<vThreads.size();i++)
        vThreads[i].join();

	bool ok = true;
	int cntNotOK=0;
	std::vector<bool> vOK( vPrime.size() - 1 );

	for(size_t j=1;j<vPrime.size();j++)
	{
		vOK[j-1] = Q_checkN(vPrime[0], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES);
		if (vOK[j-1] == false)
		{
			ok = false;
			cntNotOK++;
		}
	}

	if (ok)
	{
		for(size_t i=1;i<vPrime.size();i++)
		{
			for(size_t j=i+1;j<vPrime.size();j++)
			{
				if(!Q_checkN(vPrime[i], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES))
				{
					ok = false;
					break;
				}
			}
		}
	}

	uint32_t cnt=0;
    while( ok == false )
    {
		cnt++;
		if (cnt > NPRIMES-1)
		{
            // Redo P
            vPrime[0] = gen->getBig(PRIME_NSIZE(size, NPRIMES));
            Prime::ParallelNextPrime(&vPrime[0], PRIME_NSIZE(size, NPRIMES), precision,
                                     std::max(int(1), (int)(threads)) );

            cnt = 0;
            ok = true;
			cntNotOK = 0;
			for(size_t j=1;j<vPrime.size();j++)
			{
				vOK[j-1] = Q_checkN(vPrime[0], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES);
				if (vOK[j-1] == false)
				{
					ok = false;
					cntNotOK++;
				}
			}
			if (ok)
			{
				for(size_t i=1;i<vPrime.size();i++)
				{
					for(size_t j=i+1;j<vPrime.size();j++)
					{
						if(!Q_checkN(vPrime[i], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES))
						{
							ok = false;
							break;
						}
					}
				}
			}
		}

		vThreads.clear();
		for(size_t i=1;i<vPrime.size();i++)
		{
			while (vOK[i-1] == false)
			{
				vPrime[i] = gen->getBig(PRIME_NSIZE(size, NPRIMES));

                // Try to use max threads every times
                ParallelNextPrime(  &vPrime[i], PRIME_NSIZE(size, NPRIMES), precision,
                                    std::max(int(1), (int)(threads)) );
                vOK[i-1] = Q_checkN(vPrime[0], vPrime[i], PRIME_NSIZE(size, NPRIMES), NPRIMES);

                //diff between primes >= nth root, so very small, enough space to fit all primes
                {
                    if (vOK[i-1] == true)
                    {
                        for(size_t j=1;j<i;j++) // check balanced and coprime with all previous
                        {
                            vOK[i-1] = Q_checkN(vPrime[j], vPrime[i], PRIME_NSIZE(size, NPRIMES), NPRIMES);
                            if (vOK[i-1] == false)
                            {
                                break;
                            }
                        }
                    }
                }
             }
		}

        ok = true;
        cntNotOK = 0;
        for(size_t j=1;j<vPrime.size();j++)
        {
            vOK[j-1] = Q_checkN(vPrime[0], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES);
            if (vOK[j-1] == false)
            {
                ok = false;
                cntNotOK++;
            }
        }

        if (ok)
        {
            for(size_t i=1;i<vPrime.size();i++)
            {
                for(size_t j=i+1;j<vPrime.size();j++)
                {
                    if(!Q_checkN(vPrime[i], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES))
                    {
                        ok = false;
                        break;
                    }
                }
            }
        }
    }

//	for(size_t i=0;i<vPrime.size();i++)
//    {
//        std::cout << vPrime[i]<< std::endl;
//    }
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

	mpzBigInteger primeP = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, 3)), PRIME_NSIZE(size, 3), precision);
	mpzBigInteger primeQ = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, 3)), PRIME_NSIZE(size, 3), precision);
	mpzBigInteger primeR = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, 3)), PRIME_NSIZE(size, 3), precision);

	while(true)
	{
		while(!Q_checkN(primeP, primeQ, PRIME_NSIZE(size, 3), 3))
		{
		  primeQ = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, 3)), PRIME_NSIZE(size, 3), precision);
		}
		while(!Q_checkN(primeP, primeR, PRIME_NSIZE(size, 3), 3))
		{
		  primeR = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, 3)), PRIME_NSIZE(size, 3), precision);
		}
		if(Q_checkN(primeQ, primeR, PRIME_NSIZE(size, 3), 3))
		{
			break;
		}
	}
	return KeygenRoutine3(primeP, primeQ, primeR, pubkey, privkey, modulus, gen, size);
}

// N PRIMES
bool RSAGMP::KeygenN(mpzBigInteger &pubkey,
					 mpzBigInteger &privkey,
					 mpzBigInteger &modulus,
					 RSAGMP::Utils::Generator* gen,
					 unsigned int size,
					 unsigned int precision,
					 unsigned int NPRIMES)
{
	if ((size < NPRIMES*32) || (precision < 2))
	  return false;

    std::vector<mpzBigInteger> vPrime(NPRIMES);
    for(size_t i=0;i<vPrime.size();i++)
    {
        vPrime[i] = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, NPRIMES)), PRIME_NSIZE(size, NPRIMES), precision);
    }

    bool ok;
	while(true)
	{
        for(size_t i=0;i<1;i++)
        {
            for(size_t j=i+1;j<vPrime.size();j++)
            {
                while(!Q_checkN(vPrime[0], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES))
                {
                    vPrime[j] = Prime::NextPrime(gen->getBig(PRIME_NSIZE(size, NPRIMES)), PRIME_NSIZE(size, NPRIMES), precision);
                }
             }
         }

        ok = true;
        for(size_t i=0;i<vPrime.size();i++)
        {
            for(size_t j=i+1;j<vPrime.size();j++)
            {
                if(!Q_checkN(vPrime[i], vPrime[j], PRIME_NSIZE(size, NPRIMES), NPRIMES))
                {
                    ok = false;
                    break;
                }
            }
        }

		if (ok)
		{
			break;
		}

		for(size_t i=0;i<vPrime.size();i++)
        {
// TODO
//undefined reference to `operator<<(std::ostream&, __mpz_struct const*)'
//			std::cout << vPrime[i] << std::endl;
		}
	}

	return KeygenRoutineN(vPrime, pubkey, privkey, modulus, gen, size, NPRIMES);
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

// N PRIMES
bool RSAGMP::ParallelKeygenN(mpzBigInteger &pubkey, mpzBigInteger &privkey, mpzBigInteger &modulus,
							 RSAGMP::Utils::Generator *gen, unsigned int size, int threads, unsigned int precision,
							 unsigned int NPRIMES)
{
	if (threads < (int)NPRIMES)
	  return KeygenN(pubkey, privkey, modulus, gen, size, precision, NPRIMES);

	if ( (size < NPRIMES*32) || (precision < 2))
	  return false;

	std::vector<mpzBigInteger> vPrime(NPRIMES);

	if(threads < (int) (NPRIMES*2))
        DualRoutineN(vPrime, gen, size, precision, NPRIMES);
	else
        ParallelRoutineN(vPrime, gen, size, precision, threads, NPRIMES);

    return KeygenRoutineN(vPrime, pubkey, privkey, modulus, gen, size, NPRIMES);
}
