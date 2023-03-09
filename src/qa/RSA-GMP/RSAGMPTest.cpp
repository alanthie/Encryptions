#include "RSAGMPTest.h"

bool RSAGMP::DefaultTest(unsigned int size)
{
   auto start = std::chrono::high_resolution_clock::now();

   if(size < 64)
   {
       std::cout << "RSA test invald input\n";
       return false;
   }
   mpzBigInteger pub, priv, modulus;
   Utils::TestGenerator generator;
   Keygen(pub, priv, modulus, &generator, size);
   mpzBigInteger message = generator.getBig(size) % modulus;
   mpzBigInteger crypto = Encrypt(message, pub, modulus);
   mpzBigInteger message1 = Decrypt(crypto, priv, modulus);

   auto finish = std::chrono::high_resolution_clock::now();
   std::chrono::duration<double, std::milli> elapsed = finish - start;

   bool result = (message1 == message);
   if(result)
       std::cout << "RSA GMP test OK - bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
   else
       std::cout << "RSA GMP test ERROR\n";
   return result;
}

int RSAGMP::rsa_gmp_test_key(std::string n, std::string e,std::string d, unsigned int size)
{
   mpzBigInteger modulus(n);
   mpzBigInteger pub(e);
   mpzBigInteger priv(d);

   Utils::TestGenerator generator;

   mpzBigInteger message = generator.getBig(size) % modulus;
   mpzBigInteger crypto = Encrypt(message, pub, modulus);
   mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
   bool result = message1 == message;

   if(result)
   {
       std::cout << "RSA GMP encrypt/decrypt test OK\n";
       return 0;
   }
   else
   {
       std::cout << "RSA GMP encrypt/decrypt test ERROR\n";
       return -1;
   }
}

bool RSAGMP::CustomTest(unsigned int size, Utils::Generator *generator, int threads, unsigned int precision)
{
auto start = std::chrono::high_resolution_clock::now();

   if(size < 64 || generator == NULL)
   {
       std::cout << "RSA test invalid input\n";
       return false;
   }
   mpzBigInteger pub, priv, modulus;

   ParallelKeygen(pub, priv, modulus, generator, size, threads, precision);
   mpzBigInteger message = generator->getBig(size) % modulus;
   mpzBigInteger crypto = Encrypt(message, pub, modulus);
   mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
   bool result = message1 == message;

   auto finish = std::chrono::high_resolution_clock::now();
   std::chrono::duration<double, std::milli> elapsed = finish - start;


   if(result)
       std::cout << "RSA GMP Parallel test OK- bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
   else
 		std::cout << "RSA GMP Parallel test ERROR\n";
   return result;
}

bool RSAGMP::get_keys(	unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
			Utils::mpzBigInteger& pub, Utils::mpzBigInteger& priv, Utils::mpzBigInteger& modulus)
{
	auto start = std::chrono::high_resolution_clock::now();

	if(size < 64 || generator == NULL)
	{
		std::cout << "RSA test invalid input\n";
		return false;
	}

	ParallelKeygen(pub, priv, modulus, generator, size, threads, precision);
	mpzBigInteger message = generator->getBig(size) % modulus;
	mpzBigInteger crypto = Encrypt(message, pub, modulus);
	mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
	bool result = message1 == message;

	auto finish = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> elapsed = finish - start;

	if(result)
		std::cout << "RSA GMP Parallel test OK- bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
	else
		std::cout << "RSA GMP Parallel test ERROR\n";

	return result;
}
