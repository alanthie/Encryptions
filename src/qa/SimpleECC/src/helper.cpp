/**
  * JAIST - Visiting Student 2014
  * Iskandar Setiadi s1416051@jaist.ac.jp
  *
  */

#include "boolean.hpp"
#include "helper.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#ifdef _WIN32
#else
#include <dirent.h>
#endif
#include <ctype.h>
#include <string.h>
#include <gmpxx.h>
//#include <gmp.h>


namespace cryptoSimpleECC
{

void get_random(mpz_t results, int num_bytes) 
{ 
	// multiple of 8
	unsigned long long *data = (unsigned long long*) malloc((num_bytes / 8) * sizeof(long long));

#ifdef _WIN32
	unsigned long long L;
	srand(time(NULL));
	unsigned char c[4]; //[8]...
	for (long i = 0; i < num_bytes/8; i++)
	{
		c[0] = rand() % 256;
		c[1] = rand() % 256;
		c[2] = rand() % 256;
		c[3] = rand() % 256;
		L =  (c[0]*256*256*256) + (c[1] * 256 * 256) + (c[2] * 256) + (c[3]);
		data[i] = L;
	}
#else
	int ret_val;
	FILE* fp;
	fp = fopen("/dev/urandom", "r");
	if (fp == NULL) {
		fprintf(stderr, "cannot open random number device!");
		return;
	}
	ret_val = fread(data, 8, num_bytes / 8, fp);
	fclose(fp);
#endif

	mpz_init(results);
	mpz_import(results, (num_bytes / 8), 1, sizeof(data[0]), 0, 0, data);

	mpz_t zero_value;
	mpz_init(zero_value);
}

void positive_modulo(mpz_t results, mpz_t a, mpz_t modulo) {
	mpz_t zero_value;
	mpz_init(zero_value);

	mpz_tdiv_r(results, a, modulo);
	if (mpz_cmp(results, zero_value) < 0) mpz_add(results, results, modulo);
}

/* Created by freedomofkeima - 2014 */
}
