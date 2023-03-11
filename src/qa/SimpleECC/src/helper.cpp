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
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <gmpxx.h>
//#include <gmp.h>


namespace cryptoSimpleECC
{

void get_random(mpz_t results, int num_bytes) { // multiple of 8
	unsigned long long *data = (unsigned long long*) malloc((num_bytes / 8) * sizeof(long long));
	int ret_val;
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	if (fp == NULL) {
		fprintf(stderr, "cannot open random number device!");
		return;
	}
	ret_val = fread(data, 8, num_bytes / 8, fp);
	fclose(fp);

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
