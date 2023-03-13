/**
  * JAIST - Visiting Student 2014
  * Iskandar Setiadi s1416051@jaist.ac.jp
  *
  */


#ifndef HELPER_H
#define HELPER_H

#include "boolean.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#ifdef _WIN32
#pragma warning ( disable : 4146 )
#else
#include <dirent.h>
#endif
#include <ctype.h>
#include <string.h>
#include <gmpxx.h>
//#include <gmp.h>


namespace cryptoSimpleECC
{

void get_random(mpz_t results, int num_bytes); // multiple of 8
void positive_modulo(mpz_t results, mpz_t a, mpz_t modulo);

/* Created by freedomofkeima - 2014 */
}

#endif
