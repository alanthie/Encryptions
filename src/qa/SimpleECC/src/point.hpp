/**
  * JAIST - Visiting Student 2014
  * Iskandar Setiadi s1416051@jaist.ac.jp
  *
  */

#ifndef POINT_H
#define POINT_H

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

typedef struct {
	mpz_t x;
	mpz_t y;
	boolean isInf;
} Point;

/** Constructor & Destructor */
Point init_point(Point p);
Point clean_point(Point p);
Point copy_point(Point p);

int compare_point(Point p, Point q);
int compare_point_negate(Point p, Point q);

// t(A + A) = 2M + S + I
Point affine_curve_addition(Point p, Point q, mpz_t a, mpz_t modulo);
// t(2A) = 2M + 2S + I
Point affine_curve_doubling(Point p, mpz_t a, mpz_t modulo);
Point affine_curve_subtraction(Point p, Point q, mpz_t a, mpz_t modulo);
}


#endif
/* Created by freedomofkeima - 2014 */

