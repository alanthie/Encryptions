/**
  * JAIST - Visiting Student 2014
  * Iskandar Setiadi s1416051@jaist.ac.jp
  *
  */

#include "boolean.hpp"
#include "helper.hpp"
#include "point.hpp"

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

/** Constructor & Destructor */
Point init_point(Point p) {
	mpz_init(p.x);
	mpz_init(p.y);
	p.isInf = false;
	return p;
}

Point clean_point(Point p) {
	mpz_clear(p.x);
	mpz_clear(p.y);
	return p;
}

Point copy_point(Point p) {
	Point results;
	results = init_point(results);
	mpz_set(results.x, p.x);
	mpz_set(results.y, p.y);
	results.isInf = p.isInf;
	return p;
}

int compare_point(Point p, Point q) {
	if ((mpz_cmp(p.x, q.x) == 0) && (mpz_cmp(p.y, q.y) == 0)) return 0;
	else return 1;
}

int compare_point_negate(Point p, Point q) {
	mpz_neg(q.y, q.y);
	return compare_point(p, q);
}

Point affine_curve_addition(Point p, Point q, mpz_t a, mpz_t modulo) {
	// Case INF
	if (q.isInf) return p;
	if (p.isInf) return q;

	Point results;
	results = init_point(results);

	// Case P = -Q
	if (compare_point_negate(p, q) == 0) {
		results.isInf = true;
		return results;
	}
	// Case P = Q
	if (compare_point(p, q) == 0) return affine_curve_doubling(p, a, modulo);

	mpz_t lambda, lh, rh;
	mpz_init(lambda);
	mpz_init(lh); mpz_init(rh);

	/** Create (q.x - p.x)^-1 % m */
	mpz_sub(lh, q.x, p.x);
	mpz_invert(lh, lh, modulo);

	mpz_sub(rh, q.y, p.y);
	/** Calculate lambda (q.y - p.y) . (q.x - p.x)^-1 % m */
	mpz_mul(lambda, lh, rh);
	positive_modulo(lambda, lambda, modulo);

	/** new_x = lambda^2 - p.x - q.x */
	mpz_mul(results.x, lambda, lambda);
	mpz_sub(results.x, results.x, p.x);
	mpz_sub(results.x, results.x, q.x);
	positive_modulo(results.x, results.x, modulo);

	/** new_y = lambda * (p.x - new_x) - p.y */
	mpz_sub(results.y, p.x, results.x);
	mpz_mul(results.y, results.y, lambda);
	mpz_sub(results.y, results.y, p.y);
	positive_modulo(results.y, results.y, modulo);

	return results;
}

Point affine_curve_doubling(Point p, mpz_t a, mpz_t modulo) {
	Point results;
	results = init_point(results);

	// Case p is a point in infinity
	if (p.isInf) return p;

	// Case y = 0
	mpz_t zero_value;
	mpz_init(zero_value);
	if (mpz_cmp(p.y, zero_value) == 0) {
		results.isInf = true;
		return results;
	}

	mpz_t lambda, mul, lh, rh;
	mpz_init(lambda); mpz_init(mul);
	mpz_init(lh); mpz_init(rh);

	/** Create (2y)^-1 % m */
	mpz_mul_2exp(lh, p.y, 1);
	// Assuming inverse exists (retval = 1)
	mpz_invert(lh, lh, modulo);

	mpz_set_ui(mul, 3);
	mpz_mul(rh, p.x, p.x);
	positive_modulo(rh, rh, modulo); // x^2 % m
	mpz_mul(rh, rh, mul); // (3x^2)
	mpz_add(rh, rh, a); // (3x^2 + a)
	positive_modulo(rh, rh, modulo); // (3x^2 + a) % m

	mpz_mul(lambda, lh, rh);
	positive_modulo(lambda, lambda, modulo); // (3x^2 + a) . (2y)^-1 % m

	/** new_x = lambda^2 - 2 * previous_x */
	mpz_mul(results.x, lambda, lambda);
	positive_modulo(results.x, results.x, modulo);
	mpz_sub(results.x, results.x, p.x);
	mpz_sub(results.x, results.x, p.x);
	positive_modulo(results.x, results.x, modulo);

	/** new_y = lambda * (previous_x - new_x) - previous_y */
	mpz_sub(results.y, p.x, results.x);
	mpz_mul(results.y, results.y, lambda);
	mpz_sub(results.y, results.y, p.y);
	positive_modulo(results.y, results.y, modulo);

	return results;
}

Point affine_curve_subtraction(Point p, Point q, mpz_t a, mpz_t modulo) {
	mpz_neg(q.y, q.y);
	return affine_curve_addition(p, q, a, modulo);
}
/* Created by freedomofkeima - 2014 */

}
