/**
  * JAIST - Visiting Student 2014
  * Iskandar Setiadi s1416051@jaist.ac.jp
  *
  */

#ifndef ECC_H
#define ECC_H

#include "boolean.hpp"
#include "point.hpp"
#include "j_point.hpp"

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

/** Left-to-right binary algorithm */
Point affine_left_to_right_binary(Point p, mpz_t a, mpz_t k, mpz_t modulo);
J_Point jacobian_left_to_right_binary(J_Point p, mpz_t a, mpz_t k, mpz_t modulo);
J_Point jacobian_affine_left_to_right_binary(J_Point p, Point q, mpz_t a, mpz_t k, mpz_t modulo);
/** Right-to-left binary algorithm */
Point affine_right_to_left_binary(Point p, mpz_t a, mpz_t k, mpz_t modulo);
/** Montgomery ladder algorithm */
J_Point jacobian_montgomery_ladder(J_Point p, mpz_t a, mpz_t k, mpz_t modulo);
/** Sliding window algorithm */
J_Point jacobian_affine_sliding_NAF(J_Point p, Point q, mpz_t a, mpz_t k, mpz_t modulo, int w);

/** Encrypt & Decrypt */
Point encrypt_ECIES(mpz_t encrypted_message, char* message, Point public_key, Point p, mpz_t a, mpz_t modulo); // return chosen point
void decrypt_ECIES(mpz_t encrypted_message, Point chosen_point, mpz_t private_key, Point p, mpz_t a, mpz_t modulo); // return message

#endif
/* Created by freedomofkeima - 2014 */
}
