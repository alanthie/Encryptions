/**
  * JAIST - Visiting Student 2014
  * Iskandar Setiadi s1416051@jaist.ac.jp
  *
  */

#ifndef J_POINT_H
#define J_POINT_H

#include "boolean.hpp"
#include "helper.hpp"
#include "point.hpp"

namespace cryptoSimpleECC
{

typedef struct {
	mpz_t X;
	mpz_t Y;
	mpz_t Z;
	//boolean isInf;
	bool isInf;
} J_Point; // Jacobian Coordinates

/** Constructor & Destructor */
J_Point init_j_point(J_Point p);
J_Point clean_j_point(J_Point p);
J_Point copy_j_point(J_Point p);

int compare_j_point(J_Point p, J_Point q);
int compare_j_point_negate(J_Point p, J_Point q);

// t(J + J) = 12M + 4S
J_Point jacobian_curve_addition(J_Point p, J_Point q, mpz_t a, mpz_t modulo);
// t(2J) = 4M + 6S
J_Point jacobian_curve_doubling(J_Point p, mpz_t a, mpz_t modulo);
J_Point jacobian_curve_subtraction(J_Point p, J_Point q, mpz_t a, mpz_t modulo);

/** Mixed Coordinates */
// t(J + A -> J) = 8M + 3S
J_Point jacobian_affine_curve_addition(J_Point p, Point q, mpz_t a, mpz_t modulo);
J_Point jacobian_affine_curve_subtraction(J_Point p, Point q, mpz_t a, mpz_t modulo);
// J_Point jacobian_affine_curve_doubling_addition(J_Point p, Point q, mpz_t a, mpz_t modulo); // ALG 17

/** Convert Affine <-> Jacobian */
J_Point affine_to_jacobian(Point p);
Point jacobian_to_affine(J_Point p, mpz_t modulo);

}
#endif
/* Created by freedomofkeima - 2014 */
