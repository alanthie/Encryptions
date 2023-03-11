/**
  * JAIST - Visiting Student 2014
  * Iskandar Setiadi s1416051@jaist.ac.jp
  *
  */

#include "boolean.hpp"
#include "point.hpp"
#include "j_point.hpp"
#include "ecc.hpp"

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
Point affine_left_to_right_binary(Point p, mpz_t a, mpz_t k, mpz_t modulo) {
	Point results, temp;
	results = copy_point(p); // R0
	temp = copy_point(p); // R1

	int i; // loop variable
	char * binary;
	int binary_size = 0;

	binary = mpz_get_str(NULL, 2, k);
	binary_size = (int) strlen(binary);


	for (i = binary_size - 2; i >= 0; i--) { // i = n-2 downto 0
		results = affine_curve_doubling(results, a, modulo);
		if (binary[binary_size - i - 1] == '1') results = affine_curve_addition(results, temp, a, modulo);
	}

	return results;
}

J_Point jacobian_left_to_right_binary(J_Point p, mpz_t a, mpz_t k, mpz_t modulo) {
	J_Point results, temp;
	results = copy_j_point(p); // R0
	temp = copy_j_point(p); // R1

	int i; // loop variable
	char * binary;
	int binary_size = 0;

	binary = mpz_get_str(NULL, 2, k);
	binary_size = (int) strlen(binary);


	for (i = binary_size - 2; i >= 0; i--) { // i = n-2 downto 0
		results = jacobian_curve_doubling(results, a, modulo);
		if (binary[binary_size - i - 1] == '1') results = jacobian_curve_addition(results, temp, a, modulo);
	}

	return results;
}

J_Point jacobian_affine_left_to_right_binary(J_Point p, Point q, mpz_t a, mpz_t k, mpz_t modulo) {
	J_Point results;
	results = copy_j_point(p); // R0

	int i; // loop variable
	char * binary;
	int binary_size = 0;

	binary = mpz_get_str(NULL, 2, k);
	binary_size = (int) strlen(binary);


	for (i = binary_size - 2; i >= 0; i--) { // i = n-2 downto 0
		results = jacobian_curve_doubling(results, a, modulo);
		if (binary[binary_size - i - 1] == '1') results = jacobian_affine_curve_addition(results, q, a, modulo);
	}

	return results;
}

/** Right-to-left binary algorithm */
Point affine_right_to_left_binary(Point p, mpz_t a, mpz_t k, mpz_t modulo) {
	Point results, temp;
	results = init_point(results);
	results.isInf = true;
	temp = copy_point(p);

	int i; // loop variable
	char * binary;
	int binary_size = 0;

	binary = mpz_get_str(NULL, 2, k);
	binary_size = (int) strlen(binary);

	for (i = 0; i < binary_size; i++) { // i = 0 to n-1
		if(binary[binary_size - i - 1] == '1') results = affine_curve_addition(results, temp, a, modulo);
		temp = affine_curve_doubling(temp, a, modulo);
	}

	return results;
}

/** Montgomery ladder algorithm */
J_Point jacobian_montgomery_ladder(J_Point p, mpz_t a, mpz_t k, mpz_t modulo) {
	J_Point results, temp;
	results = init_j_point(results);
	results.isInf = true;
	temp = copy_j_point(p);

	int i; // loop variable
	char * binary;
	int binary_size = 0;

	binary = mpz_get_str(NULL, 2, k);
	binary_size = (int) strlen(binary);

	for (i = binary_size - 1; i >= 0; i--) { // i = n-1 downto 0
		if (binary[binary_size - i - 1] == '1') {
			results = jacobian_curve_addition(results, temp, a, modulo);
			temp = jacobian_curve_doubling(temp, a, modulo);
		} else {
			temp = jacobian_curve_addition(results, temp, a, modulo);
			results = jacobian_curve_doubling(results, a, modulo);
		}
	}

	return results;
}

/** Sliding window algorithm */
J_Point jacobian_affine_sliding_NAF(J_Point p, Point q, mpz_t a, mpz_t k, mpz_t modulo, int w) {
	J_Point results;
	results = init_j_point(results);

	int i, j; // loop variable
	char * binary;
	int binary_size = 0;

	binary = mpz_get_str(NULL, 2, k);
	binary_size = (int) strlen(binary);

	/** Start pre-process */
	mpz_t zero, one, two, temp, remainder;
	mpz_init(zero);
	mpz_init(one); mpz_init(temp);
	mpz_init(two); mpz_init(remainder);
	mpz_set_ui(zero, 0);
	mpz_set_ui(one, 1);
	mpz_set_ui(two, 2);
	mpz_set(temp, k);
	int* naf_value = (int*) malloc((binary_size+1) * sizeof(int));
	for (i = 0; i <= binary_size; i++) naf_value[i] = 0;

	mpz_t w_mod, temp_naf;
	mpz_init(w_mod); mpz_init(temp_naf);
	mpz_mul_2exp(w_mod, two, w-2); // 2^(w-1)
	int w_mod_2 = mpz_get_ui(w_mod);
	mpz_mul_2exp(w_mod, two, w-1); // 2^w
	i = 0;
	while (mpz_cmp(temp, one) >= 0) {
		mpz_tdiv_r(remainder, temp, two);
		if (mpz_cmp(remainder, zero) != 0) { // k is odd
			mpz_set_si(temp_naf, naf_value[i]);
			positive_modulo(temp_naf, temp, w_mod);
			naf_value[i] = mpz_get_si(temp_naf);
			if (naf_value[i] > w_mod_2 - 1) {
				naf_value[i] -= mpz_get_ui(w_mod);
			}
			mpz_set_si(temp_naf, naf_value[i]);
			mpz_sub(temp, temp, temp_naf);
		}
		mpz_tdiv_q_2exp(temp, temp, 1);
		i++;
	}
	/** End pre-process */

	/** Compute Pi = [i].P for i {1, 3, 5, ... , 2^(w-1) - 1} */
	int size = w_mod_2 + 1;
	J_Point* P = (J_Point*) malloc(size * sizeof(J_Point)); // redundant allocation
	Point* P_A = (Point*) malloc(size * sizeof(Point));
	mpz_t k_value, sign_value;
	mpz_init(k_value); mpz_init(sign_value);
	P_A[0] = init_point(P_A[0]);
	P_A[0].isInf = true;
	// DP Optimization: P + 2P + 2P + ...
	for (i = 1; i <= (size-1); i+=2) {
		mpz_set_si(k_value, i);
		P[i] = jacobian_affine_left_to_right_binary(p, q, a, k_value, modulo);
		P_A[i] = jacobian_to_affine(P[i], modulo);
	}
	results.isInf = true;
	for (i = binary_size; i >= 0; i--) {
		int d = naf_value[i];
		mpz_set_si(k_value, d);
		int sign = mpz_sgn(k_value);
		mpz_set_si(sign_value, sign);
		// Absolute value
		d *= sign;
		mpz_set_si(k_value, d);
		// Jacobian doubling for w times // 2A
		results = jacobian_curve_doubling(results, a, modulo);
		mpz_mul(P_A[d].y, P_A[d].y, sign_value);
		results = jacobian_affine_curve_addition(results, P_A[d], a, modulo); // A +- Rd
		mpz_mul(P_A[d].y, P_A[d].y, sign_value);
	}

	return results;
}

/** Encrypt & Decrypt */
Point encrypt_ECIES(mpz_t encrypted_message, char* message, Point public_key, Point p, mpz_t a, mpz_t modulo) { // return chosen point
	Point chosen_point, encoded_point;
	J_Point j_chosen_point;
	J_Point j_encoded_point;
	J_Point j_p = affine_to_jacobian(p); // G in Jacobian
	J_Point j_public_key = affine_to_jacobian(public_key); // Public key receiver in Jacobian
	mpz_t k_random;
	mpz_init(k_random);
	get_random(k_random, 32); // choose random value k

	mpz_set_str(encrypted_message, message, 36);
	printf("[SIMPLIFIED ECIES] Message: ");
	mpz_out_str(stdout, 36, encrypted_message);
	printf("\n");

	// Encrypt for Simplified ECIES (Q = public_key_2)
	// Compute kP
	j_chosen_point = jacobian_left_to_right_binary(j_p, a, k_random, modulo); // kP
	gmp_printf("[SIMPLIFIED ECIES] Chosen point - Jacobian [X Y Z]: %Zd %Zd %Zd\n", j_chosen_point.X, j_chosen_point.Y, j_chosen_point.Z);
	chosen_point = jacobian_to_affine(j_chosen_point, modulo);
	gmp_printf("[SIMPLIFIED ECIES] Chosen point - Affine [X Y]: %Zd %Zd\n", chosen_point.x, chosen_point.y);
	j_encoded_point = jacobian_left_to_right_binary(j_public_key, a, k_random, modulo); // kQ
	gmp_printf("[SIMPLIFIED ECIES] Encoded point - Jacobian [X Y Z]: %Zd %Zd %Zd\n", j_encoded_point.X, j_encoded_point.Y, j_encoded_point.Z);
	encoded_point = jacobian_to_affine(j_encoded_point, modulo);
	gmp_printf("[SIMPLIFIED ECIES] Encoded point - Affine [X Y]: %Zd %Zd\n", encoded_point.x, encoded_point.y);
	mpz_mul(encrypted_message, encrypted_message, encoded_point.x);
	positive_modulo(encrypted_message, encrypted_message, modulo);

	return chosen_point;
}

void decrypt_ECIES(mpz_t encrypted_message, Point chosen_point, mpz_t private_key, Point p, mpz_t a, mpz_t modulo) { // return message
	Point decoded_point;
	J_Point j_decoded_point;
	J_Point j_chosen_point = affine_to_jacobian(chosen_point);

	// Decrypt for Simplified ECIES (using modulo inverse)
	j_decoded_point = jacobian_left_to_right_binary(j_chosen_point, a, private_key, modulo);
	gmp_printf("[SIMPLIFIED ECIES] Decoded point - Jacobian [X Y Z]: %Zd %Zd %Zd\n", j_decoded_point.X, j_decoded_point.Y, j_decoded_point.Z);
	decoded_point = jacobian_to_affine(j_decoded_point, modulo);
	gmp_printf("[SIMPLIFIED ECIES] Decoded point - Affine [X Y]: %Zd %Zd\n", decoded_point.x, decoded_point.y);
	mpz_invert(decoded_point.x, decoded_point.x, modulo);
	mpz_mul(encrypted_message, encrypted_message, decoded_point.x);
	positive_modulo(encrypted_message, encrypted_message, modulo);
	printf("[SIMPLIFIED ECIES] Original message: ");
	mpz_out_str(stdout, 36, encrypted_message);
	printf("\n\n");
}

/* Created by freedomofkeima - 2014 */

}
