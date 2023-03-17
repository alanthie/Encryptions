#include<stdio.h>
#include "ecc_curve.c"

int ecc_curve::test_functions()
{
	ecc_point* p=malloc(sizeof(ecc_point));
	ecc_point* p2=malloc(sizeof(ecc_point));
	gmp_scanf("%Zd %Zd",&(*p).x,&(*p).y);

	mpz_t c,d;
	mpz_init_set_ui(c,5);
	mpz_init_set_ui(d,3);
	mpz_and(c,c,d);
	mpz_ior(d,d,c);
	gmp_printf("And:%Zd  OR:%Zd ",c,d);
	
	int a=init_curve("2","2","11","90",1,*p);
	if (a){
		printf("Generator point failed\n");
		return -1;
	}

	ecc_point* r1=malloc(sizeof(ecc_point));
	
	mpz_init_set((*r1).x,(*p).x);
	mpz_init_set((*r1).y,(*p).y);
	mpz_neg((*r1).y,(*r1).y);
	gmp_printf("Neg: %Zd %Zd\n",(*r1).x,(*r1).y);

	ecc_point* r= sum(*p,*p);
	mpz_t m;
	r1=sum(*r,*r1);
	gmp_printf("Sub: %Zd %Zd\n",(*r1).x,(*r1).y);
	mpz_init_set_ui(m,7);
	gmp_printf("Soma: %Zd %Zd\n",(*r).x,(*r).y);
	r=mult(*p,m);
	gmp_printf("Mult7: %Zd %Zd\n",(*r).x,(*r).y);
	mpz_set_ui(m,2);
	r=mult(*r,m);
	gmp_printf("Multi2: %Zd %Zd\n",(*r).x,(*r).y);
	mpz_set_ui(m,2);
	r=mult(*p,m);
	gmp_printf("Mult2: %Zd %Zd\n",(*r).x,(*r).y);
	mpz_set_ui(m,7);
	r=mult(*r,m);
	gmp_printf("Mult7: %Zd %Zd\n",(*r).x,(*r).y);
}
