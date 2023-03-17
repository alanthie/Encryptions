#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "ecc_curve.hpp"

int ecc_curve::random_in_range (unsigned int min, unsigned int max)
{
    int base_random = rand(); /* in [0, RAND_MAX] */
    if (RAND_MAX == base_random) return random_in_range(min, max);

    /* now guaranteed to be in [0, RAND_MAX) */
    int range       = max - min,
    remainder   = RAND_MAX % range,
    bucket      = RAND_MAX / range;
    /* There are range buckets, plus one smaller interval
     within remainder of RAND_MAX */
    if (base_random < RAND_MAX - remainder)
    {
        return min + base_random/bucket;
    }
    else
    {
        return random_in_range (min, max);
    }
}

message_point ecc_curve::getECCPointFromMessage(char* message)
{
	mpz_t x;
	mpz_init(x);

    message_point rm;
	message_point* m = &rm;

    ecc_point r;
	ecc_point* result = &r;

	printf("%s\n", message);
	//printf("%c\n", message[0]);
	//printf("%d\n", (*message));

	int i=MSG_BYTES_MAX-1;
	for (i;i>=0;i--)
    {
		mpz_t temp;
		//mpz_init_set_str(temp,pot_256[i],BASE_16); // [---18 bytes--] pow256string
		mpz_init_set_str(temp,pow256string(i).data(),BASE_16);

		//gmp_printf("temp: %Zd ",temp);
		mpz_addmul_ui(x,temp,(*message));
		//printf(" m:%d \n",(*message));
		++message;
		if (!(*message))
        {
			break;
		}
	}

    // check x, x+1, ... x+9(?)
	//gmp_printf("phase 1 prime=%Zd x=%Zd\n",prime,x); //phase 1 prime
	i=0;
	do{
		printf("i-> %d",i);
		gmp_printf(" x=%Zd\n",x);

		r = existPoint(x);
		i++;
		mpz_add_ui(x,x,1);
	}
    while( (r.is_valid==false) && i<10);

	mpz_mod((r).x,(r).x,prime);
	//gmp_printf("Phase 2 Point: %Zd %Zd \n",(r).x,(r).y); //Phase 2 Point:

	if (r.is_valid)
    {
		(*m).p = r;
		(*m).qtd_adicoes = i-1;
		return rm;
	}
    else
    {
        rm.p.is_valid = false;
		return rm;
    }
}

char* ecc_curve::getMessageFromPoint(message_point& msg)
{
	char* message = (char*)malloc((MSG_BYTES_MAX+1)*sizeof(char));

	int i = MSG_BYTES_MAX ;
    message_point rm;
	message_point* m = &rm;

	mpz_init_set(((rm).p).x,((msg).p).x);
	mpz_init_set(((rm).p).y,((msg).p).y);
	(*m).qtd_adicoes=(msg).qtd_adicoes;
	//gmp_printf("X: %Zd \n",((rm).p).x);
	mpz_sub_ui(((rm).p).x,((rm).p).x,(rm).qtd_adicoes);
	//printf("\n\n");

	i=0;
	for (i;i<MSG_BYTES_MAX;i++)
    {
		mpz_t pot;
		//mpz_init_set_str(pot,pot_256[MSG_BYTES_MAX-i],BASE_16);
		mpz_init_set_str(pot,pow256string(MSG_BYTES_MAX-i).data(),BASE_16);

		mpz_sub_ui(pot,pot,1);
		//gmp_printf("i:%d pot: %Zd \n",i,pot);

		mpz_and(((rm).p).x,((rm).p).x,pot);
		//gmp_printf("and_X: %Zd ",((rm).p).x);
		mpz_t aux;
		mpz_init(aux);

        //mpz_set_str(pot,pot_256[MSG_BYTES_MAX-1-i],BASE_16);
		mpz_set_str(pot,pow256string(MSG_BYTES_MAX-1-i).data(),BASE_16);

		mpz_fdiv_q(aux,((rm).p).x,pot);
		//printf(".%d.%c ",mpz_get_ui(aux),mpz_get_ui(aux));
		message[i]=(mpz_get_ui(aux)>=32 && mpz_get_ui(aux)<127)?mpz_get_ui(aux):'\0';
	}
	message[MSG_BYTES_MAX]='\0';
	return message;
}

int ecc_curve::test()
{
	FILE* f;
	char* file="p";//argv[1];
	f= fopen(file,"r");
	char  prime_c[80],a_c[80],b_c[80],x_c[80],order_c[80];

    char* message = (char*)malloc(200*sizeof(char));
    std::string s = "23578546432889";
    strcpy(message, s.data());

    message_point rm;
	message_point* m = &rm;

	ecc_point* generator;
	ecc_point* publicKey;
	ecc_point* p;

    ecc_point rp;
	p = &rp;

    ecc_point rpublicKey;
	publicKey= &rpublicKey;

    ecc_point rgenerator;
	generator = &rgenerator;

	fscanf(f,"%s \n",prime_c);
	fscanf(f,"%s \n",a_c);
	fscanf(f,"%s \n",b_c);

	mpz_init((*generator).x);
	mpz_init((*generator).y);

	gmp_fscanf(f,"%Zd ",(*generator).x);
	gmp_fscanf(f,"%Zd ",(*generator).y);

	fscanf(f,"%s ",order_c);
	gmp_printf("readings-> prime:%s, a:%s, b: %s, , order:%s \n",prime_c,a_c,b_c,order_c); //readings-> prime

	(rm).p = rp;
	(rm).qtd_adicoes=0;

	clock_t starttime, endtime;
	starttime = clock();
	init_curve(a_c,b_c,prime_c,order_c,1,*generator);

	// key generation
	mpz_t random;
	mpz_init(random);
	gmp_randstate_t st;
	gmp_randinit_default(st);
	gmp_randseed_ui(st,time(NULL));
	mpz_urandomm(random, st, order);
	//gmp_printf("key generation privateKey is random, order: %Zd %Zd\n",random, order);

	mpz_t  privateKey;
	mpz_init_set(privateKey, random);
	//gmp_printf("key generation privateKey: %Zd \n",privateKey);

	ecc_point publicKey1;
	publicKey1 = mult(generator_point,privateKey);
	//gmp_printf("key generation pubKey (r*G) pubK.x: %Zd pubK.Y:%Zd priv: %Zd \n",(publicKey1).x,(publicKey1).y,privateKey);

	printf("message: ");
	rm = getECCPointFromMessage(message);
	if (rm.p.is_valid == false)
    {
		printf("ERROR \n");
		return -1;
	}

    gmp_printf("msg point x,y, msg add:  %Zd %Zd %d \n",((rm).p).x,((rm).p).y,(rm).qtd_adicoes);
    char* msg = getMessageFromPoint(rm);

	gmp_randseed_ui(st,time(NULL));
	mpz_urandomm(random, st, order);

	ecc_point rG    = mult(generator_point,random);
	ecc_point rPub  = mult(publicKey1,random);
	gmp_printf("rPub.x %Zd rPub.y %Zd Mp.x %Zd\n",(rPub).x,(rPub).y,((rm).p).x);
	gmp_printf("rG.x %Zd rG.y %Zd\n",(rG).x,(rG).y);

	ecc_point Cm = sum(rm.p, rPub);
	gmp_printf("Encryption [Pm+rG].x %Zd [Pm+rG].y %Zd\n",Cm.x,Cm.y);
	gmp_printf("Encryption rG.x = %Zd\n",(rG).x);

	//Decryption
	ecc_point rGPriv = mult(rG, privateKey);
	gmp_printf("Decryption privKey=%Zd rG.x=%Zd rGPriv.x=%Zd rGPriv.y=%Zd\n",privateKey,rG.x,rGPriv.x,rGPriv.y);
	mpz_neg(rGPriv.y,rGPriv.y); //-rGPriv.y

    message_point rm1;

	rm1.p = sum(Cm, rGPriv); // Cm-rGPriv
	rm1.qtd_adicoes = rm.qtd_adicoes;
	gmp_printf("Decryption [Cm-rGPriv].x: %Zd [Cm-rGPriv].y: %Zd\n", rm1.p.x, rm1.p.y);
	printf("Message final from [Cm-rGPriv] point: %s\n", getMessageFromPoint(rm1));

	endtime= clock();
	printf("Execution time was %lu miliseconds\n", (endtime - starttime)/(CLOCKS_PER_SEC/1000));

	return 0;
}


