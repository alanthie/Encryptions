#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "ecc_curve.hpp"

int ecc_curve::random_in_range (unsigned int min, unsigned int max)
{
    int base_random = rand(); /* in [0, RAND_MAX] */
    if (RAND_MAX == base_random) return random_in_range(min, max);

    int range       = max - min,
    remainder   = RAND_MAX % range,
    bucket      = RAND_MAX / range;
    if (base_random < RAND_MAX - remainder)
    {
        return min + base_random/bucket;
    }
    else
    {
        return random_in_range (min, max);
    }
}

// inital msg = x = "FFzaa234fsdf" 0xff 0x00 0x00 ---- 0x00 FULL
message_point ecc_curve::getECCPointFromMessage(cryptoAL::Buffer& message_buffer)
{
    const char* message = message_buffer.getdata();

    mpz_t x;
	mpz_init(x);

    message_point rm;
    ecc_point r;

	printf("%s\n", message);

	// msg = x = "FFzaa234fsdf"    0xff 0x00 0x00-- 0x05
	// msg = x = "FFzaa234fsdf..." 0xff 0x03
//	unsigned int N = 0;
//	for(unsigned int j = 0; j< message_buffer.size();j++)
//	{
//        if (message_buffer.get_at(j) == 0xff)
//        {
//            N++; // include delimiter
//            break;
//        }
//        else
//        {
//            N++;
//        }
//	}
//	N++; // include last byte delta

	for (int i = message_buffer.size();i>=0;i--)
    {
		mpz_t temp;
		mpz_init_set_str(temp,pow256string(i).data(),BASE_16);
		mpz_addmul_ui(x,temp,(*message));
		++message;
	}

    // check x, x+1, ... x+255 50%, 75%, ...99.9999...%
	int i=0;
	do{
		printf("i-> %d",i);
		gmp_printf(" x=%Zd\n",x);

		r = existPoint(x);
		i++;
		mpz_add_ui(x,x,1); // x++;
	}
    while( (r.is_valid==false) && i<255);

	mpz_mod(r.x,r.x,prime);

	if (r.is_valid)
    {
		rm.p = r;
		rm.qtd_adicoes = i-1;
		return rm;
	}
    else
    {
        rm.p.is_valid = false;
		return rm;
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

	int i = MSG_BYTES_MAX-1;
	// adding an empty byte
	i++;

	for (i;i>=0;i--)
    {
		mpz_t temp;
		mpz_init_set_str(temp,pow256string(i).data(),BASE_16);
		mpz_addmul_ui(x,temp,(*message));
		++message;
		if (!(*message))
        {
			break;
		}
	}

    // check x, x+1, ... x+255 50%, 75%, ...99.9999...%
	i=0;
	do{
		printf("i-> %d",i);
		gmp_printf(" x=%Zd\n",x);

		r = existPoint(x);
		i++;
		mpz_add_ui(x,x,1);
	}
    while( (r.is_valid==false) && i<255);

	mpz_mod((r).x,(r).x,prime);

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

void ecc_curve::getMessageFromPoint(message_point& msg, cryptoAL::Buffer& out_message)
{
    out_message.clear();
    out_message.increase_size(MSG_BYTES_MAX+2);
    out_message.init(0);

   	char* message = (char*)out_message.getdata();

    message_point rm;

	mpz_init_set(rm.p.x, msg.p.x);
	mpz_init_set(rm.p.y, msg.p.y);
	//rm.qtd_adicoes = msg.qtd_adicoes; // ???  // to recompute if needed...
	//mpz_sub_ui(rm.p.x,rm.p.x,rm.qtd_adicoes); // Drop last byte

    // msg = x = "FFzaa234fsdf"    0xff 0x00 0x00-- 0x05
	// msg = x = "FFzaa234fsdf..." 0xff 0x03

	bool delimiter = false;
	unsigned int c;
    unsigned int K = 2;
    unsigned int cnt = 0;
	for (unsigned int i=0;i<MSG_BYTES_MAX+K;i++)
    {
		mpz_t pot;
		mpz_init_set_str(pot,pow256string(MSG_BYTES_MAX+K-i).data(),BASE_16);

		mpz_sub_ui(pot,pot,1);
		mpz_and(rm.p.x,rm.p.x,pot);
		mpz_t aux;
		mpz_init(aux);

		mpz_set_str(pot,pow256string(MSG_BYTES_MAX+K-1-i).data(),BASE_16);
		mpz_fdiv_q(aux,rm.p.x,pot); // digit extract

        c = mpz_get_ui(aux);

        if (delimiter == false)
        {
            if (c == 0xff)
            {
                delimiter = true;
                break; // no more digits
            }
        }
        message[i] = c; // digit
        cnt++;

		//message[i] = (mpz_get_ui(aux)>=32 && mpz_get_ui(aux)<127)?mpz_get_ui(aux):'\0';
	}

	for (unsigned int i=cnt;i<MSG_BYTES_MAX+K;i++)
	{
        message[i] = 0;
	}

	//message[MSG_BYTES_MAX]='\0';
}


char* ecc_curve::getMessageFromPoint(message_point& msg)
{
	char* message = (char*)malloc((MSG_BYTES_MAX+1)*sizeof(char));

    message_point rm;

	mpz_init_set(rm.p.x,msg.p.x);
	mpz_init_set(rm.p.y,msg.p.y);
	//rm.qtd_adicoes = msg.qtd_adicoes; // ???  // to recompute if needed...
	//mpz_sub_ui(rm.p.x,rm.p.x,rm.qtd_adicoes); // Drop last byte

    // Drop last byte
    unsigned int K = 1;

	int i=0;
	for (i;i<MSG_BYTES_MAX+K;i++)
    {
		mpz_t pot;
		mpz_init_set_str(pot,pow256string(MSG_BYTES_MAX+K-i).data(),BASE_16);

		mpz_sub_ui(pot,pot,1);
		mpz_and(rm.p.x,rm.p.x,pot);
		mpz_t aux;
		mpz_init(aux);

		mpz_set_str(pot,pow256string(MSG_BYTES_MAX+K-1-i).data(),BASE_16);
		mpz_fdiv_q(aux,rm.p.x,pot);
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
    std::string s = "FF34567890000456789";
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

	rm.p = rp;
	rm.qtd_adicoes=0;

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

	mpz_t  privateKey;
	mpz_init_set(privateKey, random);

	ecc_point publicKey1;
	publicKey1 = mult(generator_point,privateKey);

	printf("message: ");
	rm = getECCPointFromMessage(message);
	if (rm.p.is_valid == false)
    {
		printf("ERROR \n");
		return -1;
	}

    gmp_printf("msg point x,y, msg add:  %Zd %Zd %d \n",rm.p.x,rm.p.y,rm.qtd_adicoes);
    char* msg = getMessageFromPoint(rm);

	gmp_randseed_ui(st,time(NULL));
	mpz_urandomm(random, st, order);

	ecc_point rG    = mult(generator_point,random);
	ecc_point rPub  = mult(publicKey1,random);
	gmp_printf("rPub.x %Zd rPub.y %Zd Mp.x %Zd\n",rPub.x,rPub.y,rm.p.x);
	gmp_printf("rG.x %Zd rG.y %Zd\n",rG.x,rG.y);

	ecc_point Cm = sum(rm.p, rPub);
	gmp_printf("Encryption [Pm+rG].x %Zd [Pm+rG].y %Zd\n",Cm.x,Cm.y);
	gmp_printf("Encryption rG.x = %Zd\n",rG.x);

	//Decryption
	ecc_point rGPriv = mult(rG, privateKey);
	gmp_printf("Decryption privKey=%Zd rG.x=%Zd rGPriv.x=%Zd rGPriv.y=%Zd\n",privateKey,rG.x,rGPriv.x,rGPriv.y);
	mpz_neg(rGPriv.y,rGPriv.y); //-rGPriv.y

    message_point rm1;

	rm1.p = sum(Cm, rGPriv); // Cm-rGPriv
	//rm1.qtd_adicoes = rm.qtd_adicoes; // ???
	gmp_printf("Decryption [Cm-rGPriv].x: %Zd [Cm-rGPriv].y: %Zd\n", rm1.p.x, rm1.p.y);
	printf("Message final from [Cm-rGPriv] point: %s\n", getMessageFromPoint(rm1));

	endtime= clock();
	printf("Execution time was %lu miliseconds\n", (endtime - starttime)/(CLOCKS_PER_SEC/1000));

	return 0;
}


