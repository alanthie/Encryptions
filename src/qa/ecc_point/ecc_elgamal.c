#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "ecc_curve.c"

char  *pot_256[21] ={"1", "100", "10000", "1000000", "100000000", "10000000000", "1000000000000", "100000000000000",
 "10000000000000000", "1000000000000000000", "100000000000000000000", "10000000000000000000000", "1000000000000000000000000",
 "100000000000000000000000000","10000000000000000000000000000", "1000000000000000000000000000000", "100000000000000000000000000000000",
 "10000000000000000000000000000000000","1000000000000000000000000000000000000","100000000000000000000000000000000000000","10000000000000000000000000000000000000000"};
int MSG_BYTES_MAX=18;
 /*{"1", "256", "65536", "16777216", "4294967296", "1099511627776", "281474976710656", "72057594037927936", "18446744073709551616",
 "4722366482869645213696", "1208925819614629174706176", "309485009821345068724781056", "79228162514264337593543950336", "20282409603651670423947251286016",
 "5192296858534827628530496329220096", "1329227995784915872903807060280344576", "340282366920938463463374607431768211456", "87112285931760246646623899502532662132736",
 "22300745198530623141535718272648361505980416", "5708990770823839524233143877797980545530986496"};
*/



typedef struct message_point{
	ecc_point* p;
	int qtd_adicoes;
} message_point;

int random_in_range (unsigned int min, unsigned int max)
{
  int base_random = rand(); /* in [0, RAND_MAX] */
  if (RAND_MAX == base_random) return random_in_range(min, max);
  /* now guaranteed to be in [0, RAND_MAX) */
  int range       = max - min,
      remainder   = RAND_MAX % range,
      bucket      = RAND_MAX / range;
  /* There are range buckets, plus one smaller interval
     within remainder of RAND_MAX */
  if (base_random < RAND_MAX - remainder) {
    return min + base_random/bucket;
  } else {
    return random_in_range (min, max);
  }
}

message_point* getECCPointFromMessage(char* message){ 
	mpz_t x;
	mpz_init(x);
	message_point* m;
	ecc_point* result;
	printf("%s\n", message);
	printf("%c\n", message[0]);
	printf("%d", (*message));

	int i=MSG_BYTES_MAX-1;  
	for (i;i>=0;i--){
		mpz_t temp;
		mpz_init_set_str(temp,pot_256[i],16);
		gmp_printf("temp: %Zd ",temp);
		mpz_addmul_ui(x,temp,(*message));
		printf(" m:%d \n",(*message));
		++message;
		if (!(*message)){
			break;
		}
	}
	gmp_printf("fase 1 prime:%Zd x= %Zd\n",prime,x);
	i=0;
	do{
		printf("i-> %d\n",i);
		result= existPoint(x);
		i++;
		mpz_add_ui(x,x,1);
	} while(result==NULL && i<10);
	mpz_mod((*result).x,(*result).x,prime);
	gmp_printf("fase 2 Ponto: %Zd %Zd \n",(*result).x,(*result).y);
	
	if (result){
		m = malloc(sizeof(message_point));
		(*m).p= result;
		(*m).qtd_adicoes=i-1;
		return m;
	}else
		return NULL;
}

char* getMessageFromPoint(message_point* msg){
	char* message= malloc((MSG_BYTES_MAX+1)*sizeof(char));
	int i=MSG_BYTES_MAX ;
	message_point* m=malloc(sizeof(message_point));
	(*m).p=malloc(sizeof(ecc_point));
	mpz_init_set((*(*m).p).x,(*(*msg).p).x);
	mpz_init_set((*(*m).p).y,(*(*msg).p).y);
	(*m).qtd_adicoes=(*msg).qtd_adicoes;
	gmp_printf("X: %Zd \n",(*(*m).p).x); 
	mpz_sub_ui((*(*m).p).x,(*(*m).p).x,(*m).qtd_adicoes);
	printf("\n\n");
	i=0;
	for (i;i<MSG_BYTES_MAX;i++){
		mpz_t pot;
		mpz_init_set_str(pot,pot_256[MSG_BYTES_MAX-i],16);
		mpz_sub_ui(pot,pot,1);
		gmp_printf("i:%d pot: %Zd \n",i,pot); 
		mpz_and((*(*m).p).x,(*(*m).p).x,pot);
		gmp_printf("and_X: %Zd ",(*(*m).p).x);
		mpz_t aux;
		mpz_init(aux);
		mpz_set_str(pot,pot_256[MSG_BYTES_MAX-1-i],16);
		mpz_fdiv_q(aux,(*(*m).p).x,pot);
		printf(".%d.%c ",mpz_get_ui(aux),mpz_get_ui(aux));
		message[i]=(mpz_get_ui(aux)>=32 && mpz_get_ui(aux)<127)?mpz_get_ui(aux):'\0';

	}
	message[MSG_BYTES_MAX]='\0';
	return message;
}

int main(int argc, char** argv){
	FILE* f;
	char* file=argv[1];
	f= fopen(file,"r");
	char prime_c[80],a_c[80],b_c[80],x_c[80],order_c[80],*message=malloc(200*sizeof(char));
	message_point* m;
	ecc_point* generator;
	ecc_point* publicKey;
	ecc_point* p;
	p=malloc(sizeof(ecc_point));
	publicKey=malloc(sizeof(ecc_point));
	generator=malloc(sizeof(ecc_point));
	fscanf(f,"%s \n",prime_c);
	fscanf(f,"%s \n",a_c);
	fscanf(f,"%s \n",b_c);
	mpz_init((*generator).x);
	mpz_init((*generator).y);
	gmp_fscanf(f,"%Zd ",(*generator).x);
	gmp_fscanf(f,"%Zd ",(*generator).y);
	fscanf(f,"%s ",order_c);
	gmp_printf("leituras-> prime:%s, a:%s, b: %s, , order:%s ",prime_c,a_c,b_c,order_c);
	m = malloc(sizeof(message_point));
	(*m).p=malloc(sizeof(ecc_point));
	(*m).p=p;
	(*m).qtd_adicoes=0;
	clock_t starttime, endtime;
	starttime = clock();
	init_curve(a_c,b_c,prime_c,order_c,1,*generator);
	//geração das chaves
	mpz_t random;
	mpz_init(random); 
	gmp_randstate_t st;
	gmp_randinit_default(st);
	gmp_randseed_ui(st,time(NULL));
	mpz_urandomm(random, st, order);
	gmp_printf(" random: %Zd %Zd",random,order);

	mpz_t  privateKey;
	mpz_init_set(privateKey,random); 
	gmp_printf(" pvt: %Zd \n",privateKey);
	ecc_point* publicKey1;
	publicKey1 = mult(generator_point,privateKey);
	gmp_printf(" pK.x: %Zd pK.Y:%Zd priv: %Zd \n",(*publicKey1).x,(*publicKey1).y,privateKey);
	//encriptação
	
	printf("mensagem: ");
	scanf("%[ -~]s",message);
	m= getECCPointFromMessage(message);
	if (!m){
		printf("ERROR \n");
		return -1;
	}
		char* msg;
		gmp_printf("x,y,a:  %Zd %Zd %d \n",(*(*m).p).x,(*(*m).p).y,(*m).qtd_adicoes);
		msg= getMessageFromPoint(m);
	
	gmp_printf("Mensagem:  %c \n", msg[1]);
	
	gmp_randseed_ui(st,time(NULL));
	mpz_urandomm(random, st, order);
	gmp_printf(" random: %Zd %Zd",random,order);
//	mpz_set_ui(random,2);
/*	gmp_randclear(st);
*/	
	ecc_point* c1 = mult(generator_point,random);
	ecc_point* aux1=mult(*publicKey1,random);
	gmp_printf("aux.x %Zd aux.y %Zd Mp.x %Zd\n",(*aux1).x,(*aux1).y,(*(*m).p).x);
	gmp_printf("C1.x %Zd C1.y %Zd\n",(*c1).x,(*c1).y);
	gmp_printf("C1.x %Zd C1.y %Zd\n",(*c1).x,(*c1).y);
	ecc_point* c2 = sum((*(*m).p), (*aux1));
	gmp_printf("C2.x %Zd C2.y %Zd\n",(*c2).x,(*c2).y);
	//return (c1,c2)					
	gmp_printf(" Fim encriptacao %Zd\n",(*c1).x);
	
	//decriptacao
	ecc_point *aux = mult(*c1,privateKey);
	gmp_printf("priv: %Zd c1.x %Zd aux.x %Zd aux.y %Zd\n",privateKey,(*c1).x,(*aux).x,(*aux).y);
	mpz_neg((*aux).y,(*aux).y);
	message_point *m1 =  malloc( sizeof(message_point));
	(*m1).p=sum(*c2,/**mult(*c1,privateKey)*/  *aux); 
	(*m1).qtd_adicoes= (*m).qtd_adicoes;
	gmp_printf("M1.x: %Zd M1.y: %Zd\n",(*(*m1).p).x,(*(*m1).p).y);
	printf("Mensagem final: %s \n",getMessageFromPoint(m1));
	endtime= clock();
	printf("Execution time was %lu miliseconds\n", (endtime - starttime)/(CLOCKS_PER_SEC/1000));
}


