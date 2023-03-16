#include <stdio.h>
#include "relic.h"
//#include "/usr/local/include/relic/low/relic_fp_low.h"
//#include <relic.h>
#include <time.h>
#define MESSAGESIZE 40

bn_t privKey;
ep_t myPublicKey;
void write_bn(FILE *out, bn_t source) { //Realiza a escrita do número source do tipo bn_t no arquivo out.
	int i;
	fwrite(&(source->alloc), sizeof(int), 1, out);
	fwrite(&(source->used), sizeof(int), 1, out);
	fwrite(&(source->sign), sizeof(int), 1, out);
	for(i = 0; i< BN_SIZE; i++) { fwrite(&(source->dp[i]),sizeof(uint32_t), 1, out); }
}
void write_ep(FILE *out, ep_t source) { //Realiza a escrita do ponto source do tipo ep_t no arquivo out.
	int i;
	fwrite(&(source->norm), sizeof(int), 1, out);
	for(i = 0; i < (FP_DIGS + PADDING(FP_BYTES)/sizeof(dig_t)); i++) {
		fwrite(&(source->x[i]), sizeof(uint32_t), 1, out);
	}
	for(i = 0; i < (FP_DIGS + PADDING(FP_BYTES)/sizeof(dig_t)); i++) {
		fwrite(&(source->y[i]), sizeof(uint32_t), 1, out);
	}
	for(i = 0; i < (FP_DIGS + PADDING(FP_BYTES)/sizeof(dig_t)); i++){
		fwrite(&(source->z[i]), sizeof(uint32_t), 1, out);
	}
}
void read_bn(FILE *in, bn_t destination) { //Realiza a leitura do número source do tipo bn_t do arquivo in.
	int i;
	fread(&(destination->alloc), sizeof(int), 1, in);
	fread(&(destination->used), sizeof(int), 1, in);
	fread(&(destination->sign), sizeof(int), 1, in);
	for(i = 0; i < BN_SIZE; i++) {
		fread(&(destination->dp[i]), sizeof(uint32_t), 1, in); }
}
void read_ep(FILE *in, ep_t destination) { //Realiza a leitura do ponto source do tipo ep_t do arquivo in.
	int i;
	fread(&(destination->norm), sizeof(int), 1, in);
	for(i = 0; i < (FP_DIGS + PADDING(FP_BYTES)/sizeof(dig_t)); i++) {
		fread(&(destination->x[i]), sizeof(uint32_t), 1, in);
	}
	for(i = 0; i < (FP_DIGS + PADDING(FP_BYTES)/sizeof(dig_t)); i++) {
		fread(&(destination->y[i]), sizeof(uint32_t), 1, in);
	}
	for(i = 0; i < (FP_DIGS + PADDING(FP_BYTES)/sizeof(dig_t)); i++) {
		fread(&(destination->z[i]), sizeof(uint32_t), 1, in);
	}
}
//Realiza a conversão de um número do tipo bn_t em uma sequência de caracteres.
void debug_bn_write_bin(unsigned char *bin, int *len, int *sign, bn_t a) {
	int size, k, i, j;
	dig_t d;
	bn_size_bin(&size, a);
	if (*len < size) { THROW(ERR_NO_BUFFER); }
	for (i = 0; i < a->used; i++) {
		d = a->dp[i];
		for (j = 0; j < (int)sizeof(dig_t); j++) {
			k = i * sizeof(dig_t) + j;
			if (k < *len) { bin[k] = d & 0xFF; d = d >> 8; }
		} }
	for (k = k; k < *len; k++) { bin[k] = 0; }
	*len = size; *sign = a->sign;
}
void keysInit() { //Representa a criação das chaves
	bn_t n;
	//Criação da chave privada.
	bn_new(n);
	bn_new(privKey);
	ep_curve_get_ord(n);
	bn_rand(privKey,BN_POS, bn_bits(n));
	//Criação da chave pública.
	ep_null(myPublicKey);
	ep_new(myPublicKey);
	ep_mul_gen(myPublicKey, privKey);
}
int desc(ep_t auxPoint,ep_t messagePoint,ep_t otherPoint,bn_t otherNumber,bn_t n, int used,int size,unsigned char* otherMessage,FILE*saida){
	ep_mul_basic(auxPoint,myPublicKey,privKey);
	ep_sub_basic(messagePoint,messagePoint,auxPoint);
	ep_null(otherPoint);
	ep_new(otherPoint);
	ep_curve_get_gen(otherPoint);
	bn_new(otherNumber);
	bn_rand(otherNumber,BN_POS, bn_bits(n));
	int i;
	for(i=0;i<used;i++) {
		otherNumber->dp[i] = messagePoint->x[i] - otherPoint->x[i];
	}
	otherNumber->used = used;
	int t1;
	size = MESSAGESIZE; t1 = 1;
	debug_bn_write_bin(otherMessage, &size,&t1,otherNumber);
	printf("result: %s",otherMessage);
	fwrite(&otherMessage, sizeof(char), (MESSAGESIZE-1), saida);
}
int main(int argc, char *argv[]) {
	ep_t a, b, c, t, publicPoint, auxPoint, messagePoint, otherPoint;
	bn_t privNumber, messageNumber, otherNumber, n;
	int i, size, index, used;
	unsigned int fileSize;
	unsigned char message[MESSAGESIZE], otherMessage[MESSAGESIZE];
	FILE *entrada, *saida, *privateKey, *publicKey;
	char caracter;
	core_init();
	clock_t start_time, end_time;
	start_time = clock();
	if (argv[1][0] == 'C') {
		if (!(privateKey = fopen("PrivateKey.prk","w"))) {
			fprintf(stderr, "ERRO ao tentar abrir arquivo PrivateKey.prk\n"); }
		if (!(publicKey = fopen("PublicKey.puk","w"))) {
			fprintf(stderr, "ERRO ao tentar abrir arquivo PublicKey.puk\n"); }
		ep_param_set(NIST_P256);
		keysInit();
		write_bn(privateKey,privKey);
		write_ep(publicKey, myPublicKey);
		fclose(privateKey);
		fclose(publicKey);
	}
	else {
		if (!(entrada = fopen(argv[2],"r"))) {
			fprintf(stderr, "ERRO ao tentar abrir %s\n", argv[2]); }
		saida = fopen(argv[3], "w");
		ep_param_set(NIST_P256);
		bn_new(n);
		bn_new(messageNumber);
		bn_new(otherNumber);
		//Leitura das chaves
		if (!(privateKey = fopen("PrivateKey.prk","r"))) {
			fprintf(stderr, "ERRO ao tentar abrir arquivo PrivateKey.prk\n"); }
		if (!(publicKey = fopen("PublicKey.puk","r"))) {
			fprintf(stderr, "ERRO ao tentar abrir arquivo PublicKey.puk\n"); }
		bn_new(n);
		bn_new(privKey);
		read_bn(privateKey, privKey);
		ep_null(myPublicKey);
		ep_new(myPublicKey);
		read_ep(publicKey, myPublicKey);
		ep_curve_get_ord(n);
		fileSize = 0;
		index = 0;
		if (argv[1][0] == 'E') {
			for(i = 0; i < MESSAGESIZE; i++) { message[i] = '\0'; }
			while (!feof(entrada)){
				if (!feof(entrada)) {
					if (fileSize != (MESSAGESIZE-1)) {
						fread(&caracter, sizeof(char), 1, entrada);
						if (!feof(entrada)) {
							message[index++] = caracter;
							fileSize++;
						}
					}
					else {
						fileSize = 0;
						index = 0;
						//Criptografia de um bloco de mensagem.
						ep_null(messagePoint);
						ep_new(messagePoint);
						bn_read_bin(messageNumber, message, MESSAGESIZE);//, BN_POS);
						size = MESSAGESIZE-1;
						int m = 1;
						ep_curve_get_gen(messagePoint);
						for(i=0;i<messageNumber->used;i++) {
							messagePoint->x[i] = messagePoint->x[i] + messageNumber->dp[i];
						}
						ep_null(auxPoint);
						ep_new(auxPoint);
						ep_mul_basic(auxPoint,myPublicKey,privKey);
						ep_add_basic(messagePoint,auxPoint,messagePoint);
						fwrite(&(messageNumber->used), sizeof(int), 1, saida);
						write_ep(saida, messagePoint);
						//printf("%s",messagePoint);
						printf("a2");
						for(i = 0; i < MESSAGESIZE; i++) { message[i] = '\0'; }
					}
				}
			}
			if (index > 0) { //Criptografia do último bloco.
				fileSize = 0;
				index = 0;
				ep_null(messagePoint);
				ep_new(messagePoint);
				bn_read_bin(messageNumber, message, MESSAGESIZE);//, BN_POS);
				ep_curve_get_gen(messagePoint);
				for(i=0;i<messageNumber->used;i++) {
					messagePoint->x[i] = messagePoint->x[i] + messageNumber->dp[i]; }
				ep_null(auxPoint);
				ep_new(auxPoint);
				ep_mul_basic(auxPoint,myPublicKey,privKey);
				ep_add_basic(messagePoint,auxPoint,messagePoint);
				fwrite(&(messageNumber->used), sizeof(int), 1, saida);
				write_ep(saida, messagePoint);
				//printf("%s",messagePoint);
						printf("a1k");
				desc(auxPoint,messagePoint,otherPoint,otherNumber, n,messageNumber->used,size,otherMessage,saida) ;
			}
			else if (argv[1][0] == 'D') {
				while (!feof(entrada)) {
					//Decriptografia de um ponto em um bloco de mensagem.
					fread(&(used), sizeof(int), 1, entrada);
					read_ep(entrada, messagePoint);
					if (!feof(entrada)) {
						ep_mul_basic(auxPoint,myPublicKey,privKey);
						ep_sub_basic(messagePoint,messagePoint,auxPoint);
						ep_null(otherPoint);
						ep_new(otherPoint);
						ep_curve_get_gen(otherPoint);
						bn_new(otherNumber);
						bn_rand(otherNumber,BN_POS, bn_bits(n));
						for(i=0;i<used;i++) {
							otherNumber->dp[i] = messagePoint->x[i] - otherPoint->x[i];
						}
						otherNumber->used = used;
						int t1;
						size = MESSAGESIZE; t1 = 1;
						debug_bn_write_bin(otherMessage, &size,&t1,otherNumber);
						fwrite(&otherMessage, sizeof(char), (MESSAGESIZE-1), saida);
					}
				}
			}
			ep_free(auxPoint);
			ep_free(myPublicKey);
			ep_free(messagePoint);
			ep_free(otherPoint);
			bn_clean(privKey);
			bn_clean(messageNumber);
			bn_clean(otherNumber);
			bn_clean(n);
			fclose(entrada); fclose(saida);
		}
		end_time = clock();
		printf("Execution time was %lu miliseconds\n", (end_time - start_time)/(CLOCKS_PER_SEC/1000));
		core_clean(); return 0;
	}}
