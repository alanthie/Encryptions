#include <stdio.h>
#include<gmp.h>

// Ponto de uma curva Elíptica
typedef struct ecc_point{
	mpz_t x,y;

} ecc_point;


//Parâmetros da curva ( variáveis globais

//a,b são os coeficientes que definem a curva
// prime é o número primo que define o tamanho(teto) do Grupo
// n é a ordem da curva
//h é o cofator  
mpz_t a,b,prime,order;
int cofactor; 
//Ponto gerador utilizado nos algoritmos do ECC
ecc_point generator_point;

// Definição como o ponto do Infinto sendo nulo
ecc_point* INFINITY_POINT=NULL;

//Função de inicialização dos Parâmetros da curva
// Retorna 0 se foi concluída sem erros, -1 do contrário
int init_curve(char* a, char* b, char* prime, char* order, int cofactor, ecc_point g);

//Função de multiplicação de um ponto na curva por um escalar 
//Retorna: Resultado da multiplicação, que também é um ponto da curva
ecc_point* mult(ecc_point p, mpz_t  value);


//Função da soma de dois pontos da curva
//Retorna: Resultado da soma, que também é um ponto da curva
ecc_point* sum(ecc_point p1,ecc_point p2);

//Função de verificação de Pontos.
// retorna 1  se um dado ponto pertence à curva, 0 do contrário
int isPoint(ecc_point p);


//Função que verifica se existe um ponto dada uma determinada coordenada x, e retorna NULL caso contrário
ecc_point* existPoint(mpz_t x);


//Função para dobrar(*2) um ponto da curva
//Retorno: Dobro do ponto passado por parâmetro, que também é um ponto da curva
ecc_point* double_p(ecc_point p);
