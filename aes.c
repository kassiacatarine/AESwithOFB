#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes.h"
#include "OFB.c"

/*
 - Adição e subtração do GF(2^8)
 */
uint8_t GfAddSub(uint8_t a, uint8_t b){
	return a^b;
}

/*
 - Multiplicação do GF(2^8)
 - Polinomio m(x) = x8 + x4 + x3 + x + 1
 */
uint8_t gmult(uint8_t a, uint8_t b){

	uint8_t p = 0, i = 0, hbs = 0;

	for (i = 0; i < 8; i++) {
		if (b & 1) {
			p ^= a;
		}

		hbs = a & 0x80;
		a <<= 1;
		if (hbs) a ^= 0x1b; // 0000 0001 0001 1011
		b >>= 1;
	}

	return (uint8_t)p;
}

/*
 - Adição de 4 byte words
 - m(x) = x4+1
 */
void coef_add(uint8_t a[], uint8_t b[], uint8_t d[]) {

	d[0] = a[0]^b[0];
	d[1] = a[1]^b[1];
	d[2] = a[2]^b[2];
	d[3] = a[3]^b[3];
}

/*
 - Multiplicação dos 4 byte
 - m(x) = x4+1
 */
void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d){

	d[0] = gmult(a[0],b[0])^gmult(a[3],b[1])^gmult(a[2],b[2])^gmult(a[1],b[3]);
	d[1] = gmult(a[1],b[0])^gmult(a[0],b[1])^gmult(a[3],b[2])^gmult(a[2],b[3]);
	d[2] = gmult(a[2],b[0])^gmult(a[1],b[1])^gmult(a[0],b[2])^gmult(a[3],b[3]);
	d[3] = gmult(a[3],b[0])^gmult(a[2],b[1])^gmult(a[1],b[2])^gmult(a[0],b[3]);
}

uint8_t * Rcon(uint8_t i){

	if (i == 1) {
		R[0] = 0x01; // x^(1-1) = x^0 = 1
	} else if (i > 1) {
		R[0] = 0x02;
		i--;
		while (i-1 > 0) {
			R[0] = gmult(R[0], 0x02);
			i--;
		}
	}

	return R;
}

/*
 - XOR bit a bit com o estado e a chave da rodada
 - Nb = 4, pois o tamanho da chave e igual ao estado, ou seja, 16 bytes com 4 colunas
*/
void AddRoundKey(uint8_t *estado, uint8_t *k, uint8_t r){

	uint8_t c;

	for (c = 0; c < Nb; c++) {
		estado[Nb*0+c] = estado[Nb*0+c]^k[4*Nb*r+4*c+0];
		estado[Nb*1+c] = estado[Nb*1+c]^k[4*Nb*r+4*c+1];
		estado[Nb*2+c] = estado[Nb*2+c]^k[4*Nb*r+4*c+2];
		estado[Nb*3+c] = estado[Nb*3+c]^k[4*Nb*r+4*c+3];
	}
}

/*
 - Mistura todos os bytes, gerando uma "nova" tabela
*/
void MixColumns(uint8_t *estado){

	uint8_t a[] = {0x02, 0x01, 0x01, 0x03};
	uint8_t i, j, col[4], res[4];

	for(j = 0; j < Nb; j++){
		for (i = 0; i < 4; i++) {
			col[i] = estado[Nb*i+j];
		}

		coef_mult(a, col, res);

		for(i = 0; i < 4; i++){
			estado[Nb*i+j] = res[i];
		}
	}
}

/*
 - Inverso da função MixColumns
 - Usado para desencriptografar
 */
void inv_MixColumns(uint8_t *estado){

	uint8_t a[] = {0x0e, 0x09, 0x0d, 0x0b}; // a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < Nb; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = estado[Nb*i+j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			estado[Nb*i+j] = res[i];
		}
	}
}

/*
 - Permutação Simples entre as linhas
 - Desloca as 3 ultimas linhas do estado
*/
void ShiftRows(uint8_t *estado){

	uint8_t i, k, s, tmp;

	for(i = 1; i < 4; i++){
		s = 0;
		while(s < i){
			tmp = estado[Nb*i+0];

			for (k = 1; k < Nb; k++){
				estado[Nb*i+k-1] = estado[Nb*i+k];
			}

			estado[Nb*i+Nb-1] = tmp;
			s++;
		}
	}
}

/*
 - Inverso da função ShiftRows
 - Usado para desencriptografar
 */
void inv_ShiftRows(uint8_t *estado){

	uint8_t i, k, s, tmp;

	for (i = 1; i < 4; i++) {
		s = 0;
		while (s < i) {
			tmp = estado[Nb*i+Nb-1];

			for (k = Nb-1; k > 0; k--) {
				estado[Nb*i+k] = estado[Nb*i+k-1];
			}

			estado[Nb*i+0] = tmp;
			s++;
		}
	}
}

/*
 - Utiliza a S-box para fazer a substituição byte a byte do bloco
 */
void SubBytes(uint8_t *estado){

	uint8_t i, j;
	uint8_t row, col;

	for (i = 0; i < 4; i++){
		for (j = 0; j < Nb; j++){
			row = (estado[Nb*i+j] & 0xf0) >> 4;
			col = estado[Nb*i+j] & 0x0f;
			estado[Nb*i+j] = s_box[16*row+col];
		}
	}
}

/*
 - Inverso do SubBytes
 - Usado para desencriptografar
 */
void inv_SubBytes(uint8_t *estado){

	uint8_t i, j;
	uint8_t row, col;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			row = (estado[Nb*i+j] & 0xf0) >> 4;
			col = estado[Nb*i+j] & 0x0f;
			estado[Nb*i+j] = inv_s_box[16*row+col];
		}
	}
}

/*
 - Aplica um S-box para cada um dos bytes
 */
void sub_word(uint8_t *w){

	uint8_t i;

	for (i = 0; i < 4; i++) {
		w[i] = s_box[16*((w[i] & 0xf0) >> 4) + (w[i] & 0x0f)];
	}
}

/*
 - Permutação usada na chave expandida
 */
void rot_word(uint8_t *w){

	uint8_t tmp;
	uint8_t i;

	tmp = w[0];

	for (i = 0; i < 3; i++) {
		w[i] = w[i+1];
	}
	w[3] = tmp;
}

/*
 - Expação da chave
 */
void key_expansion(uint8_t *key, uint8_t *w){

	uint8_t tmp[4];
	uint8_t i, j;
	uint8_t len = Nb*(round+1);//tamanho da "key" na rodada

	for(i = 0; i < Nk; i++){//Aloca a "key" no "w"
		w[4*i+0] = key[4*i+0];
		w[4*i+1] = key[4*i+1];
		w[4*i+2] = key[4*i+2];
		w[4*i+3] = key[4*i+3];
	}

	for(i = Nk; i < len; i++){//Parte extendida
		tmp[0] = w[4*(i-1)+0];
		tmp[1] = w[4*(i-1)+1];
		tmp[2] = w[4*(i-1)+2];
		tmp[3] = w[4*(i-1)+3];

		if(i%Nk == 0){
			rot_word(tmp);//Permuta
			sub_word(tmp);//Aplica S-box
			coef_add(tmp, Rcon(i/Nk), tmp);//Multiplicação dos bytes do words
		}else if(Nk > 6 && i%Nk == 4){
			sub_word(tmp);
		}

		w[4*i+0] = w[4*(i-Nk)+0]^tmp[0];
		w[4*i+1] = w[4*(i-Nk)+1]^tmp[1];
		w[4*i+2] = w[4*(i-Nk)+2]^tmp[2];
		w[4*i+3] = w[4*(i-Nk)+3]^tmp[3];
	}
}

/*
 - Função responsavel por toda a chamada de criptografia
*/
void Cipher(uint8_t *entrada, uint8_t *saida, uint8_t *w, uint8_t *k){

	uint8_t estado[4*Nb];
	uint8_t r, i, j;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			estado[Nb*i+j] = entrada[i+4*j];
		}
	}
    OutputFeedback(k, w, 0);
	AddRoundKey(estado, k, 0);

	for(r = 1; r < round; r++){
        OutputFeedback(k, w, r);
		SubBytes(estado);
		ShiftRows(estado);
		MixColumns(estado);
		AddRoundKey(estado, k, r);
	}
    OutputFeedback(k, w, r);
	SubBytes(estado);
	ShiftRows(estado);
	AddRoundKey(estado, k, round);

	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			saida[i+4*j] = estado[Nb*i+j];
		}
	}
}

/*
 - Função responsavel por toda a chamada de descriptografia
 - O inverso da função Chipher
*/
void inv_Cipher(uint8_t *entrada, uint8_t *saida, uint8_t *w, uint8_t *k){

	uint8_t estado[4*Nb];
	uint8_t r, i, j;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			estado[Nb*i+j] = entrada[i+4*j];
		}
	}
    OutputFeedback(k, w, r);
	AddRoundKey(estado, k, round);

	for (r = round-1; r >= 1; r--) {
        OutputFeedback(k, w, r);
		inv_ShiftRows(estado);
		inv_SubBytes(estado);
		AddRoundKey(estado, k, r);
		inv_MixColumns(estado);
	}

    OutputFeedback(k, w, r);
	inv_ShiftRows(estado);
	inv_SubBytes(estado);
	AddRoundKey(estado, k, 0);

	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			saida[i+4*j] = estado[Nb*i+j];
		}
	}
}

void printVetor(uint8_t *vetor){

    uint8_t i;

    for (i = 0; i < 4; i++){//Imprime o texto de entrada
		printf("%x %x %x %x ", vetor[4*i+0], vetor[4*i+1], vetor[4*i+2], vetor[4*i+3]);
	}
	printf("\n\n");
}
