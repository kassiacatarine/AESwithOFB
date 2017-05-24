/*
Questão 2 letra D
Criar um OFB com o AES
Aluna: Kássia Catarine
Matricula: 17/0052087
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>// uint8_t é usado para trabalhar com bytes, assim fica mais facil trabalhar com ele para o AES
#include "aes.h"
#include "aes.c"
#include "key.h"
#include "texto.h"

int main(int argc, char *argv[]){

	uint8_t i;
    uint8_t saida[16]; // 128 bits, saida do texto cifrado
	uint8_t *w; // Expanção da chave
    uint8_t *k; //Chave OFB

    printf("\t\t\t\t\t| AES - Criptografia |\n\n");

    printf("\nTexto em Claro Entrada:\n");
    printVetor(entrada);//Imprime o texto

    printf("\nChave Inicial:\n");
    printVetor(key);//Imprime a chave

    w = malloc(Nb*(round+1)*4);//Aloca espaço para a chave expandida
    k = malloc(Nb*4);//Alocar espaço para a key stream

    key_expansion(key, w);//expande a chave
	Cipher(entrada, saida, w, k);//Chama para Encriptografar

	printf("\nMensagem Encriptografada:\n");
    printVetor(saida);

	inv_Cipher(saida, entrada, w, k);//Chama para desencriptografar

	printf("\nTexto em Claro Saida:\n");
	printVetor(entrada);

	return 0;
}
