#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "vetor_inicializacao.h"
/*
 - Aplicação do Output Feedback Mode
 - Objetivo: Realimentar a chave com a saída da anterior para gerar uma "nova"
*/

void OutputFeedback(uint8_t *k, uint8_t *w, uint8_t r){

    uint8_t i;

    /*
     - Desloca para esquerda(Shift to left)
     - key = b - s
     - b = bits existentes
     - s = bits que seram incruidos
     - Desloca as 2 ultimas words para a esquerda
     - Os primeiros 8 bytes sai e os 8 ultimos permanece em seu lugar
    */
    for(i = 0; i < 2; i++){
        //Desloca os ultimos 8 bytes para esquerda
        k[4*i+0] = k[4*(i+2)+0];
		k[4*i+1] = k[4*(i+2)+1];
        k[4*i+2] = k[4*(i+2)+2];
		k[4*i+3] = k[4*(i+2)+3];
        //Aloca os primeiros 8 bytes da chave da rodada nos 8 bytes finais vetor
        k[4*(i+2)+0] = w[4*Nb*r+4*i+0];
		k[4*(i+2)+1] = w[4*Nb*r+4*i+1];
        k[4*(i+2)+2] = w[4*Nb*r+4*i+2];
		k[4*(i+2)+3] = w[4*Nb*r+4*i+3];
    }
    if(r == 0){//Se na o round for 0 substituir os primeiro 8 bytes pelo vetor de inicialização (iv)
        for(i=0; i < 2; i++){
            k[4*i+0] = iv[4*i+0];
            k[4*i+1] = iv[4*i+1];
            k[4*i+2] = iv[4*i+2];
            k[4*i+3] = iv[4*i+3];
        }
    }
}
