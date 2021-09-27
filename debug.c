#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include "debug.h"


const char* info[] = {"Block before crypt", "Block after crypt", "Block after XOR with KEY", "Block after S-BLOCK", "Block after SHIFT", "Block after XOR with IV"};


Debug* init(int blocks){
  Debug* new = (Debug*)malloc(sizeof(Debug));
  new->blocks_num = blocks;
  new->key = (unsigned int*)malloc(3 * sizeof(unsigned int));
  new->real_num = 0;
  new->all = (unsigned int*)malloc(14 * blocks);
  return new;
}


void print_debug(Debug* debug, int crypt_mode, char mode){
  int mess[7] = {0, 2, 3, 4, 2, 1};
  int num_mes, ind;
  printf("KEY0:   %x\n", debug->skey);
  printf("KEY1:   %x\n", debug->key[0]);
  printf("KEY2:   %x\n", debug->key[1]);
  if (crypt_mode == 1 && mode == 'e'){
    num_mes = 6;
  }
  else if (crypt_mode == 2 && mode == 'e'){
    num_mes = 6;
    mess[2] = 2;
    mess[3] = 4;
    mess[4] = 3;
  }
  else if (crypt_mode == 1 && mode == 'c'){
    printf("IV:   %x\n", debug->iv);
    num_mes = 7;
    mess[2] = 5;
    mess[3] = 3;
    mess[4] = 4;
    mess[5] = 2;
    mess[6] = 1;
  }
  else if (crypt_mode == 2 && mode == 'c'){
    printf("IV:   %x\n", debug->iv);
    num_mes = 7;
    mess[3] = 4;
    mess[4] = 3;
    mess[5] = 5;
    mess[2] = 2;
    mess[6] = 1;
  }
  for(int i = 0; i < debug->real_num; i++){
    ind = i % num_mes;
    printf("%s:   %x\n", info[mess[ind]], debug->all[i]);
  }
}


void delete_debug(Debug* debug){
  free(debug->key);
  free(debug->all);
  free(debug);
}
