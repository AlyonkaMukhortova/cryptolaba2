#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <iso646.h>
#include <getopt.h>


const struct option* init_aes32(){
  const struct option* options = (struct option*)malloc(9 * sizeof(struct option));
  //options = {
  //  {"help", no_argument, NULL, 0},
  //  {"version", no_argument, NULL, 0},
    //{"mode", required_argument, NULL, 0},
    //{"enc", no_argument, NULL, 0},
    //{"dec", no_argument, NULL, 0},
    //{"key", required_argument, NULL, 0},
    //{"iv", required_argument, NULL, 0},
    //{"debug", no_argument, NULL, 0},
    //{NULL, 0, NULL, 0}
  //};
  //struct options[0] = {"help", no_argument, NULL, 0};
  //struct options[1] = {"version", no_argument, NULL, 0};
  //struct options[2] = {"mode", required_argument, NULL, 0};
  //struct options[3] = {"enc", no_argument, NULL, 0};
  //struct options[4] = {"dec", no_argument, NULL, 0};
  //struct options[5] = {"key", required_argument, NULL, 0};
  //struct options[6] = {"iv", required_argument, NULL, 0};
  //struct options[7] = {"debug", no_argument, NULL, 0};
  //struct options[8] = {NULL, 0, NULL, 0};
  return options;
}


unsigned int** xor_key(unsigned int** a, unsigned int** k, int count){
  for (int i = 0; i < count; i++){
    for (int j = 0; j < count; j++){
      a[i][j] = a[i][j] ^ k[i][j];
    }
  }
  return a;
}


unsigned int** circular_shift(unsigned int** a, int count){
  for (int shift_num = 0; shift_num < count; shift_num++){
    for (int j = 0; j < shift_num; j++){
      unsigned int ptr = a[shift_num][0];
      for (int k = 0; k < count - 1; k++){
        a[shift_num][k] = a[shift_num][k+1];
      }
      a[shift_num][count - 1] = ptr;
    }
  }
  return a;
}


unsigned int** eight_bit_blocks(unsigned int p, int count){
  unsigned int** a = (unsigned int**)malloc(count * sizeof(unsigned int*));
  for(int i = 0; i < count; i++){
    a[i] = (unsigned int*)malloc(count * sizeof(unsigned int));
  }
  for (int i = count; i > 0; i--){
    for (int j = count; j > 0; j--){
      a[i - 1][j - 1] = p % 256;
      p = p >> 8;
    }
  }
  return a;
}


unsigned int merge(unsigned int** a, int count){
  unsigned int res = 0;
  for (int i = 0; i < count; i++){
    for (int j = 0; j < count; j++){
      res = res << 8;
      res |= a[i][j];
    }
  }
  return res;
}


unsigned int** s_block(unsigned int** a, unsigned int*s_substitution, int count){
  for (int i = 0; i < count; i++){
    for (int j = 0; j < count; j++){
      a[i][j] = s_substitution[a[i][j]];
    }
  }
  return a;
}


unsigned int* load(char* file_name, unsigned int* p){
  FILE* fd;
  fd = fopen(file_name, "r");
  unsigned int* s_substitution = (unsigned int*)malloc(256 * sizeof(unsigned int));
  unsigned int* s = s_substitution;
  for (int i = 0; i < 256; i++){
    fscanf(fd, "%x", s);
    s++;
  }
  fscanf(fd, "%x", p);
  fclose(fd);
  return s_substitution;
}


unsigned int cipher_round(unsigned int* s_substitution, unsigned int p, unsigned int key){
  int count = 2;
  unsigned int** k = eight_bit_blocks(key, count);
  unsigned int** a = eight_bit_blocks(p, count);
  a = s_block(a, s_substitution, count);
  a = circular_shift(a, count);
  a = xor_key(a, k, count);
  p = merge(a, count);
  return p;
  free(a);
  free(k);
}


unsigned int cipher(unsigned int* s_substitution, unsigned int p, unsigned int* key){
  int rounds = 2;
  for (int i = 0; i < rounds; i++){
    p = cipher_round(s_substitution, p, key[i + 1]);
  }
  return p;
}


unsigned int* key_calculation (unsigned int k, unsigned int* key){
  key[0] = k;
  while (k > 0){
    key[1] = key[1] << 1;
    key[1] |= k % 2;
    k = k / 2;
  }
  key[2] = key[0] ^ key[1];
  return key;
}


int main (int argc, char** argv) {
  const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"mode", required_argument, NULL, 'm'},
    {"enc", no_argument, NULL, 'e'},
    {"dec", no_argument, NULL, 'd'},
    {"key", required_argument, NULL, 'k'},
    {"iv", required_argument, NULL, 'i'},
    {"debug", no_argument, NULL, 'g'},
    {NULL, 0, NULL, 0}
  };
  //const struct option* long_options = init_aes32();
  unsigned int* key = (unsigned int*)calloc(3, sizeof(unsigned int));
  unsigned int k, p;
  unsigned int* s_substitution = load(argv[argc - 1], &p);
  int c = getopt_long(argc, argv, "hvm:edk:i:g", long_options, NULL);
  printf("Enter key --> ");
  scanf("%d",&k);
  key = key_calculation(k, key);
  unsigned int c0 = p ^ key[0];
  p = cipher(s_substitution, c0, key);
  printf("%x\n", p);
  printf("C = %d\n", c);
  printf("optind = %s\n", optarg);
  free(s_substitution);
}
