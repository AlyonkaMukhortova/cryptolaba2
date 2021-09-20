#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <iso646.h>
#include <getopt.h>

#define SUCCESS 0
#define NO_KEY -1
#define NO_MODE -2
#define WRONG_VALUE -3



unsigned int hex_from_str(char* arg, int* err){
  unsigned int res = 0;
  for (int i = 0; i < strlen(arg); i++){
    res *= 16;
    unsigned int a = 0;
    if (arg[i] >= '0' && arg[i] <= '9'){
      a = arg[i] - '0';
    }
    else if (arg[i] >= 'a' && arg[i] <= 'f'){
      a = arg[i] - 'a' + 10;
    }
    else{
      *err = WRONG_VALUE;
      return res;
    }
    res += a;
  }
  return res;
}


int analyse_input (int argc, char** argv, unsigned int* s_substitution, unsigned int* key, unsigned int* iv){
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
  const char* short_options = "hvm:edk:i:g";
  int now_optind = 0;
  char* mode = NULL;
  int crypt_mode = 0;
  while (optind < argc - 1){
    now_optind = optind;
    int cc = getopt_long(argc, argv, short_options, long_options, NULL);
    char c = cc;
    printf("%c\n", c);
    printf("%d\n", cc);
    switch (c) {
      case 'h': {
        printf("-v, --version for software version\n");
        printf("-m, --mode=[value] for mode choice. (ecb/cbc)\n");
        printf("-e, --enc flag for encryption mode\n");
        printf("-d, --dec flag for decryption mode\n");
        printf("-k, --key=[value] for key init\n");
        printf("-i, --iv=[value] for initialization vector\n");
        printf("-g, --debug for intermediate values\n");
        continue;
      }
      case 'v':{
        printf("Software version 1.0\n");
        continue;
      }
      case 'm':{
        printf("%s\n", optarg);
        if (strcmp(optarg, "ecb") == 0){
          mode = optarg;
        }
        else if (strcmp(optarg, "cbc") == 0){
          mode = optarg;
        }
        else{
          return WRONG_VALUE;
        }
        continue;
      }
      case 'e':{
        crypt_mode = 1;
        continue;
      }
      case 'd':{
        crypt_mode = 2;
        continue;
      }
      case 'k':{
        int err = 0;
        *key = hex_from_str(optarg, &err);
        if (err == WRONG_VALUE){
          return WRONG_VALUE;
        }
        printf("%x\n", *key);
        continue;
      }
      case 'i':{
        int err1 = 0;
        *iv = hex_from_str(optarg, &err1);
        if (err1 == WRONG_VALUE){
          return WRONG_VALUE;
        }
        continue;
      }
      case 'g':{
        return 0;
      }
      case -1:{
        return -1;
      }
    }
    return 0;
  }
  return 0;
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


unsigned int** circular_backshift(unsigned int** a, int count){
  for (int shift_num = 0; shift_num < count; shift_num++){
    for (int j = 0; j < shift_num; j++){
      unsigned int ptr = a[shift_num][count - 1];
      for (int k = count - 1; k > 0; k--){
        a[shift_num][k] = a[shift_num][k-1];
        printf("%d\n", k);
      }
      a[shift_num][0] = ptr;
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


unsigned int** back_s_block(unsigned int** a, unsigned int*s_substitution, int count){
  for (int i = 0; i < count; i++){
    for (int j = 0; j < count; j++){
      int k = 0;
      while(a[i][j] != s_substitution[k]){
        k++;
      }
      a[i][j] = k;
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


unsigned int encryption_ecb_round(unsigned int* s_substitution, unsigned int p, unsigned int key){
  int count = 2;
  unsigned int** k = eight_bit_blocks(key, count);
  unsigned int** a = eight_bit_blocks(p, count);
  a = s_block(a, s_substitution, count);
  a = circular_shift(a, count);
  a = xor_key(a, k, count);
  p = merge(a, count);
  free(a);
  free(k);
  return p;

}


unsigned int decryption_ecb_round(unsigned int* s_substitution, unsigned int p, unsigned int key){
  int count = 2;
  unsigned int** k = eight_bit_blocks(key, count);
  printf("8 bit blocks key - DONE\n");
  unsigned int** a = eight_bit_blocks(p, count);
  printf("8 bit blocks text - DONE\n");
  a = xor_key(a, k, count);
  printf("XOR with key - DONE\n");
  a = circular_backshift(a, count);
  printf("Backshift - DONE\n");
  a = back_s_block(a, s_substitution, count);
  printf("S-Block - DONE\n");
  p = merge(a, count);
  free(a);
  free(k);
  return p;
}


unsigned int encryption_cbc_round(unsigned int* s_substitution, unsigned int p, unsigned int key, unsigned int iv){
  int count = 2;
  p = p ^ iv;
  unsigned int** k = eight_bit_blocks(key, count);
  unsigned int** a = eight_bit_blocks(p, count);
  a = s_block(a, s_substitution, count);
  a = circular_shift(a, count);
  a = xor_key(a, k, count);
  p = merge(a, count);
  free(a);
  free(k);
  return p;
}


unsigned int decryption_cbc_round(unsigned int* s_substitution, unsigned int p, unsigned int key, unsigned int iv){
  int count = 2;
  unsigned int** k = eight_bit_blocks(key, count);
  unsigned int** a = eight_bit_blocks(p, count);
  a = xor_key(a, k, count);
  a = circular_backshift(a, count);
  a = back_s_block(a, s_substitution, count);
  p = merge(a, count);
  p = p ^ iv;
  free(a);
  free(k);
  return p;

}


unsigned int encryption_ecb(unsigned int* s_substitution, unsigned int p, unsigned int* key){
  int rounds = 2;
  for (int i = 0; i < rounds; i++){
    p = encryption_ecb_round(s_substitution, p, key[i + 1]);
  }
  return p;
}


unsigned int decryption_ecb(unsigned int* s_substitution, unsigned int p, unsigned int* key){
  int rounds = 2;
  for (int i = 0; i < rounds; i++){
    p = decryption_ecb_round(s_substitution, p, key[i + 1]);
  }
  return p;
}


unsigned int encryption_cbc(unsigned int* s_substitution, unsigned int p, unsigned int* key, unsigned int iv){
  int rounds = 2;
  for (int i = 0; i < rounds; i++){
    p = encryption_cbc_round(s_substitution, p, key[i + 1], iv);
  }
  return p;
}


unsigned int decryption_cbc(unsigned int* s_substitution, unsigned int p, unsigned int* key, unsigned int iv){
  int rounds = 2;
  for (int i = 0; i < rounds; i++){
    p = decryption_cbc_round(s_substitution, p, key[i + 1], iv);
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
  unsigned int* key = (unsigned int*)calloc(3, sizeof(unsigned int));
  unsigned int k, p, iv;
  unsigned int* s_substitution = load(argv[argc - 1], &p);
  int a = analyse_input(argc, argv, s_substitution, &k, &iv);
  key = key_calculation(k, key);
  unsigned int c0 = p ^ key[0];
  p = encryption_cbc(s_substitution, c0, key, iv);
  printf("%x\n", p);
  free(s_substitution);
}
