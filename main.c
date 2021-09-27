#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "debug.h"

#define SUCCESS 0
#define NO_KEY -1
#define NO_ARGS -2
#define WRONG_VALUE -3


char* fgetstr (FILE* fd) {
	char* ptr = (char*)malloc(1);
	char buf[81];
	int n, len = 0;
	*ptr = '\0';
	do {
		n = fscanf(fd, "%80[^\n]", buf);
		//if (n < 0) {
		//	free(ptr);
		//	ptr = NULL;
		//	continue;
			//break;
		//}
		if (n == 0) {
			fscanf(fd, "%*c");
			//break;
		}
		else if (n>0){
			len += strlen(buf);
			ptr = (char*)realloc(ptr, len + 1);
			int k = strlen(buf);
			int l = strlen(ptr) + k + 1;
			strncat(ptr,buf, k);
		}
	} while (n > 0);
	return ptr;
}


unsigned int hex_from_str (char* arg, int* err) {
  //printf("str hex = %s\n", arg);
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
      printf("%c --- wrong value\n", arg[i]);
      *err = WRONG_VALUE;
      return res;
    }
    res += a;
  }
  return res;
}


char* str_from_hex (unsigned int hex, long int size) {
  char* res = (char*)malloc(size);
  int a = 0;
  for(int i = 1; i<size + 1; i++){
      a = hex % 16;
      if (a < 10)
			   res[size - i] = a + '0';
      else
        res[size - i] = 'a' + a -10;
    //printf("symbol = %c\n", res[size - i]);
		hex = hex >> 4;
	}
  //printf("str hex = %s\n", res);
  return res;
}


int analyse_input (int argc, char** argv, unsigned int* key, unsigned int* iv, int* crypt_mode, char* mode, int* debugger) {
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
	key[0] = '\0';
	iv[0] = '\0';
  const char* short_options = "hvm:edk:i:g";
  int wrong = 0;
  while (optind < argc - 1 || optind < 2){
    int cc = getopt_long(argc, argv, short_options, long_options, NULL);
    char c = cc;
    printf("option = %c\n", c);
    switch (c) {
      case 'h': {
        printf("-v, --version for software version\n");
        printf("-m, --mode=[value] for mode choice. (ecb/cbc)\n");
        printf("-e, --enc flag for encryption mode\n");
        printf("-d, --dec flag for decryption mode\n");
        printf("-k, --key=[value] for key init\n");
        printf("-i, --iv=[value] for initialization vector\n");
        printf("-g, --debug for intermediate values\n");
        return NO_ARGS;
      }
      case 'v':{
        printf("Software version 1.0\n");
				return NO_ARGS;
      }
      case 'm':{
        printf("arg of option m = %s\n", optarg);
        if (strcmp(optarg, "ecb") == 0){
          *mode = 'e';
        }
        else if (strcmp(optarg, "cbc") == 0){
          *mode = 'c';
        }
        else{
          return WRONG_VALUE;
        }
        continue;
      }
      case 'e':{
        *crypt_mode = 1;
        continue;
      }
      case 'd':{
        *crypt_mode = 2;
        continue;
      }
      case 'k':{
        int err = 0;
        *key = hex_from_str(optarg, &err);
        if (err == WRONG_VALUE){
					return WRONG_VALUE;
        }
        printf("key = %x\n", *key);
        continue;
      }
      case 'i':{
        int err1 = 0;
        *iv = hex_from_str(optarg, &err1);
				printf("iv = %x\n", *iv);
        if (err1 == WRONG_VALUE){
					return WRONG_VALUE;
        }
        continue;
      }
      case 'g':{
				*debugger = 1;
      }
      case -1:{
				optind++;
				break;
      }
    }
  }
	if (*mode == '\0' || *crypt_mode == 0 || *key == '\0' || (*iv == '\0' && *mode == 'c'))
		return WRONG_VALUE;
  return 0;
}

unsigned int xor_key (unsigned int p, unsigned int k, int count) {
  p = p ^ k;
  return p;
}


unsigned int circular_shift (unsigned int p, int count) {
	p = (p >> 16 << 16) | (p << 16 >> 24) | (p << 24 >> 16);
  return p;
}


unsigned int circular_backshift (unsigned int p, int count) {
	p = (p >> 16 << 16) | (p << 16 >> 24) | (p << 24 >> 16);
  return p;
}


unsigned int s_block (unsigned int p, unsigned int*s_substitution, int count) {
	p = (s_substitution[p >> 24] << 24) + (s_substitution[p << 8 >> 24] << 16) + (s_substitution[p << 16 >> 24] << 8) + (s_substitution[p << 24 >> 24]);
  return p;
}


void load_subs_back (FILE* fd, unsigned int** s_substitution) {
  unsigned int* s = *s_substitution;
  char* str = (char*)malloc(3);
  str[2] = '\0';
  for (int i = 0; i < 256; i++){
    fgets(str, 3, fd);
    int err = 0;
    (*s_substitution)[hex_from_str(str, &err)] = i;
    unsigned int t = hex_from_str(str, &err);
    if (err == WRONG_VALUE){
    }
    s++;
  }
}


void load_subs_straight (FILE* fd, unsigned int** s_substitution) {
  unsigned int* s = *s_substitution;
  char* str = (char*)malloc(3);
  str[2] = '\0';
  for (int i = 0; i < 256; i++){
    fgets(str, 3, fd);
    int err = 0;
    (*s_substitution)[i] = hex_from_str(str, &err);
    if (err == WRONG_VALUE){
    }
    s++;
  }
}


void load_straight (char* file_name, char** p, unsigned int** s_substitution) {
  FILE* fd;
  fd = fopen(file_name, "r");
  load_subs_straight(fd, s_substitution);
  *p = fgetstr(fd);
  fclose(fd);
}


void load_back (char* file_name, char** p, unsigned int** s_substitution) {
  FILE* fd;
  fd = fopen(file_name, "r");
  load_subs_back(fd, s_substitution);
  *p = fgetstr(fd);
  fclose(fd);
}


unsigned int encryption_ecb_round (unsigned int* s_substitution, unsigned int p, unsigned int key, Debug* debug) {
  int count = 2;
	printf("WALK into round DONE\n");
  p = s_block(p, s_substitution, count);
	printf("S-block DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = circular_shift(p, count);
	printf("Shift DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = xor_key(p, key, count);
	printf("XOR DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  return p;

}


unsigned int decryption_ecb_round (unsigned int* s_substitution, unsigned int p, unsigned int key, Debug* debug) {
	int count = 2;
	printf("WALK into round DONE\n");
	p = xor_key(p, key, count);
	printf("XOR DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	p = circular_backshift(p, count);
	printf("Shift DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = s_block(p, s_substitution, count);
	printf("S-block DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  return p;
}


unsigned int encryption_cbc_round (unsigned int* s_substitution, unsigned int p, unsigned int key, unsigned int iv, Debug* debug) {
  int count = 2;
	printf("WALK into round DONE\n");
  p = p ^ iv;
	printf("XOR IV DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	p = s_block(p, s_substitution, count);
	printf("S-block DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = circular_shift(p, count);
	printf("Shift DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = xor_key(p, key, count);
	printf("XOR DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  return p;
}


unsigned int decryption_cbc_round (unsigned int* s_substitution, unsigned int p, unsigned int key, unsigned int iv, Debug* debug) {
  int count = 2;
	printf("WALK into round DONE\n");
	p = xor_key(p, key, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	printf("XOR DONE - %x\n", p);
	p = circular_backshift(p, count);
	printf("Shift DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	p = s_block(p, s_substitution, count);
	printf("S-block DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	p = p ^ iv;
	printf("XOR IV DONE - %x\n", p);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  return p;
}


void make_block (char** block, char* p, unsigned int* ptr, int* err, Debug* debug){
	strncpy(*block, p, 8);
	printf("block = %s\n", *block);
	if(strlen(*block) < 8){
		for (int j = strlen(*block); j < 8; j++){
			(*block)[j] = '0';
		}
	}
	*ptr = hex_from_str(*block, err);
	printf("hex = %x\n", *ptr);
	debug->all[debug->real_num] = *ptr;
	debug->real_num++;
}


void res_block(int k, char** res, unsigned int ptr, char** p){
	if (k == 0){
		strncpy(*res, str_from_hex(ptr, 8), 8);
		(*res)[8] = '\0';
	}
	else{
		strncat(*res, str_from_hex(ptr, 8), 8);
	}
	printf("p before block encrypt = %s\n", *p);
	(*p)+=8;
	printf("p after block encrypt = %s\n", *p);
}

unsigned int cbc_round(unsigned int* s_substitution, unsigned int ptr, unsigned int* key,
	 									unsigned int* iv, unsigned int iv1, int i, int crypt_mode, int k, Debug* debug){
	if(i == 0){
		ptr = ptr ^ key[0];
	}
	printf("hex1 = %x\n", ptr);
	debug->all[debug->real_num] = ptr;
	debug->real_num++;
	if (k == 0){
		*iv = iv1;
	}
	if (crypt_mode == 1){
		ptr = encryption_cbc_round(s_substitution, ptr, key[i + 1], *iv, debug);
	}
	else{
		ptr = decryption_cbc_round(s_substitution, ptr, key[i + 1], *iv, debug);
	}
	*iv = ptr;
	return ptr;
}


unsigned int ecb_round(unsigned int* s_substitution, unsigned int ptr, unsigned int* key, int i, int crypt_mode, Debug* debug){
	if(i ==0 ){
		ptr = ptr ^ key[0];
	}
	printf("hex1 = %x\n", ptr);
	debug->all[debug->real_num] = ptr;
	debug->real_num++;
	if (crypt_mode == 1){
		ptr = encryption_ecb_round(s_substitution, ptr, key[i + 1], debug);
	}
	else{
		ptr = decryption_ecb_round(s_substitution, ptr, key[i + 1], debug);
	}
	return ptr;
}


char* crypt (unsigned int* s_substitution, char* p, unsigned int* key, unsigned int iv, int blocks,
				int rounds, unsigned int iv1, unsigned int ptr, char* res, char* block, int err, char*first,
				int crypt_mode, char mode, Debug* debug){
  for (int i = 0; i < rounds; i++){
    for (int k = 0; k < blocks; k++){
			make_block (&block, p, &ptr, &err, debug);
			if (mode == 'e'){
				ptr = ecb_round (s_substitution, ptr, key, i, crypt_mode, debug);
			}
			else{
				ptr = cbc_round (s_substitution, ptr, key, &iv, iv1, i, crypt_mode, k, debug);
			}
      printf("hex after encryption = %x\n", ptr);
			debug->all[debug->real_num] = ptr;
			debug->real_num++;
			res_block(k, &res, ptr, &p);
    }
    printf("res of round = %s\n", res);
    strcpy(p, res);
    first = res;
  }
  res[8 * blocks] = '\0';
  return res;
}


void load (int argc, char** argv, char** p, int crypt_mode, char mode, unsigned int** s_substitution){
  if (crypt_mode == 1){
		load_straight(argv[argc - 1], p, s_substitution);
  }
  else if (crypt_mode == 2){
		load_back(argv[argc - 1], p, s_substitution);
	}
}


char* init_n_cipher (int argc, char** argv, char* p, unsigned int* key, unsigned int iv, int crypt_mode, char mode, int debugger){
	unsigned int* s_substitution = (unsigned int*)malloc(256 * sizeof(unsigned int));
	load(argc, argv, &p, crypt_mode, mode, &s_substitution);
	long int size = strlen(p);
	char* first = p;
	char* res = (char*)malloc(size + 1);
	char* block = (char*)malloc(9);
	unsigned int ptr = 0, iv1 = iv;
  int rounds = 2, err = 0, blocks = size / 8;
	if(size % 8 != 0)
    blocks++;
  res[0] = '\0';
  block[8] = '\0';
	Debug* debug = init(blocks);
	debug->skey = key[0];
	for (int i = 0; i < 2; i++){
		debug->key[i] = key[i+1];
	}
	debug->iv = iv;
	printf("Init debug DONE\n");
	p = crypt (s_substitution, p, key, iv, blocks, rounds, iv1, ptr,
						res, block, err, first, crypt_mode, mode, debug);
	if (debugger == 1)
		print_debug(debug, crypt_mode, mode);
	free(s_substitution);
  return p;
}


unsigned int* key_calculation (unsigned int k, unsigned int* key) {
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
  unsigned int k, iv;
  char * p, mode = '\0';
  int crypt_mode = 0, debugger = 0;
  int a = analyse_input(argc, argv, &k, &iv, &crypt_mode, &mode, &debugger);
	if(a == 0){
	  key = key_calculation(k, key);
	  p = init_n_cipher(argc, argv, p, key, iv, crypt_mode, mode, debugger);
	  printf("%s\n", p);
	}
	else if (a == WRONG_VALUE){
		printf("Something wrong in command. If you need help enter -h flag.\n");
	}
	else{
		printf("Please, try again.\n");
	}
	printf ("That's all. Bye!\n");
	return 0;
}
