#ifndef DEBUG_H
#define DEBUG_H


typedef struct Debug{
  int real_num;
  int blocks_num;
  unsigned int iv;
  unsigned int* all;
  unsigned int skey; //start key
  unsigned int * key; //round keys
}Debug;


Debug* init(int blocks);
void print_debug(Debug* debug, int crypt_mode, char mode);
void delete_debug();


#endif //DEBUG_H
