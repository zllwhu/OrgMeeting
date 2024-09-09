#ifndef PRINT_H
#define PRINT_H

using namespace std;

#include "global.h"

extern const size_t LINE_LEN;     // the length of split line

void SplitLine_print(char ch);

void BN_print_dec(BIGNUM *&a);

void BN_print_dec(BIGNUM *&a, string note);

void BN_print(BIGNUM *&a);

void BN_print(BIGNUM *&a, string note);

void ECP_print(EC_POINT *&A);

void ECP_print(EC_POINT *&A, string note);

void ECP_vec_print(vector<EC_POINT *> &vec_A, string name);

void BN_vec_print(vector<BIGNUM *> &vec_a, string name);

#endif