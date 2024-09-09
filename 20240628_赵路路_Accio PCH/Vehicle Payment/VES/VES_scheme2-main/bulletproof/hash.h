#ifndef HASH_H
#define HASH_H

#include "global.h"

using namespace std;

extern const size_t HASH_OUTPUT_LEN;

void Hash_String_to_BN(string &str, BIGNUM *&y);

void Hash_BN_to_BN(BIGNUM *&str, BIGNUM *&y);

void Hash_ECP_to_ECP(EC_POINT *&g, EC_POINT *&h);

#endif