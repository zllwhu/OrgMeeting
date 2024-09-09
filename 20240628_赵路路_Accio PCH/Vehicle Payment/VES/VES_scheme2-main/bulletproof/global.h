#ifndef GLOBAL_H
#define GLOBAL_H

using namespace std;

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cmath>
#include <vector>
#include <unordered_map>
#include <thread>

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>

/* global constants */
const size_t POINT_LEN = 33;
const size_t BN_LEN = 32;
/* global constants */
extern const size_t POINT_LEN; // the compressed expression of an EC points is 33 bytes
extern const size_t BN_LEN;    // assume base field and scalar field are less than 2^256 (stored in 32-bytes)

/* global variables of OpenSSL */
extern EC_GROUP *group;
extern const BIGNUM *order;
extern const EC_POINT *generator;
extern BN_CTX *bn_ctx;

extern BIGNUM *BN_0;
extern BIGNUM *BN_1;
extern BIGNUM *BN_2;

bool global_initialize(int curve_id);

void global_finalize();

#endif