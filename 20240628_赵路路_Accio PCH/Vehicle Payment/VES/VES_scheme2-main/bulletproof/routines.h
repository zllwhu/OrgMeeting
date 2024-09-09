#ifndef ROUTINES_H
#define ROUTINES_H

#include "global.h"

using namespace std;

void BN_random(BIGNUM *&result);

void BN_vec_random(vector<BIGNUM *> vec_a);

void BN_vec_new(vector<BIGNUM *> &vec_a);

void BN_vec_free(vector<BIGNUM *> &vec_a);

void BN_vec_copy(vector<BIGNUM *> &vec_to, vector<BIGNUM *> &vec_from);

void BN_serialize(BIGNUM *&x, ofstream &fout);

void BN_deserialize(BIGNUM *&x, ifstream &fin);

void BN_vec_one(vector<BIGNUM *> &vec_a);

void BN_mod_negative(BIGNUM *&a);

void ECP_random(EC_POINT *&result);

void ECP_vec_random(vector<EC_POINT *> vec_A);

void ECP_vec_new(vector<EC_POINT *> &vec_A);

void ECP_vec_free(vector<EC_POINT *> &vec_A);

void ECP_vec_copy(vector<EC_POINT *> &vec_to, vector<EC_POINT *> &vec_from);

void ECP_serialize(EC_POINT *&A, ofstream &fout);

void ECP_deserialize(EC_POINT *&A, ifstream &fin);

void ECP_vec_serialize(vector<EC_POINT *> &vec_A, ofstream &fout);

void ECP_vec_deserialize(vector<EC_POINT *> &vec_A, ifstream &fin);

int EC_POINT_sub(EC_POINT *&r, EC_POINT *&a, EC_POINT *&b);

int EC_POINT_sub_without_bnctx(EC_POINT *&r, EC_POINT *&a, EC_POINT *&b);

string ECP_ep2string(EC_POINT *&A);

string BN_bn2string(BIGNUM *&a);

inline bool FILE_exist(const string &filename)
{
	bool existing_flag;
	ifstream fin;
	fin.open(filename);
	if (!fin)  existing_flag = false;
	else existing_flag = true;
	return existing_flag;
}


#endif