#include "bch.h"
#include "ecc.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*(arr)))

#define GF_M(_p)               ((_p)->m)
#define GF_T(_p)               ((_p)->t)
#define GF_N(_p)               ((_p)->n)
#define BCH_ECC_WORDS(_p)      DIV_ROUND_UP(GF_M(_p)*GF_T(_p), 32)
#define DIV_ROUND_UP(a, b) ((a + b - 1) / b)

#include <x86intrin.h>
#include <inttypes.h>

void cmov_char(unsigned char *r, const unsigned char *x, size_t len, unsigned char executeFlag)
{
  size_t i;
  executeFlag = -executeFlag;
  
  for(i=0; i < len; i++) {
  	*(r+i) ^= executeFlag & (x[i] ^ *(r+i));
  }
}

//error corretion encode
int ecc_enc(const unsigned char *d, unsigned char *c)
{
	unsigned char ecc[ECCBUF_LEN];
	//init ecc to be 0 as requited by encode_bch function
	memset(ecc,0,ECCBUF_LEN);
	//encode
	uint32_t ecc_buff[(MAX_ERROR * LOG_CODE_LEN + 32 - 1) / 32];
	encode_bch(ecc_buff,d,DATA_LEN,ecc);
	//copy data to the first part of code
	cmov_char(c,d,DATA_LEN,1);
	// compy ecc to the second part of code
	cmov_char(c+DATA_LEN,ecc,ECC_LEN,1);
	return 0;
}

int pos_arr[29] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28};

//error corrction decode
int ecc_dec(unsigned char *d, unsigned char *c)
{
	int error_num=-1;
	
	#ifndef TEST_ROW_ERROR_RATE
	unsigned char ecc[ECCBUF_LEN];
	int j;
	unsigned int ecc_buff_size = ECC_BITS / 32 + 2;
	uint32_t ecc_buff[ecc_buff_size];
	
	for(j = 0; j < 29; j++) {
		int temp = pos_arr[j];
		int randomIndex = rand() % 29;
		pos_arr[j] = pos_arr[randomIndex];
		pos_arr[randomIndex] = temp;
	}
	
	// -- Create error
	uint8_t *code_with_error = (uint8_t *)c;
	for(int j = 0; j < num_errors; j++) {
		code_with_error[pos_arr[j]] = code_with_error[pos_arr[j]] ^ (1 << (j & 7));
	}
	
	cmov_char(d,c,DATA_LEN,1);
	
	//compy correction code to ecc
	cmov_char(ecc,c+DATA_LEN,ECC_LEN,1);
	memset(ecc+ECC_LEN,0,ECCBUF_LEN-ECC_LEN);
	
	encode_bch(ecc_buff, d, DATA_LEN, NULL);
	
	//prepare data
	prepare_ecc_buff(ecc_buff, ecc);
	
	//bch decode
	error_num=decode_bch_const(d, ecc_buff, DATA_LEN);
	#endif
	
	return error_num;
}
