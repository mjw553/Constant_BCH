#include "lac_param.h"

#if defined(LAC128)
//bch(511,385,29)
#define DATA_LEN 33//MESSAGE_LEN+one byte for message length
#define DATABUF_LEN 48//CODE_LEN-ECC_LEN
#define ECCBUF_LEN 64
#define ECC_LEN 23
#define MAX_ERROR 20
#define CODE_LEN 64
#define LOG_CODE_LEN 9
#define ECC_BITS 171
#endif

#if defined(LAC192)
//bch(511,457,13)
#define DATA_LEN 33
#define DATABUF_LEN 48
#define ECCBUF_LEN 64
#define ECC_LEN 23
#define MAX_ERROR 20
#define CODE_LEN 64
#define LOG_CODE_LEN 9
#define ECC_BITS 171
#endif

#if defined(LAC256)
//D2+bch(511,376,31)
#define DATA_LEN 33
#define DATABUF_LEN 48
#define ECCBUF_LEN 64
#define ECC_LEN 23
#define MAX_ERROR 20
#define CODE_LEN 64 
#define LOG_CODE_LEN 9
#define ECC_BITS 171
#endif

int num_errors;

//error correction encode
int ecc_enc(const unsigned char *d, unsigned char *c);

//error corrction decode
int ecc_dec(unsigned char *d, unsigned char *c);

