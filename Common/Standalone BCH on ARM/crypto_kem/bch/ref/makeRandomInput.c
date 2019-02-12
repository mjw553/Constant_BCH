#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "makeRandomInput.h"

// Header file with random function. 
#include "randombytes.h"

//test bch for correctness
int generate_input(unsigned char *buf, size_t random_len)
{
	randombytes(buf,random_len);
	return 0;
}
