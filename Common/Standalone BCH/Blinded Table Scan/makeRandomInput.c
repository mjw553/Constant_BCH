#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "makeRandomInput.h"

// Header file with random function. 
#include "rng.h"

unsigned char entropy_input[48];

void seed_rng() {
	int i;
	for(i = 0; i < 48; i++) {
		entropy_input[i] = i;
	}
	randombytes_init(entropy_input,NULL,256);
}

//test bch for correctness
int generate_input(unsigned char *buf, size_t random_len)
{
	int ret; 
	
	ret = randombytes(buf,random_len);

	return ret;
}
