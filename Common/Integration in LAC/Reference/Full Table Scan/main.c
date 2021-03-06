#include "test_correctness.h"
#include "test_speed.h"
#include "test_cpucycles.h"
#include "rand.h"
#include "rng.h"
#include "api.h"
#include "ecc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if(argc < 2 || argc > 3)
	{
		printf("command format:\n");
		printf("lac speed : test the speed of lac\n");
		printf("lac cpucycles: test the cpucycles of lac\n");
		printf("lac correctness: test the correctness of lac\n");
		printf("lac basicblock: test the speed of basic blocks used in lac\n");
	}
	else
	{
		if(strcmp(argv[1],"speed")==0)
		{
			test_pke_speed();
			test_kem_fo_speed();
			test_ke_speed();
			test_ake_speed();	
		}
		
		if(strcmp(argv[1],"cpucycles")==0)
		{
			unsigned char entropy_input[48];
			for(int l = 0; l < 48; l++)
				entropy_input[l] = l;
			randombytes_init(entropy_input, NULL, 256);

			for(int k = 0; k <= 20; k++) {
				num_errors = k;
				//if(argc == 3)
				//	num_errors = atoi(argv[2]);
				test_pke_cpucycles();
				test_kem_fo_cpucycles();
				test_ke_cpucycles();
				test_ake_cpucycles();
				print_results();
			}
		}
		
		if(strcmp(argv[1],"correctness")==0)
		{
			test_pke_correctness();
			test_kem_fo_correctness();
			test_ke_correctness();
			test_ake_correctness();	
		}
		
		if(strcmp(argv[1],"basicblock")==0)
		{
			//test_hash_cpucycles();
			//test_aes_cpucycles();
			test_gen_psi_cpucycles();
			test_gen_a_cpucycles();
			test_poly_mul_cpucycles();
		}
	}

	return 0;
}
