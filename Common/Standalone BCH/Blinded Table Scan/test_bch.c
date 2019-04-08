/*
* Author: Matthew Walters
* Class to test BCH changes.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ecc.h"
#include "bch.h"
#include "rand.h"
#include "test_bch.h"
#include "math.h"
#include "makeRandomInput.h"

#include <x86intrin.h>
#include <inttypes.h>
#define cpucycles() _rdtsc()

int print_to_file = 1; // 0 = output to screen, 1 = output to file.
int extras = 0;

//test bch for correctness
int test_bch()
{
	int i;
	int j;
	int k;
	repeatNum = 0;
	
	cycles = malloc(sizeof(unsigned long long *) * REPEATS);
	for(k = 0; k < REPEATS; k++)
		cycles[k] = calloc(sizeof(unsigned long long), MAX_Err+1);
		
	int pos_arr[29] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28};

	seed_rng();

	for(k=0;k<REPEATS + extras;k++){
		for(i=0;i<=MAX_Err;i++)
		{
			unsigned char mlen = MESSAGE_LEN;
	        	unsigned char mlenP;
	        	unsigned char * mlenP2 = &mlenP;
			unsigned char * buf = (unsigned char *)calloc(MESSAGE_LEN+CIPHER_LEN,sizeof(unsigned char)); //[MESSAGE_LEN+CIPHER_LEN];
	        	unsigned char * buf2 = (unsigned char *)calloc(MESSAGE_LEN+CIPHER_LEN,sizeof(unsigned char));
	        	unsigned char * m_buf = (unsigned char *)calloc(MESSAGE_LEN+1,sizeof(unsigned char));
	        	unsigned char * code1 = (unsigned char *)calloc(CODE_LEN,sizeof(unsigned char));
			
			if(k >= extras) repeatNum = k - extras; // row index to Cycles array
			errNum = i; // column index to Cycles array

			memset(buf,0,MESSAGE_LEN+CIPHER_LEN);
			memset(buf2,0,MESSAGE_LEN+CIPHER_LEN);

			// -- Encode a random message
			//generate random message m, stored in buf
			generate_input(buf, MESSAGE_LEN);
			
			//package m_buf
			memset(m_buf,0,MESSAGE_LEN+1);
			memcpy(m_buf,&mlen,1);
			memcpy(m_buf+1,buf,mlen);
			
			//encode m with ecc code
			ecc_enc(m_buf,code1);
			
			for(j = 0; j < 29; j++) {
				int temp = pos_arr[j];
				int randomIndex = rand() % 29;
				pos_arr[j] = pos_arr[randomIndex];
				pos_arr[randomIndex] = temp;
			}
			
			uint8_t *code3 = (uint8_t *)code1;
			// -- Create error
			for(j = 0; j < i; j++) {
				code3[pos_arr[j]] = code3[pos_arr[j]] ^ (1 << (j & 7));
			}
			
			unsigned long long start;
			// -- Decode message
			start = cpucycles();
			ecc_dec(m_buf,code1);
			cycles[repeatNum][errNum] = cpucycles() - start;

			memcpy(mlenP2,m_buf,1);
			memcpy(buf2,m_buf+1,*mlenP2);
			
			// -- Compare to ensure error was fixed
			if(memcmp(buf,buf2,MESSAGE_LEN)!=0){
				cycles[repeatNum][errNum] = 0;
			}

			free(buf);
			free(buf2);
			free(m_buf);
			free(code1);
		}
	}
	
	if(!print_to_file) {
		for(i = 0; i < REPEATS; i++)
			for(j = 0; j <= MAX_Err; j++)
				printf("%llu\n",cycles[i][j]);
	}
	if(print_to_file) {
		FILE * fp = fopen("cycles.csv","w");
		for(i = 2000;i<REPEATS;i++)
		{
			for(j = 0;j<MAX_Err;j++)
				fprintf(fp,"%llu,",cycles[i][j]);
			fprintf(fp,"%llu\n",cycles[i][MAX_Err]);
		}
		fclose(fp);
	}
	
	for(i = 0;i<REPEATS;i++)
		free(cycles[i]);
	free(cycles);
	return 0;
}
