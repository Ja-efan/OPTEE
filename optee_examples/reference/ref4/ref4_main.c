/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#include <unistd.h>

#define MAX_LEN 100


int main(int argc, char *argv[])
{
   TEEC_Result res;
   TEEC_Context ctx;
   TEEC_Session sess;
   TEEC_Operation op;
   TEEC_UUID uuid = TA_TEEencrypt_UUID;
   uint32_t err_origin;

   /* Buffer */
   char plaintext[MAX_LEN] = {0, };
   char ciphertext[MAX_LEN] = {0, };
	/* encrypted key */
   int encKey;

   /* File Pointer */
   FILE* fp;

   /* Initialize a context connecting us to the TEE */
   res = TEEC_InitializeContext(NULL, &ctx);
   

   res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
   
   /* Clear the TEEC_Operation struct */
   memset(&op, 0, sizeof(op));

   op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,		// read and write
					 TEEC_VALUE_INOUT,		// read only 
					 TEEC_MEMREF_TEMP_NONE, TEEC_MEMREF_TEMP_NONE);	// NONE

   /* Encryption */
   if (strcmp(argv[1], "-e") == 0){
 
		if (argc != 3 ){
			perror("Invalid options\n");
			return 1;
   		}

	/* Func(1): open, read plaintext file */	
		fp = fopen(argv[2], "r");

		if(fp == NULL){
			perror("File not found");
			return 1;
		}
		fread(plaintext, 1, MAX_LEN, fp);
		fclose(fp);

		printf("\n========================Encryption========================\n");
		printf("------------------------Plaintext-------------------------\n%s\n", plaintext);

		/* 메모리 지정 안해주면 segmentation fault */
		op.params[0].tmpref.buffer = plaintext;
   		op.params[0].tmpref.size = MAX_LEN;

		/* Func(2): send plaintext file */
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC, &op, &err_origin);

		/* Func(3): receive ciphertext, enc_key file */
		memcpy(ciphertext, op.params[0].tmpref.buffer, MAX_LEN);
		printf("------------------------Ciphertext------------------------\n%s\n", ciphertext);

		/* Func(4): save cipher.txt file */
   		fp = fopen("cipher.txt", "w");
		fputs(ciphertext, fp); 
		fclose(fp);

		/* Func(5): save enckey.txt file */
		fp = fopen("enckey.txt", "w");
		int enc_key = op.params[1].value.a;
		fprintf(fp, "%d", enc_key);
		fclose(fp);
   }

   /* Decryption */
   else if (strcmp(argv[1], "-d") == 0){ 
		op.params[0].tmpref.buffer = ciphertext;
   		op.params[0].tmpref.size = MAX_LEN;

       	/* Func(1): open, read ciphertext file */
		fp = fopen(argv[2], "r");
		
		if (fp == NULL){
			perror("Ciphertext file not found");
			return 1;
		}

		fread(ciphertext, 1, MAX_LEN, fp);
		fclose(fp);

		printf("\n========================Decryption========================\n");
		printf("------------------------Ciphertext------------------------\n%s\n", ciphertext);

		/* Func(2): open, read enc_key file */
		fp = fopen(argv[3], "r");
		
		if (fp == NULL){
			perror("Encryptedkey file not found");
			return 1;
		}

		fscanf(fp, "%d", &encKey);
		fclose(fp);
        
		/* Func(3): send ciphertext, enc_key file */
		memcpy(op.params[0].tmpref.buffer, ciphertext, MAX_LEN);
		op.params[1].value.a = encKey;

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC, &op, &err_origin);
	
		/* Func(4): receive plaintext file */
		memcpy(plaintext, op.params[0].tmpref.buffer, MAX_LEN);
		printf("------------------------Plaintext-------------------------\n%s\n", plaintext);

		/* Func(5): save plain.txt file */
		fp = fopen("plain.txt", "w");
		fputs(plaintext, fp);
		fclose(fp);
   	}
   /* Error */
   else{
	perror("Invalid option\n");
	return 1;
   }

	/* close connection with TEE and TA*/
   TEEC_CloseSession(&sess);
   TEEC_FinalizeContext(&ctx);

   return 0;
}