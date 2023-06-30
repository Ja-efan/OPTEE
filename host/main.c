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

/* CA가 파일로 부터 읽어올 버퍼의 크기 */
#define MAX_LEN 100


int main(int argc, char *argv[])
{
   TEEC_Result res; // uint32_t ; 함수 결과 값 저장 변수 (erorr 저장 가능)
   TEEC_Context ctx; // TEE와의 논리적인 연결
   TEEC_Session sess; // TA와의 session 
   TEEC_Operation op; // CA<->TA 간의 전달 객체 
   TEEC_UUID uuid = TA_TEEencrypt_UUID; // CA와 TA의 연결을 위한 ID
   uint32_t err_origin;

   /* Buffer ; plaintext와 ciphertext를 담고 있을 buffer */
   char plaintext[MAX_LEN] = {0, };
   char ciphertext[MAX_LEN] = {0, };
	
	/* encrypted key ; TA의 rootkey로 암호화 된 randomkey (cipertext와 pair를 이룸) */
   int encKey;

   /* File Pointer ; 읽거나 쓸 파일에 대한 file pointer */
   FILE* fp;

   /* Initialize a context connecting us to the TEE 
   ; REE와 TEE의 논리적인 연결을 구성한다.  */
   res = TEEC_InitializeContext(NULL, &ctx);
   
	/* Open session between CA and TA 
	; REE의 CA와 TEE의 TA간의 session을 생성한다. */
   res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
   
   /* Clear the TEEC_Operation struct 
   ; CA와 TA간의 데이터 교환을 위한 구조체 초기화 */
   memset(&op, 0, sizeof(op));

	/* op.paramTypes는 op.params에 대한 정보를 가진다. 
	아래 코드의 경우 TEEC_PARAM_TYPES 매크로를 통해 op.params의 type을 지정한다.*/
   op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, // read and write (text buffer)
					 TEEC_VALUE_INOUT,		// read only (enckey)
					 TEEC_NONE, TEEC_NONE);	// NONE


   /* Encryption ; */
   if (strcmp(argv[1], "-e") == 0){
 
     /* Check the number of options 
	 ; encryption에 필요한 인자가 충분히 전달되지 않을 경우 error를 표시 */
		if (argc != 3 ){
			perror("Invalid options\n");
			return 1;
   		}

	/* file pointer를 입력으로 사용할 파일의 경로로 지정 (read) */	
		fp = fopen(argv[2], "r");
		/* file경로가 올바르지 않거나 파일이 존재하지 않는 경우 error*/
		if(fp == NULL){
			perror("File not found");
			return 1;
		}
		/* 지정된 file pointer에서 MAX_LEN만큼 text를 읽어온다. -> plaintext*/
		fread(plaintext, 1, MAX_LEN, fp);
		fclose(fp); // close file pointer

		printf("\n========================Encryption========================\n");
		printf("------------------------Plaintext-------------------------\n%s\n", plaintext);

		/* TEE에 encryption task request를 보내기 전에 
		 op.params의 멤버들에 값을 지정 해준다. */
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = MAX_LEN;

		/* Request Encryption task to TA of TEE 
		; op.params에 담긴 plaintext를 암호화 하는 요청을 TA에 보낸다. */
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC, &op, &err_origin);

		/* 위에서 보낸 요청에 대한 결과를 저장한다. */
		memcpy(ciphertext, op.params[0].tmpref.buffer, MAX_LEN);
		printf("------------------------Ciphertext------------------------\n%s\n", ciphertext);

		/* 암호화된 plaintext, 즉 cipertext를 파일에 저장 */
   		fp = fopen("cipher.txt", "w");
		fputs(ciphertext, fp); 
		fclose(fp);

		/* TA에서 암호화에 사용된 키를 암호화 한 키(encrypted key)를 저장 */
		fp = fopen("enckey.txt", "w");
		int enc_key = op.params[1].value.a;
		fprintf(fp, "%d", enc_key);
		fclose(fp);
   }

   /* Decryption */
   else if (strcmp(argv[1], "-d") == 0){ 

		/* Decryption에 필요한 인자가 충분히 전달되지 않은 경우 error*/
		if (argc != 4 ){
			perror("Invalid options\n");
			return 1;
   		}
		/* Encryption과 마찬가지로 op.params를 지정 */
		op.params[0].tmpref.buffer = ciphertext;
   		op.params[0].tmpref.size = MAX_LEN;

       	/* command의 3번째 인자인 ciphertext의 경로로 file pointer 지정*/
		fp = fopen(argv[2], "r");
		
		/* 지정한 경로가 올바르지 않을 경우 error */
		if (fp == NULL){
			perror("Ciphertext file not found");
			return 1;
		}
		
		/* file pointer에서 ciphertext를 MAX_LEN만큼 읽어온다. */
		fread(ciphertext, 1, MAX_LEN, fp);
		fclose(fp);

		printf("\n========================Decryption========================\n");
		printf("------------------------Ciphertext------------------------\n%s\n", ciphertext);

		/* Decryption에 필요한 enckey를 가져온다. */
		fp = fopen(argv[3], "r");
		
		/* enckey 파일의 경로가 올바르지 않을 경우 error */
		if (fp == NULL){
			perror("Encryptedkey file not found");
			return 1;
		}

		/* file pointer의 값(enckey)를 가져온다. */
		fscanf(fp, "%d", &encKey);
		fclose(fp);
        
		/* ciphertext 및 enckey 를 TA에 전달할 op구조체에 전달 */
		memcpy(op.params[0].tmpref.buffer, ciphertext, MAX_LEN);
		op.params[1].value.a = encKey;

		/* Request Decryption task to TA of TEE */
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC, &op, &err_origin);
	
		/* TA에서 Decryption이 완료된 ciphertext, 
		즉 plaintext를 받아 저장 */
		memcpy(plaintext, op.params[0].tmpref.buffer, MAX_LEN);
		printf("------------------------Plaintext-------------------------\n%s\n", plaintext);

		/* 저장한 plaintext를 새로운 파일에 저장 */
		fp = fopen("plain.txt", "w");
		fputs(plaintext, fp);
		fclose(fp);
   	}
   /* Error ; -e 혹은 -d 가 아닌 option에 대한 handling */
   else{
	perror("Invalid option\n");
	return 1;
   }

	/* close connection with TEE and TA
	; TEE 및 TA와의 연결을 모두 종료한다. */
   TEEC_CloseSession(&sess);
   TEEC_FinalizeContext(&ctx);

   return 0;
}