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


int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	
	uint32_t err_origin;
	char plaintext[64] = {0,}; // plaintext를 저장할 버퍼 (64bytes)
	char ciphertext[64] = {0,}; // ciphertext를 저장할 버퍼 (64bytes)
	char path[100] = "/root/"; // 입력으로 받을 파일의 경로 
	int len=64;
	int cipherkey = 0;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);


	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, // 암호화 또는 복호화된 결과가 저장된다.
					 TEEC_VALUE_INOUT,		//param for encrypted key
					 TEEC_NONE, TEEC_NONE); // 3,4번째 매개변수는 사용하지 않는다.
	op.params[0].tmpref.buffer = plaintext; // op에서 text를 저장할 버퍼로 plaintext 지정 .. ?
	op.params[0].tmpref.size = len; // 크기 지정

	/******************************Encryption******************************/
	if(strcmp(argv[1], "-e") == 0)
	{	
		/* 기본 paht(/root/)와 프로그램 실행 시 입력으로 받은 파일 명을 이어준다.*/
		strcat(path, argv[2]); // string concatenation 
		FILE *fp = fopen(path, "r"); // 입력으로 사용할 파일 open
		fgets(plaintext, sizeof(plaintext), fp); // 입력 파일로부터 text를 읽어 plaintext buffer에 저장
		memcpy(op.params[0].tmpref.buffer, plaintext, len); 
		// 암호화할 plaintext가 op.params[0].tmpref.buffer에 저장된다.
		// 이때 크기는 64bytes로 설정된다.

		fclose(fp); // file close

		/* Call encryption task from TEE*/
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);

		/* 암호화된 파일이 저장될 경로 및 파일 명('encrypted_원본파일명') */
		char encrypted_path[100] = "/root/encrypted_"; 
		strcat(encrypted_path, argv[2]);
		/* 위에서 지정한 암호화 파일을 write권한으로 open*/
		FILE *fp_encrypted = fopen(encrypted_path, "w");

		/* 암호화가 완료된 후 op객체의 buffer에 담겨져온 ciphertext를 
		파일에 옮겨 쓰기 위해 ciphertext라는 변수에 옮겨준다. */
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		fputs(ciphertext, fp_encrypted); // ciphertext를 파일에 넣어준다.
		fclose(fp_encrypted); // file close

		/* root key를 저장하기 위한 process*/
		char key_path[100] = "/root/key_"; // 저장할 경로 지정
		strcat(key_path, argv[2]); // 파일 명 지정 : /root/key_원본파일명
		FILE *fp_key = fopen(key_path, "w"); // write권한으로 open
		/* 암호화가 완료된 후 TEE에서 돌아온 op객체에 담겨온 cipherkey를 cipherkey변수에 옮겨준다 */
		cipherkey = op.params[1].value.a; 
		/* fp_key 파일에 cipherkey 저장 후 file close*/
		fprintf(fp_key, "%d", cipherkey);
		fclose(fp_key);

	}

	/******************************Decryption******************************/
	else if(strcmp(argv[1], "-d") == 0)
	{	
		/* encryptkey 파일경로를 지정 concatenation*/
		strcat(path, argv[3]);
		/* file open(read only) based path */
		FILE *fp_key = fopen(path, "r");
		/* fp_key파일에서 key를 읽어와서 cipherkey에 저장 */
		fscanf(fp_key, "%d", &cipherkey);
		/* op 객체 cipherkey 인자 부분에 cipherkey 지정 */
		op.params[1].value.a = cipherkey;
		fclose(fp_key); // fileclose
		
		/* 복호화할 파일 경로 지정 */
		char path2[100] = "/root/";
		strcat(path2, argv[2]);
		/* file open */
		FILE *fp = fopen(path2, "r");
		/* file pointer에서 ciphertext 크기(64bytes)만큼 읽어서 ciphertext에 저장 */
		fgets(ciphertext, sizeof(ciphertext), fp);
		/* op 객체의 buffer에 ciphertext 메모리 영역 복사 (64bytes)*/
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		fclose(fp); // file close

		/* Call decryption task from TEE*/
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);

		/* Decrypted text를 저장할 경로 지정하여 open ; write */
		FILE *fp_decrypted = fopen("/root/decrypted.txt", "w");

		/* op객체에 담겨온 decrypted text를 plaintext에 옮겨준다.*/
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		/* fp_decrypted 파일에 작성해주고, close file pointer*/
		fputs(plaintext, fp_decrypted);
		fclose(fp_decrypted);
		
	}
	

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);


	TEEC_CloseSession(&sess); // close session (CA-TA)

	TEEC_FinalizeContext(&ctx); // close context (REE-TEE)

	return 0;
}
