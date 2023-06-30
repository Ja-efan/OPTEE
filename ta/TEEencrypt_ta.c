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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>

#define MAX_LEN 100 // buffer의 최대 길이 

/* encryption에 사용한 randomkey를 암호화할 TA의 rootkey */
int rootKey = 5;

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	IMSG("******************************OPEN SESSION*****************************\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{

	IMSG("******************************CLOSE SESSION****************************\n");
}

static TEE_Result encrypt(uint32_t param_types,
	TEE_Param params[4])
{

	/* Encryption에 사용할 randomkey 생성 */
	int randomKey = 0; 

	/* randomkey에 random값 할당 [0,25] */
	/*
	while(randomKey % 26 == 0 || randomKey < 0){
		TEE_GenerateRandom(&randomKey, sizeof(randomKey));
		randomKey %= 26;
	}*/

	TEE_GenerateRandom(&randomKey, sizeof(randomKey));
	randomKey %= 26;

	DMSG("randomKey: %d", randomKey);

	/* CA로 부터 전달된 plaintext 및 길이 저장 */
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	/* TA에서 Encrypt된 문자열이 담길 배열 선언 및 초기화 */
	char encrypted [MAX_LEN] = {0, };

	DMSG("========================Encryption========================\n");
        DMSG("------------------------Plaintext-------------------------\n%s\n", in);
	
	/* in을 encrypted에 전달(메모리 복사) */
	memcpy(encrypted, in, in_len);

	/*
     * <Encryption process>
     * 1. 입력 문자의 case(lower/upper)를 구분해준다.
     * 2. 입력 문자의 case별 인덱스를 구해준다. a,A = 0,  b,B = 1 , ...
     * 3. 구한 인덱스에 암호화 키(randomkey)값을 더해준다.
     * 4. 더해준 값이 알파벳 개수를 넘어가면 안되므로 26으로 나머지 연산을 해준다.
     * 5. 나머지 연산 결과 값에 'a' 혹은 'A'를 더해주게 되면 입력 문자에 대한 암호 문자가 생성된다.
     */

	for (int i = 0; i < in_len; i++){
		/* lower case */
		if (encrypted[i] >= 'a' && encrypted[i] <= 'z'){
			encrypted[i] -= 'a';
			encrypted[i] += randomKey;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		/* upper case */
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += randomKey;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	DMSG("------------------------Cyphertext------------------------\n%s\n", encrypted);
	
	/* 암호화 된 문자열을 op의 버퍼에 옮겨줌 */
	memcpy(in, encrypted, in_len);

	/* Encryption에 사용된 randomkey를 rootkey로 한번 더 암호화 하여,
	 * op객체에 담아 CA에 전달 
	*/
	int encKey = rootKey + randomKey;
	params[1].value.a = encKey;
	DMSG("encKey: %d\n", encKey);

	return TEE_SUCCESS;
}


static TEE_Result decrypt(uint32_t param_types,
	TEE_Param params[4])
{

	DMSG("has been called");

	/* 암호화 하여 전달한 randomkey를 다시 복호화 하여 저장 */
	int encKey = params[1].value.a;
	int randomKey = encKey - rootKey;
	
	/* CA로 부터 전달된 ciphertext 및 길이 저장 */
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	/* Decryption이 완료된 문자열이 담길 배열 선언 및 초기화 */
	char decrypted [MAX_LEN] = {0, };
	
	DMSG("========================Decryption========================\n");
	DMSG("------------------------Cyphertext------------------------\n%s\n", in);
	/* 현재 ciphertext를 decrypted에 복사 (메모리 복사))*/
	memcpy(decrypted, in, in_len);
	
	/* 
     * Decryption Process
     * 1. 입력 문자의 case(lower/upper)를 구분한다.
     * 2. 입력 문자의 case별 index를 구해준다. 
     * 3. 구한 index에서 randomkey값을 빼준다.
     * 4. 3의 결과 값이 음수인 경우도 존재하므로 26을 더해준다.
     * 5. 4의 결과 를 26으로 나머지 계산을 해준다. 
     * 6. 나머지 연산 결과 값에 case에 맞게끔 'a' 혹은 'A'를 더해주면 입력 문자에 대한 복호화가 완료된다.
     */

	for (int i = 0; i < in_len; i++){
		if (decrypted[i] >= 'a' && decrypted[i] <= 'z'){
			decrypted[i] -= 'a';
			decrypted[i] -= randomKey;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= randomKey;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	DMSG("------------------------Plaintext-------------------------\n%s\n", decrypted);
	
	/* Decryption이 완료된 문자열을 다시 op 구조체에 저장 */
	memcpy(in, decrypted, in_len);
	
	return TEE_SUCCESS;
}


/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	/* CA에서 요청한 task에 맞춰 함수 호출 및 결과 반환  */
	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC:
		return encrypt(param_types, params);
	case TA_TEEencrypt_CMD_DEC:
		return decrypt(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

