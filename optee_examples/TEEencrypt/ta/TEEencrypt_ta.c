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

/* Enc/Dec에 사용할 key를 암호화할 Key */
int rootkey;

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
	
	return TEE_SUCCESS
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

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("******************************OPEN SESSION*****************************\n");

	//IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("******************************CLOSE SESSION****************************\n");
}

static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t randomkey;

	/* Create random key in range [1,25] */
	TEE_GenerateRandom(&randomkey, sizeof(randomkey));
	randomkey = randomkey % 25 + 1;

	DMSG("randomKey: %d", randomkey);

	/* encrypt randomkey using rootkey (caesar)*/
	int cipherkey = randomkey + rootkey;
	/* op 객체 cipherkey 부분에 cipherkey 담아줌 */
	params[1].value.a = cipherkey;


	/* op의 buffer에 닮겨온 plaintext를 배열 input에 옮김 */
	char * input = (char *)params[0].memref.buffer;
	/* length 저장 */
	int input_len = strlen(params[0].memref.buffer);
	/* CipherText가 저장될 buffer */
	char encrypted[64] = {0,};

	/* kernel에 log 출력 */
	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", input);
	
	/* input의 주소를 encrypted에 복사 */
	memcpy(encrypted, input, input_len);

	 
	for(int i = 0; i<input_len; i++){
		/* lower case*/
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrytped[i] = ((encrypted[i] - 'a' + randomkey) % 26) + 'a';
		}
		/* upper case */
		else if(encrypted[i]>='A' && encrypted[i] <='Z'){
			encrytped[i] = ((encrypted[i] - 'A' + randomkey) % 26) + 'A';
		}
		/* other cases */
		else{
			encrypted[i] = encrypted[i];
		}
	}

	DMSG("Ciphertext : %s", encrypted);
	memcpy(input, encrypted, input_len);

	return TEE_SUCCESS;
}


static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	/* set cipherkey and randomkey */
	int cipherkey = params[1].value.a;
	int randomkey = cipherkey - rootkey;

	/* 
	op의 buffer에 닮겨온 ciphertext 배열 input에 옮김 
	(pointer input이 param[0].memeref.buffer의 주소를 가리킴)
	 */
	char * input = (char*)param[0].memref.buffer;
	int input_len = strlen(param[0].memref.buffer);
	/* PlainText가 저장될 buffer */
	char decrypted[64] = {0,};


	/* log 출력 */
	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", input);

	/* input을 decrypted[64]에 저장 */
	memcpy(decrypted, input, input_len);

	/* 
	Decryption Process
	1. 입력 문자의 case(lower/upper)를 구분한다.
	2. 입력 문자의 case별 index를 구해준다. 
	3. 구한 index에서 randomkey값을 빼준다.
	4. 3의 결과 값이 음수인 경우도 존재하므로 26을 더해준다.
	5. 4의 결과 를 26으로 나머지 계산을 해준다. 
	6. 나머지 연산 결과 값에 case에 맞게끔 'a' 혹은 'A'를 더해주면 입력 문자에 대한 복호화가 완료된다.
	*/
	for(int i = 0; i<input_len; i++){
		/* lower case*/
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			encrytped[i] = ((encrypted[i] - 'a' - randomkey + 26) % 26) + 'a';
		}
		/* upper case */
		else if(decrypted[i]>='A' && decrypted[i] <='Z'){
			decrytped[i] = ((decrypted[i] - 'A' - randomkey + 26) % 26) + 'A';
		}
		/* other cases */
		else{
			decrypted[i] = decrypted[i];
		}
	}

	DMSG("Plaintext : %s", decrypted)
	/* decrypted값을 input에 옮겨준다. */
	memcpy(input, decrypted, input_len);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */

/* REE에서 TEE에 실행요청할 때 실행되는 함수 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	rootkey = 18;
	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	/*
	case TA_TEEencrypt_CMD_RANDOMKEY_GET;
		return dec_value(param_types, params);
	*/
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
