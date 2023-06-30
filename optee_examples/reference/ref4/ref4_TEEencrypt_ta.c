
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>

#define MAX_LEN 100
//#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
//#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int rootKey = 5;

struct rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};

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

static TEE_Result encrypt(uint32_t param_types,
	TEE_Param params[4])
{

	/* Func(1): generate random key */
	int randomKey = 0;

	while(randomKey % 26 == 0 || randomKey < 0){
		TEE_GenerateRandom(&randomKey, sizeof(randomKey));
		randomKey %= 26;
	}

	DMSG("randomKey: %d", randomKey);

	/* Func(2): encrypt plaintext */
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [MAX_LEN] = {0, };

	DMSG("========================Encryption========================\n");
        DMSG("------------------------Plaintext-------------------------\n%s\n", in);
	memcpy(encrypted, in, in_len);

	for (int i = 0; i < in_len; i++){
		if (encrypted[i] >= 'a' && encrypted[i] <= 'z'){
			encrypted[i] -= 'a';
			encrypted[i] += randomKey;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += randomKey;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	DMSG("------------------------Cyphertext------------------------\n%s\n", encrypted);
	memcpy(in, encrypted, in_len);

	/* Func(3): encrypt randomkey */
	int encKey = rootKey + randomKey;
	params[1].value.a = encKey;
	DMSG("encKey: %d\n", encKey);

	return TEE_SUCCESS;
}

static TEE_Result decrypt(uint32_t param_types,
	TEE_Param params[4])
{

	DMSG("has been called");

	/* Func(1): decrypt encKey */
	int encKey = params[1].value.a;
	int randomKey = encKey - rootKey;
	
	/* Func(2): decrypt ciphtertext */
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [MAX_LEN] = {0, };
	
	DMSG("========================Decryption========================\n");
	DMSG("------------------------Cyphertext------------------------\n%s\n", in);
	memcpy(decrypted, in, in_len);
	
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
	memcpy(in, decrypted, in_len);
	
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC:
		return encrypt(param_types, params);
	case TA_TEEencrypt_CMD_DEC:
		return decrypt(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

