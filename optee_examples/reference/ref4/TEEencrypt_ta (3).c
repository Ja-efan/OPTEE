
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>

#define MAX_LEN 100
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

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

	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);

	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*sess_ctx = (void *)sess;
	DMSG("\nSession %p: newly allocated\n", *sess_ctx);

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

	struct rsa_session *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", sess_ctx);
	sess = (struct rsa_session *)sess_ctx;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);

	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);

	TEE_Free(sess);

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

static TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle _key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(_key, &key_info);

	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GETObjectInfo1\n");
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("------------- Operation allocated successfully.\n");

	ret = TEE_SetOperationKey(*handle, _key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
    	DMSG("------------- Operation key already set.\n");

	return ret;
}

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("--------------- Transient object allocated.\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("--------------- Keys generated.\n");

	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	size_t key_size = RSA_KEY_SIZE;

	DMSG("=======================Encryption======================\n");
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("----------------------- Transient object allocated.\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}

	DMSG("----------------------- Keys generated.\n");
	void *plain_txt = params[2].memref.buffer;
	size_t plain_len = params[2].memref.size;
	void *cipher_txt = params[3].memref.buffer;
	size_t cipher_len = params[3].memref.size;

	DMSG("----------------------- Preparing encryption operation\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("------------------------Plaintext-----------------------\n%s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, NULL, 0, 
					plain_txt, plain_len, cipher_txt, &cipher_len);	

	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err; 
	}
	memcpy(params[3].memref.buffer, cipher_txt, cipher_len);
	DMSG("------------------------Cyphertext----------------------\n%s\n", (char *) cipher_txt);
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
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

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC:
		return encrypt(param_types, params);
	case TA_TEEencrypt_CMD_DEC:
		return decrypt(param_types, params);
	case TA_TEEencrypt_RSA_CMD_GENKEYS:
		return RSA_create_key_pair(sess_ctx);
	case TA_TEEencrypt_RSA_CMD_ENC:
		return RSA_encrypt(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

