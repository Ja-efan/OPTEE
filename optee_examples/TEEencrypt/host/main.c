#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[]){

	TEEC_Result res; // uint32_t ; 함수 호출 결과 값을 나타냄 (오류 표현 가능)
	TEEC_Context ctx; // CA와 TEE의 논리적인 연결 
	TEEC_Session sess; // CA와 TA의 연결 세션
	TEEC_Operation op; // REE와 TEE간의 데이터 교환을 위한 연산을 정의 
	TEEC_UUID uuid = TA_TEEencrypt_UUID; // TA UUID 정의 
	
	uint32_t err_origin; // 함수 실행 오류 저장 변수 
	char plaintext[64] = {0,}; // buffer for plaintext
	char ciphertext[64] = {0,}; // buffer for ciphertext
	int len = 64; // length of plaintext and ciphertext
	char path[100] = ""; // 입력으로 받을 파일의 경로 
	int cipherkey = 0; // TA에서 rootkey of TA로 암호화한 랜덤키(key when using encrypt and decrypt)

	/* Context 초기화 및 error handling */
	res = TEEC.InitializeContext(NULL, &ctx);
	if(res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

	/* Session open 및 error handling*/
	res = TEEC_OpenSession(&ctx, &sses, &uuid, 
					TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	if (res != TEEC_SUCCESS){
		errx(1,"TEEC_OpenSession failed with code 0x%x origin 0x%x",
			 res, err_origin);
	}

	/* op 초기화 */
	memset(&op, 0, sizeof(op));

	/*
	op.params의 정보 
	op.params[0] : 암호화/복호화 될 문자열 혹은 암호화/복호화 된 문자열 저장할 buffer
	 	(CA<->TA간 주고받을 데이터가 저장되는 buffer)
	 	OUTPUT인 이유 : 저장된 데이터를 다른 world의 App.에 출력하니까?
	 	Q. INPUT으로 타입 지정하면 오류 발생? 
		YES, INPUT일 경우 CA에서 보낸 데이터를 TA단에서 변경 불가능(read only)

	op.params[1] : TA의 rootkey로 암호화된 randomkey (cipherkey)
	op.params[2], [3]  : NONE
	*/
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
								TEEC_VALUE_INOUT,
								TEEC_NONE, TEEC_NONE);

	/* 
	op 객체 첫 parameter의 buffer에 plaintext 할당 및 크기 지정 
	(아래 memcpy 부분 있어서 굳이 없어도 될듯)
	*/
	//op.params[0].tmpref.buffer = plaintext;
	//op.params[0].tmpref.size = len;

	/* command 구조 : TEEencrypt [-e|-d] [filename] [cipherkey] */

	/* Encryption */
	if (strcmp(argv[1], "-e") == 0){
		
		/* 입력으로 사용할 파일의 경로 지정 : /root/[filename] */
		//strcat(path,argv[2]);
		path = argv[2];
		/* paht에 대한 file pointer 생성 및 내용 읽어오기 */
		FILE *fp = fopen(path, "r");
		fgets(plaintext, len, fp);
		/* plaintext의 (메모리)주소를 op 구조체 buffer에 복사 */
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		/* close file pointer */
		fclose(fp);


		/* Call Encryption task from TEE and Error handling */
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypte_CMD_ENC_VAlUE, &op, &err_origin);

		if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
		
		/* 암호화된 파일이 저장될 경로 '/root/encrypted_[filenema]' */
		char encrypted_path[100] = "/root/encrypted_";
		strcat(encrypted_path,argv[2]);
		/* encrypted_path에 대한 file pointer 생성*/
		FILE * fp_encrypted = fopen(encrypted_path,"w");

		/* encryptin task를 마친 ciphertext를 파일에 옮겨 쓰기 위해 배열 ciphertext에 주소 복사 */
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		/* ciphertext에 저장된 암호화된 문자열을 파일에 작성 */
		fputs(ciphertext, fp_encrypted);
		fclose(fp_encrypted); // close file

		/* TA의 rootkey로 암호화된 key(cipherkey)를 저장하기 위한 process*/
		/* cipherkey를 저장할 경로 지정 '/root/key_[filename]' */
		char key_path[100] = "/root/key_";
		strcat(key_path, argv[2]);
		/* key_path에 대한 file pointer 생성 */
		FILE * fp_key = fopen(key_path,"w");

		/* op.params[1.value.a에 담겨온 cipherkey를 변수 cipherkey에 저장 */
		cipherkey = op.params[1].value.a;
		/* cipherkey를 fp_key가 가리키는 파일에 저장 후 close file */
		fprintf(fp_key,"%d",cipherkey);
		fclose(fp_key);
	}

	/* Decryption*/
	else if(strcmp(argv[1],"-d") == 0){
		
		/* Decryption에 필요한 cipherkey가 저장된 경로 지정 및 file pointer 생성*/
		strcat(path, argv[3]);
		FILE * fp_key = fopen(path, "r");
		/* fp_key에 저장된 키 읽어서 변수 cipherkey에 저장 */
		fscanf(fp_key, "%d", &cipherkey);
		/* Decrtyption task를 위해 TEE에 넘겨질 op 객체의 cipherkey 부분에 cipherkey 할당 */
		op.params[1].value.a = cipherkey;
		fclose(fp_key); // close file 

		/* Decryption 진행할 파일 경로 지정 및 file pointer 생성*/
		char decrypted_path[100] = "/root/";
		strcat(decrypted_path, argv[2]);
		FILE * fp = fopen(decrypted_path, "r");
		/* file pointer로 부터 ciphertext 가져오기 */
		fgets(ciphertext, len, fp);
		/* op 객체의 임시 buffer부분에 ciphertext 복사 */
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		fclose(fp); // close file 

		/* Call Decryption task from TEE and Error handling */
		res = TEEC_InvokeCommand(&sses, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

		/* Decryption이 완료된 파일의 내용을 저장할 경로 지정 및 file pointer 생성 */
		FILE *fp_decrypted = fopen("/root/decrypted.txt", "w");
		/* Decryption이 완료된 내용이 저장되어있는 op 객체의 buffer에서 내용 읽어서 plaintext에 저장 */
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		/* plaintext의 내용을 파일에 저장 및 close file */
		fputs(plaintext, fp_decrypted);
		fclose(fp_decrypted);
	}

	TEEC_CloseSession(&sess); // close session (CA-TA)

	TEEC_FinalizeContext(&ctx); // close context (REE-TEE)

	return 0;


}