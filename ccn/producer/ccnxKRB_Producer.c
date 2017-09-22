
#include <stdio.h>

#include <getopt.h>

#include <LongBow/runtime.h>

#include <parc/algol/parc_Object.h>

#include <parc/algol/parc_Clock.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_IdentityFile.h>

#include <ccnx/common/ccnx_Name.h>

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include "../ccnxKRB_Common.h"

//#include "sodium.h"

typedef enum {
	REG_PROD = 0,  	// Non kerberized service
    TGT_PROD,	   		// Produces TGTs
    TGS_PROD,      		// Produces TGSs when given valid TGTs
    KRB_SERVICE   		// Produces Content when given valid TGSs
} CCNxProducerMode;

typedef struct ccnx_ping_server {
    CCNxPortal *portal;
    CCNxName *prefix;
    size_t payloadSize;
    CCNxProducerMode mode; // Could be TGT, TGS, KRB_SERVICE, REG_SERVICE

    uint8_t generalPayload[ccnx_MaxPayloadSize];

    uint8_t username[MAX_USERNAME_LEN];
    uint8_t user_pk_sig[crypto_sign_PUBLICKEYBYTES];
    uint8_t user_pk_enc[crypto_box_PUBLICKEYBYTES];

    unsigned char k_tgs[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char k_producer[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char k_service[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
    char *namespace;

    char *keystoreName;
    char *keystorePassword;
} CCNxServer;

/**
 * Create a new CCNxPortalFactory instance using a randomly generated identity saved to
 * the specified keystore.
 *
 * @return A new CCNxPortalFactory instance which must eventually be released by calling ccnxPortalFactory_Release().
 */
static CCNxPortalFactory *
_setupServerPortalFactory(char *keystoreName, char *keystorePassword)
{
    return ccnxVPNCommon_SetupPortalFactory(keystoreName, keystorePassword);
}

/**
 * Release the references held by the `CCNxVPNClient`.
 */
static bool
_CCNxServer_Destructor(CCNxServer **serverPtr)
{
    CCNxServer *server = *serverPtr;
    if (server->portal != NULL) {
        ccnxPortal_Release(&(server->portal));
    }
    if (server->prefix != NULL) {
        ccnxName_Release(&(server->prefix));
    }
    return true;
}

parcObject_Override(CCNxServer, PARCObject,
                    .destructor = (PARCObjectDestructor *) _CCNxServer_Destructor);

parcObject_ImplementAcquire(CCNxServer, CCNxServer);
parcObject_ImplementRelease(CCNxServer, CCNxServer);


/**
 * Create a new empty `CCNxServer` instance.
 */
static CCNxServer *
ccnxRegServer_Create(CCNxServer *server)
{
    server->prefix = ccnxName_CreateFromCString(ccnx_DefaultPrefix);
    server->payloadSize = ccnx_DefaultPayloadSize;
    server->mode = REG_PROD;

    return server;
}

static CCNxServer *
ccnxTGTServer_Create(CCNxServer *server)
{
    server->prefix = ccnxName_CreateFromCString(ccnx_TGT_DefaultPrefix);
    server->payloadSize = ccnx_DefaultPayloadSize;
    server->mode = TGT_PROD;

    return server;
}

static CCNxServer *
ccnxTGSServer_Create(CCNxServer *server)
{
   server->prefix = ccnxName_CreateFromCString(ccnx_TGS_DefaultPrefix);
    server->payloadSize = ccnx_DefaultPayloadSize;
    server->mode = TGS_PROD;

    return server;
}

static CCNxServer *
ccnxKBRService_Create(CCNxServer *server, char* name)
{
	printf("service name: %s\n",name);
    server->prefix = ccnxName_CreateFromCString(name);
    server->payloadSize = ccnx_DefaultPayloadSize;
    server->mode = KRB_SERVICE;

    randombytes_buf(server->k_producer, sizeof server->k_producer);

    char nameBuffer[strlen(name)+1];
    strcpy(nameBuffer,name);
    for (int i=0; i<strlen(name)+1; i++){
    	if (nameBuffer[i] == '/') {
    		nameBuffer[i] = '.';
    	}
    }

    char fname[strlen(nameBuffer) + strlen(serverKDCDir) +1];
    memset(fname,0,strlen(nameBuffer) + strlen(serverKDCDir) +1);

    strcat(fname,serverKDCDir);
    strcat(fname,nameBuffer);
    printf("file name: %s\n",fname);
    FILE* fp = fopen(fname,"w");
    fwrite(server->k_producer, sizeof server->k_producer, 1, fp);
    fclose(fp);

    return server;
}


static CCNxServer *
ccnxServer_Create(void)
{
    CCNxServer *server = parcObject_CreateInstance(CCNxServer);

    //server->prefix = ccnxName_CreateFromCString(ccnx_DefaultPrefix);
    server->payloadSize = ccnx_DefaultPayloadSize;

    return server;
}

/**
 * Convert a timeval struct to a single microsecond count.
 */
static uint64_t
_ccnx_CurrentTimeInUs(PARCClock *clock)
{
    struct timeval currentTimeVal;
    parcClock_GetTimeval(clock, &currentTimeVal);
    uint64_t microseconds = currentTimeVal.tv_sec * 1000000 + currentTimeVal.tv_usec;
    return microseconds;
}

/**
 * Create a `PARCBuffer` payload of the server-configured size.
 */
PARCBuffer *
_CCNxServer_MakePayload(CCNxServer *server, int size)
{
	printf("Creating a packet.\n");
    PARCBuffer *payload = parcBuffer_Wrap(server->generalPayload, size, 0, size);
    return payload;
}

PARCBuffer *
_CCNxServer_MakeTGTPayload(CCNxServer *server, bool result)
{
	uint8_t code;
	PARCBuffer *payload = NULL;


	if (result) {
		code = TGT_SUCCESS;
		PARCClock *clock = parcClock_Wallclock();
		// K_TGS: the key used by the client to decrypt TGSs
	    unsigned char k_tgs[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
		randombytes_buf(k_tgs, sizeof k_tgs);

		// random nonce s
		uint8_t s_nonce[sizeof k_tgs];
		randombytes_buf(s_nonce, sizeof s_nonce);

		// expiration time of TGT
		uint64_t expiration = _ccnx_CurrentTimeInUs(clock) + TGT_EXPIRATION;


		uint8_t C_TGS_token[sizeof k_tgs + sizeof(uint64_t)];
		memset(C_TGS_token, 0, sizeof k_tgs + sizeof(uint64_t)); //set buffer to zero

		memcpy(C_TGS_token,k_tgs, sizeof k_tgs);
		memcpy(C_TGS_token + sizeof k_tgs, &expiration, sizeof (uint64_t));

		// TODO: encrypt C_TGS_token reading the appropriate keys from file
		/* Recipient creates a long-term key pair */
		//unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
		//unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];
		//crypto_box_keypair(recipient_pk, recipient_sk);

		/* Anonymous sender encrypts a message using an ephemeral key pair
		 * and the recipient's public key */
	    // TODO: change this to authenticated encryption
	    int ct_len = crypto_box_SEALBYTES + sizeof k_tgs + sizeof(uint64_t);
		unsigned char enc_C_TGS_token[ct_len];
		crypto_box_seal(enc_C_TGS_token, C_TGS_token, sizeof k_tgs + sizeof(uint64_t), server->user_pk_enc);

		//printf("Message: %s\n", C_TGS_token);

		//TODO: create TGT
		// TGT plaintext buffer
		int tgt_size = MAX_USERNAME_LEN + 2 * sizeof k_tgs + sizeof (uint64_t);
		uint8_t TGT[tgt_size]; //plaintext TGT
		memset(TGT, 0, tgt_size * sizeof(TGT[0])); //set buffer to zero

		uint8_t *position = TGT;

		memcpy(position, server->username, MAX_USERNAME_LEN); //copy username to buffer
		//printf("%s\n",position);
		position += MAX_USERNAME_LEN;

		memcpy(position, s_nonce, sizeof s_nonce); //copy random nonce to buffer
		//printf("\n%s\n%s\n",position, s_nonce);
		position += sizeof s_nonce;

		memcpy(position, &expiration, sizeof (uint64_t)); //copy expiration date to buffer

		position += sizeof (uint64_t);

		memcpy(position, k_tgs, sizeof k_tgs); //copy TGS key to buffer

		position += sizeof k_tgs;

		// At this point the TGT is ready to be encrypted

		//TODO: Read these guys from file at parse of command line.////////////////////
		unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
		unsigned char KDC_key[crypto_aead_aes256gcm_KEYBYTES];
		unsigned long long ciphertext_len;

		FILE* kdcKeyFile = fopen(keyFileKDC,"r");
		fread(KDC_key, 1, crypto_aead_aes256gcm_KEYBYTES, kdcKeyFile);
		fread(nonce, 1, crypto_aead_aes256gcm_NPUBBYTES, kdcKeyFile);
		fclose(kdcKeyFile);

		unsigned char enc_TGT[tgt_size + crypto_aead_aes256gcm_ABYTES];

		crypto_aead_aes256gcm_encrypt(enc_TGT, &ciphertext_len,
			                          TGT, tgt_size,
			                          NULL, 0,
			                          NULL, nonce, KDC_key);


		int size = sizeof(uint8_t) + sizeof enc_TGT + sizeof enc_C_TGS_token;
		payload = parcBuffer_Allocate(size);
	    parcBuffer_PutUint8(payload, code);
	    parcBuffer_PutArray(payload, sizeof enc_TGT, enc_TGT);
	    parcBuffer_PutArray(payload, sizeof enc_C_TGS_token, enc_C_TGS_token);
		parcBuffer_Flip(payload);


	} else {
		code = TGT_AUTH_FAIL;
		int size = sizeof(uint8_t);
		payload = parcBuffer_Allocate(size);
		parcBuffer_PutUint8(payload, code);
		parcBuffer_Flip(payload);
	}

    return payload;
}


PARCBuffer *
_CCNxServer_MakeTGSPayload(CCNxServer *server, bool result)
{
	uint8_t code;
	PARCBuffer *payload = NULL;


	if (result) {
		code = TGS_SUCCESS;
		PARCClock *clock = parcClock_Wallclock();
		// K_N: the key used by the client to actual content
	    uint8_t k_N[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
		randombytes_buf(k_N, sizeof k_N);

		int tgs_size = strlen(server->namespace) + crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES + sizeof(uint64_t);
		uint8_t tgs_plaintext[tgs_size];

		// expiration time of TGS
		uint64_t expiration = _ccnx_CurrentTimeInUs(clock) + TGS_EXPIRATION;

		// START: setup TGS structure: [len(N) | N | kN | expiration]
		uint8_t* p = tgs_plaintext;
		int namespaceStringLen =  strlen(server->namespace);
		memcpy(p, &namespaceStringLen, sizeof(int));
		p += sizeof(int);

		memcpy(p,server->namespace,strlen(server->namespace));
		p += strlen(server->namespace);

		memcpy(p, k_N, crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES);
		p += crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES;

		memcpy(p,&expiration,sizeof(uint64_t));
		// END: setup TGS structure: [len(N) | N | kN | expiration]

		//START: TGS Encryption

		unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
		unsigned char service_key[crypto_aead_aes256gcm_KEYBYTES];
		unsigned long long ciphertext_len;


	    char nameBuffer[strlen(server->namespace)+1];
	    strcpy(nameBuffer,server->namespace);
	    for (int i=0; i<strlen(server->namespace)+1; i++){
	    	if (nameBuffer[i] == '/') {
	    		nameBuffer[i] = '.';
	    	}
	    }

	    char fname[strlen(nameBuffer) + strlen(serverKDCDir) +1];
	    memset(fname,0,strlen(nameBuffer) + strlen(serverKDCDir) +1);
	    strcat(fname,serverKDCDir);
	    strcat(fname,nameBuffer);

	    printf("service file:%s\n", fname);

		FILE* serviceKeyFile = fopen(fname,"r");
		if (!serviceKeyFile) {
			printf("Requested service was not registered to this KDC\n");
			code = TGS_AC_FAIL;
			int size = sizeof(uint8_t);
			payload = parcBuffer_Allocate(size);
			parcBuffer_PutUint8(payload, code);
			parcBuffer_Flip(payload);
		    return payload;
		}

		fread(service_key, 1, crypto_aead_aes256gcm_KEYBYTES, serviceKeyFile);
		fread(nonce, 1, crypto_aead_aes256gcm_NPUBBYTES, serviceKeyFile);
		fclose(serviceKeyFile);


		unsigned char enc_TGS[tgs_size + crypto_aead_aes256gcm_ABYTES];
		unsigned long long ct_len;


		crypto_aead_aes256gcm_encrypt(enc_TGS, &ct_len,
									  tgs_plaintext, tgs_size,
			                          NULL, 0,
			                          NULL, nonce, service_key);

		uint8_t cs_token_plain[crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES + sizeof(uint64_t)];

		memcpy(cs_token_plain, k_N, crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES);
		memcpy(cs_token_plain + crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES, &expiration, sizeof(uint64_t));

		uint8_t cs_token_enc[crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES + sizeof(uint64_t) + crypto_aead_aes256gcm_ABYTES];
		unsigned long long token_enc_len;

		crypto_aead_aes256gcm_encrypt(cs_token_enc, &token_enc_len,
									  cs_token_plain, crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES + sizeof(uint64_t),
			                          NULL, 0,
			                          NULL, server->k_tgs + crypto_aead_aes256gcm_KEYBYTES, server->k_tgs);


		int size = sizeof(uint8_t) + sizeof enc_TGS + sizeof cs_token_enc;
		payload = parcBuffer_Allocate(size);
	    parcBuffer_PutUint8(payload, code);
	    parcBuffer_PutArray(payload, sizeof enc_TGS, enc_TGS);
	    parcBuffer_PutArray(payload, sizeof cs_token_enc, cs_token_enc);
		parcBuffer_Flip(payload);

	} else {
		code = TGS_AC_FAIL;
		int size = sizeof(uint8_t);
		payload = parcBuffer_Allocate(size);
		parcBuffer_PutUint8(payload, code);
		parcBuffer_Flip(payload);
	}

    return payload;
}

PARCBuffer *
_CCNxServer_MakeKRBPayload(CCNxServer *server, bool result)
{
	uint8_t code;
	PARCBuffer *payload = NULL;

	printf("Sending KRB payload\n");

	if (result) {
		code = KRB_SUCCESS;
		PARCClock *clock = parcClock_Wallclock();
		// K_N: the key used by the client to actual content

		uint8_t content[server->payloadSize];
		memset(content, 0, server->payloadSize);
		memcpy(content, "This is content: ", strlen("This is content: "));
		memcpy(content+strlen("This is content: "), server->namespace, strlen(server->namespace));

		unsigned char enc_content[server->payloadSize + crypto_aead_aes256gcm_ABYTES];
		unsigned long long ct_len;


		crypto_aead_aes256gcm_encrypt(enc_content, &ct_len,
									  content, server->payloadSize,
			                          NULL, 0,
			                          NULL, server->k_service + crypto_aead_aes256gcm_KEYBYTES, server->k_service);

		int size = sizeof(uint8_t) + sizeof enc_content;
		payload = parcBuffer_Allocate(size);
	    parcBuffer_PutUint8(payload, code);
	    parcBuffer_PutArray(payload, sizeof enc_content, enc_content);
		parcBuffer_Flip(payload);
	} else {
		code = KRB_FAIL;
		int size = sizeof(uint8_t);
		payload = parcBuffer_Allocate(size);
		parcBuffer_PutUint8(payload, code);
		parcBuffer_Flip(payload);
	}
    return payload;
}

bool ccnx_krb_VerifyUser(CCNxServer *server, PARCBuffer *recvPayload){
	uint8_t username[MAX_USERNAME_LEN];
	uint8_t sig[crypto_sign_BYTES];

	int payloadSize = parcBuffer_Remaining(recvPayload);

	parcBuffer_GetBytes(recvPayload, MAX_USERNAME_LEN, username);

	parcBuffer_GetBytes(recvPayload, crypto_sign_BYTES, sig);

	printf("Receiving authentication request from <%s>.\n",username);

	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	char filename_pk[strlen(username) + strlen(userPrvDir) + strlen("-pub-sig")+1]; // +5 to concat -prv\0
	strcpy(filename_pk, userPrvDir);
	strcat(filename_pk,username);

	if (1) {
		strcat(filename_pk,"-pub-sig");
	} else {
		// ADD symmetric key based TGT support here later
		printf("never happens\n");
	}

	FILE* fp = fopen(filename_pk, "r");
	if (!fp) {
		printf("ERROR: Could not find public key file:\n");
		printf("%s\n",filename_pk);
	} else {
		fread(pk, 1, crypto_sign_PUBLICKEYBYTES, fp);
		fclose(fp);
	}

	unsigned char enc_pk[crypto_box_PUBLICKEYBYTES];
	strcpy(filename_pk, userPrvDir);
	strcat(filename_pk,username);

	if (1) {
		strcat(filename_pk,"-pub-enc");
	} else {
		// ADD symmetric key based TGT support here later
		printf("never happens\n");
	}

	fp = fopen(filename_pk, "r");
	if (!fp) {
		printf("ERROR: Could not find public key file:\n");
		printf("%s\n",filename_pk);
	} else {
		fread(enc_pk, 1, crypto_box_PUBLICKEYBYTES, fp);
		fclose(fp);
	}

	if (crypto_sign_verify_detached(sig, username, MAX_USERNAME_LEN, pk) != 0) {
	    /* Incorrect signature! */
		printf("Invalid client signature\n");
		return false;
	} else {
		memcpy(server->username, username, MAX_USERNAME_LEN);
		memcpy(server->user_pk_sig, pk, crypto_sign_PUBLICKEYBYTES);
		memcpy(server->user_pk_enc, enc_pk, crypto_box_PUBLICKEYBYTES);
		return true;
	}

}

bool verifyPolicyAndFetchKey(CCNxServer *server) {
	printf("Authorization Verification\n");
	printf("User: <%s>; Namespace: <%s>.\n", server->username, server->namespace);
	printf("Authorization successfull!\n");
	memcpy(server->k_service, server->k_tgs, sizeof server->k_tgs);

	// XXX: Implement real AC policy checker. For this prototype this was not implemented.
	// verifyPolicyAndFetchKey(server); always return true

	return true;
}

bool ccnx_krb_VerifyTGT(CCNxServer *server, PARCBuffer *recvPayload){

	PARCClock *clock = parcClock_Wallclock();

	printf("Received TGS Request.\n");
	printf("Starting TGT verification ...\n");

	int payloadSize = parcBuffer_Remaining(recvPayload);

	int namespace_len;

	parcBuffer_GetBytes(recvPayload, sizeof(namespace_len), (uint8_t *)&namespace_len);

	server->namespace = malloc(namespace_len+1);
	memset(server->namespace, 0, namespace_len+1);
	parcBuffer_GetBytes(recvPayload, namespace_len, server->namespace);

	uint8_t tgt[RECEIVE_TGT_SIZE];
	memset(tgt, 0, RECEIVE_TGT_SIZE);
	parcBuffer_GetBytes(recvPayload, RECEIVE_TGT_SIZE, tgt);


	//printf("namespace: %s\n", server->namespace);
	//printf("TGT:\n %s\n", tgt);

	//TODO: Read these guys from file at parse of command line.////////////////////
	unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
	unsigned char KDC_key[crypto_aead_aes256gcm_KEYBYTES];
	unsigned long long ciphertext_len;

	FILE* kdcKeyFile = fopen(keyFileKDC,"r");
	fread(KDC_key, 1, crypto_aead_aes256gcm_KEYBYTES, kdcKeyFile);
	fread(nonce, 1, crypto_aead_aes256gcm_NPUBBYTES, kdcKeyFile);
	fclose(kdcKeyFile);

	unsigned char TGTData[RECEIVE_TGT_SIZE - crypto_aead_aes256gcm_ABYTES];
	unsigned long long decrypted_len;
	//Now we are ready to decrypt the TGT:

	if (RECEIVE_TGT_SIZE < crypto_aead_aes256gcm_ABYTES ||
		crypto_aead_aes256gcm_decrypt(TGTData, &decrypted_len,
		                              NULL,
		                              tgt, RECEIVE_TGT_SIZE,
		                              "",
		                              0,
		                              nonce, KDC_key) != 0) {

		printf("TGT Forged!\n");
		return false;
	}

	uint8_t s_nonce[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];

	uint8_t *position = TGTData;
	memcpy(server->username, position, MAX_USERNAME_LEN);
	//printf("%s\n", server->username);
	position += MAX_USERNAME_LEN;


	memcpy(s_nonce, position, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES); //copy random nonce to buffer
	position += crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES;

	uint64_t expiration;

	memcpy(&expiration, position, sizeof (uint64_t)); //copy expiration date to buffer
	position += sizeof (uint64_t);

	memcpy(server->k_tgs, position, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES);
	position += crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES;

	// Done splitting TGT data;
	// Now we verify expiration date;

	uint64_t current_time = _ccnx_CurrentTimeInUs(clock);

	if (current_time > expiration) {
		printf("TGT expired.\n Run TGT request for user client <%s> under domain again.",server->username);
		return false;
	} else {
		printf("TGT integrity check OK.\n");
	}

	//Now we know that the TGT is authentic and not expired.
	//It's time for access control !!
	return verifyPolicyAndFetchKey(server);
	// If AC policy doesn't allow access returns false
	// otherwise set appropriate service key on server structure.

	// XXX: Implement real AC policy checker. For this prototype this was not implemented.
	// verifyPolicyAndFetchKey(server); always return true
}

bool ccnx_krb_VerifyTGS(CCNxServer *server, PARCBuffer *recvPayload){

	PARCClock *clock = parcClock_Wallclock();

	printf("Received content request.\n");
	printf("Starting TGS verification ...\n");

	int tgsSize = parcBuffer_Remaining(recvPayload);
	uint8_t tgs[tgsSize];

	memset(tgs, 0, tgsSize);
	parcBuffer_GetBytes(recvPayload, tgsSize, tgs);

	unsigned char TGSData[tgsSize - crypto_aead_aes256gcm_ABYTES];
	unsigned long long decrypted_len;
	//Now we are ready to decrypt the TGT:

	if (tgsSize < crypto_aead_aes256gcm_ABYTES ||
		crypto_aead_aes256gcm_decrypt(TGSData, &decrypted_len,
		                              NULL,
		                              tgs, tgsSize,
		                              "",
		                              0,
		                              server->k_producer + crypto_aead_aes256gcm_KEYBYTES, server->k_producer) != 0) {

		printf("TGS Forged!\n");
		return false;
	}

	printf("TGS authentic!\n");

	uint8_t *position = TGSData;

	int namespace_len;
	memcpy(&namespace_len, position, sizeof(int));
	position += sizeof(int);

	server->namespace = (char*)malloc(namespace_len + 1);

	memcpy(server->namespace, position, namespace_len);
	printf("%s\n", server->namespace);
	position += namespace_len;

	memcpy(server->k_service, position, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES);
	position += crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES;

	uint64_t expiration;
	memcpy(&expiration, position, sizeof (uint64_t)); //copy expiration date to buffer
	position += sizeof (uint64_t);

	// Done splitting TGS data;
	// Now we verify expiration date;

	uint64_t current_time = _ccnx_CurrentTimeInUs(clock);

	if (current_time > expiration) {
		printf("TGS expired.\n ");
		return false;
	}

	//Verify if the authorized namespace from TGS is prefix of this producer.

	char *server_prefix = ccnxName_ToString(server->prefix);
	printf("\nPREFIXES\n");
	printf("%s\n",server_prefix);
	printf("%s\n",server->namespace);
	char prefix_buffer[strlen(server->namespace)+1];
	memset(prefix_buffer, 0, strlen(server->namespace)+1);
	memcpy(prefix_buffer,server_prefix,strlen(server->namespace));

	bool isMyPrefix = !strcmp(prefix_buffer,server->namespace);
	//TODO: verify is the namespace prefix in TGS matched the service name.

	if (isMyPrefix) {
		return true;
	} else {
		return false;
	}

}



static void
_CCNxTGTServer_Run(CCNxServer *server)
{
    CCNxPortalFactory *factory = _setupServerPortalFactory(server->keystoreName, server->keystorePassword);
    server->portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
    ccnxPortalFactory_Release(&factory);

    size_t yearInSeconds = 60 * 60 * 24 * 365;

    size_t sizeIndex = ccnxName_GetSegmentCount(server->prefix) + 1;

    if (ccnxPortal_Listen(server->portal, server->prefix, yearInSeconds, CCNxStackTimeout_Never)) {
        while (true) {
            CCNxMetaMessage *request = ccnxPortal_Receive(server->portal, CCNxStackTimeout_Never);

            // This should never happen.
            if (request == NULL) {
                break;
            }

            CCNxInterest *interest = ccnxMetaMessage_GetInterest(request);
            if (ccnxMetaMessage_IsInterest(request)) {
                if (interest != NULL) {
                    CCNxName *interestName = ccnxInterest_GetName(interest);
                    PARCBuffer *interestPayload = ccnxInterest_GetPayload(interest);

                    uint8_t result = 0;
                    if(interestPayload){
                    	result = ccnx_krb_VerifyUser(server, interestPayload);
                    } else {
                    	printf("Payload is null.\n");
                    }

                    if (result) {
                    	printf("User authentication successful\n");
                    	printf("Issuing TGT \n");
                    } else {
                    	printf("User authentication failed\n");
                    	printf("Issuing error msg content \n");
                    }

                    PARCBuffer *payload = _CCNxServer_MakeTGTPayload(server, result);
                    printf("Sending %d bytes. TGT and token.\n\n",(int)parcBuffer_Remaining(payload));
                    CCNxContentObject *contentObject = ccnxContentObject_CreateWithNameAndPayload(interestName, payload);

                    // debug
                    char *responseName = ccnxName_ToString(interestName);
                    //printf("Replying to: %s\n", responseName);
                    parcMemory_Deallocate(&responseName);

                    CCNxMetaMessage *message = ccnxMetaMessage_CreateFromContentObject(contentObject);

                    if (ccnxPortal_Send(server->portal, message, CCNxStackTimeout_Never) == false) {
                        fprintf(stderr, "ccnxPortal_Send failed: %d\n", ccnxPortal_GetError(server->portal));
                    }

                    ccnxMetaMessage_Release(&message);
                    parcBuffer_Release(&payload);

                }
            } else {
                printf("Received a control message\n");
                ccnxMetaMessage_Display(request, 0);
                exit(1);
            }
            ccnxMetaMessage_Release(&request);

        }
    }
}

static void
_CCNxTGSServer_Run(CCNxServer *server)
{
    CCNxPortalFactory *factory = _setupServerPortalFactory(server->keystoreName, server->keystorePassword);
    server->portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
    ccnxPortalFactory_Release(&factory);

    size_t yearInSeconds = 60 * 60 * 24 * 365;

    size_t sizeIndex = ccnxName_GetSegmentCount(server->prefix) + 1;

    if (ccnxPortal_Listen(server->portal, server->prefix, yearInSeconds, CCNxStackTimeout_Never)) {
        while (true) {
            CCNxMetaMessage *request = ccnxPortal_Receive(server->portal, CCNxStackTimeout_Never);

            // This should never happen.
            if (request == NULL) {
                break;
            }

            CCNxInterest *interest = ccnxMetaMessage_GetInterest(request);
            if (ccnxMetaMessage_IsInterest(request)) {
                if (interest != NULL) {
                    CCNxName *interestName = ccnxInterest_GetName(interest);
                    PARCBuffer *interestPayload = ccnxInterest_GetPayload(interest);

                    uint8_t result = 0;
                    if(interestPayload){
                    	result = ccnx_krb_VerifyTGT(server, interestPayload);
                    } else {
                    	printf("Payload is null.\n");
                    }

                    if (result) {
                    	printf("User TGT verification successful\n");
                    	printf("Issuing TGS \n");
                    } else {
                    	printf("User TGT verification failed\n");
                    	printf("Issuing error msg content \n");
                    }

                    PARCBuffer *payload = _CCNxServer_MakeTGSPayload(server, result);
                    printf("Sending %d bytes. TGS and token.\n\n",(int)parcBuffer_Remaining(payload));
                    CCNxContentObject *contentObject = ccnxContentObject_CreateWithNameAndPayload(interestName, payload);

                    // debug
                    char *responseName = ccnxName_ToString(interestName);
                    //printf("Replying to: %s\n", responseName);
                    parcMemory_Deallocate(&responseName);

                    CCNxMetaMessage *message = ccnxMetaMessage_CreateFromContentObject(contentObject);

                    if (ccnxPortal_Send(server->portal, message, CCNxStackTimeout_Never) == false) {
                        fprintf(stderr, "ccnxPortal_Send failed: %d\n", ccnxPortal_GetError(server->portal));
                    }

                    ccnxMetaMessage_Release(&message);
                    parcBuffer_Release(&payload);

                }
            } else {
                printf("Received a control message\n");
                ccnxMetaMessage_Display(request, 0);
                exit(1);
            }
            ccnxMetaMessage_Release(&request);

        }
    }
}

static void
_CCNxKRBService_Run(CCNxServer *server)
{
    CCNxPortalFactory *factory = _setupServerPortalFactory(server->keystoreName, server->keystorePassword);
    server->portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
    ccnxPortalFactory_Release(&factory);

    size_t yearInSeconds = 60 * 60 * 24 * 365;

    size_t sizeIndex = ccnxName_GetSegmentCount(server->prefix) + 1;

    if (ccnxPortal_Listen(server->portal, server->prefix, yearInSeconds, CCNxStackTimeout_Never)) {
        while (true) {
            CCNxMetaMessage *request = ccnxPortal_Receive(server->portal, CCNxStackTimeout_Never);

            // This should never happen.
            if (request == NULL) {
                break;
            }

            CCNxInterest *interest = ccnxMetaMessage_GetInterest(request);
            if (ccnxMetaMessage_IsInterest(request)) {
                if (interest != NULL) {
                    CCNxName *interestName = ccnxInterest_GetName(interest);
                    PARCBuffer *interestPayload = ccnxInterest_GetPayload(interest);

                    uint8_t result = 0;
                    if(interestPayload){
                    	result = ccnx_krb_VerifyTGS(server, interestPayload);
                    } else {
                    	printf("Payload is null.\n");
                    }

                    if (result) {
                    	printf("User TGS verification successful\n");
                    	printf("Issuing requested content \n");
                    } else {
                    	printf("User TGS verification failed\n");
                    	printf("Issuing error msg content \n");
                    }

                    PARCBuffer *payload = _CCNxServer_MakeKRBPayload(server, result);
                    printf("Sending %d bytes. Encrypted content.\n\n",(int)parcBuffer_Remaining(payload));
                    CCNxContentObject *contentObject = ccnxContentObject_CreateWithNameAndPayload(interestName, payload);

                    // debug
                    char *responseName = ccnxName_ToString(interestName);
                    //printf("Replying to: %s\n", responseName);
                    parcMemory_Deallocate(&responseName);

                    CCNxMetaMessage *message = ccnxMetaMessage_CreateFromContentObject(contentObject);

                    if (ccnxPortal_Send(server->portal, message, CCNxStackTimeout_Never) == false) {
                        fprintf(stderr, "ccnxPortal_Send failed: %d\n", ccnxPortal_GetError(server->portal));
                    }

                    ccnxMetaMessage_Release(&message);
                    parcBuffer_Release(&payload);

                }
            } else {
                printf("Received a control message\n");
                ccnxMetaMessage_Display(request, 0);
                exit(1);
            }
            ccnxMetaMessage_Release(&request);

        }
    }
}

/**
 * Display the usage message.
 */
static void
_displayUsage(char *progName)
{
    printf("CCNx Simple VPN Performance Test\n");
    printf("\n");
    printf("Usage: %s [-l locator] [-s size] \n", progName);
    printf("       %s -h\n", progName);
    printf("\n");
    printf("Example:\n");
    printf("    ccnx_Server -l ccnx:/some/prefix -s 4096\n");
    printf("\n");
    printf("Options:\n");
    printf("     -h (--help) Show this help message\n");
    printf("     -l (--locator) Set the locator for this server. The default is 'ccnx:/locator'. \n");
    printf("     -s (--size) Set the payload size (less than 64000 - see `ccnx_MaxPayloadSize` in ccnx_Common.h)\n");
}

/**
 * Parse the command lines to initialize the state of the
 */
static bool
_CCNxServer_ParseCommandline(CCNxServer *server, int argc, char *argv[argc])
{
    static struct option longopts[] = {
    	{ "TGT prod", required_argument, NULL, 'a' },
    	{ "TGS prod", required_argument, 't' },
    	{ "KRB Serv prod", required_argument, NULL, 'k' },
        { "help",    no_argument,       NULL, 'h' },
        { NULL,      0,                 NULL, 0   }
    };

    // Default value
    server->payloadSize = ccnx_MaxPayloadSize;

    if (argc == 1) {
    	_displayUsage(argv[0]);
    	exit(0);
    }

    int c;
    while ((c = getopt_long(argc, argv, "a:t:k:l:s:i:p:h", longopts, NULL)) != -1) {
        switch (c) {
        	case 'a':
        		printf("Starting TGT Producer.\n");
        		ccnxTGTServer_Create(server);
        		server->keystoreName = malloc(strlen("producer_identity1") + 1);
        		strcpy(server->keystoreName, "producer_identity1");
                server->keystorePassword = malloc(strlen("producer_identity1") + 1);
                strcpy(server->keystorePassword, "producer_identity1");
        		break;
        	case 't':
        		printf("Starting TGS Producer.\n");
        		ccnxTGSServer_Create(server);
        		server->keystoreName = malloc(strlen("producer_identity1") + 1);
        		strcpy(server->keystoreName, "producer_identity1");
                server->keystorePassword = malloc(strlen("producer_identity1") + 1);
                strcpy(server->keystorePassword, "producer_identity1");

        		break;
        	case 'k':
        		printf("Starting Kerberized Service Producer.\n");
        		ccnxKBRService_Create(server,optarg);
        		server->keystoreName = malloc(strlen("producer_identity1") + 1);
        		strcpy(server->keystoreName, "producer_identity1");
                server->keystorePassword = malloc(strlen("producer_identity1") + 1);
                strcpy(server->keystorePassword, "producer_identity1");
        		break;
            case 'h':
                _displayUsage(argv[0]);
                return false;
            default:
                break;
        }
    }

    return true;
};

int main(int argc, char *argv[argc])
{

    parcSecurity_Init();

	int check = sodium_init();
	if (check) {
		printf("Crypto lib Sodium not available.\n");
	}

    CCNxServer *server = ccnxServer_Create();
    bool runServer = _CCNxServer_ParseCommandline(server, argc, argv);

    if (runServer) {
    	if (server->mode == TGT_PROD) {
    		_CCNxTGTServer_Run(server);
    	}

    	if (server->mode == TGS_PROD) {
    		_CCNxTGSServer_Run(server);
    	}

    	if (server->mode == KRB_SERVICE) {
    		printf("calling run service");
    	    _CCNxKRBService_Run(server);
    	}

    }

    CCNxServer_Release(&server);

    parcSecurity_Fini();

    return EXIT_SUCCESS;
}
