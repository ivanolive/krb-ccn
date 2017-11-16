#include <stdio.h>
#include <getopt.h>

#include <LongBow/runtime.h>

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include <parc/algol/parc_Clock.h>

#include <parc/algol/parc_Object.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_IdentityFile.h>
#include <parc/algol/parc_DisplayIndented.h>

#include "../ccnxKRB_Common.h"
#include "../ccnxKRB_Stats.h"
//#include "sodium.h"

int verbose = 0;
int rtt_test = 0;
int pings = 0;
int b_pings = 0;
int thput_test = 0;

typedef enum {
    CCNxConsumerMode_None = 0,
    CCNxConsumerMode_Flood,
    CCNxConsumerMode_VPNPong,
    CCNxConsumerMode_TGTReq,
    CCNxConsumerMode_TGSReq,
    CCNxConsumerMode_KRBServReq,
    CCNxConsumerMode_KRBConfig,
    CCNxConsumerMode_All
} CCNxConsumerMode;

typedef struct tgt {
	uint64_t expiration;
	uint8_t tgtData[RECEIVE_TGT_SIZE];
	uint8_t k_tgs[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
} TGT;

typedef struct tgs {
	uint64_t expiration;
	uint8_t *tgsData;
	int size;
	uint8_t k_N[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
} TGS;

typedef struct ccnx_client {
    CCNxPortal *portal;
    CCNxVPNStats *stats;
    CCNxConsumerMode mode;

    CCNxName *prefix;

    size_t numberOfOutstanding;
    uint64_t receiveTimeoutInUs;
    int interestCounter;
    int count;
    uint64_t intervalInMs;
    int payloadSize;
    uint8_t generalPayload[ccnx_MaxPayloadSize];
    int nonce;

    //client secret keys
    char user_sk_sig[crypto_sign_SECRETKEYBYTES];
    char user_sk_enc[crypto_box_SECRETKEYBYTES];

    //client encryption PK
    char user_pk_enc[crypto_box_PUBLICKEYBYTES];

    char *keystoreName;
    char *keystorePassword;
    char *username;
    char *domainname;
    char *namespace;

    TGT tgt;
    TGS tgs;
} CCNxConsumer;

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
 * Create a new CCNxPortalFactory instance using a randomly generated identity saved to
 * the specified keystore.
 *
 * @return A new CCNxPortalFactory instance which must eventually be released by calling ccnxPortalFactory_Release().
 */
static CCNxPortalFactory *
_setupConsumerPortalFactory(char *keystoreName, char *keystorePassword)
{
    return ccnxVPNCommon_SetupPortalFactory(keystoreName, keystorePassword);
}

/**
 * Release the references held by the `CCNxConsumer`.
 */
static bool
_ccnx_Destructor(CCNxConsumer **clientPtr)
{
    CCNxConsumer *client = *clientPtr;
    if (client->portal != NULL) {
        ccnxPortal_Release(&(client->portal));
    }
    if (client->prefix != NULL) {
        ccnxName_Release(&(client->prefix));
    }

    if (client->username != NULL) {
            free(client->username);
    }
    if (client->keystoreName != NULL) {
            free(client->keystoreName);
    }
    if (client->keystorePassword != NULL) {
            free(client->keystorePassword);
    }

    return true;
}

parcObject_Override(CCNxConsumer, PARCObject,
                    .destructor = (PARCObjectDestructor *) _ccnx_Destructor);

parcObject_ImplementAcquire(ccnxVPN, CCNxConsumer);
parcObject_ImplementRelease(ccnxVPN, CCNxConsumer);

/**
 * Create a new empty `CCNxConsumer` instance.
 */
static CCNxConsumer *
ccnx_Create(void)
{
    CCNxConsumer *client = parcObject_CreateInstance(CCNxConsumer);

    client->stats = ccnxVPNStats_Create();
    client->interestCounter = 100;
    client->prefix = ccnxName_CreateFromCString(ccnx_DefaultPrefix);
    //TODO: check this
    client->receiveTimeoutInUs = 1000000;// 1 sec
    client->count = 10;
    client->intervalInMs = 1000;
    client->nonce = rand();
    client->numberOfOutstanding = 0;

    client->keystoreName = NULL;
    client->keystorePassword = NULL;
    client->username = NULL;

    return client;
}

PARCBuffer *
_CCNxClient_MakeTGTInterestPayload(CCNxConsumer *client)
{
	int size = ccnx_DefaultPayloadSize;

	uint8_t username[MAX_USERNAME_LEN];
	memset(username, 0, MAX_USERNAME_LEN * sizeof(username[0]));

	if (strlen(client->username) < MAX_USERNAME_LEN) {
		strcpy(username, client->username);
	}else{
		// This should never happen.
		printf("ERROR: username must have at most 16 characters\n");
	    return NULL;
	}

	unsigned char sig[crypto_sign_BYTES];

	//crypto_sign_detached(sig, NULL, username, MAX_USERNAME_LEN, sk);
	crypto_sign_detached(sig, NULL, username, MAX_USERNAME_LEN, client->user_sk_sig);

	size = MAX_USERNAME_LEN;// + crypto_sign_BYTES;
	uint8_t payload[size];
	memcpy(payload, username, MAX_USERNAME_LEN);
	//memcpy(payload + MAX_USERNAME_LEN, sig, crypto_sign_BYTES);

	PARCBuffer *ccnx_payload = parcBuffer_Allocate(size);
	parcBuffer_PutArray(ccnx_payload, size, payload);
	parcBuffer_Flip(ccnx_payload);
    return ccnx_payload;
}

PARCBuffer *
_CCNxClient_MakeTGSInterestPayload(CCNxConsumer *client) {

	PARCClock *clock = parcClock_Wallclock();

	//printf("expiration   %llu\n",client->tgt.expiration);
	uint64_t current_time = _ccnx_CurrentTimeInUs(clock);
	//printf("current time %llu\n", current_time);

	if (current_time > client->tgt.expiration) {
		printf("TGT expired.\nRun TGT request for user <%s> under domain <%s> again.\n",client->username, client->domainname);
		exit(0);
	} else {

		if (verbose) printf("Valid TGT found! Issuing Interest.\n");

		int size = ccnx_DefaultPayloadSize;

		uint8_t payload[size];

		uint8_t *p = payload;
		memset(p, 0, size);

		int len = strlen(client->namespace);

		//printf("Requested namespace: <%s>.\n", client->namespace);

		memcpy(p, &len, sizeof(int));
		p += sizeof(int);

		memcpy(p, client->namespace, len);
		p += len;

		memcpy(p, client->tgt.tgtData, sizeof(client->tgt.tgtData));
		p += sizeof(client->tgt.tgtData);

		int usefulDataSize = p-payload;

		//printf("TGS interest size %d.\n", usefulDataSize);

		PARCBuffer *ccnx_payload = parcBuffer_Allocate(usefulDataSize);
		parcBuffer_PutArray(ccnx_payload, usefulDataSize, payload);
		parcBuffer_Flip(ccnx_payload);

	    return ccnx_payload;
	}
	return NULL;
}

PARCBuffer *
_CCNxClient_MakeKRBInterestPayload(CCNxConsumer *client) {
	PARCClock *clock = parcClock_Wallclock();

	char * TGSFile = (char*)malloc(strlen(userTGSDir) + strlen(client->username) + strlen(client->domainname) + strlen(client->namespace) +2);
	memset(TGSFile, 0, strlen(userTGTDir) + strlen(client->username) + strlen(client->domainname) + strlen(client->namespace) + 2);
	strcat(TGSFile, userTGSDir);
	strcat(TGSFile,client->username);
	strcat(TGSFile,"@");
	strcat(TGSFile,client->domainname);
	char nameSpace_buffer[strlen(client->namespace)+1];
	memset(nameSpace_buffer,0,strlen(client->namespace)+1);
	strcpy(nameSpace_buffer, client->namespace);
	for (int i=0; i<strlen(client->namespace)+1; i++) {
		if (nameSpace_buffer[i] == '/') {
			nameSpace_buffer[i] = '.';
		}
	}
	strcat(TGSFile, nameSpace_buffer);

	if (verbose) printf("TGS file name:\n %s\n",TGSFile);

	uint64_t exp;
	FILE* fp = fopen(TGSFile,"r");
	if (fp == NULL) {
		printf("TGS not found\n");
		exit(0);
	}

	fread(&(client->tgs.expiration), sizeof(uint64_t), 1, fp);
	fscanf(fp,"\n");
	fread(&(client->tgs.size), sizeof(int), 1, fp);
	fscanf(fp,"\n");
	client->tgs.tgsData = (uint8_t*)malloc(client->tgs.size * sizeof(uint8_t));
	fread(client->tgs.tgsData, 1, client->tgs.size, fp);
	fscanf(fp,"\n");
	fread(&(client->tgs.k_N), 1, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES, fp);
	fscanf(fp,"\n");
	fclose(fp);

	//printf("expiration   %llu\n",client->tgt.expiration);
	uint64_t current_time = _ccnx_CurrentTimeInUs(clock);
	//printf("current time %llu\n", current_time);

	if (current_time > client->tgs.expiration) {
		printf("TGS expired.\nRun TGS request for user <%s> under domain <%s> with namespace <%s> again.\n",client->username, client->domainname, client->namespace);
		exit(0);
	} else {
		if (verbose) printf("Valid TGS found! Issuing Interest for authorized content.\n");

		int size = client->tgs.size;
		uint8_t payload[size];
		memcpy(payload, client->tgs.tgsData, client->tgs.size);

		PARCBuffer *ccnx_payload = parcBuffer_Allocate(size);
		parcBuffer_PutArray(ccnx_payload, size, payload);
		parcBuffer_Flip(ccnx_payload);
	    return ccnx_payload;
	}
	return NULL;
}

/**
 * Get the next `CCNxName` to issue. Increment the interest counter
 * for the client.
 */
static CCNxName *
_ccnx_CreateNextName(CCNxConsumer *client)
{
    client->interestCounter++;
    char *suffixBuffer = NULL;
    asprintf(&suffixBuffer, "%x", client->nonce);
    CCNxName *name1 = ccnxName_ComposeNAME(ccnxName_Copy(client->prefix), suffixBuffer);
    parcMemory_Deallocate(&suffixBuffer);

    suffixBuffer = NULL;
    asprintf(&suffixBuffer, "%u", client->payloadSize);
    CCNxName *name2 = ccnxName_ComposeNAME(name1, suffixBuffer);
    ccnxName_Release(&name1);

    suffixBuffer = NULL;
    asprintf(&suffixBuffer, "%06lu", (long) client->interestCounter);
    CCNxName *name3 = ccnxName_ComposeNAME(name2, suffixBuffer);
    ccnxName_Release(&name2);

    return name3;
}

void
storeTGT(CCNxConsumer *client, PARCBuffer *TGTPayload) {
	if (verbose) printf("Received %d bytes. TGT and token are probably there.\n",(int)parcBuffer_Remaining(TGTPayload));
	if (verbose) printf("Storing authentication ticket for <%s> \n", client->username);

	uint8_t TGTBuffer[RECEIVE_TGT_SIZE];
	uint8_t TGTTokenBuffer[TGT_token_size];

	parcBuffer_GetBytes(TGTPayload, RECEIVE_TGT_SIZE, TGTBuffer);
	parcBuffer_GetBytes(TGTPayload, TGT_token_size, TGTTokenBuffer);

	int message_len = TGT_token_size - crypto_box_SEALBYTES;

	uint8_t tokenData[message_len];

	//Token decryption:

	if (crypto_box_seal_open(tokenData, TGTTokenBuffer, TGT_token_size, client->user_pk_enc, client->user_sk_enc) != 0) {
		/* message corrupted or not intended for this recipient */
		printf("TGT Reply was not authentic and, therefore, not stored\n");
		exit(0);
	} else{
		//printf("TGT Reply authentic: %s\n",tokenData);
	}

	uint8_t k_tgs[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
	uint64_t expiration;

	memcpy(k_tgs, tokenData, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES);
	memcpy(&expiration, &(tokenData[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES]), sizeof(uint64_t));

	char filename[strlen(userTGTDir) + strlen(client->username) + strlen("@") + strlen(client->domainname) +10];
	memset(filename,0,sizeof(filename));
	memcpy(filename, userTGTDir, sizeof userTGTDir);
	strcat(filename, client->username);
	strcat(filename, "@");
	strcat(filename, client->domainname);

	if (verbose) printf("PATH: %s\n",filename);

	//Writting TGT to disk:
	FILE* fp = fopen(filename,"w");
	if (fp) {
		fwrite(&expiration, sizeof(uint64_t), 1, fp);
		fprintf(fp,"\n");
		fwrite(TGTBuffer, 1, RECEIVE_TGT_SIZE, fp);
		fprintf(fp,"\n");
		fwrite(k_tgs, 1, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES, fp);
		fprintf(fp,"\n");
		fclose(fp);
	} else{
		printf("can't open file\n");
	}


	if (verbose) printf("TGT stored.\n");
	if (verbose) printf("Expiration: %llu\n", expiration);
}

void
storeTGS(CCNxConsumer *client, PARCBuffer *TGSPayload) {
	int total_size = (int)parcBuffer_Remaining(TGSPayload);
	int token_size = TGS_token_size;

	if (verbose) printf("Received %d bytes. TGS and token are probably there.\n", total_size);
	if (verbose) printf("Storing authorization ticket for <%s> \n", client->username);

	int receive_tgs_size = total_size - token_size;

	uint8_t TGSTokenBuffer[token_size];
	uint8_t TGSBuffer[receive_tgs_size];


	parcBuffer_GetBytes(TGSPayload, receive_tgs_size, TGSBuffer);
	parcBuffer_GetBytes(TGSPayload, token_size, TGSTokenBuffer);

	int message_len = token_size - crypto_aead_aes256gcm_ABYTES;

	uint8_t tokenData[message_len];

	//Token decryption:

	int decrypted_len;

	if (TGS_token_size < crypto_aead_aes256gcm_ABYTES ||
		crypto_aead_aes256gcm_decrypt(tokenData, &decrypted_len,
		                              NULL,
		                              TGSTokenBuffer, token_size,
		                              "",
		                              0,
		                              (client->tgt.k_tgs) + crypto_aead_aes256gcm_KEYBYTES, client->tgt.k_tgs) != 0) {

		//printf("TGS Forged!\n");
		return false;
	}

	uint8_t k_N[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
	uint64_t expiration;

	memcpy(k_N,tokenData, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES);
	memcpy(&expiration, tokenData +crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES, sizeof(uint64_t));

	char filename[strlen(userTGSDir) + strlen(client->username) + strlen("@") + strlen(client->domainname) + strlen(client->namespace) +10];
	memset(filename,0,sizeof(filename));
	memcpy(filename, userTGSDir, sizeof userTGSDir);
	strcat(filename, client->username);
	strcat(filename, "@");
	strcat(filename, client->domainname);
	char buffer[strlen(client->namespace)+1];
	memset(buffer,0,strlen(client->namespace)+1);
	memcpy(buffer,client->namespace,strlen(client->namespace)+1);
	for(int i = 0; i<strlen(client->namespace)+1; i++){
		if (buffer[i]=='/') {
			buffer[i] = '.';
		}
	}
	strcat(filename, buffer);
	//printf("PATH: %s\n",filename);

	//Writting TGS to disk:

	FILE* fp = fopen(filename,"w");
	if (fp) {

		fwrite(&expiration, sizeof(uint64_t), 1, fp);
		fprintf(fp,"\n");
		fwrite(&receive_tgs_size, 1, sizeof(receive_tgs_size), fp);
		fprintf(fp,"\n");
		fwrite(TGSBuffer, 1, receive_tgs_size, fp);
		fprintf(fp,"\n");
		fwrite(k_N, 1, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES, fp);
		fprintf(fp,"\n");
		fclose(fp);
	} else{
		printf("can't open file\n");
	}

	if (verbose) printf("TGS stored.\n");
	if (verbose) printf("Expiration: %llu\n", expiration);
}

void
decryptContent(CCNxConsumer *client, PARCBuffer *payload) {
	int total_size = (int)parcBuffer_Remaining(payload);

	if (verbose) printf("Received %d bytes. Content is probably there.\n", total_size);

	uint8_t enc_content[total_size];

	parcBuffer_GetBytes(payload, total_size, enc_content);

	int message_len = total_size - crypto_aead_aes256gcm_ABYTES;

	uint8_t data[message_len];

	//Token decryption:

	long long unsigned decrypted_len;

	if (total_size < crypto_aead_aes256gcm_ABYTES ||
		crypto_aead_aes256gcm_decrypt(data, &decrypted_len,
		                              NULL,
		                              enc_content, total_size,
		                              "",
		                              0,
		                              (client->tgs.k_N) + crypto_aead_aes256gcm_KEYBYTES, client->tgs.k_N) != 0) {

		//printf("Content Forged!\n");
		exit(0);
	} else {
		if (verbose) printf("Content received successfully\n");
		if (verbose) printf("%s\n", data);
	}
}

void
_ccnx_RunTGTReq(CCNxConsumer *client, size_t totalVPNs, uint64_t delayInUs)
{
    PARCClock *clock = parcClock_Wallclock();

    if (verbose) printf("Starting TGT request for user <%s>.\n", client->username);

    size_t outstanding = 0;
    bool checkOustanding = client->numberOfOutstanding > 0;

    uint64_t nextPacketSendTime = 0;
    uint64_t currentTimeInUs = 0;

    int flag = 1;

    if (!rtt_test && !thput_test){
    	pings = 1;
    }
    int count = 0;

    uint64_t cum_delay = 0;

    while (count < pings) {
    	count++;

    	if (verbose) printf("Interest %d\n", count);

        if (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding)) {

        	// Creates a TGT interest///
        	PARCBuffer *payload = _CCNxClient_MakeTGTInterestPayload(client);
        	if (payload == NULL) {
        		printf("Closing client\n");
        		return;
        	}
        	////////////////////////////
        	CCNxName *name = _ccnx_CreateNextName(client);
            CCNxInterest *interest = ccnxInterest_CreateSimple(name);
            ccnxInterest_SetPayloadAndId(interest, payload);
            CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);

            if (ccnxPortal_Send(client->portal, message, CCNxStackTimeout_Never)) {
                currentTimeInUs = current_time();//_ccnx_CurrentTimeInUs(clock);
                nextPacketSendTime = currentTimeInUs + delayInUs;

                ccnxVPNStats_RecordRequest(client->stats, name, currentTimeInUs);
            }

            outstanding++;
            ccnxName_Release(&name);
        	parcBuffer_Release(&payload);
        	if (verbose) printf("Sent TGT request\n");
        }
    }

    while (outstanding > 0) {
        // Now wait for the response and record it`s time
        uint64_t receiveDelay = client->receiveTimeoutInUs;
        CCNxMetaMessage *response = ccnxPortal_Receive(client->portal, &receiveDelay);
        while (response != NULL && (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding))) {
            uint64_t currentTimeInUs = current_time();//_ccnx_CurrentTimeInUs(clock);
            if (ccnxMetaMessage_IsContentObject(response)) {
                CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(response);
                CCNxName *responseName = ccnxContentObject_GetName(contentObject);

                PARCBuffer *contentPayload = ccnxContentObject_GetPayload(contentObject);
                uint8_t reply;
                parcBuffer_GetBytes(contentPayload, 1, &reply);

                if (reply == TGT_SUCCESS) {
                	if (verbose) printf("<%s> authentication successful.\n", client->username);
                	//TODO: Impplement this function properly.
                	if (flag) {
                		storeTGT(client, contentPayload);
                		flag = 0;
                	}

                } else {
                	printf("User credentials for <%s> rejected. Contact your system administrator.\n", client->username);
                }

                size_t delta = ccnxVPNStats_RecordResponse(client->stats, responseName, currentTimeInUs, response);

                // Only display output if we're in ping mode
                if (client->mode == CCNxConsumerMode_VPNPong || client->mode == CCNxConsumerMode_TGTReq) {
                    size_t contentSize = parcBuffer_Remaining(ccnxContentObject_GetPayload(contentObject));
                    char *nameString = ccnxName_ToString(responseName);
                    //printf("%zu bytes from %s: time=%zu us\n", contentSize, nameString, delta);
                    cum_delay += delta;
                    parcMemory_Deallocate(&nameString);
                }
            }
            ccnxMetaMessage_Release(&response);
            if (!thput_test) response = ccnxPortal_Receive(client->portal, &receiveDelay);
            outstanding--;
        }
    }
    if (rtt_test && ! thput_test) printf("%d ", cum_delay/pings);
}

void
_ccnx_RunTGSReq(CCNxConsumer *client, size_t totalVPNs, uint64_t delayInUs)
{
    PARCClock *clock = parcClock_Wallclock();


    if (verbose) printf("Starting TGS request for user <%s>.\n", client->username);

    size_t outstanding = 0;
    bool checkOustanding = client->numberOfOutstanding > 0;

    uint64_t nextPacketSendTime = 0;
    uint64_t currentTimeInUs = 0;

    int flag = 1;

    if (!rtt_test && !thput_test){
    	pings = 1;
    }
    int count = 0;

    uint64_t cum_delay = 0;

    while (count < pings) {
    	count++;
    	if (verbose) printf("Interest %d\n", count);

        if (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding)) {

        	// Creates a TGS interest///
        	PARCBuffer *payload = _CCNxClient_MakeTGSInterestPayload(client);
        	if (payload == NULL) {
        		printf("Closing client\n");
        		return;
        	}

        	////////////////////////////
        	CCNxName *name = _ccnx_CreateNextName(client);
            CCNxInterest *interest = ccnxInterest_CreateSimple(name);
            ccnxInterest_SetPayloadAndId(interest, payload);
            CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);

            if (ccnxPortal_Send(client->portal, message, CCNxStackTimeout_Never)) {
                currentTimeInUs = current_time();//_ccnx_CurrentTimeInUs(clock);
                nextPacketSendTime = currentTimeInUs + delayInUs;

                ccnxVPNStats_RecordRequest(client->stats, name, currentTimeInUs);
            }

            outstanding++;
            ccnxName_Release(&name);
        	//parcBuffer_Release(&payload);
        	if (verbose) printf("Sent TGS request\n");

        }
    }

    while (outstanding > 0) {
        // Now wait for the response and record it`s time
        uint64_t receiveDelay = client->receiveTimeoutInUs;
        CCNxMetaMessage *response = ccnxPortal_Receive(client->portal, &receiveDelay);

        while (response != NULL && (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding))) {

            uint64_t currentTimeInUs = current_time();//_ccnx_CurrentTimeInUs(clock);
            if (ccnxMetaMessage_IsContentObject(response)) {

                CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(response);
                CCNxName *responseName = ccnxContentObject_GetName(contentObject);

                PARCBuffer *contentPayload = ccnxContentObject_GetPayload(contentObject);
                uint8_t reply;
                parcBuffer_GetBytes(contentPayload, 1, &reply);

                if (reply == TGS_SUCCESS) {
                	if (verbose) printf("<%s> authorization successful.\n", client->username);
                	if (flag) {
                		storeTGS(client, contentPayload);
                		flag=0;
                	}


                } else {
                	printf("User credentials for <%s> rejected. Contact your system administrator.\n", client->username);
                }

                size_t delta = ccnxVPNStats_RecordResponse(client->stats, responseName, currentTimeInUs, response);

                // Only display output if we're in ping mode
                if (client->mode == CCNxConsumerMode_VPNPong || client->mode == CCNxConsumerMode_TGSReq) {
                    size_t contentSize = parcBuffer_Remaining(ccnxContentObject_GetPayload(contentObject));
                    char *nameString = ccnxName_ToString(responseName);
                   // printf("%zu bytes from %s: time=%zu us\n", contentSize, nameString, delta);
                    cum_delay += delta;
                    parcMemory_Deallocate(&nameString);
                }
            }
            ccnxMetaMessage_Release(&response);
            if (!thput_test) response = ccnxPortal_Receive(client->portal, &receiveDelay);
            outstanding--;
        }
    }
    if (rtt_test && ! thput_test) printf("%d ", cum_delay/pings);
}

void
_ccnx_RunKRBServiceReq(CCNxConsumer *client, size_t totalVPNs, uint64_t delayInUs)
{
    PARCClock *clock = parcClock_Wallclock();

    if (verbose) printf("Starting content request for user <%s>.\n", client->username);


    size_t outstanding = 0;
    bool checkOustanding = client->numberOfOutstanding > 0;

    uint64_t nextPacketSendTime = 0;
    uint64_t currentTimeInUs = 0;

    if (!rtt_test && !thput_test){
    	pings = 1;
    }
    int count = 0;

    uint64_t cum_delay = 0;

    while (count < pings) {
    	count++;
    	if (verbose) printf("Interest %d\n", count);

        if (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding)) {

        	// Creates a KRB content interest///
        	PARCBuffer *payload = _CCNxClient_MakeKRBInterestPayload(client);
        	if (payload == NULL) {
        		printf("Closing client\n");
        		return;
        	}
        	////////////////////////////
        	CCNxName *name = _ccnx_CreateNextName(client);
            CCNxInterest *interest = ccnxInterest_CreateSimple(name);
            ccnxInterest_SetPayloadAndId(interest, payload);
            CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);

            if (ccnxPortal_Send(client->portal, message, CCNxStackTimeout_Never)) {
                currentTimeInUs = current_time();//_ccnx_CurrentTimeInUs(clock);
                nextPacketSendTime = currentTimeInUs + delayInUs;

                ccnxVPNStats_RecordRequest(client->stats, name, currentTimeInUs);
            }

            outstanding++;
            ccnxName_Release(&name);
        	parcBuffer_Release(&payload);
        	if (verbose) printf("Sent content request\n");
        }
    }

    while (outstanding > 0) {
        // Now wait for the response and record it`s time
        uint64_t receiveDelay = client->receiveTimeoutInUs;
        CCNxMetaMessage *response = ccnxPortal_Receive(client->portal, &receiveDelay);
        while (response != NULL && (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding))) {
            uint64_t currentTimeInUs = current_time();//_ccnx_CurrentTimeInUs(clock);
            if (ccnxMetaMessage_IsContentObject(response)) {
                CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(response);
                CCNxName *responseName = ccnxContentObject_GetName(contentObject);

                PARCBuffer *contentPayload = ccnxContentObject_GetPayload(contentObject);
                uint8_t reply;
                parcBuffer_GetBytes(contentPayload, 1, &reply);

                if (reply == KRB_SUCCESS) {
                	if (verbose) printf("Content received successfully.\n");
                	decryptContent(client, contentPayload);

                } else {
                	printf("User credentials for <%s> rejected. Contact your system administrator.\n", client->username);
                }

                size_t delta = ccnxVPNStats_RecordResponse(client->stats, responseName, currentTimeInUs, response);

                // Only display output if we're in ping mode
                if (client->mode == CCNxConsumerMode_VPNPong || client->mode == CCNxConsumerMode_KRBServReq) {
                    size_t contentSize = parcBuffer_Remaining(ccnxContentObject_GetPayload(contentObject));
                    char *nameString = ccnxName_ToString(responseName);
                   // printf("%zu bytes from %s: time=%zu us\n", contentSize, nameString, delta);
                    cum_delay += delta;
                    parcMemory_Deallocate(&nameString);
                }
            }
            ccnxMetaMessage_Release(&response);
            if (rtt_test && ! thput_test) response = ccnxPortal_Receive(client->portal, &receiveDelay);
            outstanding--;
        }
    }
    if (rtt_test && ! thput_test) printf("%d ", cum_delay/pings);
}

void
_ccnx_RunRegServiceReq(CCNxConsumer *client, size_t totalVPNs, uint64_t delayInUs)
{
    PARCClock *clock = parcClock_Wallclock();

    if (verbose) printf("Starting content request for user <%s>.\n", client->username);

    size_t outstanding = 0;
    bool checkOustanding = client->numberOfOutstanding > 0;

    uint64_t nextPacketSendTime = 0;
    uint64_t currentTimeInUs = 0;

    if (!rtt_test && !thput_test){
    	pings = 1;
    }
    int count = 0;

    uint64_t cum_delay = 0;

    while (count < pings) {
    	count++;
    	if (verbose) printf("Interest %d\n", count);

        if (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding)) {

        	// Creates a KRB content interest///
        	//PARCBuffer *payload = _CCNxServer_MakePayload(client, client->payloadSize);
        	//if (payload == NULL) {
        	//	printf("Closing client\n");
        	//	return;
        	//}
        	////////////////////////////
        	CCNxName *name = _ccnx_CreateNextName(client);
            CCNxInterest *interest = ccnxInterest_CreateSimple(name);
            //ccnxInterest_SetPayloadAndId(interest, payload);
            CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);

            if (ccnxPortal_Send(client->portal, message, CCNxStackTimeout_Never)) {
                currentTimeInUs = current_time();//_ccnx_CurrentTimeInUs(clock);
                nextPacketSendTime = currentTimeInUs + delayInUs;

                ccnxVPNStats_RecordRequest(client->stats, name, currentTimeInUs);
            }

            outstanding++;
            ccnxName_Release(&name);
        	//parcBuffer_Release(&payload);
        	if (verbose) printf("Sent content request\n");
        }
    }

    while (outstanding > 0) {
        // Now wait for the response and record it`s time
        uint64_t receiveDelay = client->receiveTimeoutInUs;
        CCNxMetaMessage *response = ccnxPortal_Receive(client->portal, &receiveDelay);
        while (response != NULL && (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding))) {
            uint64_t currentTimeInUs = current_time();//_ccnx_CurrentTimeInUs(clock);
            if (ccnxMetaMessage_IsContentObject(response)) {
                CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(response);
                CCNxName *responseName = ccnxContentObject_GetName(contentObject);

                PARCBuffer *contentPayload = ccnxContentObject_GetPayload(contentObject);

                size_t delta = ccnxVPNStats_RecordResponse(client->stats, responseName, currentTimeInUs, response);

                // Only display output if we're in ping mode
                if (client->mode == CCNxConsumerMode_Flood || client->mode == CCNxConsumerMode_KRBServReq) {
                    size_t contentSize = parcBuffer_Remaining(ccnxContentObject_GetPayload(contentObject));
                    char *nameString = ccnxName_ToString(responseName);
                   // printf("%zu bytes from %s: time=%zu us\n", contentSize, nameString, delta);
                    cum_delay += delta;
                    parcMemory_Deallocate(&nameString);
                }
            }
            ccnxMetaMessage_Release(&response);
            response = ccnxPortal_Receive(client->portal, &receiveDelay);
            outstanding--;
        }
    }
    if (rtt_test && !thput_test) printf("%d ", cum_delay/pings);
}


/**
 * Display the usage message.
 */
static void
_displayUsage(char *progName)
{
    printf("CCNx Kerberos Implementation\n");
    printf("   (you must have ccnx_Server running)\n");
    printf("\n");
    printf("Usage:\n", progName);
    printf("       Add a new user:\n", progName);
    printf("       %s n <userName>\n", progName);
    printf("       Request a TGT:\n", progName);
    printf("       %s a <username> <domainName>\n", progName);
    printf("       Request a TGS:\n", progName);
    printf("       %s t <username> <domainName> <contentName>\n", progName);
    printf("       Fetch a content:\n", progName);
    printf("       %s k <username> <domainName> <contentName>\n", progName);

    printf("\n");
    printf("Examples:\n");
    printf("    0.      ./ccnxKRB_Client n ivan\n");
    printf("    1.      ./ccnxKRB_Client a ivan ccnx:/localhost\n");
    printf("    2.      ./ccnxKRB_Client t ivan ccnx:/localhost ccnx:/localhost/filesystem \n");
    printf("    3.      ./ccnxKRB_Client k ivan ccnx:/localhost ccnx:/localhost/filesystem/image.png \n");
    printf("\n");

    // Kerberos services///
        printf("\nKerberos services description\n");
        printf("     n <username> creates a new user on the client host \n");
        printf("     a <username> User authentication and TGT issuance \n");
        printf("     t <namespace> Access control and TGS issuance \n");
        printf("     k <interest name> Access to kerberized service using existent TGS \n\n");
        ///////////////////////
}

/*
 * Generates and store cryptographic material for a given user (see Common.h for default storage directory paths)
 */
static bool
ccnx_KRB_addUser(char* userName)
{
	if (strlen(userName) > MAX_USERNAME_LEN) {
		printf("Username must have at most %d characters\n", MAX_USERNAME_LEN);
		return false;
	}

	//USER KEY PAIR FOR SIGNATURES
	unsigned char user_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char user_sk[crypto_sign_SECRETKEYBYTES];
	crypto_sign_keypair(user_pk, user_sk);

	//USER KEY PAIR FOR ENCRYPTION
	unsigned char enc_user_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char enc_user_sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(enc_user_pk, enc_user_sk);

	//USER KEY FOR SYMMETRIC ENCRYPTION
    unsigned char sym_key[crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES];
	randombytes_buf(sym_key, sizeof sym_key);


	/*
	 * Writting keys to files.
	 */

	char* fileName = (char*) malloc(strlen(userName) + strlen(userPrvDir) + strlen("-prv-sig") + 1);
	strcpy(fileName, userPrvDir);
	strcat(fileName, userName);
	strcat(fileName, "-prv-sig");

	if (!fopen(fileName,"r")) {

/*
 *
 */
		// Writing secret signature key to default location////////
		FILE* user_keys = fopen(fileName,"w");
		fwrite(user_sk, sizeof(char), crypto_sign_SECRETKEYBYTES, user_keys);
		fclose(user_keys);
		////////////////////////////////////////////////

		// Writing public signature key to default location////////
		strcpy(fileName, userPrvDir);
		strcat(fileName, userName);
		strcat(fileName, "-pub-sig");
		user_keys = fopen(fileName,"w");
		fwrite(user_pk, sizeof(char), crypto_sign_PUBLICKEYBYTES, user_keys);
		fclose(user_keys);
		/////////////////////////////////////////////////
/*
 *
 */


/*
 *
 */
		// Writing secret encryption key to default location////////
		strcpy(fileName, userPrvDir);
		strcat(fileName, userName);
		strcat(fileName, "-prv-enc");

		user_keys = fopen(fileName,"w");
		fwrite(enc_user_sk, sizeof(char), crypto_box_SECRETKEYBYTES, user_keys);
		fclose(user_keys);
		////////////////////////////////////////////////

		// Writing public encryption key to default location////////
		strcpy(fileName, userPrvDir);
		strcat(fileName, userName);
		strcat(fileName, "-pub-enc");

		user_keys = fopen(fileName,"w");
		fwrite(enc_user_pk, sizeof(char), crypto_box_PUBLICKEYBYTES, user_keys);
		fclose(user_keys);
		/////////////////////////////////////////////////
/*
 *
 */






		// Writing symmetric to default location//////////
		strcpy(fileName, userPrvDir);
		strcat(fileName, userName);
		strcat(fileName, "-sym");
		user_keys = fopen(fileName,"w");
		fwrite(sym_key,sizeof(char),crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES,user_keys);
		fclose(user_keys);
		/////////////////////////////////////////////////

		printf("User <%s> was created successfully.\n", userName);
	} else {
		printf("Username <%s> is already in use.\n", userName);
	}
	free(fileName);
	return false;	//close software after adding the user
}

void
loadUserKeys(CCNxConsumer *client) {
	char* filename_sig[100];
	char* filename_enc[100];
	char* filename_enc_pk[100];

	memset(filename_sig,0,100);
	memset(filename_enc,0,100);
	memset(filename_enc_pk,0,100);

	memcpy (filename_sig, userPrvDir, sizeof(userPrvDir));
	strcat(filename_sig, (char*)client->username);
	strcat(filename_sig, (char*)"-prv-sig");

	memcpy (filename_enc, userPrvDir, sizeof(userPrvDir));
	strcat(filename_enc, (char*)client->username);
	strcat(filename_enc, (char*)"-prv-enc");

	memcpy (filename_enc_pk, userPrvDir, sizeof(userPrvDir));
		strcat(filename_enc_pk, (char*)client->username);
		strcat(filename_enc_pk, (char*)"-pub-enc");

	//Load the signature key
	FILE* fp = fopen(filename_sig, "r");
	if (!fp) {
		printf("\nERROR: Could not find secret key file in default dir for user <%s>\nThis user probably does not exist yet.", client->username);
		printf("Try running with | -n <username> | to\ngenerate user's cryptographic material.\n");
		printf("Then add user credentials to KDC server.\n\n");
		exit(0);
	} else {
		fread(client->user_sk_sig, 1, crypto_sign_SECRETKEYBYTES, fp);
		fclose(fp);
	}

	//Load the encryption key
	fp = fopen(filename_enc, "r");
	if (!fp) {
		printf("\nERROR: Could not find secret key file in default dir for user <%s>\nThis user probably does not exist yet.", client->username);
		printf("Try running with | -n <username> | to\ngenerate user's cryptographic material.\n");
		printf("Then add user credentials to KDC server.\n\n");
		exit(0);
	} else {
		fread(client->user_sk_enc, 1, crypto_box_SECRETKEYBYTES, fp);
		fclose(fp);
	}

	//Load the encryption keya
	fp = fopen(filename_enc_pk, "r");
	if (!fp) {
		printf("\nERROR: Could not find secret key file in default dir for user <%s>\nThis user probably does not exist yet.", client->username);
		printf("Try running with | -n <username> | to\ngenerate user's cryptographic material.\n");
		printf("Then add user credentials to KDC server.\n\n");
		exit(0);
	} else {
		fread(client->user_pk_enc, 1, crypto_box_PUBLICKEYBYTES, fp);
		fclose(fp);
	}

}

static void
_ccnx_DisplayStatistics(CCNxConsumer *client)
{
    bool ableToCompute = ccnxVPNStats_Display(client->stats);
    if (!ableToCompute) {
        //parcDisplayIndented_PrintLine(0, "No packets were received. Check to make sure the client and server are configured correctly and that the forwarder is running.\n");
    }else {
        storeThroughput(client->stats,client->payloadSize);
    }
}

static void
_ccnx_RunKerberizedClient(CCNxConsumer *client)
{

	CCNxPortalFactory *factory = _setupConsumerPortalFactory(client->keystoreName, client->keystorePassword);
    client->portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
    ccnxPortalFactory_Release(&factory);

    switch (client->mode) {

        case CCNxConsumerMode_TGTReq:
            _ccnx_RunTGTReq(client, client->count, client->intervalInMs);
            //_ccnx_DisplayStatistics(client);
            break;

        case CCNxConsumerMode_TGSReq:
            _ccnx_RunTGSReq(client, client->count, client->intervalInMs);
            //_ccnx_DisplayStatistics(client);
            break;

        case CCNxConsumerMode_KRBServReq:
            _ccnx_RunKRBServiceReq(client, client->count, client->intervalInMs);
            //_ccnx_DisplayStatistics(client);
            break;

        case CCNxConsumerMode_Flood:
            _ccnx_RunRegServiceReq(client, client->count, client->intervalInMs);
            //_ccnx_DisplayStatistics(client);
            break;


        case CCNxConsumerMode_None:
        default:
            fprintf(stderr, "Error, unknown mode");
            break;
    }
}

static void
_ccnx_RunFullKerberizedClient(CCNxConsumer *client)
{
	if (verbose) printf("running full req\n");

	CCNxPortalFactory *factory = _setupConsumerPortalFactory(client->keystoreName, client->keystorePassword);
    client->portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
    ccnxPortalFactory_Release(&factory);

	char * TGTFile = (char*)malloc(strlen(userTGTDir) + strlen(client->username) + strlen(client->domainname) + 2);
	memset(TGTFile, 0, strlen(userTGTDir) + strlen(client->username) + strlen(client->domainname) + 2);
	strcat(TGTFile, userTGTDir);
	strcat(TGTFile,client->username);
	strcat(TGTFile,"@");
	strcat(TGTFile,client->domainname);

	//printf("TGT file name:\n %s\n",TGTFile);

	char trash;
	uint64_t exp;
	FILE* fp = fopen(TGTFile,"r");
	if (fp == NULL) {
		printf("TGT not found\n");
		exit(0);
	}

	fread(&(client->tgt.expiration), sizeof(uint64_t), 1, fp);
	fscanf(fp,"\n");
	fread(client->tgt.tgtData, 1, RECEIVE_TGT_SIZE, fp);
	fscanf(fp,"\n");
	fread(&(client->tgt.k_tgs), 1, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES, fp);
	fscanf(fp,"\n");
	fclose(fp);

    uint64_t end;
/*
    		client->prefix = ccnxName_CreateFromCString("ccnx:/localhost/TGT");
            _ccnx_RunTGTReq(client, client->count, 0);

            client->prefix = ccnxName_CreateFromCString("ccnx:/localhost/TGS");
            _ccnx_RunTGSReq(client, client->count, 0);


            char interest_name[strlen("ccnx:/localhost/uci/edu/fileA") + 1];
            memset(interest_name, 0, strlen("ccnx:/localhost/uci/edu/fileA")+ 1);
            strcat(interest_name, "ccnx:/localhost/uci/edu/fileA");
            if (verbose) printf("content_name: <%s>\n", interest_name);
            client->prefix = ccnxName_CreateFromCString(interest_name);
       		client->namespace = malloc(strlen("ccnx:/localhost/uci/edu/fileA") + 1);
       		strcpy(client->namespace, "ccnx:/localhost/uci/edu/fileA");
            _ccnx_RunKRBServiceReq(client, client->count, 0);
*/
     uint64_t start = current_time();
     	 	 client->mode = CCNxConsumerMode_Flood;
     	 	 client->prefix = ccnxName_CreateFromCString(ccnx_DefaultPrefix);
       		_ccnx_RunRegServiceReq(client, client->count, 0);
     end = current_time();
     int delay;
     if ((end-start) < 1000000) {
    	 delay = 1000000;
     } else {
    	 delay = end-start;
     }
     printf("%f ",8*1000000*(10240.0 *(pings)/delay));
}

static bool
_ccnx_KRB_Commandline(CCNxConsumer *client, int argc, char *argv[argc]) {
	if (argc < 3) {
		_displayUsage(argv[0]);
		return false;
	}

	switch (argv[1][0]) {
		case 'n':

			if (argc == 3) {
				ccnx_KRB_addUser(argv[2]);
				client->mode = CCNxConsumerMode_KRBConfig;
			} else {
				_displayUsage(argv[0]);
			}
    	    return false;

		case 'p':

    		//XXX: TGT Req network options
    		client->count = 1;
    		client->intervalInMs = 10;
    		client->payloadSize = 1024;
    		client->mode = CCNxConsumerMode_Flood;
    		//XXX: End of TGT Req network options

    		client->keystoreName = malloc(strlen("consumer_identity1") + 1);
    		strcpy(client->keystoreName, "consumer_identity1");
            client->keystorePassword = malloc(strlen("consumer_identity1") + 1);
            strcpy(client->keystorePassword, "consumer_identity1");

			client->prefix = ccnxName_CreateFromCString(ccnx_DefaultPrefix);
    	    return true;


		case 'a':
			if (argc == 4) {
				if (verbose) printf("TGT User Authentication Request.\n");

        		//XXX: TGT Req network options
        		client->count = 1;
        		client->intervalInMs = 10;
        		client->payloadSize = 1024;
        		client->mode = CCNxConsumerMode_TGTReq;
        		//XXX: End of TGT Req network options

        		client->username = malloc(strlen(argv[2]) + 1);
                strcpy(client->username, argv[2]);
                if (verbose) printf("%s\n",client->username);
                loadUserKeys(client);

        		client->keystoreName = malloc(strlen("consumer_identity1") + 1);
        		strcpy(client->keystoreName, "consumer_identity1");
                client->keystorePassword = malloc(strlen("consumer_identity1") + 1);
                strcpy(client->keystorePassword, "consumer_identity1");

        		client->domainname = malloc(strlen(argv[3]) + 1);
                strcpy(client->domainname, argv[3]);

                int i;
                for (i=0; i<strlen(client->domainname);i++) {
                	if (client->domainname[i] == '/') {
                		client->domainname[i] = '.';
                	}
                }
                //printf("writable domain name: %s\n", client->domainname);
                char TGT_name[strlen(argv[3])+10];
                memset(TGT_name,0,strlen(argv[3])+10);
                strcat(TGT_name,argv[3]);
                strcat(TGT_name,"/TGT");
                client->prefix = ccnxName_CreateFromCString(TGT_name);
                return true;
			} else {
				_displayUsage(argv[0]);
				return false;
			}

		case 't':
			if (argc == 5) {
				if (verbose) printf("TGS Authorization Request.\n");

        		//XXX: TGS Req network options
        		client->count = 1;
        		client->intervalInMs = 10;
        		client->payloadSize = 1024;
        		client->mode = CCNxConsumerMode_TGSReq;
        		//XXX: End of TGS Req network options

        		client->username = malloc(strlen(argv[2]) + 1);
                strcpy(client->username, argv[2]);
                loadUserKeys(client);

        		client->keystoreName = malloc(strlen("consumer_identity1") + 1);
        		strcpy(client->keystoreName, "consumer_identity1");
                client->keystorePassword = malloc(strlen("consumer_identity1") + 1);
                strcpy(client->keystorePassword, "consumer_identity1");

        		client->domainname = malloc(strlen(argv[3]) + 1);
                strcpy(client->domainname, argv[3]);

                int i;
                for (i=0; i<strlen(client->domainname);i++) {
                	if (client->domainname[i] == '/') {
                		client->domainname[i] = '.';
                	}
                }

                char TGS_name[strlen(argv[3])+10];
                memset(TGS_name,0,strlen(argv[3])+10);
                strcat(TGS_name,argv[3]);
                strcat(TGS_name,"/TGS");
                client->prefix = ccnxName_CreateFromCString(TGS_name);

           		client->namespace = malloc(strlen(argv[4]) + 1);
           		strcpy(client->namespace, argv[4]);


           		char * TGTFile = (char*)malloc(strlen(userTGTDir) + strlen(client->username) + strlen(client->domainname) + 2);
           		memset(TGTFile, 0, strlen(userTGTDir) + strlen(client->username) + strlen(client->domainname) + 2);
           		strcat(TGTFile, userTGTDir);
           		strcat(TGTFile,client->username);
           		strcat(TGTFile,"@");
           		strcat(TGTFile,client->domainname);

           		//printf("TGT file name:\n %s\n",TGTFile);

           		char trash;
           		uint64_t exp;
           		FILE* fp = fopen(TGTFile,"r");
           		if (fp == NULL) {
           			printf("TGT not found\n");
           			exit(0);
           		}

           		fread(&(client->tgt.expiration), sizeof(uint64_t), 1, fp);
           		fscanf(fp,"\n");
           		fread(client->tgt.tgtData, 1, RECEIVE_TGT_SIZE, fp);
           		fscanf(fp,"\n");
           		fread(&(client->tgt.k_tgs), 1, crypto_aead_aes256gcm_KEYBYTES+crypto_aead_aes256gcm_NPUBBYTES, fp);
           		fscanf(fp,"\n");
           		fclose(fp);

           		free(TGTFile);

                return true;
			} else {
				_displayUsage(argv[0]);
				return false;
			}

		case 'k':
			if (argc == 5) {
				if (verbose) printf("Issuing authorized interest for content <%s>.\n", argv[4]);

        		//XXX: Content Req network options
        		client->count = 1;
        		client->intervalInMs = 10;
        		client->payloadSize = 1024;
        		client->mode = CCNxConsumerMode_KRBServReq;
        		//XXX: End of TGS Req network options

        		client->username = malloc(strlen(argv[2]) + 1);
                strcpy(client->username, argv[2]);
                loadUserKeys(client);

        		client->keystoreName = malloc(strlen("consumer_identity1") + 1);
        		strcpy(client->keystoreName, "consumer_identity1");
                client->keystorePassword = malloc(strlen("consumer_identity1") + 1);
                strcpy(client->keystorePassword, "consumer_identity1");

        		client->domainname = malloc(strlen(argv[3]) + 1);
                strcpy(client->domainname, argv[3]);

                int i;
                for (i=0; i<strlen(client->domainname);i++) {
                	if (client->domainname[i] == '/') {
                		client->domainname[i] = '.';
                	}
                }
                if (verbose) printf("writable domain name: %s\n", client->domainname);
/*
                char interest_name[strlen(argv[3]) + strlen(argv[4]) + 10];
                memset(interest_name, 0, strlen(argv[3]) + strlen(argv[4]) + 10);
                strcat(interest_name, argv[3]);
                strcat(interest_name, argv[4]);
*/
                char interest_name[strlen(argv[4]) + 1];
                memset(interest_name, 0, strlen(argv[4])+ 1);
                strcat(interest_name, argv[4]);

                if (verbose) printf("content_name: <%s>\n", interest_name);
                client->prefix = ccnxName_CreateFromCString(interest_name);

           		client->namespace = malloc(strlen(argv[4]) + 1);
           		strcpy(client->namespace, argv[4]);
                return true;
			} else {
				_displayUsage(argv[0]);
				return false;
			}


    	default:
    		_displayUsage(argv[0]);
    		return false;
	}
}

int
main(int argc, char *argv[argc])
{
	parcSecurity_Init();

// test variables:
//	verbose = 1;
	rtt_test = 1;
	thput_test = 1;
	pings = 1;
	b_pings = 1;

	if (rtt_test || thput_test) {
		FILE* fp = fopen("pings.csv","r");
		if (fp == NULL) {
			printf("ping file not found\n");
			exit(0);
		} else {
			fscanf(fp,"%d",&pings);
			b_pings = pings;
			//printf("file found; %d\n", pings);
			fclose(fp);
		}
	}

	int check = sodium_init();
	if (check) {
		printf("Crypto lib Sodium not available.\n");
	}

    CCNxConsumer *client = ccnx_Create();

    bool runKRB = _ccnx_KRB_Commandline(client, argc, argv);

	if (runKRB && !thput_test) {
		_ccnx_RunKerberizedClient(client);
	} else {
		thput_test = 1;
		_ccnx_RunFullKerberizedClient(client);
	}


    ccnxVPN_Release(&client);

    parcSecurity_Fini();

    if (verbose) printf("\n");

    return EXIT_SUCCESS;
}
