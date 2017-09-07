
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

#include "sodium.h"

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
ccnxKBRService_Create(CCNxServer *server)
{
    server->prefix = ccnxName_CreateFromCString(ccnx_KRB_Serv_DefaultPrefix);
    server->payloadSize = ccnx_DefaultPayloadSize;
    server->mode = KRB_SERVICE;

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

	    printf("encrypting token with client key\n");

		/* Anonymous sender encrypts a message using an ephemeral key pair
		 * and the recipient's public key */
	    // TODO: change this to authenticated encryption
	    int ct_len = crypto_box_SEALBYTES + sizeof k_tgs + sizeof(uint64_t);
		unsigned char enc_C_TGS_token[ct_len];
		crypto_box_seal(enc_C_TGS_token, C_TGS_token, sizeof k_tgs + sizeof(uint64_t), server->user_pk_enc);

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
		//testing
		//uint64_t test = 0;
		//memcpy(&test,position,sizeof (uint64_t));
		//printf("\n%llu\n%llu\n%d\n", test,expiration, sizeof (uint64_t));
		//end testing
		position += sizeof (uint64_t);

		memcpy(position, k_tgs, sizeof k_tgs); //copy TGS key to buffer
		//printf("\n%s\n%s\n", position, k_tgs);
		position += sizeof k_tgs;

		// At this point the TGT is ready to be encrypted

		//TODO: Read these guys from file.////////////////////
		unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
		unsigned char KDC_key[crypto_aead_aes256gcm_KEYBYTES];
		unsigned long long ciphertext_len;

		FILE* kdcKeyFile = fopen(keyFileKDC,"r");
		fread(KDC_key, 1, crypto_aead_aes256gcm_KEYBYTES, kdcKeyFile);
		fread(nonce, 1, crypto_aead_aes256gcm_NPUBBYTES, kdcKeyFile);
		fclose(kdcKeyFile);

		//randombytes_buf(KDC_key, sizeof KDC_key);
		//randombytes_buf(nonce, sizeof nonce);

		unsigned char enc_TGT[tgt_size + crypto_aead_aes256gcm_ABYTES];

		crypto_aead_aes256gcm_encrypt(enc_TGT, &ciphertext_len,
			                          TGT, tgt_size,
			                          NULL, 0,
			                          NULL, nonce, KDC_key);

		// TODO: move this part to TGS producer
		unsigned char decrypted[tgt_size];
		unsigned long long decrypted_len;
		if (ciphertext_len < crypto_aead_aes256gcm_ABYTES ||
			crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
			                              NULL,
			                              enc_TGT, ciphertext_len,
			                              NULL,
			                              0,
			                              nonce, KDC_key) != 0) {
				printf("message forged");
		}else{
			printf("Message ok!\n");
			printf("Content: %s\n",decrypted);
		}

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

	printf("Sending response content.\n");
    return payload;
}


/**
 * Run the `CCNxServer` indefinitely.
 */

bool ccnx_krb_VerifyUser(CCNxServer *server, PARCBuffer *recvPayload){
	uint8_t username[MAX_USERNAME_LEN];
	uint8_t sig[crypto_sign_BYTES];

	int payloadSize = parcBuffer_Remaining(recvPayload);

	parcBuffer_GetBytes(recvPayload, MAX_USERNAME_LEN, username);

	parcBuffer_GetBytes(recvPayload, crypto_sign_BYTES, sig);

	printf("Received authentication request from <%s>.\n",username);

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

	if (crypto_sign_verify_detached(sig, username, MAX_USERNAME_LEN, pk) != 0) {
	    /* Incorrect signature! */
		return false;
	} else {
		memcpy(server->username, username, MAX_USERNAME_LEN);
		memcpy(server->user_pk_sig, pk, crypto_sign_PUBLICKEYBYTES);
		return true;
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
		return false;
	} else {
		//sets the server structure with appropriate keys to allow generation of TGT and auth TOKEN
		memcpy(server->username, username, MAX_USERNAME_LEN);
		memcpy(server->user_pk_sig, pk, crypto_sign_PUBLICKEYBYTES);
		memcpy(server->user_pk_enc, enc_pk, crypto_box_PUBLICKEYBYTES);
		return true;
	}


}


static void
_CCNxServer_Run(CCNxServer *server)
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
                    printf("Sending %d bytes. TGT and token are probably there.\n",parcBuffer_Remaining(payload));
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

            // Why releasing this fucks up the whole shit?
            //parcBuffer_Release(&interestPayload);

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
    	{ "TGT prod", no_argument, NULL, 'a' },
    	{ "TGS prod", no_argument, NULL, 't' },
    	{ "KRB Serv prod", no_argument, NULL, 'k' },

        { "locator", required_argument, NULL, 'l' },
        { "size",    required_argument, NULL, 's' },
        { "help",    no_argument,       NULL, 'h' },
        { "identity file", required_argument, NULL, 'i'},
        { "password", required_argument, NULL, 'p'},
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

        		//TODO: temporary ////////////
        		server->keystoreName = malloc(strlen("producer_identity1") + 1);
        		strcpy(server->keystoreName, "producer_identity1");
                server->keystorePassword = malloc(strlen("producer_identity1") + 1);
                strcpy(server->keystorePassword, "producer_identity1");
                //end TODO //////////////////

        		break;
        	case 't':
        		printf("Starting TGS Producer.\n");
        		ccnxTGSServer_Create(server);
        		break;
        	case 'k':
        		printf("Starting Kerberized Service Producer.\n");
        		ccnxKBRService_Create(server);
        		break;
        	case 'l':
                server->prefix = ccnxName_CreateFromCString(optarg);
                break;
            case 's':
                sscanf(optarg, "%zu", &(server->payloadSize));
                if (server->payloadSize > ccnx_MaxPayloadSize) {
                    _displayUsage(argv[0]);
                    return false;
                }
                break;
            case 'i':
                server->keystoreName = malloc(strlen(optarg) + 1);
                strcpy(server->keystoreName, optarg);
                break;
            case 'p':
                server->keystorePassword = malloc(strlen(optarg) + 1);
                strcpy(server->keystorePassword, optarg);
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
        _CCNxServer_Run(server);
    }

    CCNxServer_Release(&server);

    parcSecurity_Fini();

    return EXIT_SUCCESS;
}
