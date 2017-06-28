/*
 * Copyright (c) 2016, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL XEROX OR PARC BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ################################################################################
 * #
 * # PATENT NOTICE
 * #
 * # This software is distributed under the BSD 2-clause License (see LICENSE
 * # file).  This BSD License does not make any patent claims and as such, does
 * # not act as a patent grant.  The purpose of this section is for each contributor
 * # to define their intentions with respect to intellectual property.
 * #
 * # Each contributor to this source code is encouraged to state their patent
 * # claims and licensing mechanisms for any contributions made. At the end of
 * # this section contributors may each make their own statements.  Contributor's
 * # claims and grants only apply to the pieces (source code, programs, text,
 * # media, etc) that they have contributed directly to this software.
 * #
 * # There is no guarantee that this section is complete, up to date or accurate. It
 * # is up to the contributors to maintain their portion of this section and up to
 * # the user of the software to verify any claims herein.
 * #
 * # Do not remove this header notification.  The contents of this section must be
 * # present in all distributions of the software.  You may only modify your own
 * # intellectual property statements.  Please provide contact information.
 *
 * - Palo Alto Research Center, Inc
 * This software distribution does not grant any rights to patents owned by Palo
 * Alto Research Center, Inc (PARC). Rights to these patents are available via
 * various mechanisms. As of January 2016 PARC has committed to FRAND licensing any
 * intellectual property used by its contributions to this software. You may
 * contact PARC at cipo@parc.com for more information or visit http://www.ccnx.org
 */
/**
 * @author Nacho Solis, Christopher A. Wood, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2016, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */
#include <stdio.h>

#include <getopt.h>

#include <LongBow/runtime.h>

#include <parc/algol/parc_Object.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_IdentityFile.h>

#include <ccnx/common/ccnx_Name.h>

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include "../ccnxVPN_Common.h"

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
    uint8_t user_pk[crypto_sign_PUBLICKEYBYTES];

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

	if (result) {
		code = TGT_SUCCESS;
	} else {
		code = TGT_AUTH_FAIL;
	}

	int size = sizeof(uint8_t);
	PARCBuffer *payload = parcBuffer_Allocate(size);
    parcBuffer_PutUint8(payload, code);
	parcBuffer_Flip(payload);

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
	char filename_pk[strlen(username) + strlen(userPrvDir) + 5]; // +5 to concat -prv\0
	strcpy(filename_pk, userPrvDir);
	strcat(filename_pk,username);

	if (1) {
		strcat(filename_pk,"-pub");
	} else {
		// ADD symmetric key based TGT support here later
		printf("never happens\n");
	}

	FILE* fp = fopen(filename_pk, "r");
	if (!fp) {
		printf("ERROR: Could not find public key file\n");
	} else {
		fread(pk, 1, crypto_sign_PUBLICKEYBYTES, fp);
		fclose(fp);
	}

	if (crypto_sign_verify_detached(sig, username, MAX_USERNAME_LEN, pk) != 0) {
	    /* Incorrect signature! */
		return false;
	} else {
		memcpy(server->username, username, MAX_USERNAME_LEN);
		memcpy(server->user_pk, pk, crypto_sign_PUBLICKEYBYTES);
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
