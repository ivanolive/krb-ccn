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

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include <parc/algol/parc_Clock.h>

#include <parc/algol/parc_Object.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_IdentityFile.h>
#include <parc/algol/parc_DisplayIndented.h>

#include "../ccnxVPN_Common.h"
#include "../ccnxVPN_Stats.h"

typedef enum {
    CCNxConsumerMode_None = 0,
    CCNxConsumerMode_Flood,
    CCNxConsumerMode_VPNPong,
    CCNxConsumerMode_TGTReq,
    CCNxConsumerMode_TGSReq,
    CCNxConsumerMode_KRBServReq,
    CCNxConsumerMode_All
} CCNxConsumerMode;

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
    int nonce;

    char *keystoreName;
    char *keystorePassword;
    char *username;
} CCNxConsumer;

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
    client->receiveTimeoutInUs = 1000000;//*60; //ccnx_DefaultReceiveTimeoutInUs;
    client->count = 10;
    client->intervalInMs = 1000;
    client->nonce = rand();
    client->numberOfOutstanding = 0;

    client->keystoreName = NULL;
    client->keystorePassword = NULL;
    client->username = NULL;

    return client;
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
 * Run a single ping test.
 */
static void
_ccnx_RunVPN(CCNxConsumer *client, size_t totalVPNs, uint64_t delayInUs)
{
    PARCClock *clock = parcClock_Wallclock();

    CCNxPortalFactory *factory = _setupConsumerPortalFactory(client->keystoreName, client->keystorePassword);
    client->portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
    ccnxPortalFactory_Release(&factory);

    size_t outstanding = 0;
    bool checkOustanding = client->numberOfOutstanding > 0;

    for (int pings = 0; pings <= totalVPNs; pings++) {
        uint64_t nextPacketSendTime = 0;
        uint64_t currentTimeInUs = 0;

        // Continue to send ping messages until we've reached the capacity
        if (pings < totalVPNs && (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding))) {
            CCNxName *name = _ccnx_CreateNextName(client);
            CCNxInterest *interest = ccnxInterest_CreateSimple(name);
            CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);

            if (ccnxPortal_Send(client->portal, message, CCNxStackTimeout_Never)) {
                currentTimeInUs = _ccnx_CurrentTimeInUs(clock);
                nextPacketSendTime = currentTimeInUs + delayInUs;

                ccnxVPNStats_RecordRequest(client->stats, name, currentTimeInUs);
            }

            outstanding++;
            ccnxName_Release(&name);
        } else {
            // We're done with pings, so let's wait to see if we have any stragglers
            currentTimeInUs = _ccnx_CurrentTimeInUs(clock);
            nextPacketSendTime = currentTimeInUs + client->receiveTimeoutInUs;
        }

        // Now wait for the responses and record their times
        uint64_t receiveDelay = nextPacketSendTime - currentTimeInUs;
        CCNxMetaMessage *response = ccnxPortal_Receive(client->portal, &receiveDelay);
        while (response != NULL && (!checkOustanding || (checkOustanding && outstanding < client->numberOfOutstanding))) {
            uint64_t currentTimeInUs = _ccnx_CurrentTimeInUs(clock);
            if (ccnxMetaMessage_IsContentObject(response)) {
                CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(response);

                CCNxName *responseName = ccnxContentObject_GetName(contentObject);
                size_t delta = ccnxVPNStats_RecordResponse(client->stats, responseName, currentTimeInUs, response);

                // Only display output if we're in ping mode
                if (client->mode == CCNxConsumerMode_VPNPong || client->mode == CCNxConsumerMode_TGTReq) {
                    size_t contentSize = parcBuffer_Remaining(ccnxContentObject_GetPayload(contentObject));
                    char *nameString = ccnxName_ToString(responseName);
                    printf("%zu bytes from %s: time=%zu us\n", contentSize, nameString, delta);
                    parcMemory_Deallocate(&nameString);
                }
            }
            ccnxMetaMessage_Release(&response);

            if (pings < totalVPNs) {
                receiveDelay = nextPacketSendTime - currentTimeInUs;
            } else {
                receiveDelay = client->receiveTimeoutInUs;
            }

            response = ccnxPortal_Receive(client->portal, &receiveDelay);
            outstanding--;
        }
    }
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
    printf("Usage: %s -p [ -c count ] [ -s size ] [ -i interval ]\n", progName);
    printf("       %s -f [ -c count ] [ -s size ]\n", progName);
    printf("       %s -h\n", progName);
    printf("\n");
    printf("Example:\n");
    printf("    ccnx_Consumer -l ccnx:/some/prefix -c 100 -f\n");
    printf("\n");
    printf("Options:\n");

    printf("     -h (--help) Show this help message\n");
    printf("     -p (--ping) ping mode - \n");
    printf("     -f (--flood) flood mode - send as fast as possible\n");
    printf("     -c (--count) Number of count to run\n");
    printf("     -i (--interval) Interval in milliseconds between interests in ping mode\n");
    printf("     -s (--size) Size of the interests\n");
    printf("     -l (--locator) Set the locator for this server. The default is 'ccnx:/locator'. \n");

    // Kerberos services///
        printf("\nKerberos services \n");
        printf("     -a <username> User authentication and TGT issuance \n");
        printf("     -t <namespace> Access control and TGS issuance \n");
        printf("     -k <interest name> Access to kerberized service using existent TGS \n\n");
        ///////////////////////
}

static bool
_ccnx_KRB_ParseCommandline(CCNxConsumer *client, int argc, char *argv[argc])
{

	static struct option longopts[] = {
    	{ "TGT",		required_argument,       NULL, 'a' },
    	{ "TGS",		required_argument,       NULL, 't' },
    	{ "KRB_SERV",   required_argument,       NULL, 'k' },
    	{ "flood",      no_argument,       NULL, 'f' },
        { "count",      required_argument, NULL, 'c' },
        { "size",       required_argument, NULL, 's' },
        { "locator",     required_argument, NULL, 'l' },
        { "outstanding", required_argument, NULL, 'o' },
        { "identity file", required_argument, NULL, 'i' },
        { "password",    required_argument, NULL, 'p' },
        { "help",        no_argument,       NULL, 'h' },
        { NULL,          0,                 NULL, 0   }
    };

    client->payloadSize = ccnx_DefaultPayloadSize;

    int c;
    while ((c = getopt_long(argc, argv, "a:t:k:p:i:h:f:c:s:l:o:", longopts, NULL)) != -1) {
        switch (c) {
        	case 'a':
        		printf("TGT User Authentication.\n");

        		//XXX: TGT Req network options
        		client->count = 1;
        		client->intervalInMs = 1;
        		client->payloadSize = 1024;
        		client->mode = CCNxConsumerMode_TGTReq;
        		//XXX: End of TGT Req network options

        		//Reading username
        		client->username = malloc(strlen(optarg) + 1);
                strcpy(client->username, optarg);

        		//TODO: temporary ////////////
        		client->keystoreName = malloc(strlen("consumer_identity1") + 1);
        		strcpy(client->keystoreName, "consumer_identity1");
                client->keystorePassword = malloc(strlen("consumer_identity1") + 1);
                strcpy(client->keystorePassword, "consumer_identity1");
                //end TODO //////////////////

        		break;
        	case 't':
        	    printf("TGS Service Access Control Verification.\n");
        	    break;
        	case 'k':
        	    printf("Kerberized service interest issuance.\n");
        	    break;
            case 'f':
                if (client->mode != CCNxConsumerMode_None) {
                    return false;
                }
                //sscanf(optarg, "%u", &(client->intervalInMs));
                //TODO: check this
                client->intervalInMs = 1000000/atoi(argv[8]);
                printf("%d us period between two interests.\n",client->intervalInMs);

                client->mode = CCNxConsumerMode_VPNPong;
                break;
            case 'i':
                client->keystoreName = malloc(strlen(optarg) + 1);
                strcpy(client->keystoreName, optarg);
                break;
            case 'p':
                client->keystorePassword = malloc(strlen(optarg) + 1);
                strcpy(client->keystorePassword, optarg);
                break;
            case 'c':
                sscanf(optarg, "%u", &(client->count));
                break;
            // case 'i':
            //     sscanf(optarg, "%llu", &(client->intervalInMs));
            //     break;
            case 's':
                sscanf(optarg, "%u", &(client->payloadSize));
                break;
            case 'o':
                sscanf(optarg, "%zu", &(client->numberOfOutstanding));
                break;
            case 'l':
                client->prefix = ccnxName_CreateFromCString(optarg);
                break;
            case 'h':
                _displayUsage(argv[0]);
                return false;
            default:
                break;
        }
    }

    //end:
    if (client->mode == CCNxConsumerMode_None) {
        _displayUsage(argv[0]);
        return false;
    }

    return true;
};

static void
_ccnx_DisplayStatistics(CCNxConsumer *client)
{
    bool ableToCompute = ccnxVPNStats_Display(client->stats);
    if (!ableToCompute) {
        parcDisplayIndented_PrintLine(0, "No packets were received. Check to make sure the client and server are configured correctly and that the forwarder is running.\n");
    }else {
        storeThroughput(client->stats,client->payloadSize);
    }
}

static void
_ccnx_RunKerberizedClient(CCNxConsumer *client)
{
    switch (client->mode) {
        case CCNxConsumerMode_All:
            _ccnx_RunVPN(client, mediumNumberOfVPNs, 0);
            _ccnx_DisplayStatistics(client);

            ccnxVPNStats_Release(&client->stats);
            client->stats = ccnxVPNStats_Create();

            _ccnx_RunVPN(client, smallNumberOfVPNs, ccnx_DefaultReceiveTimeoutInUs);
            _ccnx_DisplayStatistics(client);
            break;
        case CCNxConsumerMode_Flood:
            _ccnx_RunVPN(client, client->count, 0);
            _ccnx_DisplayStatistics(client);
            break;
        case CCNxConsumerMode_VPNPong:
            //TODO: check this
            _ccnx_RunVPN(client, client->count, client->intervalInMs);
            _ccnx_DisplayStatistics(client);
            break;
        case CCNxConsumerMode_TGTReq:
            //TODO: check this
            _ccnx_RunVPN(client, client->count, client->intervalInMs);
            _ccnx_DisplayStatistics(client);
            break;


        case CCNxConsumerMode_None:
        default:
            fprintf(stderr, "Error, unknown mode");
            break;
    }
}

int
main(int argc, char *argv[argc])
{
	printf("KBR-CCN: Initializing Consumer...\n");

	parcSecurity_Init();

    CCNxConsumer *client = ccnx_Create();

    printf("KBR-CCN: Preparing to Run Consumer...\n");

    bool runKRB = _ccnx_KRB_ParseCommandline(client, argc, argv);
    if (runKRB) {
        _ccnx_RunKerberizedClient(client);
    }

    ccnxVPN_Release(&client);

    parcSecurity_Fini();

    return EXIT_SUCCESS;
}
