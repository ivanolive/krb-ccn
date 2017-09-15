

#ifndef ccnxKRBCommon_h
#define ccnxKRBCommon_h

#include <stdint.h>

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>

#include "sodium.h"

/**
 * The `CCNxName` default prefixes for the servers.
 */
#define ccnx_DefaultPrefix "ccnx:/localhost"
#define ccnx_TGT_DefaultPrefix "ccnx:/localhost/TGT"
#define ccnx_TGS_DefaultPrefix "ccnx:/localhost/TGS"
#define ccnx_KRB_Serv_DefaultPrefix "ccnx:/localhost/kbr_serv"

typedef enum {
	TGT_AUTH_FAIL = 0,
    TGT_SUCCESS
} KDCCodes;

////////////////KRB-CCN default directories//////////////////////
/**
 * The default user local database directories.
 * Must be in the client host
 */
#define userPrvDir "/tmp/krbccn-user/prv/"	//Stores users secret keys locally
#define userTGTDir "/tmp/krbccn-user/tgt/"	//Stores user tgts locally
#define userTGSDir "/tmp/krbccn-user/tgs/"	//Stores user tgss locally
/**
 * The default KDC database directories.
 * Must be in the KDC host
 */
#define userKDCDir 		"/tmp/krbccn-kdc/users/"			//Stores users public key (or hashed passwd) on KDC
#define controlKDCDir 	"/tmp/krbccn-kdc/authorization/"	//Stores users authorized namespaces
#define serverKDCDir 	"/tmp/krbccn-kdc/servers/"		//Stores shared keys with servers
#define keyFileKDC 	"/tmp/krbccn-kdc/keyA"		//Stores shared keys with servers
/**
 * The default Server database directories.
 * Must be in the server host
 */
#define serverPrvDir "/tmp/krbccn-server/prv/"			//Stores Service symm key that are shared with KDC

#define MAX_USERNAME_LEN 16 //max username lenght in bytes

#define NONCE_LEN 16 // random nonce size in bytes

#define TGT_EXPIRATION 60*60*1000*1000 // TGT expiration time in usec (default 1 hour)

#define RECEIVE_TGT_SIZE	MAX_USERNAME_LEN + 2 * (crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES) + sizeof (uint64_t) + crypto_aead_aes256gcm_ABYTES
#define TGT_token_size		crypto_box_SEALBYTES + (crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_NPUBBYTES) + sizeof (uint64_t)

//////////////NETWORKING CONSTANTS////////////////////////////
/**
 * The default client receive timeout (in microseconds).
 */
extern const size_t ccnx_DefaultReceiveTimeoutInUs;

/**
 * The default size of a content object payload.
 */
extern const size_t ccnx_DefaultPayloadSize;

/**
 * The maximum size of a content object payload.
 * 64KB is the limit imposed by the packet structure
 */
#define ccnx_MaxPayloadSize 64000

/**
 * A default "medium" number of messages to send.
 */
extern const size_t mediumNumberOfVPNs;

/**
 * A default "small" number of messages to send.
 */
extern const size_t smallNumberOfVPNs;

/**
 * Initialize and return a new instance of CCNxPortalFactory. A randomly generated identity is
 * used to initialize the factory. The returned instance must eventually be released by calling
 * ccnxPortalFactory_Release().
 *
 * @param [in] keystoreName The name of the file to save the new identity.
 * @param [in] keystorePassword The password of the file holding the identity.
 *
 * @return A new instance of a CCNxPortalFactory initialized with a randomly created identity.
 */
CCNxPortalFactory *ccnxVPNCommon_SetupPortalFactory(const char *keystoreName,
                                                    const char *keystorePassword);
#endif // ccnxVPNCommon_h.h
