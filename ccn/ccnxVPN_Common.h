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
 * @author Christopher A. Wood, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2016, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */

#ifndef ccnxVPNCommon_h
#define ccnxVPNCommon_h

#include <stdint.h>

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>



/**
 * The `CCNxName` default prefixes for the servers.
 */
#define ccnx_DefaultPrefix "ccnx:/localhost"
#define ccnx_TGT_DefaultPrefix "ccnx:/localhost/TGT"
#define ccnx_TGS_DefaultPrefix "ccnx:/localhost/TGS"
#define ccnx_KRB_Serv_DefaultPrefix "ccnx:/localhost/kbr_serv"







////////////////KRB-CCN default directories//////////////////////
/**
 * The default user local database directories.
 * Must be in the client host
 */
#define userPrvDir "/tmp/krbccn-user/prv"	//Stores users secret keys locally
#define userTGTDir "/tmp/krbccn-user/tgt"	//Stores user tgts locally
#define userTGSDir "/tmp/krbccn-user/tgs"	//Stores user tgss locally
/**
 * The default KDC database directories.
 * Must be in the KDC host
 */
#define userKDCDir 		"/tmp/krbccn-kdc/users"			//Stores users public key (or hashed passwd) on KDC
#define controlKDCDir 	"/tmp/krbccn-kdc/authorization"	//Stores users authorized namespaces
#define serverKDCDir 	"/tmp/krbccn-kdc/servers"		//Stores shared keys with servers
/**
 * The default Server database directories.
 * Must be in the server host
 */
#define serverPrvDir "/tmp/krbccn-server/prv"			//Stores Service symm key that are shared with KDC








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
