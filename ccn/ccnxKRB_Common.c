
#include <stdio.h>

#include "ccnxKRB_Common.h"

#include <LongBow/runtime.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_Pkcs12KeyStore.h>
#include <parc/security/parc_IdentityFile.h>

const size_t ccnx_DefaultReceiveTimeoutInUs = 1000000; // 1 second
const size_t ccnx_DefaultPayloadSize = 10240;
const size_t mediumNumberOfVPNs = 100;
const size_t smallNumberOfVPNs = 10;


uint64_t
current_time()
{
    struct timeval currentTimeVal;
    gettimeofday(&currentTimeVal, NULL);
    uint64_t microseconds = currentTimeVal.tv_sec * 1000000 + currentTimeVal.tv_usec;
    return microseconds;
}

static PARCIdentity *
_ccnxVPNCommon_CreateIdentityFromFile(const char *keystoreName,
                                      const char *keystorePassword)
{
    parcSecurity_Init();

    unsigned int keyLength = 1024;
    unsigned int validityDays = 30;
    char *subjectName = "anonymous";

    bool success = parcPkcs12KeyStore_CreateFile(keystoreName, keystorePassword, subjectName, keyLength, validityDays);
    assertTrue(success,
               "parcPkcs12KeyStore_CreateFile('%s', '%s', '%s', %d, %d) failed.",
               keystoreName, keystorePassword, subjectName, keyLength, validityDays);

    PARCIdentityFile *identityFile = parcIdentityFile_Create(keystoreName, keystorePassword);
    PARCIdentity *result = parcIdentity_Create(identityFile, PARCIdentityFileAsPARCIdentity);
    parcIdentityFile_Release(&identityFile);

    parcSecurity_Fini();

    return result;
}

CCNxPortalFactory *
ccnxVPNCommon_SetupPortalFactory(const char *keystoreName, const char *keystorePassword)
{
    PARCIdentity *identity = _ccnxVPNCommon_CreateIdentityFromFile(keystoreName, keystorePassword);
    CCNxPortalFactory *result = ccnxPortalFactory_Create(identity);
    parcIdentity_Release(&identity);

    return result;
}
