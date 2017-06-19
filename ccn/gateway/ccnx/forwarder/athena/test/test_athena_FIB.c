/*
 * Copyright (c) 2013-2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC)
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
 * @author Alan Walendowski, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2013-2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */

// Include the file(s) containing the functions to be tested.
// This permits internal static functions to be visible to this Test Framework.
#include "../athena_FIB.c"

#include <parc/algol/parc_SafeMemory.h>
#include <LongBow/unit-test.h>

#include <stdio.h>

#include <sodium.h>

typedef struct test_data {
    AthenaFIB *testFIB;
    CCNxName *testName1;
    CCNxName *testName2;
    CCNxName *testName3;
    CCNxName *testName4;
    PARCBitVector *testVector1;
    PARCBitVector *testVector2;
    PARCBitVector *testVector12;
    PARCBitVector *testVector3;
    PARCBitVector *testVectorTooBig;
} TestData;


LONGBOW_TEST_RUNNER(athena_FIB)
{
    // The following Test Fixtures will run their corresponding Test Cases.
    // Test Fixtures are run in the order specified, but all tests should be idempotent.
    // Never rely on the execution order of tests or share state between them.
    LONGBOW_RUN_TEST_FIXTURE(Global);
}

// The Test Runner calls this function once before any Test Fixtures are run.
LONGBOW_TEST_RUNNER_SETUP(athena_FIB)
{
    parcMemory_SetInterface(&PARCSafeMemoryAsPARCMemory);
    return LONGBOW_STATUS_SUCCEEDED;
}

// The Test Runner calls this function once after all the Test Fixtures are run.
LONGBOW_TEST_RUNNER_TEARDOWN(athena_FIB)
{
    return LONGBOW_STATUS_SUCCEEDED;
}

// ========================================================================================

LONGBOW_TEST_FIXTURE(Global)
{

    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_Create);
    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_AcquireRelease);
    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_AddRoute);
    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_Lookup);
    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_Lookup_EmptyPath);
    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_DeleteRoute);
    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_RemoveLink);
    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_CreateEntryList);
    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_ProcessMessage);

    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_AddTranslationRoute);

//    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_Equals);
//    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_NotEquals);
//    LONGBOW_RUN_TEST_CASE(Global, athenaFIB_ToString);
}

LONGBOW_TEST_FIXTURE_SETUP(Global)
{
    TestData *data = parcMemory_AllocateAndClear(sizeof(TestData));
    assertNotNull(data, "parcMemory_AllocateAndClear(%lu) returned NULL", sizeof(TestData));

    data->testFIB = athenaFIB_Create();
    data->testName1 = ccnxName_CreateFromCString("lci:/a/b/c");
    data->testName2 = ccnxName_CreateFromCString("lci:/a/b/a");
    data->testName3 = ccnxName_CreateFromCString("lci:/");
    data->testName4 = ccnxName_CreateFromCString("lci:/a/b/c/d");
    data->testVector1 = parcBitVector_Create();
    parcBitVector_Set(data->testVector1, 0);
    data->testVector2 = parcBitVector_Create();
    parcBitVector_Set(data->testVector2, 42);
    data->testVector12 = parcBitVector_Create();
    parcBitVector_Set(data->testVector12, 0);
    parcBitVector_Set(data->testVector12, 42);
    data->testVector3 = parcBitVector_Create();
    parcBitVector_Set(data->testVector3, 23);
    data->testVectorTooBig = parcBitVector_Create();
    parcBitVector_Set(data->testVectorTooBig, 999);

    longBowTestCase_SetClipBoardData(testCase, data);

    return LONGBOW_STATUS_SUCCEEDED;
}

LONGBOW_TEST_FIXTURE_TEARDOWN(Global)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);
    athenaFIB_Release(&data->testFIB);
    ccnxName_Release(&data->testName1);
    ccnxName_Release(&data->testName2);
    ccnxName_Release(&data->testName3);
    ccnxName_Release(&data->testName4);
    parcBitVector_Release(&data->testVector1);
    parcBitVector_Release(&data->testVector2);
    parcBitVector_Release(&data->testVector12);
    parcBitVector_Release(&data->testVector3);
    parcBitVector_Release(&data->testVectorTooBig);

    parcMemory_Deallocate((void **) &data);

    if (parcSafeMemory_ReportAllocation(STDOUT_FILENO) != 0) {
        printf("('%s' leaks memory by %d (allocs - frees)) ", longBowTestCase_GetName(testCase), parcMemory_Outstanding());
        return LONGBOW_STATUS_TEARDOWN_FAILED;
    }
    return LONGBOW_STATUS_SUCCEEDED;
}

LONGBOW_TEST_CASE(Global, athenaFIB_Create)
{
    AthenaFIB *fib = athenaFIB_Create();
    assertNotNull(fib, "Expected athenaFIB_Create to return a non-NULL value");

    athenaFIB_Release(&fib);
    assertNull(fib, "Expected athenaFIB_Release to NULL the pointer");
}


LONGBOW_TEST_CASE(Global, athenaFIB_AcquireRelease)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    AthenaFIB *acquiredFib = athenaFIB_Acquire(data->testFIB);
    assertNotNull(acquiredFib, "Expected athenaFIB_Acquire to return a non-NULL value");

    athenaFIB_Release(&acquiredFib);
    assertNull(acquiredFib, "Expected athenaFIB_Release to NULL the pointer");
}

LONGBOW_TEST_CASE(Global, athenaFIB_AddRoute)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    assertTrue(athenaFIB_AddRoute(data->testFIB, data->testName1, data->testVector1), "Failed to add a route");
    assertTrue(athenaFIB_AddRoute(data->testFIB, data->testName1, data->testVector1), "Failed to add a route");
}

LONGBOW_TEST_CASE(Global, athenaFIB_AddTranslationRoute)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    assertTrue(sodium_init()!=-1,"Crypto lib sodium not available");

    unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(recipient_pk, recipient_sk);
    PARCBuffer *publicKey = parcBuffer_CreateFromArray(recipient_pk, crypto_box_PUBLICKEYBYTES);

    assertTrue(athenaFIB_AddTranslationRoute(data->testFIB, data->testName1, data->testName2, publicKey, data->testVector1), "Failed to add a route");

    parcBuffer_Release(&publicKey);
}


LONGBOW_TEST_CASE(Global, athenaFIB_Lookup)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    athenaFIB_AddRoute(data->testFIB, data->testName1, data->testVector1);
    AthenaFIBValue *vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    PARCBitVector *result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector1), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    //
    // Name3 (the default route) contains both vector1 and vector2.
    // Name1 (a/b/c) contains only vector 1.
    // Name4 (a/b/c/d) is what we're looking for.
    // Although Name1 is a match for Name4, it only contains the ingress vector1.
    // We must the search until we match the default route. Ingress vector1
    // must be removed from the returned vector list from the default route.
    //
    // Make sure we see only vector2 in the result.
    //
    athenaFIB_AddRoute(data->testFIB, data->testName3, data->testVector12);
    vector = athenaFIB_Lookup(data->testFIB, data->testName4, data->testVector1);
    result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector2), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);
}

LONGBOW_TEST_CASE(Global, athenaFIB_Lookup_EmptyPath)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    athenaFIB_AddRoute(data->testFIB, data->testName3, data->testVector1);
    AthenaFIBValue *vector = athenaFIB_Lookup(data->testFIB, data->testName3, NULL);
    PARCBitVector *result = athenaFIBValue_GetVector(vector);
    assertNotNull(result, "Expect non-null match to global path (\"/\")");
    assertTrue(parcBitVector_Equals(result, data->testVector1), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertNotNull(result, "Expect non-null match to global path (\"/\")");
    assertTrue(parcBitVector_Equals(result, data->testVector1), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    vector = athenaFIB_Lookup(data->testFIB, data->testName2, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertNotNull(result, "Expect non-null match to global path (\"/\")");
    assertTrue(parcBitVector_Equals(result, data->testVector1), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    athenaFIB_AddRoute(data->testFIB, data->testName3, data->testVector2);
    vector = athenaFIB_Lookup(data->testFIB, data->testName3, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertNotNull(result, "Expect non-null match to global path (\"/\")");
    assertTrue(parcBitVector_Equals(result, data->testVector12), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertNotNull(result, "Expect non-null match to global path (\"/\")");
    assertTrue(parcBitVector_Equals(result, data->testVector12), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    vector = athenaFIB_Lookup(data->testFIB, data->testName2, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertNotNull(result, "Expect non-null match to global path (\"/\")");
    assertTrue(parcBitVector_Equals(result, data->testVector12), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);
}

LONGBOW_TEST_CASE(Global, athenaFIB_DeleteRoute)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    // Add/Remove default routes
    bool res = athenaFIB_AddRoute(data->testFIB, data->testName3, data->testVector3);
    assertTrue(res, "Expected add of route to succeed (res=%d)", res);
    res = athenaFIB_AddRoute(data->testFIB, data->testName3, data->testVector1);
    assertTrue(res, "Expected add of route to succeed (res=%d)", res);
    res = athenaFIB_DeleteRoute(data->testFIB, data->testName3, data->testVector1);
    assertTrue(res, "Expected delete of route to succeed (res=%d)", res);
    res = athenaFIB_DeleteRoute(data->testFIB, data->testName3, data->testVector3);
    assertTrue(res, "Expected delete of route to succeed (res=%d)", res);

    athenaFIB_AddRoute(data->testFIB, data->testName1, data->testVector12);

    AthenaFIBValue *vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    assertNotNull(vector, "Lookup result NULL");
    PARCBitVector *result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector12), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    res = athenaFIB_DeleteRoute(data->testFIB, data->testName1, data->testVector1);
    assertTrue(res, "Expected delete of route to succeed (res=%d)", res);
    vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    assertNotNull(vector, "2nd Lookup result NULL");
    result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector2), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    res = athenaFIB_DeleteRoute(data->testFIB, data->testName1, data->testVector1);
    assertFalse(res, "Expected delete of same route to fail");
    vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    assertNotNull(vector, "3rd Lookup result NULL");
    result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector2), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    res = athenaFIB_DeleteRoute(data->testFIB, data->testName1, data->testVector12);
    assertTrue(res, "Expected delete of route to succeed");
    vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    assertNull(vector, "Expecting a NULL result from Lookup after Delete Route");
}

LONGBOW_TEST_CASE(Global, athenaFIB_RemoveLink)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    athenaFIB_RemoveLink(data->testFIB, data->testVectorTooBig);

    // Add a default route
    athenaFIB_AddRoute(data->testFIB, data->testName3, data->testVector3);

    athenaFIB_AddRoute(data->testFIB, data->testName1, data->testVector1);
    athenaFIB_AddRoute(data->testFIB, data->testName2, data->testVector2);

    AthenaFIBValue *vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    PARCBitVector *result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector1), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);
    vector = athenaFIB_Lookup(data->testFIB, data->testName2, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector2), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    athenaFIB_RemoveLink(data->testFIB, data->testVector1);
    vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector3), "Expecting lookup to equal default vector");
    athenaFIBValue_Release(&vector);

    vector = athenaFIB_Lookup(data->testFIB, data->testName2, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector2), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    athenaFIB_AddRoute(data->testFIB, data->testName1, data->testVector12);
    athenaFIB_RemoveLink(data->testFIB, data->testVector3);

    athenaFIB_RemoveLink(data->testFIB, data->testVector2);
    vector = athenaFIB_Lookup(data->testFIB, data->testName2, NULL);
    assertNull(vector, "Expecting a NULL result from Lookup after Delete Route");
    vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector1), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);
}

LONGBOW_TEST_CASE(Global, athenaFIB_CreateEntryList)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    // Add a default route
    athenaFIB_AddRoute(data->testFIB, data->testName3, data->testVector1);

    athenaFIB_AddRoute(data->testFIB, data->testName1, data->testVector12);

    AthenaFIBValue *vector = athenaFIB_Lookup(data->testFIB, data->testName1, NULL);
    PARCBitVector *result = athenaFIBValue_GetVector(vector);
    assertTrue(parcBitVector_Equals(result, data->testVector12), "Expected lookup to equal test vector");
    athenaFIBValue_Release(&vector);

    PARCList *entryList = athenaFIB_CreateEntryList(data->testFIB);
    assertTrue(parcList_Size(entryList) == 3, "Expected the EntryList to have 3 elements");

    AthenaFIBListEntry *entry = parcList_GetAtIndex(entryList, 0);
    assertNotNull(entry, "Expect entry at 0 to be non-NULL");
    assertTrue(ccnxName_Equals(data->testName3, athenaFIBListEntry_GetName(entry)), "Expect the name at 0 to be testName3");
    assertTrue(athenaFIBListEntry_GetLinkId(entry) == 0, "Expect the routeId at 0 to be 0");

    entry = parcList_GetAtIndex(entryList, 1);
    assertNotNull(entry, "Expect entry at 1 to be non-NULL");
    assertTrue(ccnxName_Equals(data->testName1, athenaFIBListEntry_GetName(entry)), "Expect the name at 1 to be testName1");
    assertTrue(athenaFIBListEntry_GetLinkId(entry) == 0, "Expect the routeId at 1 to be 0");

    entry = parcList_GetAtIndex(entryList, 2);
    assertNotNull(entry, "Expect entry at 2 to be non-NULL");
    assertTrue(ccnxName_Equals(data->testName1, athenaFIBListEntry_GetName(entry)), "Expect the name at 2 to be testName1");
    assertTrue(athenaFIBListEntry_GetLinkId(entry) == 42, "Expect the routeId at 2 to be 42");

    parcList_Release(&entryList);
}

LONGBOW_TEST_CASE(Global, athenaFIB_ProcessMessage)
{
    TestData *data = longBowTestCase_GetClipBoardData(testCase);

    CCNxMetaMessage *ccnxMetaMessage = athenaFIB_ProcessMessage(data->testFIB, NULL);
    assertNull(ccnxMetaMessage, "Expected NULL control message response");
}

//LONGBOW_TEST_CASE(Global, athenaFIB_Equals)
//{
//    TestData *data = longBowTestCase_GetClipBoardData(testCase);
//}

//LONGBOW_TEST_CASE(Global, athenaFIB_NotEquals)
//{
//}

//LONGBOW_TEST_CASE(Global, athenaFIB_ToString)
//{
//    TestData *data = longBowTestCase_GetClipBoardData(testCase);
//}



int
main(int argc, char *argv[])
{
    LongBowRunner *testRunner = LONGBOW_TEST_RUNNER_CREATE(athena_FIB);
    int exitStatus = longBowMain(argc, argv, testRunner, NULL);
    longBowTestRunner_Destroy(&testRunner);
    exit(exitStatus);
}
