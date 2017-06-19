/*
 * Copyright (c) 2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC)
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
 * @author Michael Slominski, Kevin Fox, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */

#include <config.h>

#include <stdio.h>

#include "athena.h"
#include "athena_PIT.h"

#include <ccnx/common/ccnx_NameSegmentNumber.h>
#include <ccnx/common/ccnx_WireFormatMessage.h>
#include <ccnx/common/ccnx_ContentObject.h>

#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_JSON.h>
#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_LinkedList.h>
#include <parc/algol/parc_TreeMap.h>
#include <parc/algol/parc_Time.h>
#include <parc/algol/parc_Clock.h>
#include <parc/security/parc_CryptoHash.h>

#define DEFAULT_CAPACITY 100000

static const char *_athenaPIT_Name = "AthenaPIT 20150913";

typedef struct _time {
    uint64_t value;
} _Time;

static bool
_time_Equals(const _Time *a, const _Time *b)
{
    return a->value == b->value;
}

static int
_time_Compare(const _Time *a, const _Time *b)
{
    int result = 0;

    if (a->value > b->value) {
        result = 1;
    } else if (a->value < b->value) {
        result = -1;
    }

    return result;
}

static PARCHashCode
_time_HashCode(const _Time *time)
{
    return parcHashCode_Hash((uint8_t *) &time->value, sizeof(time->value));
}

parcObject_ExtendPARCObject(_Time, NULL, NULL, NULL, _time_Equals, _time_Compare, _time_HashCode, NULL);

static
parcObject_ImplementRelease(_time, _Time);

static
parcObject_ImplementAcquire(_time, _Time);

static _Time *
_time_Create(uint64_t time)
{
    _Time *timeObject = parcObject_CreateInstance(_Time);
    timeObject->value = time;

    return timeObject;
}

static void
_time_Set(_Time *time, uint64_t timeValue)
{
    time->value = timeValue;
}

static uint64_t
_time_Get(_Time *time)
{
    return time->value;
}

/**
 * @typedef AthenaPITEntry
 * @brief PIT table entry, vector of links to forward to and expiration
 */
typedef struct athena_pitEntry {
    PARCBuffer *key;
    CCNxInterest *ccnxMessage;
    PARCBitVector *ingress;
    PARCBitVector *egress; // FIB egress at entry, used to validate return of content on expected link
    CCNxName *originalName; // The original name that was used to route the packet to this node (the encapsulation name)
    PARCBuffer *encapKey; // one-time encryption key used to decapsulate the response
    _Time *expiration; // not predecessor lifetime, but longest for all
    _Time *creationTime; // not predecessor lifetime, but longest for all
    bool isEncap;
} _AthenaPITEntry;

static void
_athenaPITEntry_Destroy(_AthenaPITEntry**entryHandle)
{
    _AthenaPITEntry *entry = *entryHandle;
    if (entry != NULL) {
        parcBuffer_Release(&entry->key);
        ccnxMetaMessage_Release(&entry->ccnxMessage);
        parcBitVector_Release(&entry->ingress);
        parcBitVector_Release(&entry->egress);
        if (entry->encapKey != NULL) {
            parcBuffer_Release(&entry->encapKey);
        }
        if (entry->originalName != NULL) {
            ccnxName_Release(&entry->originalName);
        }
        _time_Release(&entry->expiration);
        _time_Release(&entry->creationTime);
    }
}

static bool
_athenaPITEntry_Equals(const _AthenaPITEntry *a, const _AthenaPITEntry *b)
{
    return parcBuffer_Equals(a->key, b->key);
}

static bool
_athenaPITEntry_Compare(const _AthenaPITEntry *a, const _AthenaPITEntry *b)
{
    return parcBuffer_Compare(a->key, b->key);
}

static PARCHashCode
_athenaPITEntry_HashCode(const _AthenaPITEntry *a)
{
    return parcBuffer_HashCode(a->key);
}

parcObject_ExtendPARCObject(_AthenaPITEntry,
                            _athenaPITEntry_Destroy,
                            NULL, NULL,
                            _athenaPITEntry_Equals,
                            _athenaPITEntry_Compare,
                            _athenaPITEntry_HashCode,
                            NULL);

static
parcObject_ImplementRelease(_athenaPITEntry, _AthenaPITEntry);

static
parcObject_ImplementAcquire(_athenaPITEntry, _AthenaPITEntry);

static _AthenaPITEntry *
_athenaPITEntry_Create(const PARCBuffer *key,
                       const CCNxInterest *message,
                       const PARCBitVector *ingress,
                       const PARCBitVector *egress,
                       CCNxName *originalName,
                       PARCBuffer *encapKey,
                       bool isEncap,
                       time_t expiration,
                       time_t creationTime)
{
    _AthenaPITEntry *entry = parcObject_CreateInstance(_AthenaPITEntry);
    if (entry != NULL) {
        entry->key = parcBuffer_Acquire(key);
        entry->ccnxMessage = ccnxMetaMessage_Acquire(message);
        entry->ingress = parcBitVector_Copy(ingress);
        entry->egress = parcBitVector_Acquire(egress);
        entry->originalName = originalName == NULL ? NULL : ccnxName_Acquire(originalName);
        entry->encapKey = encapKey == NULL ? NULL : parcBuffer_Acquire(encapKey);
        entry->isEncap = isEncap;
        entry->expiration = _time_Create(expiration);
        entry->creationTime = _time_Create(creationTime);
    }

    return entry;
}

static uint64_t
_athenaPITEntry_Age(_AthenaPITEntry *entry, uint64_t now)
{
    return now - _time_Get(entry->creationTime);
}

#define LATENCY_ARRAY_SIZE 100

struct athena_pit {
    size_t capacity;

    PARCHashMap *entryTable;

    PARCList *linkCleanupList;

    PARCTreeMap *timeoutTable;

    PARCClock *clock;

    // Stats
    size_t interestCount;
    time_t latencySum;
    time_t latencyArray[LATENCY_ARRAY_SIZE];
    size_t latencyArrayIndex;
    size_t latencyArrayCount;
};

static void
_athenaPIT_Destroy(AthenaPIT **pitHandle)
{
    AthenaPIT *pit = *pitHandle;
    if (pit != NULL) {
        parcHashMap_Release(&pit->entryTable);
        parcTreeMap_Release(&pit->timeoutTable);
        parcList_Release(&pit->linkCleanupList);
        parcClock_Release(&pit->clock);
    }
}

parcObject_ExtendPARCObject(AthenaPIT, _athenaPIT_Destroy, NULL, NULL, NULL, NULL, NULL, NULL);

parcObject_ImplementAcquire(athenaPIT, AthenaPIT);
parcObject_ImplementRelease(athenaPIT, AthenaPIT);


struct athena_pit_value {
    PARCBitVector *vector;
    PARCBuffer *key;
    CCNxName *name;
    bool isEncap;
};

static void
_athenaPITValue_Destroy(AthenaPITValue **valueHandle)
{
    AthenaPITValue *value = *valueHandle;
    if (value != NULL) {
        if (value->vector != NULL) {
            parcBitVector_Release(&value->vector);
        }
        if (value->key != NULL) {
            parcBuffer_Release(&value->key);
        }
        if (value->name != NULL) {
            ccnxName_Release(&value->name);
        }
    }
}


parcObject_ExtendPARCObject(AthenaPITValue, _athenaPITValue_Destroy, NULL, NULL, NULL, NULL, NULL, NULL);

parcObject_ImplementAcquire(athenaPITValue, AthenaPITValue);
parcObject_ImplementRelease(athenaPITValue, AthenaPITValue);

AthenaPITValue *
athenaPITValue_Create(void)
{
    AthenaPITValue *value = parcObject_CreateInstance(AthenaPITValue);
    if (value != NULL) {
        value->vector = parcBitVector_Create();
        value->key = NULL;
        value->name = NULL;
        value->isEncap = false;
    }
    return value;
}

PARCBuffer *
athenaPITValue_GetKey(AthenaPITValue *value)
{
    return value->key;
}

PARCBitVector *
athenaPITValue_GetVector(AthenaPITValue *value)
{
    return value->vector;
}

CCNxName *
athenaPITValue_GetName(AthenaPITValue *value)
{
    return value->name;
}

AthenaPIT *
athenaPIT_CreateCapacity(size_t capacity)
{
    AthenaPIT *pit = parcObject_CreateInstance(AthenaPIT);
    if (pit != NULL) {
        pit->entryTable = parcHashMap_Create();
        pit->timeoutTable = parcTreeMap_Create();
        pit->linkCleanupList = parcList(parcArrayList_Create((void (*)(void**))parcTreeMap_Release), PARCArrayListAsPARCList);
        pit->clock = parcClock_Monotonic();
        pit->capacity = capacity;

        pit->interestCount = 0;
        pit->latencyArrayIndex = 0;
        pit->latencyArrayCount = 0;
        pit->latencySum = 0;
        for (size_t i = 0; i < LATENCY_ARRAY_SIZE; ++i) {
            pit->latencyArray[i] = 0;
        }
    }

    return pit;
}

AthenaPIT *
athenaPIT_Create()
{
    return athenaPIT_CreateCapacity(DEFAULT_CAPACITY);
}

// Returns a buffer that is a concatination of a CCNxName and optional contentId/keyId components
static PARCBuffer *
_athenaPIT_createCompoundKey(const CCNxName *name, const PARCBuffer *contentId, const PARCBuffer *keyId)
{
    PARCBufferComposer *composer = parcBufferComposer_Create();

    if (name != NULL) {
        composer = ccnxName_BuildString(name, composer);
    }

    if (contentId != NULL) {
        parcBufferComposer_PutBuffer(composer, contentId);
    }

    if (keyId != NULL) {
        parcBufferComposer_PutBuffer(composer, keyId);
    }

    // We add a unique byte to the end of the KeyId so it doesn't collide with
    // potentially identical ContentId entries.
    if ((keyId != NULL) && (contentId == NULL)) {
        parcBufferComposer_PutString(composer, "K");
    }

    PARCBuffer *key = parcBufferComposer_ProduceBuffer(composer);

    parcBufferComposer_Release(&composer);
    return key;
}

// Returns the most restrictive key for the interest depending on KeyId
// Restriction and Content Hash Restriction
static PARCBuffer *
_athenaPIT_acquireInterestKey(const CCNxInterest *interest)
{
    PARCBuffer *result = NULL;
    CCNxName *name = ccnxInterest_GetName(interest);
    PARCBuffer *hash = ccnxInterest_GetContentObjectHashRestriction(interest);
    PARCBuffer *keyId = ccnxInterest_GetKeyIdRestriction(interest);

    result = _athenaPIT_createCompoundKey(name, hash, keyId);

    return result;
}

static void
_athenaPIT_addInterestToTimeoutTable(AthenaPIT *athenaPIT, time_t expiration, const _AthenaPITEntry *entry)
{
    _Time *timeKey = _time_Create(expiration);
    PARCLinkedList *list = (PARCLinkedList *) parcTreeMap_Get(athenaPIT->timeoutTable, timeKey);
    if (list == NULL) {
        PARCLinkedList *newList = parcLinkedList_Create();
        parcTreeMap_Put(athenaPIT->timeoutTable, timeKey, newList);
        list = newList;
        parcLinkedList_Release(&newList);
    }
    parcLinkedList_Append(list, (PARCObject *) entry);
    _time_Release(&timeKey);
}

static bool
_athenaPIT_removeInterestFromTimeoutTable(AthenaPIT *athenaPIT, const _AthenaPITEntry *entry)
{
    bool result = false;

    _Time *timeKey = _time_Acquire(entry->expiration);
    PARCLinkedList *list = (PARCLinkedList *) parcTreeMap_Get(athenaPIT->timeoutTable, timeKey);
    if (list != NULL) {
        PARCIterator *it = parcLinkedList_CreateIterator(list);
        while (parcIterator_HasNext(it)) {
            _AthenaPITEntry *testEntry = (_AthenaPITEntry *) parcIterator_Next(it);
            if (_athenaPITEntry_Equals(entry, testEntry)) {
                parcIterator_Remove(it);
                result = true;
                break;
            }
        }
        parcIterator_Release(&it);
        if (parcLinkedList_IsEmpty(list)) {
            parcTreeMap_RemoveAndRelease(athenaPIT->timeoutTable, timeKey);
        }
    }
    _time_Release(&timeKey);

    return result;
}

static void
_athenaPIT_addInterestToLinkCleanupList(AthenaPIT *athenaPIT, const PARCBitVector *links, const _AthenaPITEntry *entry)
{
    // for each bit in the link vector, add an entry for the interest in the list of links for future
    // cleanup
    for (int i = 0, bit = 0; i < parcBitVector_NumberOfBitsSet(links); ++i, ++bit) {
        bit = parcBitVector_NextBitSet(links, bit);

        if (bit >= parcList_Size(athenaPIT->linkCleanupList)) {
            //Expand the list if needed
            for (size_t j = parcList_Size(athenaPIT->linkCleanupList); j <= bit; ++j) {
                parcList_Add(athenaPIT->linkCleanupList, NULL);
            }
        }

        // Use the ingress link bit as an index into the ingressLinks array
        PARCTreeMap *entryMap =
            (PARCTreeMap *) parcList_GetAtIndex((PARCList *) athenaPIT->linkCleanupList, bit);
        if (entryMap == NULL) {
            // No map to store interests yet for this link so we'll need to add one
            entryMap = parcTreeMap_Create();
            parcList_SetAtIndex(athenaPIT->linkCleanupList, bit, (PARCObject *) entryMap);
        }

        // Store the interest in the link's hash map
        PARCBuffer *keyBuffer = _athenaPIT_acquireInterestKey(entry->ccnxMessage);
        parcTreeMap_Put(entryMap, keyBuffer, entry);

        parcBuffer_Release(&keyBuffer);
    }
}

static void
_athenaPIT_removeInterestFromCleanupList(AthenaPIT *athenaPIT, const PARCBitVector  *links, PARCObject *key)
{
    int numberOfBitsSet = (int) parcList_Size(athenaPIT->linkCleanupList);
    if (links != NULL) {
        numberOfBitsSet = parcBitVector_NumberOfBitsSet(links);
    }

    for (int i = 0, bit = 0; i < numberOfBitsSet; ++i, ++bit) {
        if (links != NULL) {
            bit = parcBitVector_NextBitSet(links, bit);
        }
        if (parcList_Size(athenaPIT->linkCleanupList) > bit) {
            PARCTreeMap *entryMap =
                (PARCTreeMap *) parcList_GetAtIndex(athenaPIT->linkCleanupList, bit);
            if (entryMap != NULL) {
                _AthenaPITEntry *entry = (_AthenaPITEntry *) parcTreeMap_Remove(entryMap, key);
                if (entry != NULL) {
                    parcBitVector_Clear(entry->ingress, bit);
                    _athenaPITEntry_Release(&entry);
                }
            }
        }
    }
}

static bool
_athenaPIT_RemoveInterestFromMap(AthenaPIT *athenaPIT, CCNxInterest *interest, const PARCBitVector *link)
{
    bool result = false;

    PARCBuffer *key = _athenaPIT_acquireInterestKey(interest);

    _AthenaPITEntry *entry = (_AthenaPITEntry *) parcHashMap_Get(athenaPIT->entryTable, key);

    if (entry != NULL) {
        if (link != NULL) {
            parcBitVector_ClearVector(entry->ingress, link);
        } else {
            parcBitVector_Release(&entry->ingress);
            entry->ingress = parcBitVector_Create();
        }

        if (parcBitVector_NumberOfBitsSet(entry->ingress) == 0) {
            result = parcHashMap_Remove(athenaPIT->entryTable, key);
        }
    }

    parcBuffer_Release(&key);

    return result;
}

static void
_athenaPIT_PurgeExpired(AthenaPIT *pit)
{
    _Time *now = _time_Create(parcClock_GetTime(pit->clock));

    PARCList *timeoutList = parcTreeMap_AcquireKeys(pit->timeoutTable);
    for (size_t i = 0; i < parcList_Size(timeoutList); ++i) {
        _Time *timeKey = (_Time *) parcList_GetAtIndex(timeoutList, i);
        if (_time_Compare(now, timeKey) < 0) {
            break;
        }

        PARCLinkedList *entryList = (PARCLinkedList *) parcTreeMap_Remove(pit->timeoutTable, timeKey);
        PARCIterator *it = parcLinkedList_CreateIterator(entryList);
        while (parcIterator_HasNext(it)) {
            _AthenaPITEntry *entry = (_AthenaPITEntry *) parcIterator_Next(it);
            // Necessary because the entry's expiration time may have been increased since being added to the list
            if (_time_Compare(now, entry->expiration) > 0) {
                _athenaPIT_RemoveInterestFromMap(pit, entry->ccnxMessage, entry->ingress);
                PARCBuffer *nameKey = _athenaPIT_acquireInterestKey(entry->ccnxMessage);
                _athenaPIT_removeInterestFromCleanupList(pit, entry->ingress, nameKey);
                parcBuffer_Release(&nameKey);
            }
        }
        parcIterator_Release(&it);
        parcLinkedList_Release(&entryList);
    }

    parcList_Release(&timeoutList);
    _time_Release(&now);
}

static void
_athenaPIT_AddLifetimeStat(AthenaPIT *pit, time_t latencyEntry)
{
    pit->latencySum -= pit->latencyArray[pit->latencyArrayIndex];
    pit->latencyArray[pit->latencyArrayIndex] = latencyEntry;
    pit->latencySum += pit->latencyArray[pit->latencyArrayIndex];
    pit->latencyArrayIndex++;
    pit->latencyArrayIndex %= LATENCY_ARRAY_SIZE;
    if (pit->latencyArrayCount < LATENCY_ARRAY_SIZE) {
        pit->latencyArrayCount++;
    }
}

AthenaPITResolution
athenaPIT_AddInterest(AthenaPIT *athenaPIT,
                      const CCNxInterest *ccnxInterestMessage,
                      const PARCBitVector *ingressVector,
                      CCNxName *originalName,
                      PARCBuffer *encapKey,
                      PARCBitVector **expectedReturnVector)
{
    AthenaPITResolution result = AthenaPITResolution_Error;

    // Get expiration time
    uint64_t expiration = ccnxInterest_GetLifetime(ccnxInterestMessage);
    uint64_t now = parcClock_GetTime(athenaPIT->clock);
    expiration += now;

    // XXX: temp
    bool isEncap = false;

    // Get the most restrictive key
    PARCBuffer *key = _athenaPIT_acquireInterestKey(ccnxInterestMessage);
    _AthenaPITEntry *entry = (_AthenaPITEntry *) parcHashMap_Get(athenaPIT->entryTable, key);

    if (entry == NULL) { // New PIT entry
        // Make sure we don't exceed our desired limit
        if (parcHashMap_Size(athenaPIT->entryTable) >= athenaPIT->capacity) {
            // Try and free up some entries
            _athenaPIT_PurgeExpired(athenaPIT);
        }

        if (parcHashMap_Size(athenaPIT->entryTable) < athenaPIT->capacity) {
            PARCBitVector *newEgressVector = parcBitVector_Create();

            // Add the default entry which contains the Interest name
            _AthenaPITEntry *newEntry =
                _athenaPITEntry_Create(key, ccnxInterestMessage, ingressVector, newEgressVector,
                                       originalName, encapKey, isEncap, expiration, now);

            parcHashMap_Put(athenaPIT->entryTable, key, newEntry);
            ++athenaPIT->interestCount;

            _athenaPIT_addInterestToLinkCleanupList(athenaPIT, ingressVector, newEntry);
            _athenaPIT_addInterestToTimeoutTable(athenaPIT, expiration, newEntry);

            entry = newEntry;

            // Add an entry without a name, but only if a ContentObjectHashRestriction was provided
            const PARCBuffer *contentId = ccnxInterest_GetContentObjectHashRestriction(ccnxInterestMessage);
            if (contentId != NULL) {
                PARCBuffer *namelessKey = _athenaPIT_createCompoundKey(NULL, contentId, NULL);

                _AthenaPITEntry *namelessEntry =
                        _athenaPITEntry_Create(namelessKey, ccnxInterestMessage, ingressVector, newEgressVector,
                                               originalName, encapKey, isEncap, expiration, now);
                parcHashMap_Put(athenaPIT->entryTable, namelessKey, namelessEntry);

                _athenaPIT_addInterestToLinkCleanupList(athenaPIT, ingressVector, namelessEntry);
                _athenaPIT_addInterestToTimeoutTable(athenaPIT, expiration, namelessEntry);

                _athenaPITEntry_Release(&namelessEntry);
                parcBuffer_Release(&namelessKey);
            }

            _athenaPITEntry_Release(&newEntry);
            parcBitVector_Release(&newEgressVector);
            result = AthenaPITResolution_Forward;
        }
    } else if (parcBitVector_Contains(entry->ingress, ingressVector)) {
        // Duplicate Entry
        if (expiration > _time_Get(entry->expiration)) {
            _athenaPIT_removeInterestFromTimeoutTable(athenaPIT, entry);
            _time_Set(entry->expiration, expiration);
            _athenaPIT_addInterestToTimeoutTable(athenaPIT, expiration, entry);
        }
        result = AthenaPITResolution_Forward;
    } else {
        // Aggregated Entry - Just update the ingress vector
        if (expiration > _time_Get(entry->expiration)) {
            _athenaPIT_removeInterestFromTimeoutTable(athenaPIT, entry);
            _time_Set(entry->expiration, expiration);
            _athenaPIT_addInterestToTimeoutTable(athenaPIT, expiration, entry);
        }

        parcBitVector_SetVector(entry->ingress, ingressVector);

        ++athenaPIT->interestCount;
        _athenaPIT_addInterestToLinkCleanupList(athenaPIT, ingressVector, entry);

        result = AthenaPITResolution_Aggregated;
    }

    parcBuffer_Release(&key);

    if (entry != NULL) {
        *expectedReturnVector = entry->egress;
    }

    return result;
}

bool
athenaPIT_RemoveInterest(AthenaPIT *athenaPIT,
                         const CCNxInterest *ccnxInterestMessage,
                         const PARCBitVector *ingressVector)
{
    assertNotNull(ingressVector, "Parameter ingressVector must not be NULL");

    bool result = false;
    PARCBuffer *key = _athenaPIT_acquireInterestKey(ccnxInterestMessage);

    _AthenaPITEntry *entry = (_AthenaPITEntry *) parcHashMap_Get(athenaPIT->entryTable, key);
    if (entry != NULL) {
        entry = _athenaPITEntry_Acquire(entry);

        const PARCBitVector *clearVector = ingressVector;

        size_t nPreEntries = parcBitVector_NumberOfBitsSet(entry->ingress);
        parcBitVector_ClearVector(entry->ingress, clearVector);

        size_t nPostEntries = parcBitVector_NumberOfBitsSet(entry->ingress);
        if (nPostEntries == 0) {
            parcHashMap_Remove(athenaPIT->entryTable, key);
        }

        athenaPIT->interestCount -= (nPreEntries - nPostEntries);
        _athenaPITEntry_Release(&entry);

        _athenaPIT_removeInterestFromCleanupList(athenaPIT, clearVector, key);

        if (nPostEntries < nPreEntries) {
            result = true;
        }
    }

    if (key != NULL) {
        parcBuffer_Release(&key);
    }

    return result;
}

static void
_athenaPIT_LookupKey(AthenaPIT *athenaPIT, PARCBuffer *key, AthenaPITValue *value)
{
    _AthenaPITEntry *entry = (_AthenaPITEntry *) parcHashMap_Get(athenaPIT->entryTable, key);

    // We have an entry, set the match vector and remove
    if (entry != NULL) {
        uint64_t now = parcClock_GetTime(athenaPIT->clock);
        _athenaPIT_AddLifetimeStat(athenaPIT, _athenaPITEntry_Age(entry, now));

        // Set the egress vector
        parcBitVector_SetVector(value->vector, entry->ingress);
        if (entry->encapKey != NULL) {
            if (value->key != NULL) {
                parcBuffer_Release(&value->key);
            }
            value->key = parcBuffer_Acquire(entry->encapKey);
        }
        if (entry->originalName != NULL) {
            if (value->name != NULL) {
                ccnxName_Release(&value->name);
            }
            value->name = ccnxName_Acquire(entry->originalName);
        }

        // Remove Match
        _athenaPIT_removeInterestFromCleanupList(athenaPIT, entry->ingress, key);
        parcHashMap_Remove(athenaPIT->entryTable, key);
        _athenaPIT_removeInterestFromTimeoutTable(athenaPIT, entry);
        athenaPIT->interestCount -= parcBitVector_NumberOfBitsSet(value->vector);
    }
}

AthenaPITValue *
athenaPIT_Match(AthenaPIT *athenaPIT,
                const CCNxName *name,
                const PARCBuffer *keyId,
                const PARCBuffer *contentId,
                const PARCBitVector *ingressVector)
{
    //TODO: Add egress check.

    PARCBuffer *key;
    AthenaPITValue *result = athenaPITValue_Create(); // parcBitVector_Create();

    // Match based on Name & Content Id Restriction & Key Id
    if ((contentId != NULL) && (keyId != NULL)) {
        key = _athenaPIT_createCompoundKey(name, contentId, keyId);
        _athenaPIT_LookupKey(athenaPIT, key, result);
        parcBuffer_Release(&key);
    }

    // Match based on Name & Content Id Restriction
    // M.S. Nominally, the contentId should not be null as any content message received
    // should be hashable. But because locally generated contentObjects are not currently
    // hashable, we need to support this case.
    if (contentId != NULL) {
        key = _athenaPIT_createCompoundKey(name, contentId, NULL);
        _athenaPIT_LookupKey(athenaPIT, key, result);
        parcBuffer_Release(&key);
    }

    // Match based on Name & Key Id
    if (keyId != NULL) {
        key = _athenaPIT_createCompoundKey(name, NULL, keyId);
        _athenaPIT_LookupKey(athenaPIT, key, result);
        parcBuffer_Release(&key);
    }

    // Match based on Name only
    key = _athenaPIT_createCompoundKey(name, NULL, NULL);
    _athenaPIT_LookupKey(athenaPIT, key, result);
    parcBuffer_Release(&key);

    return result;
}

bool
athenaPIT_RemoveLink(AthenaPIT *athenaPIT, const PARCBitVector *ccnxLinkVector)
{
    bool result = true;

    for (int i = 0, bit = 0; i < parcBitVector_NumberOfBitsSet(ccnxLinkVector); ++i, bit++) {
        bit = parcBitVector_NextBitSet(ccnxLinkVector, bit);
        if (parcList_Size(athenaPIT->linkCleanupList) <= bit) {
            break;
        }

        PARCTreeMap *interestMap =
            parcList_GetAtIndex(athenaPIT->linkCleanupList, bit);
        if (interestMap == NULL) {
            continue;
        }

        PARCList*valueList = parcTreeMap_AcquireValues(interestMap);
        for (size_t i = 0; i < parcList_Size(valueList); ++i) {
            _AthenaPITEntry *entry = (_AthenaPITEntry *) parcList_GetAtIndex(valueList, i);
            CCNxInterest *interest = entry->ccnxMessage;
            _athenaPIT_RemoveInterestFromMap(athenaPIT, interest, ccnxLinkVector);
            result = true;
        }
        parcList_Release(&valueList);

        parcList_SetAtIndex(athenaPIT->linkCleanupList, bit, NULL);

        parcTreeMap_Release(&interestMap);
    }

    return result;
}

size_t
athenaPIT_GetNumberOfTableEntries(const AthenaPIT *athenaPIT)
{
    return parcHashMap_Size(athenaPIT->entryTable);
}

size_t
athenaPIT_GetNumberOfPendingInterests(const AthenaPIT *athenaPIT)
{
    return athenaPIT->interestCount;
}

time_t
athenaPIT_GetMeanEntryLifetime(const AthenaPIT *athenaPIT)
{
    time_t result = athenaPIT->latencySum;
    if (athenaPIT->latencyArrayCount > 0) {
        result /= athenaPIT->latencyArrayCount;
    }

    return result;
}

static void
_getChunkNumberFromName(const CCNxName *name, uint64_t *chunkNum, bool *hasChunkNum)
{
    // XXX: This could be a utility in CCNxName.

    size_t numSegments = ccnxName_GetSegmentCount(name);
    CCNxNameSegment *lastSeg = ccnxName_GetSegment(name, numSegments - 1);

    if (ccnxNameSegment_GetType(lastSeg) == CCNxNameLabelType_CHUNK) {
        *hasChunkNum = true;
        *chunkNum = ccnxNameSegmentNumber_Value(lastSeg);
    } else {
        *hasChunkNum = false;
        *chunkNum = 0;
    }
}

static PARCBuffer *
_createStatSizeResponsePayload(const AthenaPIT *athenaPIT, PARCClock *clock, CCNxName *queryName, uint64_t chunkNumber)
{
    PARCJSON *json = parcJSON_Create();

    parcJSON_AddString(json, "moduleName", _athenaPIT_Name);
    parcJSON_AddInteger(json, "time", parcClock_GetTime(clock));
    parcJSON_AddInteger(json, "numEntries", athenaPIT_GetNumberOfTableEntries(athenaPIT));
    parcJSON_AddInteger(json, "numPendingEntries", athenaPIT_GetNumberOfPendingInterests(athenaPIT));

    char *jsonString = parcJSON_ToString(json);

    parcJSON_Release(&json);

    PARCBuffer *result = parcBuffer_CreateFromArray(jsonString, strlen(jsonString));

    parcMemory_Deallocate(&jsonString);

    return parcBuffer_Flip(result);
}

static PARCBuffer *
_createStatAvgEntryLifetimeResponsePayload(const AthenaPIT *athenaPIT, PARCClock *clock, CCNxName *queryName, uint64_t chunkNumber)
{
    PARCJSON *json = parcJSON_Create();

    parcJSON_AddString(json, "moduleName", _athenaPIT_Name);
    parcJSON_AddInteger(json, "time", parcClock_GetTime(clock));
    parcJSON_AddInteger(json, "avgEntryLifetime", athenaPIT_GetMeanEntryLifetime(athenaPIT));
    char *jsonString = parcJSON_ToString(json);

    parcJSON_Release(&json);

    PARCBuffer *result = parcBuffer_CreateFromArray(jsonString, strlen(jsonString));

    parcMemory_Deallocate(&jsonString);

    return parcBuffer_Flip(result);
}

static PARCBuffer *
_processStatQuery(const AthenaPIT *athenaPIT, CCNxName *queryName, size_t argIndex, uint64_t chunkNumber)
{
    PARCBuffer *result = NULL;

    if (argIndex < ccnxName_GetSegmentCount(queryName)) {
        PARCClock *wallClock = parcClock_Wallclock();

        CCNxNameSegment *segment = ccnxName_GetSegment(queryName, argIndex);
        char *queryString = ccnxNameSegment_ToString(segment);

        char *sizeString = "size";
        char *hitsString = "avgEntryLifetime";

        if (strncasecmp(queryString, sizeString, strlen(sizeString)) == 0) {
            result = _createStatSizeResponsePayload(athenaPIT, wallClock, queryName, chunkNumber);
        } else if (strncasecmp(queryString, hitsString, strlen(hitsString)) == 0) {
            result = _createStatAvgEntryLifetimeResponsePayload(athenaPIT, wallClock, queryName, chunkNumber);
        }

        parcMemory_Deallocate(&queryString);
        parcClock_Release(&wallClock);
    }

    return result;
}

static bool
_getSegmentIndexOfQueryArgs(CCNxName *name, char *nameString, size_t *segmentNumber)
{
    bool result = false;
    size_t numSegments = ccnxName_GetSegmentCount(name);
    size_t curSegment = 0;
    while (curSegment < numSegments) {
        CCNxNameSegment *segment = ccnxName_GetSegment(name, curSegment);
        if (ccnxNameSegment_GetType(segment) == CCNxNameLabelType_NAME) {
            char *segString = ccnxNameSegment_ToString(segment);
            if (strncasecmp(segString, nameString, strlen(nameString)) == 0) {
                parcMemory_Deallocate(&segString);
                *segmentNumber = curSegment + 1;
                result = true;
                break;
            }
            parcMemory_Deallocate(&segString);
            curSegment++;
        }
    }
    return result;
}

CCNxMetaMessage *
athenaPIT_ProcessMessage(const AthenaPIT *athenaPIT, const CCNxMetaMessage *message)
{
    CCNxMetaMessage *result = NULL;

    if (ccnxMetaMessage_IsInterest(message)) {
        CCNxInterest *interest = ccnxMetaMessage_GetInterest(message);
        CCNxName *queryName = ccnxInterest_GetName(interest);

        uint64_t chunkNumber = 0;
        bool hasChunkNumber = false;
        _getChunkNumberFromName(queryName, &chunkNumber, &hasChunkNumber);
        assertFalse(hasChunkNumber, "AthenaPIT queries don't yet support more than 1 chunk.");

        PARCBuffer *responsePayload = NULL;

        // Find the arguments to our query.
        size_t argSegmentIndex = 0;
        if (_getSegmentIndexOfQueryArgs(queryName, AthenaModule_PIT, &argSegmentIndex)) {
            CCNxNameSegment *queryTypeSegment = ccnxName_GetSegment(queryName, argSegmentIndex);
            char *queryTypeString = ccnxNameSegment_ToString(queryTypeSegment);  // e.g. "stat"

            char *statString = "stat";
            if (strncasecmp(queryTypeString, statString, strlen(statString)) == 0) {
                responsePayload = _processStatQuery(athenaPIT, queryName, argSegmentIndex + 1, chunkNumber);
            }
            parcMemory_Deallocate(&queryTypeString);
        }

        if (responsePayload != NULL) {
            CCNxContentObject *contentObjectResponse =
                ccnxContentObject_CreateWithNameAndPayload(ccnxInterest_GetName(interest), responsePayload);

            result = ccnxMetaMessage_CreateFromContentObject(contentObjectResponse);

            ccnxContentObject_Release(&contentObjectResponse);
            parcBuffer_Release(&responsePayload);
        }
    }

    return result;  // could be NULL
}

PARCList *
athenaPIT_CreateEntryList(const AthenaPIT *athenaPIT)
{
    PARCList *result =
            parcList(parcArrayList_Create((void (*)(void **)) parcBuffer_Release), PARCArrayListAsPARCList);

    char lineStr[512];
    PARCIterator *it = parcHashMap_CreateValueIterator(athenaPIT->entryTable);
    snprintf (lineStr, 512, "Name,ingress,egress,KeyIdRestricted,HashRestricted,Nameless");
    PARCBuffer *line = parcBuffer_AllocateCString(lineStr);
    parcList_Add(result, (PARCObject *)line);
    while(parcIterator_HasNext(it)) {
        _AthenaPITEntry *entry = (_AthenaPITEntry *)parcIterator_Next(it);
        CCNxName *name = ccnxInterest_GetName(entry->ccnxMessage);
        char nameStr[256];
        if (name != NULL) {
            PARCBufferComposer *composer = parcBufferComposer_Create();
            composer = ccnxName_BuildString(name, composer);
            char *temp = parcBufferComposer_ToString(composer);
            parcBufferComposer_Release(&composer);
            snprintf(nameStr, 256, "%s", temp);
            parcMemory_Deallocate(&temp);
        } else {
            sprintf(nameStr, "[nameless]");
        }
        char *ingressStr = parcBitVector_ToString(entry->ingress);
        char *egressStr = parcBitVector_ToString(entry->egress);
        PARCBuffer *contentId =
            ccnxInterest_GetContentObjectHashRestriction(entry->ccnxMessage);
        bool hashRestricted = (contentId != NULL);
        bool keyIdRestricted =
            (ccnxInterest_GetKeyIdRestriction(entry->ccnxMessage) != NULL);
        bool nameless = false;
        if (hashRestricted) {
            PARCBuffer *testKey = _athenaPIT_createCompoundKey(NULL, contentId, NULL);
            nameless = parcBuffer_Equals(testKey, entry->key);
            parcBuffer_Release(&testKey);
        }
        snprintf (lineStr, 512, "%s,%s,%s,%s,%s,%s",
                  nameStr,
                  ingressStr,
                  egressStr,
                  (keyIdRestricted ? "true" : "false"),
                  (hashRestricted ? "true" : "false"),
                  (nameless ? "true" : "false")
        );
        parcMemory_Deallocate(&ingressStr);
        parcMemory_Deallocate(&egressStr);

        PARCBuffer *line = parcBuffer_AllocateCString(lineStr);
        parcList_Add(result, (PARCObject *)line);
    }
    parcIterator_Release(&it);

    return result;
}
