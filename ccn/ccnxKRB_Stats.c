
#include <stdio.h>

#include <ccnx/common/ccnx_Name.h>
#include <ccnx/transport/common/transport_MetaMessage.h>

#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_DisplayIndented.h>

#include "ccnxKRB_Stats.h"

typedef struct vpn_stats_entry {
    uint64_t sendTimeInUs;
    uint64_t receivedTimeInUs;
    uint64_t rtt;
    size_t size;
    CCNxName *nameSent;
    CCNxMetaMessage *message;
} CCNxVPNStatsEntry;

struct vpn_stats {
    uint64_t totalRtt;
    uint64_t firstTime;
    uint64_t lastTime;
    size_t totalReceived;
    size_t totalSent;
    PARCHashMap *pings;
};

static bool
_ccnxVPNStatsEntry_Destructor(CCNxVPNStatsEntry **statsPtr)
{
    CCNxVPNStatsEntry *entry = *statsPtr;
    ccnxName_Release(&entry->nameSent);
    if (entry->message) {
        ccnxMetaMessage_Release(&entry->message);
    }
    return true;
}

static bool
_ccnxVPNStats_Destructor(CCNxVPNStats **statsPtr)
{
    CCNxVPNStats *stats = *statsPtr;
    parcHashMap_Release(&stats->pings);
    return true;
}

parcObject_Override(CCNxVPNStatsEntry, PARCObject,
                    .destructor = (PARCObjectDestructor *) _ccnxVPNStatsEntry_Destructor);

parcObject_ImplementAcquire(ccnxVPNStatsEntry, CCNxVPNStatsEntry);
parcObject_ImplementRelease(ccnxVPNStatsEntry, CCNxVPNStatsEntry);

CCNxVPNStatsEntry *
ccnxVPNStatsEntry_Create()
{
    return parcObject_CreateInstance(CCNxVPNStatsEntry);
}

parcObject_Override(CCNxVPNStats, PARCObject,
                    .destructor = (PARCObjectDestructor *) _ccnxVPNStats_Destructor);

parcObject_ImplementAcquire(ccnxVPNStats, CCNxVPNStats);
parcObject_ImplementRelease(ccnxVPNStats, CCNxVPNStats);

CCNxVPNStats *
ccnxVPNStats_Create(void)
{
    CCNxVPNStats *stats = parcObject_CreateInstance(CCNxVPNStats);

    stats->pings = parcHashMap_Create();
    stats->totalSent = 0;
    stats->totalReceived = 0;
    stats->totalRtt = 0;
    stats->firstTime = 0;
    stats->lastTime = 0;

    return stats;
}

void
ccnxVPNStats_RecordRequest(CCNxVPNStats *stats, CCNxName *name, uint64_t currentTime)
{
    CCNxVPNStatsEntry *entry = ccnxVPNStatsEntry_Create();

    entry->nameSent = ccnxName_Acquire(name);
    entry->message = NULL;
    entry->sendTimeInUs = currentTime;

    stats->totalSent++;

    if (currentTime < stats->firstTime || stats->firstTime == 0)
    {
        stats->firstTime = currentTime;
    }

    parcHashMap_Put(stats->pings, name, entry);
}

size_t
ccnxVPNStats_RecordResponse(CCNxVPNStats *stats, CCNxName *nameResponse, uint64_t currentTime, CCNxMetaMessage *message)
{
    size_t pingsReceived = stats->totalReceived + 1;
    CCNxVPNStatsEntry *entry = (CCNxVPNStatsEntry *) parcHashMap_Get(stats->pings, nameResponse);

    if (entry != NULL) {
        stats->totalReceived++;

        entry->receivedTimeInUs = currentTime;
        entry->rtt = entry->receivedTimeInUs - entry->sendTimeInUs;
        stats->totalRtt += entry->rtt;

        if (currentTime > stats->lastTime || stats->lastTime == 0)
        {
               stats->lastTime = currentTime;
        }

        CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(message);
        PARCBuffer *payload = ccnxContentObject_GetPayload(contentObject);
        entry->size = parcBuffer_Remaining(payload);

        return entry->rtt;
    }

    return 0;
}

bool
ccnxVPNStats_Display(CCNxVPNStats *stats)
{
    FILE* fp = fopen("dropped.csv", "a");
    fprintf(fp, "%d,%.2f\n", stats->totalSent,1.0*(stats->totalSent - stats->totalReceived)/stats->totalSent);
    fclose(fp);

    if (stats->totalReceived > 0) {

        parcDisplayIndented_PrintLine(0, "Sent = %zu : Received = %zu : AvgDelay %llu us",
                                      stats->totalSent, stats->totalReceived, stats->totalRtt / stats->totalReceived);

        return true;
    }

    return false;
}

void
storeThroughput(CCNxVPNStats *stats, long long int payloadSize)
{
    double delay = (stats->totalRtt / stats->totalReceived)/1000000.0; // converting time to seconds
    FILE* fp = fopen("throughput.csv", "a");
    double thgp = (stats->totalReceived * payloadSize * 8) / delay;
    if (delay != 0) {
        fprintf(fp, "%f,%f,%d,%d\n", delay, thgp, stats->lastTime - stats->firstTime, stats->totalReceived * payloadSize * 8);
    }
    fclose(fp);
}
