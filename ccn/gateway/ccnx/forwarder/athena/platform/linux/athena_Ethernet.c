/*
 * Copyright (c) 2015-2016, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC)
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
 * @author Kevin Fox, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2015-2016, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */
#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <LongBow/runtime.h>
#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_Memory.h>
#include <ccnx/forwarder/athena/athena_TransportLink.h>
#include <ccnx/forwarder/athena/athena_Ethernet.h>

typedef struct AthenaEthernet {
    int fd;
    struct ether_addr mac;
    uint16_t etherType;
    uint32_t mtu;
    PARCLog *log;
    const char *ifname;
} AthenaEthernet;

static void
_athenaEthernet_Destroy(AthenaEthernet **athenaEthernet)
{
    if ((*athenaEthernet)->ifname) {
        parcMemory_Deallocate(&((*athenaEthernet)->ifname));
    }
    close((*athenaEthernet)->fd);
}

parcObject_ExtendPARCObject(AthenaEthernet, _athenaEthernet_Destroy, NULL, NULL, NULL, NULL, NULL, NULL);

parcObject_ImplementAcquire(athenaEthernet, AthenaEthernet);

parcObject_ImplementRelease(athenaEthernet, AthenaEthernet);

AthenaEthernet *
athenaEthernet_Create(PARCLog *log, const char *interface, uint16_t etherType)
{
    AthenaEthernet *athenaEthernet = parcObject_CreateAndClearInstance(AthenaEthernet);
    athenaEthernet->log = log;
    athenaEthernet->etherType = etherType;

    athenaEthernet->fd = socket(AF_PACKET, SOCK_RAW, htons(athenaEthernet->etherType));
    if (athenaEthernet->fd == -1) {
        parcLog_Error(athenaEthernet->log, "socket: %s", strerror(errno));
        athenaEthernet_Release(&athenaEthernet);
        return NULL;
    }

    // Get index of specified interface
    struct ifreq if_idx;
    bzero(&if_idx, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, strlen(interface) + 1);
    if (ioctl(athenaEthernet->fd, SIOCGIFINDEX, &if_idx) == -1) {
        parcLog_Error(athenaEthernet->log, "SIOCGIFINDEX: %s", strerror(errno));
        athenaEthernet_Release(&athenaEthernet);
        return NULL;
    }

    // Bind to interface index
    struct sockaddr_ll my_addr = { 0 };
    my_addr.sll_family = PF_PACKET;
    my_addr.sll_protocol = htons(athenaEthernet->etherType);
    my_addr.sll_ifindex = if_idx.ifr_ifindex;

    if (bind(athenaEthernet->fd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr_ll)) == -1) {
        parcLog_Error(athenaEthernet->log, "bind: %s", strerror(errno));
        athenaEthernet_Release(&athenaEthernet);
        return NULL;
    }

    // Populate the configured physical MAC
    struct ifreq if_mac;
    bzero(&if_mac, sizeof(struct ifreq));
    memset(&if_mac, 0, sizeof(if_mac));
    strncpy(if_mac.ifr_name, interface, strlen(interface) + 1);
    if (ioctl(athenaEthernet->fd, SIOCGIFHWADDR, &if_mac) == -1) {
        parcLog_Error(athenaEthernet->log, "SIOCGIFHWADDR: %s", strerror(errno));
        athenaEthernet_Release(&athenaEthernet);
        return NULL;
    }
    memcpy(&(athenaEthernet->mac), if_mac.ifr_hwaddr.sa_data, ETHER_ADDR_LEN * sizeof(uint8_t));

    // Lookup our interface MTU
    if (ioctl(athenaEthernet->fd, SIOCGIFMTU, &if_mac) == -1) {
        parcLog_Error(athenaEthernet->log, "SIOCGIFMTU: %s", strerror(errno));
        athenaEthernet_Release(&athenaEthernet);
        return NULL;
    }
    athenaEthernet->mtu = if_mac.ifr_mtu;

    athenaEthernet->ifname = parcMemory_StringDuplicate(interface, strlen(interface));

    return athenaEthernet;
}

const char *
athenaEthernet_GetName(AthenaEthernet *athenaEthernet)
{
    return athenaEthernet->ifname;
}

uint32_t
athenaEthernet_GetMTU(AthenaEthernet *athenaEthernet)
{
    return athenaEthernet->mtu;
}

void
athenaEthernet_GetMAC(AthenaEthernet *athenaEthernet, struct ether_addr *ether_addr)
{
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        ether_addr->ether_addr_octet[i] = athenaEthernet->mac.ether_addr_octet[i];
    }
}

int
athenaEthernet_GetInterfaceMAC(const char *device, struct ether_addr *ether_addr)
{
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }

    // Get index of specified interface
    struct ifreq ifr;
    bzero(&ifr, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, device);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFHWADDR");
        close(fd);
        return -1;
    }
    memcpy(ether_addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN * sizeof(uint8_t));
    close(fd);

    return 0;
}

uint16_t
athenaEthernet_GetEtherType(AthenaEthernet *athenaEthernet)
{
    return athenaEthernet->etherType;
}

PARCBuffer *
athenaEthernet_Receive(AthenaEthernet *athenaEthernet, int timeout, AthenaTransportLinkEvent *events)
{
    size_t readLength = athenaEthernet->mtu + sizeof(struct ether_header);
    PARCBuffer *wireFormatBuffer = parcBuffer_Allocate(readLength);
    uint8_t *buffer = parcBuffer_Overlay(wireFormatBuffer, 0);

    ssize_t readCount = recv(athenaEthernet->fd, buffer, readLength, 0);
    if (readCount == -1) {
        if ((errno == EAGAIN) || (errno == EINTR)) {
            parcLog_Info(athenaEthernet->log, "Ethernet recv retry");
            return NULL;
        }
        parcLog_Error(athenaEthernet->log, "recv: %s", strerror(errno));
        *events = AthenaTransportLinkEvent_Error;
        parcBuffer_Release(&wireFormatBuffer);
        return NULL;
    }
    parcBuffer_SetLimit(wireFormatBuffer, readCount);

    return wireFormatBuffer;
}

// Ethernet collision detection requires a minimum packet length.
static unsigned char padding[ETHER_MIN_LEN] = { 0 };

ssize_t
athenaEthernet_Send(AthenaEthernet *athenaEthernet, struct iovec *iov, int iovcnt)
{
    ssize_t writeCount;

    // If the message is less than the required minimum packet size we must pad it out
    size_t messageLength = 0;
    for (int i = 0; i < iovcnt; i++) {
        messageLength += iov[i].iov_len;
    }
    if (messageLength < ETHER_MIN_LEN) {
        struct iovec paddedIovec[iovcnt + 1];
        bzero(padding, ETHER_MIN_LEN - messageLength);

        for (int i = 0; i < iovcnt; i++) {
            paddedIovec[i].iov_len = iov[i].iov_len;
            paddedIovec[i].iov_base = iov[i].iov_base;
        }
        paddedIovec[iovcnt].iov_len = ETHER_MIN_LEN - messageLength;
        paddedIovec[iovcnt].iov_base = padding;
        iovcnt++;
        writeCount = writev(athenaEthernet->fd, paddedIovec, iovcnt);
    } else {
        writeCount = writev(athenaEthernet->fd, iov, iovcnt);
    }

    if (writeCount == -1) {
        parcLog_Error(athenaEthernet->log, "writev: %s", strerror(errno));
    } else {
        parcLog_Debug(athenaEthernet->log, "sending message (size=%d/%d)", writeCount, messageLength);
    }

    return (writeCount < messageLength) ? writeCount : messageLength;
}

int
athenaEthernet_GetDescriptor(AthenaEthernet *athenaEthernet)
{
    return athenaEthernet->fd;
}
