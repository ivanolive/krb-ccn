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
 * @author Kevin Fox, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2016, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */
#ifndef libathena_Fragmenter
#define libathena_Fragmenter

#include <ccnx/common/codec/ccnxCodec_EncodingBuffer.h>

/**
 * @typedef AthenaFragmenter
 * @brief Fragmenter instance private data
 */
typedef struct AthenaFragmenter AthenaFragmenter;

/**
 * @typedef AthenaFragmenter_CreateFragment
 * @brief Fragmenter create fragment method
 */
typedef CCNxCodecEncodingBufferIOVec *(AthenaFragmenter_CreateFragment)(AthenaFragmenter *athenaFragmenter,
                                                                        PARCBuffer *message,
                                                                        size_t mtu, int fragmentNumber);

/**
 * @typedef AthenaFragmenter_ReceiveFragment
 * @brief Fragmenter receive method
 */
typedef PARCBuffer *(AthenaFragmenter_ReceiveFragment)(AthenaFragmenter *athenaFragmenter,
                                                       PARCBuffer *wireFormatBuffer);

/**
 * @typedef AthenaFragmenter_Init
 * @brief Fragmenter initialization method
 */
typedef AthenaFragmenter *(*AthenaFragmenter_Init)(AthenaFragmenter *athenaFragmenter);

/**
 * @typedef AthenaFragmenter_Init
 * @brief Fragmenter initialization method
 */
typedef void (AthenaFragmenter_Fini)(AthenaFragmenter *athenaFragmenter);

//
// Private data for each fragmented connection
//
struct AthenaFragmenter {
    AthenaTransportLink *athenaTransportLink; // link associated with fragmenter
    const char *moduleName;
    AthenaFragmenter_CreateFragment *createFragment;
    AthenaFragmenter_ReceiveFragment *receiveFragment;
    AthenaFragmenter_Fini *fini;
    void *fragmenterData;
};

/**
 * @abstract create a new fragmenter instance
 * @discussion
 *
 * @param [in] athenaTransportLink associated with the fragmenter
 * @param [in] fragmenterName of new fragmenter
 * @return pointer to new instance
 *
 * Example:
 * @code
 * void
 * {
 *     AthenaFragmenter *athenaFragmenter = athenaFragmenter_Create(athenaTransportLink, "BEFS");
 * }
 * @endcode
 */
AthenaFragmenter *athenaFragmenter_Create(AthenaTransportLink *athenaTransportLink, const char *fragmenterName);

/**
 * @abstract obtain a new reference to a fragmenter instance
 * @discussion
 *
 * @param [in] athenaFragmenter instance to acquire a reference to
 * @return pointer to new reference
 *
 * Example:
 * @code
 * void
 * {
 *     AthenaFragmenter *newReference = athenaFragmenter_Acquire(athenaFragmenter);
 * }
 * @endcode
 */
AthenaFragmenter *athenaFragmenter_Acquire(const AthenaFragmenter *athenaFragmenter);

/**
 * @abstract release a fragmenter reference
 * @discussion
 *
 * @param [in] athenaFragmenter instance to release
 *
 * Example:
 * @code
 * void
 * {
 *     athenaFragmenter_Release(&athenaFragmenter);
 * }
 * @endcode
 */
void athenaFragmenter_Release(AthenaFragmenter **);

/**
 * @abstract send a message fragmenting it by the provided mtu size
 * @discussion
 *
 * @param [in] athenaFragmenter
 * @param [in] ccnxMetaMessage
 * @param [in] mtu
 * @param [in] fragmentNumber
 * @return 0 on success, -1 on failure with errno set to indicate failure
 *
 * Example:
 * @code
 * void
 * {
 *     // Get the first fragment from a message
 *     CCNxCodecEncodingBufferIOVec *ioVectorBuffer = athenaFragmenter_CreateFragment(athenaFragmenter, ccnxMetaMessage, 1200, 0);
 *     const struct iovec *iov = ioVectorBuffer->iov;
 *     size_t iovcnt = ioVectorBuffer->iovcnt;
 * }
 * @endcode
 */
CCNxCodecEncodingBufferIOVec *athenaFragmenter_CreateFragment(AthenaFragmenter *athenaFragmenter,
                                                              PARCBuffer *message,
                                                              size_t mtu, int fragmentNumber);

/**
 * @abstract construct a message from received fragments
 * @discussion
 *
 * @param [in] athenaFragmenter
 * @param [in] wireFormatBuffer
 * @return pointer to reassembled message,
 *         NULL if waiting for more fragments,
 *         or original inputWireFormatBuffer if it was not recognized as a fragment.
 *
 * Example:
 * @code
 * void
 * {
 *     PARCBuffer *wireFormatBuffer = athenaFragmenter_ReceiveFragment(athenaFragmenter, inputWireFormatBuffer);
 * }
 * @endcode
 */
PARCBuffer *athenaFragmenter_ReceiveFragment(AthenaFragmenter *athenaFragmenter,
                                             PARCBuffer *wireFormatBuffer);

#endif // libathena_Fragmenter
