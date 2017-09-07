
#ifndef ccnxKRB_Stats_h
#define ccnxKRB_Stats_h

/**
 * Structure to collect and display the performance statistics.
 */
struct vpn_stats;
typedef struct vpn_stats CCNxVPNStats;

/**
 * Create an empty `CCNxVPNStats` instance.
 *
 * The returned result must be freed via {@link ccnxVPNStats_Release}
 *
 * @return A newly allocated `CCNxVPNStats`.
 *
 * Example
 * @code
 * {
 *     CCNxVPNStats *stats = ccnxVPNStats_Create();
 * }
 * @endcode
 */
CCNxVPNStats *ccnxVPNStats_Create(void);

/**
 * Increase the number of references to a `CCNxVPNStats`.
 *
 * Note that new `CCNxVPNStats` is not created,
 * only that the given `CCNxVPNStats` reference count is incremented.
 * Discard the reference by invoking `ccnxVPNStats_Release`.
 *
 * @param [in] clock A pointer to a `CCNxVPNStats` instance.
 *
 * @return The input `CCNxVPNStats` pointer.
 *
 * Example:
 * @code
 * {
 *     CCNxVPNStats *stats = ccnxVPNStats_Create();
 *     CCNxVPNStats *copy = ccnxVPNStats_Acquire(stats);
 *     ccnxVPNStats_Release(&stats);
 *     ccnxVPNStats_Release(&copy);
 * }
 * @endcode
 */
CCNxVPNStats *ccnxVPNStats_Acquire(const CCNxVPNStats *stats);

/**
 * Release a previously acquired reference to the specified instance,
 * decrementing the reference count for the instance.
 *
 * The pointer to the instance is set to NULL as a side-effect of this function.
 *
 * If the invocation causes the last reference to the instance to be released,
 * the instance is deallocated and the instance's implementation will perform
 * additional cleanup and release other privately held references.
 *
 * @param [in,out] clockPtr A pointer to a pointer to the instance to release.
 *
 * Example:
 * @code
 * {
 *     CCNxVPNStats *stats = ccnxVPNStats_Create();
 *     CCNxVPNStats *copy = ccnxVPNStats_Acquire(stats);
 *     ccnxVPNStats_Release(&stats);
 *     ccnxVPNStats_Release(&copy);
 * }
 * @endcode
 */
void ccnxVPNStats_Release(CCNxVPNStats **statsPtr);

/**
 * Record the name and time for a request (e.g., interest).
 *
 * @param [in] stats The `CCNxVPNStats` instance.
 * @param [in] name The `CCNxName` name structure.
 * @param [in] timeInUs The send time (in microseconds).
 */
void ccnxVPNStats_RecordRequest(CCNxVPNStats *stats, CCNxName *name, uint64_t timeInUs);

/**
 * Record the name and time for a response (e.g., content object).
 *
 * @param [in] stats The `CCNxVPNStats` instance.
 * @param [in] name The `CCNxName` name structure.
 * @param [in] timeInUs The send time (in microseconds).
 * @param [in] message The response `CCNxMetaMessage`.
 *
 * @return The delta between the request and response (in microseconds).
 */
size_t ccnxVPNStats_RecordResponse(CCNxVPNStats *stats, CCNxName *name, uint64_t timeInUs, CCNxMetaMessage *message);

/**
 * Display the average statistics stored in this `CCNxVPNStats` instance.
 *
 * @param [in] stats The `CCNxVPNStats` instance from which to draw the average data.
 *
 * @retval true If the stats were displayed correctly
 * @retval false Otherwise
 */
bool ccnxVPNStats_Display(CCNxVPNStats *stats);
#endif // ccnxVPN_Stats_h
