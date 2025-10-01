/*
 * Custom Tick64 implementation for Linux
 * Uses clock_gettime with CLOCK_MONOTONIC for reliable timing
 */

#include <time.h>
#include <stdint.h>

// Forward declare types to avoid including full SoftEther headers
typedef uint64_t UINT64;

// State for monotonic time
static struct timespec start_time = {0, 0};
static int initialized = 0;

static void tick64_init_once(void) {
    if (!initialized) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        initialized = 1;
    }
}

// Returns milliseconds since program start
UINT64 Tick64(void) {
    struct timespec current;
    tick64_init_once();
    
    clock_gettime(CLOCK_MONOTONIC, &current);
    
    // Calculate elapsed time
    uint64_t elapsed_sec = current.tv_sec - start_time.tv_sec;
    int64_t elapsed_nsec = current.tv_nsec - start_time.tv_nsec;
    
    // Handle nanosecond underflow
    if (elapsed_nsec < 0) {
        elapsed_sec--;
        elapsed_nsec += 1000000000L;
    }
    
    // Convert to milliseconds
    return elapsed_sec * 1000ULL + elapsed_nsec / 1000000ULL;
}

// High-resolution version (same as regular for our use case)
UINT64 TickHighres64(void) {
    return Tick64();
}

// Nanosecond resolution
UINT64 TickHighresNano64(void) {
    struct timespec current;
    tick64_init_once();
    
    clock_gettime(CLOCK_MONOTONIC, &current);
    
    // Calculate elapsed time in nanoseconds
    uint64_t elapsed_sec = current.tv_sec - start_time.tv_sec;
    int64_t elapsed_nsec = current.tv_nsec - start_time.tv_nsec;
    
    if (elapsed_nsec < 0) {
        elapsed_sec--;
        elapsed_nsec += 1000000000L;
    }
    
    return elapsed_sec * 1000000000ULL + elapsed_nsec;
}

// Convert Tick64 value to TIME64
void Tick64ToTime64(UINT64 tick, void *time64) {
    if (time64) {
        *((UINT64*)time64) = tick;
    }
}

// Convert tick to time structure (simplified stub)
void TickToTime(void *time_struct, UINT64 tick) {
    (void)time_struct;
    (void)tick;
}

// Cleanup function (no-op)
void FreeTick64(void) {
    // Nothing to free
}
