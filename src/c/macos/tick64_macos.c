/*
 * Custom Tick64 implementation for macOS
 * Overrides SoftEther's threaded version which hangs during init
 */

#include <mach/mach_time.h>
#include <stdint.h>

// Forward declare types to avoid including full SoftEther headers
typedef uint64_t UINT64;

// State for monotonic time
static mach_timebase_info_data_t timebase_info = {0, 0};
static uint64_t start_time = 0;
static int initialized = 0;

static void tick64_init_once(void) {
    if (!initialized) {
        mach_timebase_info(&timebase_info);
        start_time = mach_absolute_time();
        initialized = 1;
    }
}

// Returns milliseconds since program start
UINT64 Tick64(void) {
    tick64_init_once();
    
    uint64_t current = mach_absolute_time();
    uint64_t elapsed = current - start_time;
    
    // Convert to nanoseconds
    uint64_t elapsed_ns = elapsed * timebase_info.numer / timebase_info.denom;
    
    // Convert to milliseconds
    return elapsed_ns / 1000000ULL;
}

// High-resolution version (same as regular for our use case)
UINT64 TickHighres64(void) {
    return Tick64();
}

// Nanosecond resolution
UINT64 TickHighresNano64(void) {
    tick64_init_once();
    
    uint64_t current = mach_absolute_time();
    uint64_t elapsed = current - start_time;
    
    // Convert to nanoseconds
    return elapsed * timebase_info.numer / timebase_info.denom;
}

// Convert Tick64 value to TIME64
void Tick64ToTime64(UINT64 tick, void *time64) {
    // time64 is milliseconds since Unix epoch
    // tick is milliseconds since program start
    // We can't accurately convert without knowing program start time
    // For now, just pass through the value (this may not work correctly)
    if (time64) {
        *((UINT64*)time64) = tick;
    }
}

// Convert tick to time structure (simplified stub)
void TickToTime(void *time_struct, UINT64 tick) {
    // This would normally convert to a time structure
    // For now, minimal stub implementation
    (void)time_struct;
    (void)tick;
}

// Cleanup function (no-op for our simple implementation)
void FreeTick64(void) {
    // Nothing to free
}
