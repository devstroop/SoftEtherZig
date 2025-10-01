/*
 * Custom Tick64 implementation for Windows
 * Uses QueryPerformanceCounter for high-resolution timing
 */

#ifdef _WIN32

#include <windows.h>
#include <stdint.h>

// Forward declare types to avoid including full SoftEther headers
typedef uint64_t UINT64;

// State for high-resolution timing
static LARGE_INTEGER frequency = {0};
static LARGE_INTEGER start_counter = {0};
static int initialized = 0;

static void tick64_init_once(void) {
    if (!initialized) {
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start_counter);
        initialized = 1;
    }
}

// Returns milliseconds since program start
UINT64 Tick64(void) {
    LARGE_INTEGER current;
    tick64_init_once();
    
    QueryPerformanceCounter(&current);
    
    // Calculate elapsed ticks
    UINT64 elapsed = current.QuadPart - start_counter.QuadPart;
    
    // Convert to milliseconds
    return (elapsed * 1000ULL) / frequency.QuadPart;
}

// High-resolution version (same as regular for our use case)
UINT64 TickHighres64(void) {
    return Tick64();
}

// Nanosecond resolution
UINT64 TickHighresNano64(void) {
    LARGE_INTEGER current;
    tick64_init_once();
    
    QueryPerformanceCounter(&current);
    
    // Calculate elapsed ticks
    UINT64 elapsed = current.QuadPart - start_counter.QuadPart;
    
    // Convert to nanoseconds
    return (elapsed * 1000000000ULL) / frequency.QuadPart;
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

#endif // _WIN32
