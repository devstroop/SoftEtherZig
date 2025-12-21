// Security utility functions implementation
// These functions provide secure memory handling for sensitive data

#include "security_utils.h"
#include <string.h>

// Platform-specific includes
#ifdef UNIX_MACOS
#include <sys/mman.h>
#endif

#ifdef UNIX_LINUX
#include <sys/mman.h>
#endif

#ifdef OS_WIN32
#include <windows.h>
#endif

/**
 * Securely zero memory using volatile pointer
 * This prevents the compiler from optimizing away the zeroing operation
 */
void secure_zero(void* ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    
    // Use volatile pointer to prevent optimization
    volatile unsigned char* volatile p = (volatile unsigned char*)ptr;
    
    while (len--) {
        *p++ = 0;
    }
    
    // Memory barrier to ensure completion
    __asm__ __volatile__("" ::: "memory");
}

/**
 * Securely zero memory using platform-specific explicit functions
 * Falls back to secure_zero() if not available
 */
void secure_zero_explicit(void* ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
    // glibc 2.25+ has explicit_bzero
    explicit_bzero(ptr, len);
    return;
#endif
#endif

#ifdef OS_WIN32
    // Windows has SecureZeroMemory
    SecureZeroMemory(ptr, len);
    return;
#endif

#ifdef __STDC_LIB_EXT1__
    // C11 Annex K has memset_s
    memset_s(ptr, len, 0, len);
    return;
#endif

    // Fallback to our volatile implementation
    secure_zero(ptr, len);
}

/**
 * Lock memory pages to prevent swapping to disk
 * This keeps sensitive data in RAM only
 */
int secure_lock_memory(void* addr, size_t len) {
    if (addr == NULL || len == 0) {
        return 0;
    }
    
#if defined(UNIX_MACOS) || defined(UNIX_LINUX)
    // Use mlock to prevent swapping
    if (mlock(addr, len) == 0) {
        return 1;
    }
    // mlock may fail due to permissions, but that's ok
    return 0;
#elif defined(OS_WIN32)
    // Windows VirtualLock
    if (VirtualLock(addr, len)) {
        return 1;
    }
    return 0;
#else
    // Platform doesn't support memory locking
    return 0;
#endif
}

/**
 * Unlock previously locked memory pages
 */
int secure_unlock_memory(void* addr, size_t len) {
    if (addr == NULL || len == 0) {
        return 0;
    }
    
#if defined(UNIX_MACOS) || defined(UNIX_LINUX)
    if (munlock(addr, len) == 0) {
        return 1;
    }
    return 0;
#elif defined(OS_WIN32)
    if (VirtualUnlock(addr, len)) {
        return 1;
    }
    return 0;
#else
    return 0;
#endif
}

/**
 * Timing-attack resistant memory comparison
 * Always compares full length regardless of where differences are found
 */
int secure_compare(const void* a, const void* b, size_t len) {
    if (a == NULL || b == NULL) {
        return -1;
    }
    
    const volatile unsigned char* volatile pa = (const volatile unsigned char*)a;
    const volatile unsigned char* volatile pb = (const volatile unsigned char*)b;
    volatile unsigned char result = 0;
    
    // XOR all bytes - will be 0 only if all match
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result;
}
