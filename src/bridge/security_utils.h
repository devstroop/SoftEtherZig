// Security utility functions for password handling
// These functions prevent compiler optimizations from removing security-critical code

#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Securely zero memory (cannot be optimized away by compiler)
 * 
 * Uses volatile pointer to prevent compiler from optimizing away the zeroing.
 * This is critical for clearing sensitive data like passwords from memory.
 * 
 * @param ptr Pointer to memory to zero
 * @param len Length of memory to zero
 */
void secure_zero(void* ptr, size_t len);

/**
 * @brief Securely zero memory with explicit_bzero if available
 * 
 * Uses platform-specific secure zeroing function if available:
 * - explicit_bzero (BSD, Linux)
 * - memset_s (C11)
 * - SecureZeroMemory (Windows)
 * 
 * Falls back to secure_zero() if not available.
 * 
 * @param ptr Pointer to memory to zero
 * @param len Length to memory to zero
 */
void secure_zero_explicit(void* ptr, size_t len);

/**
 * @brief Lock memory pages to prevent swapping to disk
 * 
 * Prevents sensitive data from being written to swap space where
 * it could be recovered later.
 * 
 * @param addr Address to lock
 * @param len Length to lock
 * @return 1 if successful, 0 on error
 */
int secure_mlock(void* addr, size_t len);

/**
 * @brief Lock memory pages to prevent swapping to disk
 * 
 * Prevents sensitive data from being written to swap space where
 * it could be recovered later.
 * 
 * @param addr Address to lock
 * @param len Length to lock
 * @return 1 if successful, 0 on error
 */
int secure_lock_memory(void* addr, size_t len);

/**
 * @brief Unlock previously locked memory pages
 * 
 * @param addr Address to unlock
 * @param len Length to unlock
 * @return 1 if successful, 0 on error
 */
int secure_unlock_memory(void* addr, size_t len);

/**
 * @brief Timing-attack resistant memory comparison
 * 
 * Compares two memory regions in constant time to prevent timing attacks.
 * Always compares the full length regardless of where differences are found.
 * 
 * @param a First memory region
 * @param b Second memory region
 * @param len Length to compare
 * @return 0 if equal, non-zero if different, -1 on error
 */
int secure_compare(const void* a, const void* b, size_t len);

#ifdef __cplusplus
}
#endif

#endif // SECURITY_UTILS_H
