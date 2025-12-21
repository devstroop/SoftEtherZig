/*
 * SoftEther VPN Compatibility Header for Zig Compilation
 * 
 * This header resolves the bool type conflict between SoftEther's
 * custom bool typedef and the standard C99 stdbool.h.
 */

#ifndef SOFTETHER_COMPAT_H
#define SOFTETHER_COMPAT_H

/* Include standard bool from C99 */
#include <stdbool.h>

/* Prevent SoftEther from defining its own bool type */
#define WIN32COM_CPP 1

/* 
 * Cedar.h also unconditionally tries to #define bool to UINT.
 * We need to prevent that redefinition for the bridge code only.
 * Note: We'll handle Cedar's bool definition separately.
 */

#endif /* SOFTETHER_COMPAT_H */
