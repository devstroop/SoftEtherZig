/*
 * iOS readline stub
 * 
 * iOS doesn't have readline, but it's only used in CLI mode
 * which we don't use on iOS. Provide stub implementations.
 */

#ifndef _READLINE_READLINE_H_
#define _READLINE_READLINE_H_

#include <stdlib.h>

// Stub implementations - these won't be called on iOS
static inline char *readline(const char *prompt) {
    return NULL;
}

#endif /* _READLINE_READLINE_H_ */
