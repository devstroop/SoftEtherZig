/*
 * iOS history stub  
 * 
 * iOS doesn't have history, but it's only used in CLI mode
 * which we don't use on iOS. Provide stub implementations.
 */

#ifndef _READLINE_HISTORY_H_
#define _READLINE_HISTORY_H_

// Stub implementations - these won't be called on iOS
static inline void add_history(const char *line) {
    // No-op
}

static inline void using_history(void) {
    // No-op
}

#endif /* _READLINE_HISTORY_H_ */
