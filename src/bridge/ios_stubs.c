// iOS Stub Functions for Terminal I/O
// These functions are not available on iOS and are only used
// in command-line utilities that don't run on iOS anyway

#ifdef BUILDING_FOR_IOS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Readline library stubs (not available on iOS)
char *readline(const char *prompt) {
    // iOS doesn't have terminal input
    // This should never be called on iOS - only used in CLI tools
    return NULL;
}

void add_history(const char *line) {
    // No-op on iOS
    // This should never be called on iOS - only used in CLI tools
}

// Curses/ncurses stub (not available on iOS)
int getch(void) {
    // iOS doesn't have terminal character input
    // This should never be called on iOS - only used in CLI tools
    return -1;
}

#endif // BUILDING_FOR_IOS
