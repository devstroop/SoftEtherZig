// SoftEther VPN Zig Client - Unified Logging Implementation

#include "logging.h"
#include <string.h>

// Global log level (default: INFO)
LogLevel g_log_level = LOG_LEVEL_INFO;

// ANSI color codes for terminal output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"  // ERROR
#define COLOR_YELLOW  "\033[1;33m"  // WARN
#define COLOR_GREEN   "\033[1;32m"  // INFO
#define COLOR_CYAN    "\033[1;36m"  // DEBUG
#define COLOR_GRAY    "\033[0;37m"  // TRACE

// Set log level at runtime
void set_log_level(LogLevel level) {
    if (level >= LOG_LEVEL_SILENT && level <= LOG_LEVEL_TRACE) {
        g_log_level = level;
    }
}

// Get log level name string
const char* get_log_level_name(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_SILENT: return "SILENT";
        case LOG_LEVEL_ERROR:  return "ERROR";
        case LOG_LEVEL_WARN:   return "WARN";
        case LOG_LEVEL_INFO:   return "INFO";
        case LOG_LEVEL_DEBUG:  return "DEBUG";
        case LOG_LEVEL_TRACE:  return "TRACE";
        default: return "UNKNOWN";
    }
}

// Parse log level from string (case-insensitive)
LogLevel parse_log_level(const char* str) {
    if (!str) return LOG_LEVEL_INFO;
    
    if (strcasecmp(str, "silent") == 0 || strcasecmp(str, "quiet") == 0) {
        return LOG_LEVEL_SILENT;
    } else if (strcasecmp(str, "error") == 0 || strcasecmp(str, "err") == 0) {
        return LOG_LEVEL_ERROR;
    } else if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0) {
        return LOG_LEVEL_WARN;
    } else if (strcasecmp(str, "info") == 0) {
        return LOG_LEVEL_INFO;
    } else if (strcasecmp(str, "debug") == 0) {
        return LOG_LEVEL_DEBUG;
    } else if (strcasecmp(str, "trace") == 0 || strcasecmp(str, "verbose") == 0) {
        return LOG_LEVEL_TRACE;
    }
    
    return LOG_LEVEL_INFO; // Default
}

// Get color for log level
static const char* get_level_color(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return COLOR_RED;
        case LOG_LEVEL_WARN:  return COLOR_YELLOW;
        case LOG_LEVEL_INFO:  return COLOR_GREEN;
        case LOG_LEVEL_DEBUG: return COLOR_CYAN;
        case LOG_LEVEL_TRACE: return COLOR_GRAY;
        default: return COLOR_RESET;
    }
}

// Get short log level symbol
static const char* get_level_symbol(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return "✗";
        case LOG_LEVEL_WARN:  return "⚠";
        case LOG_LEVEL_INFO:  return "●";
        case LOG_LEVEL_DEBUG: return "◆";
        case LOG_LEVEL_TRACE: return "·";
        default: return " ";
    }
}

// Core logging function
void log_message(LogLevel level, const char* tag, const char* fmt, ...) {
    if (level > g_log_level) return;
    
    // Format: [SYMBOL] TAG: message
    // Example: [●] VPN: Connection established
    // Example: [⚠] DHCP: Retry attempt 3
    
    const char* color = get_level_color(level);
    const char* symbol = get_level_symbol(level);
    
    // Print tag and symbol with color
    fprintf(stderr, "%s[%s] %s:%s ", color, symbol, tag, COLOR_RESET);
    
    // Print message
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
    fflush(stderr);
}
