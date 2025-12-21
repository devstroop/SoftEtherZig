// SoftEther VPN Zig Client - Unified Logging System
// Provides log level control and consistent output formatting

#ifndef SOFTETHER_LOGGING_H
#define SOFTETHER_LOGGING_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Log levels (lower = less verbose)
typedef enum {
    LOG_LEVEL_SILENT = 0,  // No output (except errors)
    LOG_LEVEL_ERROR = 1,   // Critical errors only
    LOG_LEVEL_WARN = 2,    // Warnings + errors
    LOG_LEVEL_INFO = 3,    // Important info (default)
    LOG_LEVEL_DEBUG = 4,   // Detailed debugging
    LOG_LEVEL_TRACE = 5    // Extremely verbose (packet-level)
} LogLevel;

// Global log level (can be set from CLI or config)
extern LogLevel g_log_level;

// Set log level at runtime
void set_log_level(LogLevel level);
const char* get_log_level_name(LogLevel level);
LogLevel parse_log_level(const char* str);

// Internal logging function (use macros below instead)
void log_message(LogLevel level, const char* tag, const char* fmt, ...);

// Logging macros with automatic level check
#define LOG_ERROR(tag, fmt, ...) \
    do { if (g_log_level >= LOG_LEVEL_ERROR) log_message(LOG_LEVEL_ERROR, tag, fmt, ##__VA_ARGS__); } while(0)

#define LOG_WARN(tag, fmt, ...) \
    do { if (g_log_level >= LOG_LEVEL_WARN) log_message(LOG_LEVEL_WARN, tag, fmt, ##__VA_ARGS__); } while(0)

#define LOG_INFO(tag, fmt, ...) \
    do { if (g_log_level >= LOG_LEVEL_INFO) log_message(LOG_LEVEL_INFO, tag, fmt, ##__VA_ARGS__); } while(0)

#define LOG_DEBUG(tag, fmt, ...) \
    do { if (g_log_level >= LOG_LEVEL_DEBUG) log_message(LOG_LEVEL_DEBUG, tag, fmt, ##__VA_ARGS__); } while(0)

#define LOG_TRACE(tag, fmt, ...) \
    do { if (g_log_level >= LOG_LEVEL_TRACE) log_message(LOG_LEVEL_TRACE, tag, fmt, ##__VA_ARGS__); } while(0)

// Convenience macros for common tags
#define LOG_TUN_ERROR(fmt, ...)   LOG_ERROR("TUN", fmt, ##__VA_ARGS__)
#define LOG_TUN_WARN(fmt, ...)    LOG_WARN("TUN", fmt, ##__VA_ARGS__)
#define LOG_TUN_INFO(fmt, ...)    LOG_INFO("TUN", fmt, ##__VA_ARGS__)
#define LOG_TUN_DEBUG(fmt, ...)   LOG_DEBUG("TUN", fmt, ##__VA_ARGS__)
#define LOG_TUN_TRACE(fmt, ...)   LOG_TRACE("TUN", fmt, ##__VA_ARGS__)

#define LOG_DHCP_ERROR(fmt, ...)  LOG_ERROR("DHCP", fmt, ##__VA_ARGS__)
#define LOG_DHCP_WARN(fmt, ...)   LOG_WARN("DHCP", fmt, ##__VA_ARGS__)
#define LOG_DHCP_INFO(fmt, ...)   LOG_INFO("DHCP", fmt, ##__VA_ARGS__)
#define LOG_DHCP_DEBUG(fmt, ...)  LOG_DEBUG("DHCP", fmt, ##__VA_ARGS__)
#define LOG_DHCP_TRACE(fmt, ...)  LOG_TRACE("DHCP", fmt, ##__VA_ARGS__)

#define LOG_VPN_ERROR(fmt, ...)   LOG_ERROR("VPN", fmt, ##__VA_ARGS__)
#define LOG_VPN_WARN(fmt, ...)    LOG_WARN("VPN", fmt, ##__VA_ARGS__)
#define LOG_VPN_INFO(fmt, ...)    LOG_INFO("VPN", fmt, ##__VA_ARGS__)
#define LOG_VPN_DEBUG(fmt, ...)   LOG_DEBUG("VPN", fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_LOGGING_H
