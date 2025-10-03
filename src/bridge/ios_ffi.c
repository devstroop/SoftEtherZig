// iOS FFI Implementation for SoftEther VPN Client
// This provides the C API bridge for iOS PacketTunnelProvider

#include "softether_ffi.h"
#include "softether_bridge.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <arpa/inet.h>

// JSON parsing (simple implementation for config)
#include <ctype.h>

// Opaque client structure
struct softether_client_t {
    VpnBridgeClient* bridge;
    softether_rx_cb_t rx_callback;
    void* rx_user;
    softether_ip_rx_cb_t ip_rx_callback;
    void* ip_rx_user;
    softether_state_cb_t state_callback;
    void* state_user;
    softether_event_cb_t event_callback;
    void* event_user;
    char* last_error;
    uint8_t mac_address[6];
    VpnBridgeDhcpInfo dhcp_info;
    pthread_mutex_t mutex;
    uint32_t connected;  // 0 = false, 1 = true
};

// Simple JSON parser for config
static char* json_get_string(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return NULL;
    
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return NULL;
    
    // Skip whitespace
    while (*pos && isspace(*pos)) pos++;
    if (*pos == ':') pos++;
    while (*pos && isspace(*pos)) pos++;
    
    if (*pos != '"') return NULL;
    pos++; // Skip opening quote
    
    const char* end = strchr(pos, '"');
    if (!end) return NULL;
    
    size_t len = end - pos;
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    
    memcpy(result, pos, len);
    result[len] = '\0';
    return result;
}

static int json_get_int(const char* json, const char* key, int default_value) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return default_value;
    
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return default_value;
    
    // Skip whitespace and colon
    while (*pos && (isspace(*pos) || *pos == ':')) pos++;
    
    return atoi(pos);
}

static uint32_t json_get_bool(const char* json, const char* key, uint32_t default_value) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return default_value;
    
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return default_value;
    
    // Skip whitespace and colon
    while (*pos && (isspace(*pos) || *pos == ':')) pos++;
    
    if (strncmp(pos, "true", 4) == 0) return 1;
    if (strncmp(pos, "false", 5) == 0) return 0;
    
    return default_value;
}

// Generate a locally administered MAC address
static void generate_mac_address(uint8_t mac[6]) {
    // Use SoftEther official prefix 0x5E for first vendor byte after local admin bit
    mac[0] = 0x02; // Locally administered unicast
    mac[1] = 0x00;
    mac[2] = 0x5e; // SoftEther prefix
    
    // Random bytes for the rest
    for (int i = 3; i < 6; i++) {
        mac[i] = (uint8_t)(rand() & 0xFF);
    }
}

// API Implementation
softether_client_t* softether_client_create(const char* json_config) {
    if (!json_config) return NULL;
    
    // Initialize library if needed
    static uint32_t lib_initialized = 0;  // 0 = false, 1 = true
    if (!lib_initialized) {
        if (vpn_bridge_init(0) != VPN_BRIDGE_SUCCESS) {  // 0 = FALSE (debug off)
            return NULL;
        }
        lib_initialized = 1;
    }
    
    softether_client_t* client = (softether_client_t*)calloc(1, sizeof(softether_client_t));
    if (!client) return NULL;
    
    pthread_mutex_init(&client->mutex, NULL);
    generate_mac_address(client->mac_address);
    
    // Parse JSON config
    char* server = json_get_string(json_config, "server");
    char* hub = json_get_string(json_config, "hub");
    char* username = json_get_string(json_config, "username");
    char* password_hash = json_get_string(json_config, "password_hash");
    int port = json_get_int(json_config, "port", 443);
    
    if (!server || !hub || !username) {
        free(server);
        free(hub);
        free(username);
        free(password_hash);
        free(client);
        return NULL;
    }
    
    // Create bridge client
    client->bridge = vpn_bridge_create_client();
    if (!client->bridge) {
        free(server);
        free(hub);
        free(username);
        free(password_hash);
        pthread_mutex_destroy(&client->mutex);
        free(client);
        return NULL;
    }
    
    // Configure connection
    // Note: password_hash needs to be decoded if it's base64 encoded
    int rc = vpn_bridge_configure(client->bridge, server, (uint16_t)port, hub, username, 
                                   password_hash ? password_hash : "");
    
    free(server);
    free(hub);
    free(username);
    free(password_hash);
    
    if (rc != VPN_BRIDGE_SUCCESS) {
        vpn_bridge_free_client(client->bridge);
        pthread_mutex_destroy(&client->mutex);
        free(client);
        return NULL;
    }
    
    return client;
}

int softether_client_connect(softether_client_t* handle) {
    if (!handle || !handle->bridge) return -1;
    
    if (handle->state_callback) {
        handle->state_callback(1, handle->state_user); // Connecting
    }
    
    int rc = vpn_bridge_connect(handle->bridge);
    
    if (rc == VPN_BRIDGE_SUCCESS) {
        pthread_mutex_lock(&handle->mutex);
        handle->connected = 1;  // 1 = true
        pthread_mutex_unlock(&handle->mutex);
        
        if (handle->state_callback) {
            handle->state_callback(2, handle->state_user); // Established
        }
        
        // Try to get DHCP info
        vpn_bridge_get_dhcp_info(handle->bridge, &handle->dhcp_info);
        
        return 0;
    }
    
    if (handle->state_callback) {
        handle->state_callback(0, handle->state_user); // Failed, back to idle
    }
    
    return -1;
}

int softether_client_disconnect(softether_client_t* handle) {
    if (!handle || !handle->bridge) return -1;
    
    if (handle->state_callback) {
        handle->state_callback(3, handle->state_user); // Disconnecting
    }
    
    pthread_mutex_lock(&handle->mutex);
    handle->connected = 0;  // 0 = false
    pthread_mutex_unlock(&handle->mutex);
    
    vpn_bridge_disconnect(handle->bridge);
    
    if (handle->state_callback) {
        handle->state_callback(0, handle->state_user); // Idle
    }
    
    return 0;
}

void softether_client_free(softether_client_t* handle) {
    if (!handle) return;
    
    if (handle->connected) {
        softether_client_disconnect(handle);
    }
    
    if (handle->bridge) {
        vpn_bridge_free_client(handle->bridge);
    }
    
    if (handle->last_error) {
        free(handle->last_error);
    }
    
    pthread_mutex_destroy(&handle->mutex);
    free(handle);
}

int softether_client_set_rx_callback(softether_client_t* handle, softether_rx_cb_t cb, void* user) {
    if (!handle) return -1;
    pthread_mutex_lock(&handle->mutex);
    handle->rx_callback = cb;
    handle->rx_user = user;
    pthread_mutex_unlock(&handle->mutex);
    return 0;
}

int softether_client_send_frame(softether_client_t* handle, const uint8_t* data, uint32_t len) {
    if (!handle || !handle->bridge || !data || !handle->connected) return 0;
    // TODO: Implement frame sending through bridge
    // This will require extending the bridge API or direct packet adapter access
    return 1;
}

int softether_client_set_ip_rx_callback(softether_client_t* handle, softether_ip_rx_cb_t cb, void* user) {
    if (!handle) return -1;
    pthread_mutex_lock(&handle->mutex);
    handle->ip_rx_callback = cb;
    handle->ip_rx_user = user;
    pthread_mutex_unlock(&handle->mutex);
    return 0;
}

int softether_client_send_ip_packet(softether_client_t* handle, const uint8_t* data, uint32_t len) {
    if (!handle || !handle->bridge || !data || !handle->connected) return 0;
    // TODO: Implement IP packet sending through bridge
    // This will wrap the IP packet in Ethernet frame and send via bridge
    return 1;
}

int softether_client_arp_add(softether_client_t* handle, uint32_t ipv4_be, const uint8_t mac[6]) {
    if (!handle || !handle->bridge || !mac) return -1;
    // TODO: Implement ARP table update
    // For now, just return success
    return 0;
}

int softether_client_set_state_callback(softether_client_t* handle, softether_state_cb_t cb, void* user) {
    if (!handle) return -1;
    pthread_mutex_lock(&handle->mutex);
    handle->state_callback = cb;
    handle->state_user = user;
    pthread_mutex_unlock(&handle->mutex);
    return 0;
}

int softether_client_set_event_callback(softether_client_t* handle, softether_event_cb_t cb, void* user) {
    if (!handle) return -1;
    pthread_mutex_lock(&handle->mutex);
    handle->event_callback = cb;
    handle->event_user = user;
    pthread_mutex_unlock(&handle->mutex);
    return 0;
}

int softether_b64_decode(const char* b64, unsigned char* out_buf, unsigned int out_cap) {
    // TODO: Implement base64 decoding
    return -1;
}

char* softether_client_version(void) {
    const char* version = "SoftEtherZig 1.0.0 (iOS)";
    return strdup(version);
}

void softether_string_free(char* str) {
    if (str) free(str);
}

char* softether_client_last_error(softether_client_t* handle) {
    if (!handle) return NULL;
    pthread_mutex_lock(&handle->mutex);
    char* error = handle->last_error;
    handle->last_error = NULL;
    pthread_mutex_unlock(&handle->mutex);
    return error;
}

char* softether_client_get_network_settings_json(softether_client_t* handle) {
    if (!handle || !handle->bridge) return NULL;
    
    VpnBridgeDhcpInfo dhcp;
    if (vpn_bridge_get_dhcp_info(handle->bridge, &dhcp) != VPN_BRIDGE_SUCCESS || !dhcp.valid) {
        return NULL;
    }
    
    // Convert IP addresses to strings
    struct in_addr addr;
    char ip_str[INET_ADDRSTRLEN];
    char mask_str[INET_ADDRSTRLEN];
    char gw_str[INET_ADDRSTRLEN];
    char dns1_str[INET_ADDRSTRLEN];
    char dns2_str[INET_ADDRSTRLEN];
    
    addr.s_addr = dhcp.client_ip;
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    
    addr.s_addr = dhcp.subnet_mask;
    inet_ntop(AF_INET, &addr, mask_str, sizeof(mask_str));
    
    addr.s_addr = dhcp.gateway;
    inet_ntop(AF_INET, &addr, gw_str, sizeof(gw_str));
    
    addr.s_addr = dhcp.dns_server1;
    inet_ntop(AF_INET, &addr, dns1_str, sizeof(dns1_str));
    
    addr.s_addr = dhcp.dns_server2;
    inet_ntop(AF_INET, &addr, dns2_str, sizeof(dns2_str));
    
    // Build JSON string
    char* json = (char*)malloc(1024);
    if (json) {
        int offset = snprintf(json, 1024, 
                "{\"assigned_ipv4\":\"%s\",\"subnet_mask\":\"%s\",\"gateway\":\"%s\",\"dns_servers\":[",
                ip_str, mask_str, gw_str);
        
        // Add DNS servers
        uint32_t first = 1;  // 1 = true
        if (dhcp.dns_server1 != 0) {
            offset += snprintf(json + offset, 1024 - offset, "\"%s\"", dns1_str);
            first = 0;  // 0 = false
        }
        if (dhcp.dns_server2 != 0) {
            if (!first) offset += snprintf(json + offset, 1024 - offset, ",");
            offset += snprintf(json + offset, 1024 - offset, "\"%s\"", dns2_str);
        }
        
        snprintf(json + offset, 1024 - offset, "]}");
    }
    return json;
}

int softether_client_get_mac(softether_client_t* handle, uint8_t out_mac[6]) {
    if (!handle || !out_mac) return -1;
    memcpy(out_mac, handle->mac_address, 6);
    return 0;
}
