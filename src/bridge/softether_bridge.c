/*
 * SoftEther VPN - Zig Bridge Layer Implementation
 * 
 * This implements the bridge layer between Zig and SoftEther C code.
 */

#include "softether_bridge.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================
 * SoftEther Headers
 * ============================================ */
#include "Mayaqua/Mayaqua.h"
#include "Cedar/Cedar.h"
#include "Cedar/Client.h"
#include "Cedar/Connection.h"
#include "Cedar/Session.h"
#include "Cedar/Account.h"

// Platform-specific packet adapter
#if defined(UNIX_MACOS)
    #include "packet_adapter_macos.h"
    #define NEW_PACKET_ADAPTER() NewMacOsTunAdapter()
#elif defined(UNIX_LINUX)
    #include "packet_adapter_linux.h"
    #define NEW_PACKET_ADAPTER() NewLinuxTunAdapter()
#elif defined(_WIN32)
    #include "packet_adapter_windows.h"
    #define NEW_PACKET_ADAPTER() NewWindowsTapAdapter()
#else
    #error "Unsupported platform"
#endif

/* ============================================
 * Internal State
 * ============================================ */

static bool g_initialized = false;

/* ============================================
 * Client Structure
 * ============================================ */

struct VpnBridgeClient {
    // Configuration
    char hostname[256];
    uint16_t port;
    char hub_name[256];
    char username[256];
    char password[256];
    
    // State
    VpnBridgeStatus status;
    uint32_t last_error;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t connect_time;
    
    // SoftEther internal handles
    CLIENT* softether_client;
    ACCOUNT* softether_account;
    SESSION* softether_session;
    PACKET_ADAPTER* packet_adapter;
};

/* ============================================
 * Helper Functions
 * ============================================ */

static const char* get_error_message_internal(int error_code) {
    switch (error_code) {
        case VPN_BRIDGE_SUCCESS:              return "Success";
        case VPN_BRIDGE_ERROR_INIT_FAILED:    return "Library initialization failed";
        case VPN_BRIDGE_ERROR_INVALID_PARAM:  return "Invalid parameter";
        case VPN_BRIDGE_ERROR_ALLOC_FAILED:   return "Memory allocation failed";
        case VPN_BRIDGE_ERROR_CONNECT_FAILED: return "Connection failed";
        case VPN_BRIDGE_ERROR_AUTH_FAILED:    return "Authentication failed";
        case VPN_BRIDGE_ERROR_NOT_CONNECTED:  return "Not connected";
        case VPN_BRIDGE_ERROR_ALREADY_INIT:   return "Already initialized";
        case VPN_BRIDGE_ERROR_NOT_INIT:       return "Not initialized";
        default:                               return "Unknown error";
    }
}

/* ============================================
 * Library Initialization
 * ============================================ */

int vpn_bridge_init(bool debug) {
    printf("[DEBUG] vpn_bridge_init starting...\n");
    fflush(stdout);
    
    printf("[DEBUG] Enabling minimal mode (skips hamcore/string tables)...\n");
    fflush(stdout);
    
    // Enable minimal mode BEFORE Init to skip hamcore.se2 and string table loading
    MayaquaMinimalMode();
    
    printf("[DEBUG] Attempting client initialization...\n");
    fflush(stdout);
    
    // For macOS, we need to provide a valid executable path
    // Using absolute path to current executable
    char *fake_argv[] = { "vpnclient", NULL };
    
    // Try full initialization with debug enabled
    printf("[DEBUG] Calling InitMayaqua...\n");
    fflush(stdout);
    
    InitMayaqua(false, true, 1, fake_argv);
    
    printf("[DEBUG] ✅ InitMayaqua completed successfully!\n");
    fflush(stdout);
    
    printf("[DEBUG] Calling InitCedar...\n");
    fflush(stdout);
    
    InitCedar();
    
    printf("[DEBUG] ✅ InitCedar completed successfully!\n");
    fflush(stdout);
    
    g_initialized = true;
    return VPN_BRIDGE_SUCCESS;
}

void vpn_bridge_cleanup(void) {
    if (!g_initialized) {
        return;
    }
    
    // Cleanup SoftEther layers
    FreeCedar();
    FreeMayaqua();
    
    g_initialized = false;
}

bool vpn_bridge_is_initialized(void) {
    return g_initialized;
}

/* ============================================
 * Client Management
 * ============================================ */

VpnBridgeClient* vpn_bridge_create_client(void) {
    printf("[DEBUG] vpn_bridge_create_client called\n");
    fflush(stdout);
    
    if (!g_initialized) {
        printf("[DEBUG] ERROR: Not initialized!\n");
        fflush(stdout);
        return NULL;
    }
    
    printf("[DEBUG] Allocating VpnBridgeClient structure...\n");
    fflush(stdout);
    
    VpnBridgeClient* client = (VpnBridgeClient*)calloc(1, sizeof(VpnBridgeClient));
    if (!client) {
        printf("[DEBUG] ERROR: calloc failed!\n");
        fflush(stdout);
        return NULL;
    }
    
    // Initialize with defaults
    client->status = VPN_STATUS_DISCONNECTED;
    client->last_error = VPN_BRIDGE_SUCCESS;
    client->port = 443;
    
    printf("[DEBUG] Calling CiNewClient()...\n");
    fflush(stdout);
    
    // Create real SoftEther CLIENT structure
    client->softether_client = CiNewClient();
    
    printf("[DEBUG] CiNewClient() returned: %p\n", (void*)client->softether_client);
    fflush(stdout);
    if (!client->softether_client) {
        free(client);
        return NULL;
    }
    
    return client;
}

void vpn_bridge_free_client(VpnBridgeClient* client) {
    if (!client) {
        return;
    }
    
    printf("[vpn_bridge_free_client] Cleaning up client...\n");
    fflush(stdout);
    
    // Disconnect if still connected
    if (client->status == VPN_STATUS_CONNECTED) {
        printf("[vpn_bridge_free_client] Client still connected, disconnecting...\n");
        fflush(stdout);
        vpn_bridge_disconnect(client);
    }
    
    // Free real SoftEther CLIENT structure
    // NOTE: If we already disconnected, skip CiCleanupClient as it may access freed resources
    if (client->softether_client && client->status != VPN_STATUS_DISCONNECTED) {
        printf("[vpn_bridge_free_client] Cleaning up SoftEther CLIENT...\n");
        fflush(stdout);
        CiCleanupClient(client->softether_client);
        client->softether_client = NULL;
    } else {
        printf("[vpn_bridge_free_client] Skipping CiCleanupClient (already disconnected)\n");
        fflush(stdout);
        // Just free the CLIENT structure directly
        if (client->softether_client) {
            Free(client->softether_client);
            client->softether_client = NULL;
        }
    }
    
    // Clear sensitive data
    memset(client->password, 0, sizeof(client->password));
    
    printf("[vpn_bridge_free_client] Freeing client structure...\n");
    fflush(stdout);
    
    free(client);
    
    printf("[vpn_bridge_free_client] ✅ Client freed\n");
    fflush(stdout);
}

/* ============================================
 * Connection Configuration
 * ============================================ */

int vpn_bridge_configure(
    VpnBridgeClient* client,
    const char* hostname,
    uint16_t port,
    const char* hub_name,
    const char* username,
    const char* password
) {
    if (!client || !hostname || !hub_name || !username || !password) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    // Store configuration
    strncpy(client->hostname, hostname, sizeof(client->hostname) - 1);
    client->hostname[sizeof(client->hostname) - 1] = '\0';
    
    client->port = port;
    
    strncpy(client->hub_name, hub_name, sizeof(client->hub_name) - 1);
    client->hub_name[sizeof(client->hub_name) - 1] = '\0';
    
    strncpy(client->username, username, sizeof(client->username) - 1);
    client->username[sizeof(client->username) - 1] = '\0';
    
    strncpy(client->password, password, sizeof(client->password) - 1);
    client->password[sizeof(client->password) - 1] = '\0';
    
    return VPN_BRIDGE_SUCCESS;
}

/* ============================================
 * Connection Operations
 * ============================================ */

int vpn_bridge_connect(VpnBridgeClient* client) {
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    if (!g_initialized) {
        client->last_error = VPN_BRIDGE_ERROR_NOT_INIT;
        return VPN_BRIDGE_ERROR_NOT_INIT;
    }
    
    if (client->status == VPN_STATUS_CONNECTED) {
        return VPN_BRIDGE_SUCCESS; // Already connected
    }
    
    // Validate configuration
    if (client->hostname[0] == '\0' || 
        client->hub_name[0] == '\0' ||
        client->username[0] == '\0') {
        client->last_error = VPN_BRIDGE_ERROR_INVALID_PARAM;
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    printf("[vpn_bridge_connect] Creating account...\n");
    fflush(stdout);
    
    client->status = VPN_STATUS_CONNECTING;
    
    // Create CLIENT_OPTION structure
    CLIENT_OPTION* opt = ZeroMalloc(sizeof(CLIENT_OPTION));
    
    // Set account name (used internally)
    UniStrCpy(opt->AccountName, sizeof(opt->AccountName), L"ZigBridge");
    
    // Set server connection details
    StrCpy(opt->Hostname, sizeof(opt->Hostname), client->hostname);
    opt->Port = client->port;
    StrCpy(opt->HubName, sizeof(opt->HubName), client->hub_name);
    
    // Set device name to avoid VirtualHost mode (empty DeviceName triggers NAT/VH mode)
    // Use a dummy device name - our packet adapter will handle the actual TUN device
    StrCpy(opt->DeviceName, sizeof(opt->DeviceName), "vpn_tun");
    
    // Connection settings
    opt->MaxConnection = 1;              // Single TCP connection
    opt->UseEncrypt = true;              // Use encryption
    opt->UseCompress = false;            // No compression for now
    opt->HalfConnection = false;         // Full connection
    opt->NoRoutingTracking = true;       // Don't track routing
    opt->NumRetry = 10;                  // Retry attempts
    opt->RetryInterval = 5;              // 5 seconds between retries
    opt->AdditionalConnectionInterval = 1;
    
    printf("[vpn_bridge_connect] CLIENT_OPTION created: %s:%d hub=%s\n", 
           opt->Hostname, opt->Port, opt->HubName);
    fflush(stdout);
    
    // Create CLIENT_AUTH structure for password authentication
    CLIENT_AUTH* auth = ZeroMalloc(sizeof(CLIENT_AUTH));
    auth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
    
    // Set username
    StrCpy(auth->Username, sizeof(auth->Username), client->username);
    
    // Hash the password using SoftEther's method
    HashPassword(auth->HashedPassword, client->username, client->password);
    
    printf("[vpn_bridge_connect] CLIENT_AUTH created: user=%s, type=%d\n", 
           auth->Username, auth->AuthType);
    fflush(stdout);
    
    // Create ACCOUNT structure
    ACCOUNT* account = ZeroMalloc(sizeof(ACCOUNT));
    account->lock = NewLock();
    account->ClientOption = opt;
    account->ClientAuth = auth;
    account->CheckServerCert = false;  // Don't validate server cert for now
    account->ServerCert = NULL;
    account->ClientSession = NULL;  // Will be set by SESSION
    
    client->softether_account = account;
    
    printf("[vpn_bridge_connect] Creating packet adapter...\n");
    fflush(stdout);
    
    // Create platform-specific packet adapter
    PACKET_ADAPTER* pa = NEW_PACKET_ADAPTER();
    if (!pa) {
        printf("[vpn_bridge_connect] Failed to create packet adapter\n");
        DeleteLock(account->lock);
        Free(account);
        client->last_error = VPN_BRIDGE_ERROR_CONNECT_FAILED;
        client->status = VPN_STATUS_ERROR;
        return VPN_BRIDGE_ERROR_CONNECT_FAILED;
    }
    
    printf("[vpn_bridge_connect] Packet adapter created at %p, Id=%u\\n", pa, pa->Id);
    fflush(stdout);
    
    client->packet_adapter = pa;
    
    printf("[vpn_bridge_connect] Creating session with NewClientSessionEx()...\n");
    printf("[vpn_bridge_connect] Cedar=%p, opt=%p, auth=%p, pa=%p, account=%p\n",
           client->softether_client->Cedar, opt, auth, pa, account);
    fflush(stdout);
    
    printf("[vpn_bridge_connect] About to call NewClientSessionEx - this may block...\n");
    fflush(stdout);
    
    // Create session - this will automatically connect in background
    SESSION* session = NewClientSessionEx(
        client->softether_client->Cedar,
        opt,
        auth,
        pa,
        account
    );
    
    printf("[vpn_bridge_connect] NewClientSessionEx returned: %p\n", session);
    fflush(stdout);
    
    if (!session) {
        printf("[vpn_bridge_connect] Failed to create session\n");
        FreePacketAdapter(pa);
        DeleteLock(account->lock);
        Free(account);
        client->last_error = VPN_BRIDGE_ERROR_CONNECT_FAILED;
        client->status = VPN_STATUS_ERROR;
        return VPN_BRIDGE_ERROR_CONNECT_FAILED;
    }
    
    client->softether_session = session;
    account->ClientSession = session;
    
    printf("[vpn_bridge_connect] Session created at %p, waiting for connection...\n", session);
    fflush(stdout);
    
    // Wait for connection to establish (up to 30 seconds)
    UINT64 start_time = Tick64();
    bool connected = false;
    int check_count = 0;
    
    while ((Tick64() - start_time) < 30000) {  // 30 second timeout
        UINT status;
        
        // Safely read status with lock
        Lock(session->lock);
        {
            status = session->ClientStatus;
        }
        Unlock(session->lock);
        
        if (check_count % 10 == 0) {  // Log every second
            printf("[vpn_bridge_connect] Waiting... status=%u, elapsed=%llums\n", 
                   status, (Tick64() - start_time));
            fflush(stdout);
        }
        check_count++;
        
        if (status == CLIENT_STATUS_ESTABLISHED) {
            connected = true;
            break;
        }
        
        bool should_halt = false;
        Lock(session->lock);
        {
            should_halt = session->Halt;
        }
        Unlock(session->lock);
        
        if (should_halt || status == CLIENT_STATUS_IDLE) {
            printf("[vpn_bridge_connect] Connection failed: Halt=%d, Status=%u\n",
                   should_halt, status);
            fflush(stdout);
            break;
        }
        
        SleepThread(100);  // Check every 100ms
    }
    
    if (connected) {
        printf("[vpn_bridge_connect] ✅ VPN connection established!\n");
        client->status = VPN_STATUS_CONNECTED;
        client->last_error = VPN_BRIDGE_SUCCESS;
        client->connect_time = Tick64();
        return VPN_BRIDGE_SUCCESS;
    } else {
        printf("[vpn_bridge_connect] ❌ Connection failed or timeout\n");
        
        // Cleanup failed connection
        StopSession(session);
        ReleaseSession(session);
        client->softether_session = NULL;
        account->ClientSession = NULL;
        
        FreePacketAdapter(pa);
        client->packet_adapter = NULL;
        
        DeleteLock(account->lock);
        Free(account);
        client->softether_account = NULL;
        
        client->status = VPN_STATUS_ERROR;
        client->last_error = VPN_BRIDGE_ERROR_CONNECT_FAILED;
        return VPN_BRIDGE_ERROR_CONNECT_FAILED;
    }
}

int vpn_bridge_disconnect(VpnBridgeClient* client) {
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    if (client->status != VPN_STATUS_CONNECTED) {
        return VPN_BRIDGE_ERROR_NOT_CONNECTED;
    }
    
    printf("[vpn_bridge_disconnect] Stopping VPN session...\n");
    fflush(stdout);
    
    // Stop and release SESSION
    if (client->softether_session) {
        printf("[vpn_bridge_disconnect] Calling StopSession...\n");
        fflush(stdout);
        
        StopSession(client->softether_session);
        
        printf("[vpn_bridge_disconnect] Calling ReleaseSession...\n");
        fflush(stdout);
        
        ReleaseSession(client->softether_session);
        
        printf("[vpn_bridge_disconnect] Session released\n");
        fflush(stdout);
        
        client->softether_session = NULL;
    }
    
    printf("[vpn_bridge_disconnect] Freeing packet adapter...\n");
    fflush(stdout);
    
    // Cleanup packet adapter (will close TUN device)
    if (client->packet_adapter) {
        FreePacketAdapter(client->packet_adapter);
        client->packet_adapter = NULL;
    }
    
    printf("[vpn_bridge_disconnect] Packet adapter freed\n");
    fflush(stdout);
    
    // Cleanup ACCOUNT
    if (client->softether_account) {
        printf("[vpn_bridge_disconnect] Freeing account...\n");
        fflush(stdout);
        
        ACCOUNT* account = client->softether_account;
        account->ClientSession = NULL;
        
        if (account->lock) {
            DeleteLock(account->lock);
        }
        
        // Note: CLIENT_OPTION and CLIENT_AUTH are freed by SESSION
        Free(account);
        client->softether_account = NULL;
        
        printf("[vpn_bridge_disconnect] Account freed\n");
        fflush(stdout);
    }
    
    client->status = VPN_STATUS_DISCONNECTED;
    client->last_error = VPN_BRIDGE_SUCCESS;
    
    printf("[vpn_bridge_disconnect] ✅ Disconnected cleanly\n");
    fflush(stdout);
    
    return VPN_BRIDGE_SUCCESS;
}

VpnBridgeStatus vpn_bridge_get_status(const VpnBridgeClient* client) {
    if (!client) {
        return VPN_STATUS_ERROR;
    }
    
    // If we have an active session, check its real status
    if (client->softether_session) {
        SESSION* s = client->softether_session;
        
        if (s->ClientStatus == CLIENT_STATUS_ESTABLISHED) {
            return VPN_STATUS_CONNECTED;
        } else if (s->ClientStatus == CLIENT_STATUS_CONNECTING ||
                   s->ClientStatus == CLIENT_STATUS_NEGOTIATION ||
                   s->ClientStatus == CLIENT_STATUS_AUTH) {
            return VPN_STATUS_CONNECTING;
        } else if (s->Halt || s->ClientStatus == CLIENT_STATUS_IDLE) {
            return VPN_STATUS_ERROR;
        }
    }
    
    return client->status;
}

/* ============================================
 * Connection Information
 * ============================================ */

int vpn_bridge_get_connection_info(
    const VpnBridgeClient* client,
    uint64_t* bytes_sent,
    uint64_t* bytes_received,
    uint64_t* connected_time
) {
    if (!client || !bytes_sent || !bytes_received || !connected_time) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    // Get real statistics from SESSION if available
    if (client->softether_session) {
        SESSION* s = client->softether_session;
        
        // Safely read stats with lock
        Lock(s->lock);
        {
            *bytes_sent = s->TotalSendSize;
            *bytes_received = s->TotalRecvSize;
        }
        Unlock(s->lock);
    } else {
        *bytes_sent = client->bytes_sent;
        *bytes_received = client->bytes_received;
    }
    
    if (client->connect_time > 0 && client->status == VPN_STATUS_CONNECTED) {
        *connected_time = (Tick64() - client->connect_time) / 1000;
    } else {
        *connected_time = 0;
    }
    
    return VPN_BRIDGE_SUCCESS;
}

uint32_t vpn_bridge_get_last_error(const VpnBridgeClient* client) {
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    return client->last_error;
}

const char* vpn_bridge_get_error_message(int error_code) {
    return get_error_message_internal(error_code);
}

/* ============================================
 * Version Information
 * ============================================ */

const char* vpn_bridge_version(void) {
    return "0.1.0-bridge";
}

const char* vpn_bridge_softether_version(void) {
    // TODO: Return real SoftEther version
    // return CEDAR_VERSION_STR;
    return "4.44-9807 (stub)";
}
