/*
 * Stub Functions for Minimal Client Build
 * 
 * These provide empty/stub implementations for functions that are
 * referenced by the SoftEther codebase but not needed for the minimal
 * VPN client functionality (VLan, TAP, HTTP downloads, WPC).
 */

#include "Mayaqua/Mayaqua.h"
#include "Cedar/Cedar.h"
#include "macos/packet_adapter_macos.h"

//============================================================================
// Adapter redirect - NewZigPacketAdapter calls macOS TUN adapter
//============================================================================

// Forward declaration
extern PACKET_ADAPTER *NewMacOsTunAdapter(void);

// NewZigPacketAdapter just calls the macOS TUN adapter
PACKET_ADAPTER *NewZigPacketAdapter(void) {
    return NewMacOsTunAdapter();
}

// Stub for device name (handled in C)
size_t zig_adapter_get_device_name(void *adapter, uint8_t *buf, size_t size) {
    (void)adapter; (void)buf; (void)size;
    return 0;
}

//============================================================================
// VLan/TAP stubs (not needed for TUN-based client)
//============================================================================

void UnixVLanInit(void) {}
bool UnixVLanCreate(char *name, UCHAR *mac_address) { (void)name; (void)mac_address; return false; }
void UnixVLanDelete(char *name) { (void)name; }
void UnixVLanFree(void *vlan) { (void)vlan; }
PACKET_ADAPTER *VLanGetPacketAdapter(void) { return NULL; }
bool VLanPutPacket(VLAN *v, void *buf, UINT size) { (void)v; (void)buf; (void)size; return false; }
void FreeTap(void *tap) { (void)tap; }

//============================================================================
// HTTP/URL stubs (not needed for basic VPN connectivity)
//============================================================================

bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer) { 
    (void)data; (void)str; (void)is_post; (void)referrer; 
    return false; 
}

BUF *HttpRequestEx(URL_DATA *data, INTERNET_SETTING *setting,
                   UINT timeout_connect, UINT timeout_comm,
                   UINT *error_code, bool check_ssl_trust, char *post_data,
                   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
                   bool *cancel, UINT max_recv_size) { 
    (void)data; (void)setting; (void)timeout_connect; (void)timeout_comm; 
    (void)error_code; (void)check_ssl_trust; (void)post_data; (void)recv_callback;
    (void)recv_callback_param; (void)sha1_cert_hash; (void)cancel; (void)max_recv_size;
    return NULL; 
}

BUF *HttpRequestEx3(URL_DATA *data, INTERNET_SETTING *setting,
                    UINT timeout_connect, UINT timeout_comm,
                    UINT *error_code, bool check_ssl_trust, char *post_data,
                    WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
                    bool *cancel, UINT max_recv_size, char *header_name, char *header_value) { 
    (void)data; (void)setting; (void)timeout_connect; (void)timeout_comm;
    (void)error_code; (void)check_ssl_trust; (void)post_data; (void)recv_callback;
    (void)recv_callback_param; (void)sha1_cert_hash; (void)num_hashes; (void)cancel;
    (void)max_recv_size; (void)header_name; (void)header_value;
    return NULL; 
}

//============================================================================
// WPC (Windows Proxy Configuration) stubs - not used on Unix
//============================================================================

PACK *WpcCall(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
              char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash) { 
    (void)url; (void)setting; (void)timeout_connect; (void)timeout_comm;
    (void)function_name; (void)pack; (void)cert; (void)key; (void)sha1_cert_hash;
    return NULL; 
}

PACK *WpcCallEx2(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
                 char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, UINT num_hashes, bool *cancel, UINT max_recv_size,
                 char *additional_header_name, char *additional_header_value, char *sni_string) { 
    (void)url; (void)setting; (void)timeout_connect; (void)timeout_comm;
    (void)function_name; (void)pack; (void)cert; (void)key; (void)sha1_cert_hash;
    (void)num_hashes; (void)cancel; (void)max_recv_size; (void)additional_header_name;
    (void)additional_header_value; (void)sni_string;
    return NULL; 
}

SOCK *WpcSockConnect2(char *hostname, UINT port, INTERNET_SETTING *t, UINT *error_code, UINT timeout) { 
    (void)hostname; (void)port; (void)t; (void)error_code; (void)timeout;
    return NULL; 
}
