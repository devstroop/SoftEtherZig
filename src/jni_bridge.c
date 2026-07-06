#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================================
// Forward declarations of Zig-exported C symbols from ffi.zig
// ============================================================================

typedef struct VpnClient VpnClient;

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    int64_t  connect_time_ms;
    uint32_t reconnect_count;
    uint32_t _padding;
} CStats;

VpnClient* softether_create(const char* server, unsigned short port, const char* hub,
                            const char* username, const char* password);
VpnClient* softether_create_anonymous(const char* server, unsigned short port, const char* hub);
VpnClient* softether_create_certificate(const char* server, unsigned short port, const char* hub,
                                        const unsigned char* cert_pem, unsigned int cert_pem_len,
                                        const unsigned char* key_pem, unsigned int key_pem_len);
void softether_destroy(VpnClient* client);
int  softether_connect(VpnClient* client);
void softether_disconnect(VpnClient* client);
int  softether_run_data_loop(VpnClient* client);
void softether_request_stop(VpnClient* client);
int  softether_get_state(const VpnClient* client);
int  softether_is_connected(const VpnClient* client);
int  softether_get_stats(const VpnClient* client, CStats* out);
unsigned int softether_get_assigned_ip(const VpnClient* client);
unsigned int softether_get_gateway_ip(const VpnClient* client);
unsigned int softether_get_assigned_mask(const VpnClient* client);
unsigned int softether_get_assigned_dns1(const VpnClient* client);
unsigned int softether_get_assigned_dns2(const VpnClient* client);
unsigned int softether_get_effective_server_ip(const VpnClient* client);
void softether_set_tunnel_fd(VpnClient* client, int fd);
void softether_set_tunnel_fds(VpnClient* client, int dl_fd, int ul_fd);
int  softether_replace_tun_fd(VpnClient* client, int fd);
void softether_set_encryption(VpnClient* client, int enabled);
void softether_set_compression(VpnClient* client, int enabled);
void softether_set_verify_certificate(VpnClient* client, int verify);
void softether_set_default_route(VpnClient* client, int enabled);
void softether_set_mtu(VpnClient* client, unsigned short mtu);
void softether_set_reconnect(VpnClient* client, int enabled, unsigned int max_attempts);
void softether_set_max_connections(VpnClient* client, unsigned char count);
void softether_set_half_connection(VpnClient* client, int enabled);
void softether_set_qos(VpnClient* client, int enabled);
void softether_set_udp_acceleration(VpnClient* client, int enabled);
void softether_set_connect_timeout(VpnClient* client, unsigned int ms);
void softether_set_read_timeout(VpnClient* client, unsigned int ms);
void softether_set_keepalive_interval(VpnClient* client, unsigned int ms);
void softether_set_ip_version(VpnClient* client, int version);
void softether_set_plain_password(VpnClient* client);
void softether_set_proxy(VpnClient* client, int type, const char* host, unsigned short port,
                         const char* username, const char* password);
void softether_set_accept_pushed_routes(VpnClient* client, int enabled);
void softether_set_enable_custom_routes(VpnClient* client, int enabled);
void softether_set_ipv4_include(VpnClient* client, const char* routes);
void softether_set_ipv4_exclude(VpnClient* client, const char* routes);
void softether_set_ipv6_include(VpnClient* client, const char* routes);
void softether_set_ipv6_exclude(VpnClient* client, const char* routes);
void softether_set_static_ipv4(VpnClient* client, const char* addr);
void softether_set_static_ipv4_netmask(VpnClient* client, const char* addr);
void softether_set_static_ipv4_gateway(VpnClient* client, const char* addr);
void softether_set_static_ipv6(VpnClient* client, const char* addr);
void softether_set_static_ipv6_prefix(VpnClient* client, unsigned char prefix);
void softether_set_static_ipv6_gateway(VpnClient* client, const char* addr);
void softether_set_dns_servers(VpnClient* client, const char* servers);
void softether_set_client_str(VpnClient* client, const char* str);
void softether_set_client_ver(VpnClient* client, unsigned int ver);
void softether_set_client_build(VpnClient* client, unsigned int build);
void softether_set_os_info(VpnClient* client, const char* name, const char* version, const char* title);

// ============================================================================
// Minimal JSON parser for config string
// ============================================================================

static const char* skip_ws(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static const char* skip_string(const char* p) {
    if (*p != '"') return p;
    p++;
    while (*p != '\0') {
        if (*p == '\\') { if (p[1] != '\0') p += 2; else break; }
        else if (*p == '"') { p++; return p; }
        else p++;
    }
    return p;
}

static const char* skip_value(const char* p) {
    p = skip_ws(p);
    if (*p == '"') return skip_string(p + 1);
    if (*p == '{' || *p == '[') {
        int depth = 1;
        p++;
        while (*p != '\0' && depth > 0) {
            if (*p == '"') p = skip_string(p);
            else if (*p == '{' || *p == '[') { depth++; p++; }
            else if (*p == '}' || *p == ']') { depth--; p++; }
            else p++;
        }
        return p;
    }
    while (*p != '\0' && *p != ',' && *p != '}' && *p != ']' && *p != ' ') p++;
    return p;
}

static const char* find_key(const char* json, const char* key) {
    size_t klen = strlen(key);
    const char* p = json;
    while ((p = strstr(p, key)) != NULL) {
        if ((p == json || *(p-1) == '"') && p[klen] == '"') {
            p = p + klen + 1;
            p = skip_ws(p);
            if (*p == ':') return p + 1;
        }
        p++;
    }
    return NULL;
}

static int json_get_int(const char* json, const char* key, int default_val) {
    const char* p = find_key(json, key);
    if (!p) return default_val;
    p = skip_ws(p);
    return (int)strtol(p, NULL, 10);
}

static int json_get_bool(const char* json, const char* key, int default_val) {
    const char* p = find_key(json, key);
    if (!p) return default_val;
    p = skip_ws(p);
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return default_val;
}

static const char* json_get_string(const char* json, const char* key, char* buf, size_t buf_size) {
    const char* p = find_key(json, key);
    if (!p) { buf[0] = '\0'; return buf; }
    p = skip_ws(p);
    if (*p != '"') { buf[0] = '\0'; return buf; }
    p++;
    size_t i = 0;
    while (*p != '\0' && *p != '"' && i < buf_size - 1) {
        if (*p == '\\' && *(p+1) != '\0') {
            p++;
            switch (*p) {
                case '"': buf[i++] = '"'; break;
                case '\\': buf[i++] = '\\'; break;
                default: buf[i++] = *p; break;
            }
        } else {
            buf[i++] = *p;
        }
        p++;
    }
    buf[i] = '\0';
    return buf;
}

// ============================================================================
// JNI Native method implementations
// ============================================================================

static jstring string_from_ip(JNIEnv* env, unsigned int ip) {
    if (ip == 0) return NULL;
    unsigned char bytes[4];
    bytes[0] = (ip >> 24) & 0xFF;
    bytes[1] = (ip >> 16) & 0xFF;
    bytes[2] = (ip >> 8) & 0xFF;
    bytes[3] = ip & 0xFF;
    char buf[20];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jlong JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeCreate(
    JNIEnv* env, jclass clazz, jstring configJson)
{
    const char* json = (*env)->GetStringUTFChars(env, configJson, NULL);
    if (!json) return 0;

    char server[256], hub[256], username[256], password[256];
    int port, auth_type;
    VpnClient* client = NULL;

    json_get_string(json, "server", server, sizeof(server));
    port = json_get_int(json, "port", 443);
    json_get_string(json, "hub", hub, sizeof(hub));
    json_get_string(json, "username", username, sizeof(username));
    json_get_string(json, "password", password, sizeof(password));
    auth_type = json_get_int(json, "authType", 0);

    if (auth_type == 2) {
        char cert_pem_buf[8192], key_pem_buf[8192];
        json_get_string(json, "certPem", cert_pem_buf, sizeof(cert_pem_buf));
        json_get_string(json, "keyPem", key_pem_buf, sizeof(key_pem_buf));
        if (strlen(cert_pem_buf) > 0 && strlen(key_pem_buf) > 0) {
            client = softether_create_certificate(
                server, (unsigned short)port, hub,
                (const unsigned char*)cert_pem_buf, (unsigned int)strlen(cert_pem_buf),
                (const unsigned char*)key_pem_buf, (unsigned int)strlen(key_pem_buf)
            );
        } else {
            client = NULL;
        }
    } else if (auth_type == 3 || strlen(username) == 0) {
        client = softether_create_anonymous(server, (unsigned short)port, hub);
    } else {
        client = softether_create(
            server, (unsigned short)port, hub, username, password
        );
    }

    if (!client) {
        (*env)->ReleaseStringUTFChars(env, configJson, json);
        return 0;
    }

    softether_set_encryption(client, json_get_bool(json, "useEncryption", 1));
    softether_set_compression(client, json_get_bool(json, "useCompression", 0));
    softether_set_verify_certificate(client, json_get_bool(json, "verifyCertificate", 1));
    softether_set_default_route(client, json_get_bool(json, "defaultRoute", 1));
    softether_set_mtu(client, (unsigned short)json_get_int(json, "mtu", 1400));

    softether_set_reconnect(client,
        json_get_bool(json, "autoReconnect", 1),
        (unsigned int)json_get_int(json, "maxReconnectAttempts", 10)
    );
    softether_set_max_connections(client,
        (unsigned char)json_get_int(json, "maxConnections", 1)
    );
    softether_set_half_connection(client,
        json_get_bool(json, "halfConnection", 0)
    );
    softether_set_qos(client, json_get_bool(json, "qos", 1));
    softether_set_udp_acceleration(client,
        json_get_bool(json, "udpAcceleration", 0)
    );
    softether_set_connect_timeout(client,
        (unsigned int)json_get_int(json, "connectTimeoutMs", 30000)
    );
    softether_set_read_timeout(client,
        (unsigned int)json_get_int(json, "readTimeoutMs", 60000)
    );
    softether_set_keepalive_interval(client,
        (unsigned int)json_get_int(json, "keepaliveIntervalMs", 10000)
    );

    if (json_get_bool(json, "plainPassword", 0)) {
        softether_set_plain_password(client);
    }

    int proxy_type = json_get_int(json, "proxyType", 0);
    if (proxy_type > 0) {
        char proxy_host[256], proxy_user[256], proxy_pass[256];
        json_get_string(json, "proxyServer", proxy_host, sizeof(proxy_host));
        json_get_string(json, "proxyUsername", proxy_user, sizeof(proxy_user));
        json_get_string(json, "proxyPassword", proxy_pass, sizeof(proxy_pass));
        int proxy_port = json_get_int(json, "proxyPort", 0);
        if (strlen(proxy_host) > 0 && proxy_port > 0) {
            softether_set_proxy(client, proxy_type, proxy_host,
                (unsigned short)proxy_port,
                proxy_user, proxy_pass);
        }
    }

    int ip_version = json_get_int(json, "ipVersion", 0);
    if (ip_version > 0) softether_set_ip_version(client, ip_version);

    softether_set_accept_pushed_routes(client,
        json_get_bool(json, "acceptPushedRoutes", 1)
    );
    softether_set_enable_custom_routes(client,
        json_get_bool(json, "enableCustomRoutes", 0)
    );

    char tmp[1024];
    json_get_string(json, "ipv4IncludedRoutes", tmp, sizeof(tmp));
    if (strlen(tmp) > 0) softether_set_ipv4_include(client, tmp);
    json_get_string(json, "ipv4ExcludedRoutes", tmp, sizeof(tmp));
    if (strlen(tmp) > 0) softether_set_ipv4_exclude(client, tmp);
    json_get_string(json, "ipv6IncludedRoutes", tmp, sizeof(tmp));
    if (strlen(tmp) > 0) softether_set_ipv6_include(client, tmp);
    json_get_string(json, "ipv6ExcludedRoutes", tmp, sizeof(tmp));
    if (strlen(tmp) > 0) softether_set_ipv6_exclude(client, tmp);

    json_get_string(json, "staticIpv4", tmp, sizeof(tmp));
    if (strlen(tmp) > 0) {
        softether_set_static_ipv4(client, tmp);
        json_get_string(json, "staticIpv4Netmask", tmp, sizeof(tmp));
        if (strlen(tmp) > 0) softether_set_static_ipv4_netmask(client, tmp);
        json_get_string(json, "staticIpv4Gateway", tmp, sizeof(tmp));
        if (strlen(tmp) > 0) softether_set_static_ipv4_gateway(client, tmp);
    }
    json_get_string(json, "staticIpv6", tmp, sizeof(tmp));
    if (strlen(tmp) > 0) {
        softether_set_static_ipv6(client, tmp);
        int prefix = json_get_int(json, "staticIpv6Prefix", 0);
        if (prefix > 0) softether_set_static_ipv6_prefix(client, (unsigned char)prefix);
        json_get_string(json, "staticIpv6Gateway", tmp, sizeof(tmp));
        if (strlen(tmp) > 0) softether_set_static_ipv6_gateway(client, tmp);
    }

    json_get_string(json, "dnsServers", tmp, sizeof(tmp));
    if (strlen(tmp) > 0) softether_set_dns_servers(client, tmp);

    json_get_string(json, "clientStr", tmp, sizeof(tmp));
    if (strlen(tmp) > 0) softether_set_client_str(client, tmp);

    int client_ver = json_get_int(json, "clientVer", 0);
    if (client_ver > 0) softether_set_client_ver(client, (unsigned int)client_ver);
    int client_build = json_get_int(json, "clientBuild", 0);
    if (client_build > 0) softether_set_client_build(client, (unsigned int)client_build);

    char os_name[128], os_ver[128], os_title[256];
    json_get_string(json, "osName", os_name, sizeof(os_name));
    json_get_string(json, "osVersion", os_ver, sizeof(os_ver));
    json_get_string(json, "osTitle", os_title, sizeof(os_title));
    if (strlen(os_name) > 0 && strlen(os_ver) > 0 && strlen(os_title) > 0) {
        softether_set_os_info(client, os_name, os_ver, os_title);
    }

    (*env)->ReleaseStringUTFChars(env, configJson, json);
    return (jlong)(intptr_t)client;
}

JNIEXPORT void JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeDestroy(
    JNIEnv* env, jclass clazz, jlong handle)
{
    if (handle != 0) {
        softether_destroy((VpnClient*)(intptr_t)handle);
    }
}

JNIEXPORT void JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeSetTunnelFd(
    JNIEnv* env, jclass clazz, jlong handle, jint fd)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (client) softether_set_tunnel_fd(client, fd);
}

JNIEXPORT jint JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeConnect(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return -1;
    return softether_connect(client);
}

JNIEXPORT jint JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeRunDataLoop(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return -1;
    return softether_run_data_loop(client);
}

JNIEXPORT void JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeRequestStop(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (client) softether_request_stop(client);
}

JNIEXPORT jint JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetState(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return 0;
    return softether_get_state(client);
}

JNIEXPORT jbyteArray JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetStats(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return NULL;

    CStats stats;
    memset(&stats, 0, sizeof(stats));
    int rc = softether_get_stats(client, &stats);
    if (rc != 0) return NULL;

    jbyteArray result = (*env)->NewByteArray(env, sizeof(CStats));
    if (!result) return NULL;
    (*env)->SetByteArrayRegion(env, result, 0, sizeof(CStats), (const jbyte*)&stats);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetAssignedIp(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return NULL;
    unsigned int ip = softether_get_assigned_ip(client);
    return string_from_ip(env, ip);
}

JNIEXPORT jstring JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetGatewayIp(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return NULL;
    unsigned int ip = softether_get_gateway_ip(client);
    return string_from_ip(env, ip);
}

JNIEXPORT jint JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetAssignedMask(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return 0;
    return (jint)softether_get_assigned_mask(client);
}

JNIEXPORT jint JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetAssignedDns1(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return 0;
    return (jint)softether_get_assigned_dns1(client);
}

JNIEXPORT jint JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetAssignedDns2(
    JNIEnv* env, jclass clazz, jlong handle)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return 0;
    return (jint)softether_get_assigned_dns2(client);
}

JNIEXPORT jint JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeReplaceTunFd(
    JNIEnv* env, jclass clazz, jlong handle, jint fd)
{
    VpnClient* client = (VpnClient*)(intptr_t)handle;
    if (!client) return -1;
    return softether_replace_tun_fd(client, fd);
}

// ============================================================================
// JNI_OnLoad — just return the version so the library loads.
// RegisterNatives happens via nativeRegisterNatives() called from the
// companion object's init block (where the classloader context is valid).
// ============================================================================

static const JNINativeMethod gMethods[] = {
    { "nativeCreate",        "(Ljava/lang/String;)J",  (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeCreate },
    { "nativeDestroy",       "(J)V",                   (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeDestroy },
    { "nativeSetTunnelFd",   "(JI)V",                  (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeSetTunnelFd },
    { "nativeConnect",       "(J)I",                   (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeConnect },
    { "nativeRunDataLoop",   "(J)I",                   (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeRunDataLoop },
    { "nativeRequestStop",   "(J)V",                   (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeRequestStop },
    { "nativeGetState",      "(J)I",                   (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetState },
    { "nativeGetStats",      "(J)[B",                  (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetStats },
    { "nativeGetAssignedIp",  "(J)Ljava/lang/String;",  (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetAssignedIp },
    { "nativeGetGatewayIp",   "(J)Ljava/lang/String;",  (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetGatewayIp },
    { "nativeGetAssignedMask","(J)I",                   (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetAssignedMask },
    { "nativeGetAssignedDns1","(J)I",                   (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetAssignedDns1 },
    { "nativeGetAssignedDns2","(J)I",                   (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeGetAssignedDns2 },
    { "nativeReplaceTunFd",  "(JI)I",                  (void*)Java_com_worxvpn_vpnclient_SoftetherVpnService_nativeReplaceTunFd },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    // Just return the version. FindClass for application classes can fail in
    // the :vpn child process where the classloader context is restricted.
    // nativeRegisterNatives() (called from the companion object init) handles
    // registration with the correct classloader.
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}

// Called from SoftetherVpnService.Companion.nativeRegisterNatives() after
// System.loadLibrary. The companion object's classloader context is valid,
// so FindClass succeeds here. The methods are declared in the companion
// object, so we register on the companion class directly.
JNIEXPORT void JNICALL
Java_com_worxvpn_vpnclient_SoftetherVpnService_00024Companion_nativeRegisterNatives(
    JNIEnv* env, jobject thiz)
{
    // nativeRegisterNatives() is an instance method on the companion object,
    // so thiz is the companion instance (not a jclass).  We need the actual
    // companion Class to register on — get it from the object.
    jclass companionClass = (*env)->GetObjectClass(env, thiz);
    if (!companionClass) return;

    (*env)->RegisterNatives(
        env, companionClass, gMethods,
        sizeof(gMethods) / sizeof(gMethods[0])
    );

    (*env)->DeleteLocalRef(env, companionClass);
}
