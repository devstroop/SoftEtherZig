/*
 * SoftEther VPN - Android JNI Bridge
 * 
 * This provides JNI bindings for Android VpnService integration.
 * Connects Android VpnService with SoftEther VPN client core.
 */

#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

// SoftEther includes
#include "../../src/bridge/softether_bridge.h"
#include "../../src/bridge/logging.h"

#define LOG_TAG "SoftEtherVPN-JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Global client handle
static VpnBridgeClient* g_vpn_client = NULL;
static int g_tun_fd = -1;
static volatile int g_should_stop = 0;

// Thread for packet processing
static pthread_t g_packet_thread = 0;

/*
 * JNI Method: Initialize VPN bridge
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeInit(JNIEnv *env, jobject thiz) {
    LOGI("nativeInit called");
    
    int result = vpn_bridge_init(0);
    if (result != VPN_BRIDGE_SUCCESS) {
        LOGE("vpn_bridge_init failed: %d", result);
        return result;
    }
    
    LOGI("VPN bridge initialized successfully");
    return VPN_BRIDGE_SUCCESS;
}

/*
 * JNI Method: Create VPN client
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeCreateClient(JNIEnv *env, jobject thiz) {
    LOGI("nativeCreateClient called");
    
    if (g_vpn_client != NULL) {
        LOGE("Client already exists");
        return 0;
    }
    
    g_vpn_client = vpn_bridge_create_client();
    if (g_vpn_client == NULL) {
        LOGE("Failed to create VPN client");
        return 0;
    }
    
    LOGI("VPN client created: %p", g_vpn_client);
    return (jlong)(uintptr_t)g_vpn_client;
}

/*
 * JNI Method: Connect to VPN server
 * Signature: (Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeConnect(
    JNIEnv *env, jobject thiz,
    jstring server_name,
    jint server_port,
    jstring hub_name,
    jstring username,
    jstring password) {
    
    LOGI("nativeConnect called");
    
    if (g_vpn_client == NULL) {
        LOGE("Client not initialized");
        return -1;
    }
    
    // Convert Java strings to C strings
    const char *server = (*env)->GetStringUTFChars(env, server_name, NULL);
    const char *hub = (*env)->GetStringUTFChars(env, hub_name, NULL);
    const char *user = (*env)->GetStringUTFChars(env, username, NULL);
    const char *pass = (*env)->GetStringUTFChars(env, password, NULL);
    
    LOGI("Connecting to %s:%d, hub=%s, user=%s", server, server_port, hub, user);
    
    // Create connection options
    VpnConnectionOptions opts = {0};
    strncpy(opts.ServerName, server, sizeof(opts.ServerName) - 1);
    opts.ServerPort = server_port;
    strncpy(opts.HubName, hub, sizeof(opts.HubName) - 1);
    strncpy(opts.Username, user, sizeof(opts.Username) - 1);
    strncpy(opts.Password, pass, sizeof(opts.Password) - 1);
    opts.UseEncrypt = 1;
    opts.UseCompress = 1;
    opts.HalfConnection = 0;
    opts.MaxConnection = 1;
    opts.PortUDP = 0; // TCP only for mobile
    opts.AdditionalConnectionInterval = 1;
    opts.ConnectionDisconnectSpan = 0;
    opts.RequireBridgeRoutingMode = 1;
    opts.RequireMonitorMode = 0;
    opts.DisableQoS = 0;
    opts.FromAdminPack = 0;
    opts.NoRoutingTracking = 1;
    
    // Connect
    int result = vpn_bridge_connect(g_vpn_client, &opts);
    
    // Release Java strings
    (*env)->ReleaseStringUTFChars(env, server_name, server);
    (*env)->ReleaseStringUTFChars(env, hub_name, hub);
    (*env)->ReleaseStringUTFChars(env, username, user);
    (*env)->ReleaseStringUTFChars(env, password, pass);
    
    if (result != 0) {
        LOGE("Connection failed: %d", result);
        return result;
    }
    
    LOGI("Successfully connected to VPN");
    return 0;
}

/*
 * JNI Method: Set TUN file descriptor from VpnService
 * Signature: (I)V
 */
JNIEXPORT void JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeSetTunFd(
    JNIEnv *env, jobject thiz, jint tun_fd) {
    
    LOGI("nativeSetTunFd: fd=%d", tun_fd);
    g_tun_fd = tun_fd;
    
    // Configure the TUN device with the VPN client
    if (g_vpn_client != NULL && g_vpn_client->session != NULL) {
        // The packet adapter will use g_tun_fd
        LOGI("TUN fd set successfully");
    }
}

/*
 * JNI Method: Get next packet from VPN (to write to TUN)
 * Signature: ([B)I
 * Returns: number of bytes written to buffer, or -1 on error
 */
JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeGetNextPacket(
    JNIEnv *env, jobject thiz, jbyteArray buffer) {
    
    if (g_vpn_client == NULL || g_vpn_client->session == NULL) {
        return -1;
    }
    
    // Get buffer pointer and size
    jsize buffer_size = (*env)->GetArrayLength(env, buffer);
    jbyte *buffer_ptr = (*env)->GetByteArrayElements(env, buffer, NULL);
    
    if (buffer_ptr == NULL) {
        LOGE("Failed to get buffer pointer");
        return -1;
    }
    
    // Get packet from VPN
    UINT size = 0;
    void *data = NULL;
    
    // Call packet adapter's GetNextPacket
    SESSION *s = g_vpn_client->session;
    if (s->PacketAdapter && s->PacketAdapter->GetNextPacket) {
        data = s->PacketAdapter->GetNextPacket(s->PacketAdapter, &size);
    }
    
    int result = -1;
    if (data != NULL && size > 0) {
        if (size <= (UINT)buffer_size) {
            memcpy(buffer_ptr, data, size);
            result = (jint)size;
        } else {
            LOGE("Packet too large: %u bytes (buffer=%d)", size, buffer_size);
        }
        // Free the packet data
        Free(data);
    }
    
    (*env)->ReleaseByteArrayElements(env, buffer, buffer_ptr, 0);
    return result;
}

/*
 * JNI Method: Put packet into VPN (read from TUN)
 * Signature: ([BI)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativePutPacket(
    JNIEnv *env, jobject thiz, jbyteArray packet, jint size) {
    
    if (g_vpn_client == NULL || g_vpn_client->session == NULL) {
        return JNI_FALSE;
    }
    
    if (size <= 0 || size > 65536) {
        LOGE("Invalid packet size: %d", size);
        return JNI_FALSE;
    }
    
    // Get packet data
    jbyte *packet_data = (*env)->GetByteArrayElements(env, packet, NULL);
    if (packet_data == NULL) {
        LOGE("Failed to get packet data");
        return JNI_FALSE;
    }
    
    // Put packet into VPN
    SESSION *s = g_vpn_client->session;
    jboolean result = JNI_FALSE;
    
    if (s->PacketAdapter && s->PacketAdapter->PutPacket) {
        result = s->PacketAdapter->PutPacket(s->PacketAdapter, packet_data, (UINT)size) 
                 ? JNI_TRUE : JNI_FALSE;
    }
    
    (*env)->ReleaseByteArrayElements(env, packet, packet_data, JNI_ABORT);
    return result;
}

/*
 * JNI Method: Check if connected
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeIsConnected(JNIEnv *env, jobject thiz) {
    if (g_vpn_client == NULL) {
        return JNI_FALSE;
    }
    
    return vpn_bridge_is_connected(g_vpn_client) ? JNI_TRUE : JNI_FALSE;
}

/*
 * JNI Method: Disconnect from VPN
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeDisconnect(JNIEnv *env, jobject thiz) {
    LOGI("nativeDisconnect called");
    
    if (g_vpn_client != NULL) {
        g_should_stop = 1;
        vpn_bridge_disconnect(g_vpn_client);
        LOGI("Disconnected from VPN");
    }
}

/*
 * JNI Method: Free VPN client
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeFreeClient(JNIEnv *env, jobject thiz) {
    LOGI("nativeFreeClient called");
    
    if (g_vpn_client != NULL) {
        vpn_bridge_free_client(g_vpn_client);
        g_vpn_client = NULL;
        LOGI("VPN client freed");
    }
    
    if (g_tun_fd >= 0) {
        close(g_tun_fd);
        g_tun_fd = -1;
    }
}

/*
 * JNI Method: Cleanup VPN bridge
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeCleanup(JNIEnv *env, jobject thiz) {
    LOGI("nativeCleanup called");
    
    vpn_bridge_cleanup();
    LOGI("VPN bridge cleaned up");
}

/*
 * JNI Method: Set log level
 * Signature: (I)V
 */
JNIEXPORT void JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeSetLogLevel(
    JNIEnv *env, jobject thiz, jint level) {
    
    LOGI("Setting log level to: %d", level);
    set_log_level((LogLevel)level);
}

/*
 * JNI Method: Get connection statistics
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_nativeGetStats(JNIEnv *env, jobject thiz) {
    if (g_vpn_client == NULL || g_vpn_client->session == NULL) {
        return (*env)->NewStringUTF(env, "Not connected");
    }
    
    // Build stats string
    char stats[512];
    snprintf(stats, sizeof(stats),
             "Connected: Yes\nSession: %p\nDevice: %s",
             g_vpn_client->session,
             g_vpn_client->session->ClientOption ? 
             g_vpn_client->session->ClientOption->DeviceName : "unknown");
    
    return (*env)->NewStringUTF(env, stats);
}
