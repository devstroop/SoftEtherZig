/*
 * SoftEther Mobile FFI - Android JNI Wrapper
 * 
 * JNI bindings for the generic mobile FFI layer (libsoftether_mobile.so)
 * This provides Android/Kotlin access to the platform-agnostic mobile VPN API.
 * 
 * Architecture:
 *   Android VpnService (Kotlin)
 *     ↓
 *   SoftEtherMobileClient (Kotlin bridge)
 *     ↓
 *   mobile_jni.c (this file - JNI wrapper)
 *     ↓
 *   libsoftether_mobile.so (mobile FFI)
 *     ↓
 *   Zig Packet Adapter
 */

#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

// Mobile FFI header
#include "../../include/mobile_ffi.h"

#define LOG_TAG "SoftEtherMobile-JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert Java string to C string (caller must free)
 */
static char* jstring_to_cstring(JNIEnv* env, jstring jstr) {
    if (jstr == NULL) return NULL;
    
    const char* utf = (*env)->GetStringUTFChars(env, jstr, NULL);
    if (utf == NULL) return NULL;
    
    char* result = strdup(utf);
    (*env)->ReleaseStringUTFChars(env, jstr, utf);
    
    return result;
}

/**
 * Create Java VpnStatus enum value
 */
static jobject create_vpn_status(JNIEnv* env, MobileVpnStatus status) {
    jclass statusClass = (*env)->FindClass(env, "com/softether/mobile/VpnStatus");
    if (statusClass == NULL) {
        LOGE("Failed to find VpnStatus class");
        return NULL;
    }
    
    // Get the enum value
    const char* statusName;
    switch (status) {
        case MOBILE_VPN_DISCONNECTED: statusName = "DISCONNECTED"; break;
        case MOBILE_VPN_CONNECTING: statusName = "CONNECTING"; break;
        case MOBILE_VPN_CONNECTED: statusName = "CONNECTED"; break;
        case MOBILE_VPN_RECONNECTING: statusName = "RECONNECTING"; break;
        case MOBILE_VPN_ERROR: statusName = "ERROR"; break;
        default: statusName = "DISCONNECTED"; break;
    }
    
    jfieldID fieldID = (*env)->GetStaticFieldID(env, statusClass, statusName, 
                                                 "Lcom/softether/mobile/VpnStatus;");
    if (fieldID == NULL) {
        LOGE("Failed to get field ID for %s", statusName);
        return NULL;
    }
    
    return (*env)->GetStaticObjectField(env, statusClass, fieldID);
}

// ============================================================================
// JNI Exported Functions
// ============================================================================

/**
 * Initialize mobile VPN library
 * Signature: ()I
 * Returns: 0 on success, negative on error
 */
JNIEXPORT jint JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeInit(JNIEnv* env, jclass clazz) {
    LOGI("Initializing mobile VPN library");
    
    int result = mobile_vpn_init();
    if (result != 0) {
        LOGE("mobile_vpn_init failed: %d", result);
    } else {
        LOGI("Mobile VPN library initialized successfully");
    }
    
    return (jint)result;
}

/**
 * Create VPN connection handle
 * Signature: (Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZIJJJJ)J
 * 
 * Parameters:
 *   - server: Server hostname/IP
 *   - port: Server port
 *   - hub: Hub name
 *   - username: Username
 *   - passwordHash: Password hash
 *   - useEncrypt: Use encryption
 *   - useCompress: Use compression
 *   - halfConnection: Half connection mode
 *   - maxConnection: Max connections
 *   - recvQueueSize: Receive queue size
 *   - sendQueueSize: Send queue size
 *   - packetPoolSize: Packet pool size
 *   - batchSize: Batch size
 * 
 * Returns: Handle (long) on success, 0 on failure
 */
JNIEXPORT jlong JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeCreate(
    JNIEnv* env, jobject thiz,
    jstring server, jint port, jstring hub, jstring username, jstring passwordHash,
    jboolean useEncrypt, jboolean useCompress, jboolean halfConnection, jint maxConnection,
    jlong recvQueueSize, jlong sendQueueSize, jlong packetPoolSize, jlong batchSize) {
    
    LOGI("Creating VPN client");
    
    // Convert Java strings to C strings
    char* c_server = jstring_to_cstring(env, server);
    char* c_hub = jstring_to_cstring(env, hub);
    char* c_username = jstring_to_cstring(env, username);
    char* c_password = jstring_to_cstring(env, passwordHash);
    
    if (!c_server || !c_hub || !c_username || !c_password) {
        LOGE("Failed to convert strings");
        free(c_server);
        free(c_hub);
        free(c_username);
        free(c_password);
        return 0;
    }
    
    // Build configuration
    MobileVpnConfig config = {
        .server = c_server,
        .port = (uint16_t)port,
        .hub = c_hub,
        .username = c_username,
        .password_hash = c_password,
        .use_encrypt = (bool)useEncrypt,
        .use_compress = (bool)useCompress,
        .half_connection = (bool)halfConnection,
        .max_connection = (uint8_t)maxConnection,
        .recv_queue_size = (uint64_t)recvQueueSize,
        .send_queue_size = (uint64_t)sendQueueSize,
        .packet_pool_size = (uint64_t)packetPoolSize,
        .batch_size = (uint64_t)batchSize,
    };
    
    LOGI("Creating VPN handle: server=%s:%d, hub=%s, user=%s", 
         c_server, (int)port, c_hub, c_username);
    
    // Create handle
    MobileVpnHandle handle = mobile_vpn_create(&config);
    
    // Free C strings
    free(c_server);
    free(c_hub);
    free(c_username);
    free(c_password);
    
    if (handle == NULL) {
        LOGE("mobile_vpn_create failed");
        return 0;
    }
    
    LOGI("VPN handle created: %p", handle);
    return (jlong)(uintptr_t)handle;
}

/**
 * Destroy VPN connection handle
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeDestroy(
    JNIEnv* env, jobject thiz, jlong handle) {
    
    if (handle == 0) return;
    
    LOGI("Destroying VPN handle: %p", (void*)(uintptr_t)handle);
    mobile_vpn_destroy((MobileVpnHandle)(uintptr_t)handle);
}

/**
 * Connect to VPN server
 * Signature: (J)I
 * Returns: 0 on success, negative on error
 */
JNIEXPORT jint JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeConnect(
    JNIEnv* env, jobject thiz, jlong handle) {
    
    if (handle == 0) {
        LOGE("Invalid handle");
        return -1;
    }
    
    LOGI("Connecting to VPN server");
    int result = mobile_vpn_connect((MobileVpnHandle)(uintptr_t)handle);
    
    if (result != 0) {
        LOGE("mobile_vpn_connect failed: %d", result);
    } else {
        LOGI("Connection initiated successfully");
    }
    
    return (jint)result;
}

/**
 * Disconnect from VPN server
 * Signature: (J)I
 * Returns: 0 on success, negative on error
 */
JNIEXPORT jint JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeDisconnect(
    JNIEnv* env, jobject thiz, jlong handle) {
    
    if (handle == 0) {
        LOGE("Invalid handle");
        return -1;
    }
    
    LOGI("Disconnecting from VPN server");
    int result = mobile_vpn_disconnect((MobileVpnHandle)(uintptr_t)handle);
    
    if (result != 0) {
        LOGE("mobile_vpn_disconnect failed: %d", result);
    } else {
        LOGI("Disconnected successfully");
    }
    
    return (jint)result;
}

/**
 * Get current VPN status
 * Signature: (J)I
 * Returns: VpnStatus enum value (as int)
 */
JNIEXPORT jint JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeGetStatus(
    JNIEnv* env, jobject thiz, jlong handle) {
    
    if (handle == 0) {
        return MOBILE_VPN_DISCONNECTED;
    }
    
    MobileVpnStatus status = mobile_vpn_get_status((MobileVpnHandle)(uintptr_t)handle);
    return (jint)status;
}

/**
 * Check if connected
 * Signature: (J)Z
 * Returns: true if connected, false otherwise
 */
JNIEXPORT jboolean JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeIsConnected(
    JNIEnv* env, jobject thiz, jlong handle) {
    
    if (handle == 0) return JNI_FALSE;
    
    bool connected = mobile_vpn_is_connected((MobileVpnHandle)(uintptr_t)handle);
    return connected ? JNI_TRUE : JNI_FALSE;
}

/**
 * Read packet from VPN
 * Signature: (J[BI)I
 * 
 * Parameters:
 *   - handle: VPN handle
 *   - buffer: Byte array to receive packet
 *   - timeoutMs: Timeout in milliseconds
 * 
 * Returns: Number of bytes read, 0 if no packet, negative on error
 */
JNIEXPORT jint JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeReadPacket(
    JNIEnv* env, jobject thiz, jlong handle, jbyteArray buffer, jint timeoutMs) {
    
    if (handle == 0) return -1;
    
    // Get buffer
    jsize bufferLen = (*env)->GetArrayLength(env, buffer);
    jbyte* bufferPtr = (*env)->GetByteArrayElements(env, buffer, NULL);
    
    if (bufferPtr == NULL) {
        LOGE("Failed to get buffer pointer");
        return -1;
    }
    
    // Read packet
    int bytesRead = mobile_vpn_read_packet(
        (MobileVpnHandle)(uintptr_t)handle,
        (uint8_t*)bufferPtr,
        (uint64_t)bufferLen,
        (uint32_t)timeoutMs
    );
    
    // Release buffer (copy back to Java)
    (*env)->ReleaseByteArrayElements(env, buffer, bufferPtr, 0);
    
    if (bytesRead < 0) {
        LOGE("mobile_vpn_read_packet failed: %d", bytesRead);
    } else if (bytesRead > 0) {
        LOGD("Read %d bytes from VPN", bytesRead);
    }
    
    return (jint)bytesRead;
}

/**
 * Write packet to VPN
 * Signature: (J[BI)I
 * 
 * Parameters:
 *   - handle: VPN handle
 *   - data: Packet data to write
 *   - length: Length of packet data
 * 
 * Returns: 0 on success, negative on error
 */
JNIEXPORT jint JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeWritePacket(
    JNIEnv* env, jobject thiz, jlong handle, jbyteArray data, jint length) {
    
    if (handle == 0) return -1;
    
    if (length <= 0 || length > 65536) {
        LOGE("Invalid packet length: %d", length);
        return -1;
    }
    
    // Get data buffer
    jbyte* dataPtr = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataPtr == NULL) {
        LOGE("Failed to get data pointer");
        return -1;
    }
    
    // Write packet
    int result = mobile_vpn_write_packet(
        (MobileVpnHandle)(uintptr_t)handle,
        (const uint8_t*)dataPtr,
        (uint64_t)length
    );
    
    // Release data buffer (no copy back needed)
    (*env)->ReleaseByteArrayElements(env, data, dataPtr, JNI_ABORT);
    
    if (result != 0) {
        LOGE("mobile_vpn_write_packet failed: %d", result);
    } else {
        LOGD("Wrote %d bytes to VPN", length);
    }
    
    return (jint)result;
}

/**
 * Get VPN statistics
 * Signature: (J)Lcom/softether/mobile/VpnStats;
 * Returns: VpnStats object or null on error
 */
JNIEXPORT jobject JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeGetStats(
    JNIEnv* env, jobject thiz, jlong handle) {
    
    if (handle == 0) return NULL;
    
    // Get stats from mobile FFI
    MobileVpnStats cStats;
    int result = mobile_vpn_get_stats((MobileVpnHandle)(uintptr_t)handle, &cStats);
    
    if (result != 0) {
        LOGE("mobile_vpn_get_stats failed: %d", result);
        return NULL;
    }
    
    // Create Java VpnStats object
    jclass statsClass = (*env)->FindClass(env, "com/softether/mobile/VpnStats");
    if (statsClass == NULL) {
        LOGE("Failed to find VpnStats class");
        return NULL;
    }
    
    jmethodID constructor = (*env)->GetMethodID(env, statsClass, "<init>", "(JJJJJJJ)V");
    if (constructor == NULL) {
        LOGE("Failed to find VpnStats constructor");
        return NULL;
    }
    
    jobject statsObj = (*env)->NewObject(env, statsClass, constructor,
        (jlong)cStats.bytes_sent,
        (jlong)cStats.bytes_received,
        (jlong)cStats.packets_sent,
        (jlong)cStats.packets_received,
        (jlong)cStats.connected_duration_ms,
        (jlong)cStats.queue_drops,
        (jlong)cStats.errors
    );
    
    return statsObj;
}

/**
 * Get network configuration
 * Signature: (J)Lcom/softether/mobile/NetworkInfo;
 * Returns: NetworkInfo object or null on error
 */
JNIEXPORT jobject JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeGetNetworkInfo(
    JNIEnv* env, jobject thiz, jlong handle) {
    
    if (handle == 0) return NULL;
    
    // Get network info from mobile FFI
    MobileNetworkInfo cInfo;
    int result = mobile_vpn_get_network_info((MobileVpnHandle)(uintptr_t)handle, &cInfo);
    
    if (result != 0) {
        LOGE("mobile_vpn_get_network_info failed: %d", result);
        return NULL;
    }
    
    // Convert IP addresses to strings
    char ipStr[16], gwStr[16], nmStr[16];
    snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", 
             cInfo.ip_address[0], cInfo.ip_address[1], 
             cInfo.ip_address[2], cInfo.ip_address[3]);
    snprintf(gwStr, sizeof(gwStr), "%d.%d.%d.%d",
             cInfo.gateway[0], cInfo.gateway[1],
             cInfo.gateway[2], cInfo.gateway[3]);
    snprintf(nmStr, sizeof(nmStr), "%d.%d.%d.%d",
             cInfo.netmask[0], cInfo.netmask[1],
             cInfo.netmask[2], cInfo.netmask[3]);
    
    // Create Java NetworkInfo object
    jclass infoClass = (*env)->FindClass(env, "com/softether/mobile/NetworkInfo");
    if (infoClass == NULL) {
        LOGE("Failed to find NetworkInfo class");
        return NULL;
    }
    
    jmethodID constructor = (*env)->GetMethodID(env, infoClass, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;I)V");
    if (constructor == NULL) {
        LOGE("Failed to find NetworkInfo constructor");
        return NULL;
    }
    
    // Create DNS server array
    jclass stringClass = (*env)->FindClass(env, "java/lang/String");
    jobjectArray dnsArray = (*env)->NewObjectArray(env, 4, stringClass, NULL);
    
    for (int i = 0; i < 4; i++) {
        if (cInfo.dns_servers[i][0] == 0 && cInfo.dns_servers[i][1] == 0 &&
            cInfo.dns_servers[i][2] == 0 && cInfo.dns_servers[i][3] == 0) {
            break;
        }
        
        char dnsStr[16];
        snprintf(dnsStr, sizeof(dnsStr), "%d.%d.%d.%d",
                 cInfo.dns_servers[i][0], cInfo.dns_servers[i][1],
                 cInfo.dns_servers[i][2], cInfo.dns_servers[i][3]);
        
        jstring jdns = (*env)->NewStringUTF(env, dnsStr);
        (*env)->SetObjectArrayElement(env, dnsArray, i, jdns);
        (*env)->DeleteLocalRef(env, jdns);
    }
    
    // Create NetworkInfo object
    jstring jip = (*env)->NewStringUTF(env, ipStr);
    jstring jgw = (*env)->NewStringUTF(env, gwStr);
    jstring jnm = (*env)->NewStringUTF(env, nmStr);
    
    jobject infoObj = (*env)->NewObject(env, infoClass, constructor,
        jip, jgw, jnm, dnsArray, (jint)cInfo.mtu);
    
    // Clean up
    (*env)->DeleteLocalRef(env, jip);
    (*env)->DeleteLocalRef(env, jgw);
    (*env)->DeleteLocalRef(env, jnm);
    (*env)->DeleteLocalRef(env, dnsArray);
    
    return infoObj;
}

/**
 * Get last error message
 * Signature: (J)Ljava/lang/String;
 * Returns: Error string or null
 */
JNIEXPORT jstring JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeGetError(
    JNIEnv* env, jobject thiz, jlong handle) {
    
    if (handle == 0) return NULL;
    
    const char* error = mobile_vpn_get_error((MobileVpnHandle)(uintptr_t)handle);
    if (error == NULL) return NULL;
    
    return (*env)->NewStringUTF(env, error);
}

/**
 * Get library version
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeGetVersion(
    JNIEnv* env, jclass clazz) {
    
    const char* version = mobile_vpn_get_version();
    if (version == NULL) return (*env)->NewStringUTF(env, "Unknown");
    
    return (*env)->NewStringUTF(env, version);
}

/**
 * Get build info
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeGetBuildInfo(
    JNIEnv* env, jclass clazz) {
    
    const char* buildInfo = mobile_vpn_get_build_info();
    if (buildInfo == NULL) return (*env)->NewStringUTF(env, "Unknown");
    
    return (*env)->NewStringUTF(env, buildInfo);
}

/**
 * Cleanup library resources
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_com_softether_mobile_SoftEtherMobileClient_nativeCleanup(
    JNIEnv* env, jclass clazz) {
    
    LOGI("Cleaning up mobile VPN library");
    mobile_vpn_cleanup();
}

// ============================================================================
// Callback Support (Future Enhancement)
// ============================================================================

/*
 * Note: Callback support requires:
 * 1. Creating global references to Java callback objects
 * 2. Caching method IDs
 * 3. Calling back from C to Java (requires JavaVM*)
 * 4. Proper thread handling (callbacks may come from different threads)
 * 
 * This can be added in a future version if needed.
 * For now, polling-based status checking is sufficient.
 */
