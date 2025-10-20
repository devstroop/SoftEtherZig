cmake_minimum_required(VERSION 3.18.1)
project(softether-vpn)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-unused-parameter -Wno-unused-variable")

# Add compile definitions
add_definitions(
    -DUNIX_LINUX
    -DUNIX
    -D_REENTRANT
    -DREENTRANT
    -D_THREAD_SAFE
    -D_THREADSAFE
    -DTHREAD_SAFE
    -DTHREADSAFE
    -D_FILE_OFFSET_BITS=64
    -DVPN_SPEED
)

# Find required libraries
find_library(log-lib log)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/../SoftEtherVPN/src
    ${CMAKE_SOURCE_DIR}/../SoftEtherVPN/src/Mayaqua
    ${CMAKE_SOURCE_DIR}/../SoftEtherVPN/src/Cedar
    ${CMAKE_SOURCE_DIR}/../src/bridge
    ${CMAKE_SOURCE_DIR}/../include
    ${OPENSSL_INCLUDE_DIR}
)

# Mayaqua library sources
set(MAYAQUA_SOURCES
    ../SoftEtherVPN/src/Mayaqua/Encrypt.c
    ../SoftEtherVPN/src/Mayaqua/FileIO.c
    ../SoftEtherVPN/src/Mayaqua/Internat.c
    ../SoftEtherVPN/src/Mayaqua/Kernel.c
    ../SoftEtherVPN/src/Mayaqua/Mayaqua.c
    ../SoftEtherVPN/src/Mayaqua/Memory.c
    ../SoftEtherVPN/src/Mayaqua/Microsoft.c
    ../SoftEtherVPN/src/Mayaqua/Network.c
    ../SoftEtherVPN/src/Mayaqua/Object.c
    ../SoftEtherVPN/src/Mayaqua/OS.c
    ../SoftEtherVPN/src/Mayaqua/Pack.c
    ../SoftEtherVPN/src/Mayaqua/Secure.c
    ../SoftEtherVPN/src/Mayaqua/Str.c
    ../SoftEtherVPN/src/Mayaqua/Table.c
    ../SoftEtherVPN/src/Mayaqua/TcpIp.c
    ../SoftEtherVPN/src/Mayaqua/Tracking.c
    ../SoftEtherVPN/src/Mayaqua/Cfg.c
)

# Cedar library sources
set(CEDAR_SOURCES
    ../SoftEtherVPN/src/Cedar/Account.c
    ../SoftEtherVPN/src/Cedar/Admin.c
    ../SoftEtherVPN/src/Cedar/AzureClient.c
    ../SoftEtherVPN/src/Cedar/AzureServer.c
    ../SoftEtherVPN/src/Cedar/Bridge.c
    ../SoftEtherVPN/src/Cedar/BridgeUnix.c
    ../SoftEtherVPN/src/Cedar/Cedar.c
    ../SoftEtherVPN/src/Cedar/Command.c
    ../SoftEtherVPN/src/Cedar/Connection.c
    ../SoftEtherVPN/src/Cedar/Console.c
    ../SoftEtherVPN/src/Cedar/Database.c
    ../SoftEtherVPN/src/Cedar/DDNS.c
    ../SoftEtherVPN/src/Cedar/EtherLog.c
    ../SoftEtherVPN/src/Cedar/Hub.c
    ../SoftEtherVPN/src/Cedar/Interop_OpenVPN.c
    ../SoftEtherVPN/src/Cedar/Interop_SSTP.c
    ../SoftEtherVPN/src/Cedar/IPsec.c
    ../SoftEtherVPN/src/Cedar/IPsec_EtherIP.c
    ../SoftEtherVPN/src/Cedar/IPsec_IKE.c
    ../SoftEtherVPN/src/Cedar/IPsec_IkePacket.c
    ../SoftEtherVPN/src/Cedar/IPsec_IPC.c
    ../SoftEtherVPN/src/Cedar/IPsec_L2TP.c
    ../SoftEtherVPN/src/Cedar/IPsec_PPP.c
    ../SoftEtherVPN/src/Cedar/Layer3.c
    ../SoftEtherVPN/src/Cedar/Link.c
    ../SoftEtherVPN/src/Cedar/Listener.c
    ../SoftEtherVPN/src/Cedar/Logging.c
    ../SoftEtherVPN/src/Cedar/Nat.c
    ../SoftEtherVPN/src/Cedar/NativeStack.c
    ../SoftEtherVPN/src/Cedar/NullLan.c
    ../SoftEtherVPN/src/Cedar/Radius.c
    ../SoftEtherVPN/src/Cedar/Remote.c
    ../SoftEtherVPN/src/Cedar/Sam.c
    ../SoftEtherVPN/src/Cedar/SecureNAT.c
    ../SoftEtherVPN/src/Cedar/Server.c
    ../SoftEtherVPN/src/Cedar/UdpAccel.c
    ../SoftEtherVPN/src/Cedar/Virtual.c
    ../SoftEtherVPN/src/Cedar/WaterMark.c
    ../SoftEtherVPN/src/Cedar/WebUI.c
)

# Bridge layer sources (modified for Android)
set(BRIDGE_SOURCES
    ../src/bridge/Client.c
    ../src/bridge/Protocol.c
    ../src/bridge/Session.c
    ../src/bridge/softether_bridge.c
    ../src/bridge/logging.c
    ../src/bridge/android/packet_adapter_android.c
)

# JNI sources
set(JNI_SOURCES
    jni/softether_jni.c
    jni/mobile_jni.c
)

# Mobile FFI library (pre-built by Zig)
# Note: This should be built by `zig build mobile-ffi` before Android build
set(MOBILE_FFI_LIB ${CMAKE_SOURCE_DIR}/../zig-out/lib/libsoftether_mobile.a)

# Create shared library
add_library(softether-vpn SHARED
    ${MAYAQUA_SOURCES}
    ${CEDAR_SOURCES}
    ${BRIDGE_SOURCES}
    ${JNI_SOURCES}
)

# Link libraries
target_link_libraries(softether-vpn
    ${log-lib}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    ${MOBILE_FFI_LIB}
    z
)
