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
    ${CMAKE_SOURCE_DIR}/../SoftEtherVPN_Stable/src
    ${CMAKE_SOURCE_DIR}/../SoftEtherVPN_Stable/src/Mayaqua
    ${CMAKE_SOURCE_DIR}/../SoftEtherVPN_Stable/src/Cedar
    ${CMAKE_SOURCE_DIR}/../src/bridge
    ${OPENSSL_INCLUDE_DIR}
)

# Mayaqua library sources
set(MAYAQUA_SOURCES
    ../SoftEtherVPN_Stable/src/Mayaqua/Encrypt.c
    ../SoftEtherVPN_Stable/src/Mayaqua/FileIO.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Internat.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Kernel.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Mayaqua.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Memory.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Microsoft.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Network.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Object.c
    ../SoftEtherVPN_Stable/src/Mayaqua/OS.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Pack.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Secure.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Str.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Table.c
    ../SoftEtherVPN_Stable/src/Mayaqua/TcpIp.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Tracking.c
    ../SoftEtherVPN_Stable/src/Mayaqua/Cfg.c
)

# Cedar library sources
set(CEDAR_SOURCES
    ../SoftEtherVPN_Stable/src/Cedar/Account.c
    ../SoftEtherVPN_Stable/src/Cedar/Admin.c
    ../SoftEtherVPN_Stable/src/Cedar/AzureClient.c
    ../SoftEtherVPN_Stable/src/Cedar/AzureServer.c
    ../SoftEtherVPN_Stable/src/Cedar/Bridge.c
    ../SoftEtherVPN_Stable/src/Cedar/BridgeUnix.c
    ../SoftEtherVPN_Stable/src/Cedar/Cedar.c
    ../SoftEtherVPN_Stable/src/Cedar/Command.c
    ../SoftEtherVPN_Stable/src/Cedar/Connection.c
    ../SoftEtherVPN_Stable/src/Cedar/Console.c
    ../SoftEtherVPN_Stable/src/Cedar/Database.c
    ../SoftEtherVPN_Stable/src/Cedar/DDNS.c
    ../SoftEtherVPN_Stable/src/Cedar/EtherLog.c
    ../SoftEtherVPN_Stable/src/Cedar/Hub.c
    ../SoftEtherVPN_Stable/src/Cedar/Interop_OpenVPN.c
    ../SoftEtherVPN_Stable/src/Cedar/Interop_SSTP.c
    ../SoftEtherVPN_Stable/src/Cedar/IPsec.c
    ../SoftEtherVPN_Stable/src/Cedar/IPsec_EtherIP.c
    ../SoftEtherVPN_Stable/src/Cedar/IPsec_IKE.c
    ../SoftEtherVPN_Stable/src/Cedar/IPsec_IkePacket.c
    ../SoftEtherVPN_Stable/src/Cedar/IPsec_IPC.c
    ../SoftEtherVPN_Stable/src/Cedar/IPsec_L2TP.c
    ../SoftEtherVPN_Stable/src/Cedar/IPsec_PPP.c
    ../SoftEtherVPN_Stable/src/Cedar/Layer3.c
    ../SoftEtherVPN_Stable/src/Cedar/Link.c
    ../SoftEtherVPN_Stable/src/Cedar/Listener.c
    ../SoftEtherVPN_Stable/src/Cedar/Logging.c
    ../SoftEtherVPN_Stable/src/Cedar/Nat.c
    ../SoftEtherVPN_Stable/src/Cedar/NativeStack.c
    ../SoftEtherVPN_Stable/src/Cedar/NullLan.c
    ../SoftEtherVPN_Stable/src/Cedar/Radius.c
    ../SoftEtherVPN_Stable/src/Cedar/Remote.c
    ../SoftEtherVPN_Stable/src/Cedar/Sam.c
    ../SoftEtherVPN_Stable/src/Cedar/SecureNAT.c
    ../SoftEtherVPN_Stable/src/Cedar/Server.c
    ../SoftEtherVPN_Stable/src/Cedar/UdpAccel.c
    ../SoftEtherVPN_Stable/src/Cedar/Virtual.c
    ../SoftEtherVPN_Stable/src/Cedar/WaterMark.c
    ../SoftEtherVPN_Stable/src/Cedar/WebUI.c
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
)

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
    z
)
