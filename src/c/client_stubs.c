/*
 * client_stubs.c
 * 
 * Stub implementations for server-only functions that are referenced
 * from client code. This allows building a client-only binary.
 * 
 * These stubs either return NULL/0/false or are empty void functions.
 * They should NEVER be called at runtime in a client-only build.
 */

#include "Cedar/CedarPch.h"

// ============================================
// Hub.c stubs
// ============================================
int CompareHub(void *p1, void *p2) { return 0; }
HUB *GetHub(CEDAR *cedar, char *name) { return NULL; }
void ReleaseHub(HUB *h) {}
void StopHub(HUB *h) {}
void AddSession(HUB *h, SESSION *s) {}
void DelSession(HUB *h, SESSION *s) {}
UINT GetHubAdminOption(HUB *h, char *name) { return 0; }
wchar_t *GetHubMsg(HUB *h) { return NULL; }
void IncrementHubTraffic(HUB *h) {}
void AddTrafficDiff(HUB *h, char *name, UINT type, TRAFFIC *traffic) {}
PACKET_ADAPTER *GetHubPacketAdapter(void) { return NULL; }
bool IsHub(CEDAR *cedar, char *name) { return false; }
void LockHubList(CEDAR *c) {}
void UnlockHubList(CEDAR *c) {}

// ============================================
// Server.c stubs
// ============================================
int CompareListener(void *p1, void *p2) { return 0; }
int CompareUDPEntry(void *p1, void *p2) { return 0; }
bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore) { return false; }
FARM_MEMBER *SiGetHubHostingMember(SERVER *s, HUB *h, bool admin_mode, CONNECTION *c) { return NULL; }
void SiCallCreateTicket(SERVER *s, FARM_MEMBER *f, char *hubname, char *username, char *realusername, POLICY *policy, UCHAR *ticket, UINT counter, char *groupname) {}
bool GetServerCapsBool(SERVER *s, char *name) { return false; }
UINT GetServerCapsInt(SERVER *s, char *name) { return 0; }
void FreeCapsList(CAPSLIST *caps) {}
// SLog is deleted from Protocol.c directly

// ============================================
// Sam.c stubs (authentication)
// ============================================
bool SamAuthUserByAnonymous(HUB *h, char *username) { return false; }
bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password, char *mschap_v2_password, UCHAR *mschap_v2_server_response_20, UINT *err) { return false; }
bool SamAuthUserByPlainPassword(CONNECTION *c, HUB *hub, char *username, char *password, bool ast, UCHAR *mschap_v2_server_response_20, RADIUS_LOGIN_OPTION *opt) { return false; }
bool SamAuthUserByCert(HUB *h, char *username, X *x) { return false; }
POLICY *SamGetUserPolicy(HUB *h, char *username) { return NULL; }

// ============================================
// Account.c stubs (not Account.c for client, this is HUB account DB)
// These are now deleted from Protocol.c directly
// ============================================

// ============================================
// Layer3.c stubs
// ============================================
void InitCedarLayer3(CEDAR *c) {}
void FreeCedarLayer3(CEDAR *c) {}
void L3FreeAllSw(CEDAR *c) {}
void L3PutPacket(L3IF *f, void *data, UINT size) {}

// ============================================
// WebUI.c stubs
// ============================================
WEBUI *WuNewWebUI(CEDAR *cedar) { return NULL; }
bool WuFreeWebUI(WEBUI *wu) { return true; }

// ============================================
// Bridge.c stubs
// ============================================
void InitLocalBridgeList(CEDAR *c) {}
void FreeLocalBridgeList(CEDAR *c) {}
void CloseEth(ETH *e) {}
CANCEL *EthGetCancel(ETH *e) { return NULL; }
UINT EthGetMtu(ETH *e) { return 0; }
UINT EthGetPacket(ETH *e, void **data) { return 0; }
bool EthIsChangeMtuSupported(ETH *e) { return false; }
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes) {}
bool EthSetMtu(ETH *e, UINT mtu) { return false; }

// ============================================
// Listener.c stubs
// ============================================
void AddUDPEntry(CEDAR *cedar, SESSION *session) {}
void DelUDPEntry(CEDAR *cedar, SESSION *session) {}

// ============================================
// SecureNAT.c / Nat.c stubs
// VirtualPutPacket, NatSetHubOption deleted from Connection.c directly
// ============================================
void DisableDosProtect(void) {}

// ============================================
// Admin.c stubs (RPC admin functions)
// ============================================
RPC *AdminConnect(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err) { return NULL; }
RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name) { return NULL; }
void AdminDisconnect(RPC *rpc) {}
UINT AdminReconnect(RPC *rpc) { return 0; }
void AdminWebProcGet(CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_target) {}
void AdminWebProcPost(CONNECTION *c, SOCK *s, HTTP_HEADER *h, UINT post_data_size, char *url_target) {}

// ============================================
// Logging.c stubs (server-specific)
// HLog is now deleted from Protocol.c directly
// ============================================

// ============================================
// DDNS.c / Azure stubs
// ============================================
void FreeDDNSClient(DDNS_CLIENT *c) {}
DDNS_CLIENT *NewDDNSClient(CEDAR *cedar, UCHAR *key, INTERNET_SETTING *t) { return NULL; }
void FreeAzureClient(AZURE_CLIENT *c) {}

// ============================================
// Database.c stubs
// ============================================

// ============================================
// NativeStack.c stubs
// ============================================
void FreeNativeStack(NATIVE_STACK *a) {}
NATIVE_STACK *NewNativeStack(CEDAR *cedar, char *device_name, char *mac_address_seed) { return NULL; }

// ============================================
// IPsec / IPC stubs
// ============================================
void FreeIPC(IPC *ipc) {}
IPC *NewIPC(CEDAR *cedar, char *client_name, char *postfix, char *hubname, char *username, char *password,
    UINT *error_code, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, char *client_hostname,
    char *crypt_name, bool bridge_mode, UINT mss, EAP_CLIENT *eap, X *client_cert, UINT layer) { return NULL; }
void FreeIPsecServer(IPSEC_SERVER *s) {}
void FreeOpenVpnServer(OPENVPN_SERVER *s) {}
void FreeSstpServer(SSTP_SERVER *s) {}
void ReleaseEapClient(EAP_CLIENT *e) {}
bool AcceptSstp(CONNECTION *c) { return false; }

// ============================================
// Protocol.c server stubs
// ServerAccept, NewServerSession, NewServerSessionEx are deleted from source files directly
// ============================================

// ============================================
// Command.c server stubs (Ps* functions)
// ============================================
BUF *DownloadFileFromServer(RPC *r, char *server_name, char *filepath, UINT total_size, DOWNLOAD_PROC *proc, void *param) { return NULL; }

// ============================================
// Remote.c stubs
// ============================================
// (Remote.c may be needed for client RPC)

// ============================================
// RPC stubs (Admin.c / Remote.c)
// ============================================
void EndRpc(RPC *rpc) {}
PACK *RpcCall(RPC *rpc, char *function_name, PACK *p) { return NULL; }
void RpcError(PACK *p, UINT err) {}
void RpcFree(RPC *rpc) {}
UINT RpcGetError(PACK *p) { return 0; }
bool RpcIsOk(PACK *p) { return false; }
void RpcServer(RPC *r) {}
RPC *StartRpcClient(SOCK *s, void *param) { return NULL; }
RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param) { return NULL; }

// ============================================
// Server.c additional stubs
// ============================================
void IncrementServerConfigRevision(SERVER *s) {}
UINT GetGlobalServerFlag(UINT index) { return 0; }
void GetServerProductName(SERVER *s, char *name, UINT size) { if (name && size > 0) { StrCpy(name, size, "VPN Client"); } }
bool IsAdminPackSupportedServerProduct(char *name) { return false; }
bool GetNoSstp(void) { return true; }
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message) {}
UINT SiGetSysLogSaveStatus(SERVER *s) { return 0; }
SERVER *SiNewServerEx(bool bridge, bool in_client_inner_server, bool relay_server) { return NULL; }
void SiReleaseServer(SERVER *s) {}

// ============================================
// Listener.c stubs
// ============================================
LISTENER *NewListenerEx2(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only) { return NULL; }
void ReleaseListener(LISTENER *r) {}
void StopListener(LISTENER *r) {}

// ============================================
// Logging.c stubs (server-side packet logging)
// ============================================
bool CheckMaxLoggedPacketsPerMinute(SESSION *s, UINT num_packets, UINT64 now) { return true; }

// ============================================
// Certificate stubs
// ============================================
int CompareCert(void *p1, void *p2) { return 0; }
X *GetIssuerFromList(LIST *issuer_list, X *cert) { return NULL; }

// ============================================
// IPC (Inter-Process Communication) stubs
// ============================================
IPC *NewIPCByParam(CEDAR *cedar, IPC_PARAM *param, UINT *error_code) { return NULL; }
bool IsIPCConnected(IPC *ipc) { return false; }
void IPCFlushArpTable(IPC *ipc) {}
void IPCProcessInterrupts(IPC *ipc) {}
void IPCProcessL3Events(IPC *ipc) {}
BLOCK *IPCRecvIPv4(IPC *ipc) { return NULL; }
BLOCK *IPCRecvL2(IPC *ipc) { return NULL; }
DHCPV4_DATA *IPCSendDhcpRequest(IPC *ipc, IP *dest_ip, UINT tran_id, DHCP_OPTION_LIST *opt, UINT expecting_code, UINT timeout, TUBE *discon_poll_tube) { return NULL; }
void IPCSendIPv4(IPC *ipc, void *data, UINT size) {}
void IPCSendL2(IPC *ipc, void *data, UINT size) {}
bool IPCSetIPv4Parameters(IPC *ipc, IP *ip, IP *subnet, IP *gw, DHCP_CLASSLESS_ROUTE_TABLE *rt) { return false; }
void IPCSetSockEventWhenRecvL2Packet(IPC *ipc, SOCK_EVENT *e) {}
bool IPCDhcpAllocateIP(IPC *ipc, DHCP_OPTION_LIST *opt, TUBE *discon_poll_tube) { return false; }
void IPCDhcpFreeIP(IPC *ipc, IP *dhcp_server) {}
void IPCDhcpRenewIP(IPC *ipc, IP *new_ip) {}

// ============================================
// Bridge.c additional stubs (Eth*)
// ============================================
bool IsEthSupported(void) { return false; }
TOKEN_LIST *GetEthListEx(UINT *num_not_openable, bool enum_descriptors, bool enum_rawip) { return NULL; }
UINT GetEthDeviceHash(void) { return 0; }
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr) { return NULL; }

// ============================================
// OpenVPN/SSTP stubs
// ============================================
bool OvsCheckTcpRecvBufIfOpenVPNProtocol(UCHAR *data, UINT size) { return false; }
bool OvsGetNoOpenVpnTcp(void) { return true; }
bool OvsPerformTcpServer(CEDAR *cedar, SOCK *sock) { return false; }

// ============================================
// WebUI stubs
// ============================================
void WuFreeWebPage(WU_WEBPAGE *page) {}
WU_WEBPAGE *WuGetPage(char *target, WEBUI *wu) { return NULL; }

// ============================================
// Layer3 stubs (additional)
// ============================================
UINT L3GetNextPacket(L3IF *f, void **data) { return 0; }

// ============================================
// JSON RPC stubs
// ============================================
void JsonRpcProcGet(CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_target) {}
void JsonRpcProcOptions(CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_target) {}
void JsonRpcProcPost(CONNECTION *c, SOCK *s, HTTP_HEADER *h, UINT post_data_size) {}

// ============================================
// NativeStack stubs
// ============================================
bool NsStartIpTablesTracking(NATIVE_STACK *a) { return false; }

// ============================================
// RPC serialization stubs
// ============================================
void InRpcInternetSetting(INTERNET_SETTING *t, PACK *p) {}
void OutRpcInternetSetting(PACK *p, INTERNET_SETTING *t) {}
void OutRpcNodeInfo(PACK *p, NODE_INFO *t) {}
void OutRpcWinVer(PACK *p, RPC_WINVER *t) {}

// ============================================
// SecurePassword (needed for client auth)
// ============================================
void SecurePassword(void *secure_password, void *password, void *random) {
    // Simple stub - actual implementation hashes password with random
    // For client-only, the server handles this
    if (secure_password && password) {
        memcpy(secure_password, password, SHA1_SIZE);
    }
}

// ============================================
// Global parameters (server config)
// Note: Type matches Server.h: extern UINT vpn_global_parameters[NUM_GLOBAL_PARAMS]
// ============================================
UINT vpn_global_parameters[128] = {0};
