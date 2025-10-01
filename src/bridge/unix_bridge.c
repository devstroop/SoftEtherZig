/*
 * Unix Bridge Layer
 * 
 * OS abstraction layer providing Unix/macOS system implementations.
 * These functions bridge SoftEther's OS dispatch table with native
 * pthread, file I/O, and system calls for client functionality.
 */

// Include SoftEther headers first to get their bool typedef
#include "Mayaqua/Mayaqua.h"
#include "Cedar/Cedar.h"

// System headers needed
#include <sys/stat.h>
#include <errno.h>

//============================================================================
// OS Dispatch Table Stub Functions
//============================================================================

static void stub_Init(void) {}
static void stub_Free(void) {}
static void *stub_MemoryAlloc(UINT size) { return malloc(size); }
static void *stub_MemoryReAlloc(void *addr, UINT size) { return realloc(addr, size); }
static void stub_MemoryFree(void *addr) { free(addr); }

static UINT stub_GetTick(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (UINT)(tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL);
}

static void stub_GetSystemTime(SYSTEMTIME *system_time) { 
    if (system_time) {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        if (tm) {
            system_time->wYear = tm->tm_year + 1900;
            system_time->wMonth = tm->tm_mon + 1;
            system_time->wDay = tm->tm_mday;
            system_time->wHour = tm->tm_hour;
            system_time->wMinute = tm->tm_min;
            system_time->wSecond = tm->tm_sec;
            system_time->wMilliseconds = 0;
        }
    }
}

static void stub_Inc32(UINT *value) { 
    if (value) __sync_add_and_fetch(value, 1);
}

static void stub_Dec32(UINT *value) { 
    if (value) __sync_sub_and_fetch(value, 1);
}

static void stub_Sleep(UINT time) { usleep(time * 1000); }

// Real pthread-based lock implementation
static LOCK *stub_NewLock(void) {
    // Allocate the LOCK structure using SoftEther's allocator
    LOCK *lock = (LOCK *)ZeroMalloc(sizeof(LOCK));
    if (!lock) return NULL;
    
    // Allocate the pthread mutex using malloc (pthread library manages this)
    pthread_mutex_t *mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (!mutex) {
        Free(lock);
        return NULL;
    }
    
    pthread_mutex_init(mutex, NULL);
    lock->pData = mutex;  // Store the pointer to the mutex
    lock->Ready = true;
    return lock;
}

static bool stub_Lock(LOCK *lock) { 
    if (lock && lock->pData) {
        pthread_mutex_lock((pthread_mutex_t *)lock->pData);
        return true;
    }
    return false;
}

static void stub_Unlock(LOCK *lock) { 
    if (lock && lock->pData) {
        pthread_mutex_unlock((pthread_mutex_t *)lock->pData);
    }
}

static void stub_DeleteLock(LOCK *lock) {
    if (lock) {
        if (lock->pData) {
            pthread_mutex_destroy((pthread_mutex_t *)lock->pData);
            free(lock->pData);  // pthread_mutex_t was allocated with malloc
        }
        Free(lock);  // LOCK was allocated with ZeroMalloc, use Free()
    }
}

// Real pthread-based event implementation
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool signaled;
} PTHREAD_EVENT;

static void stub_InitEvent(EVENT *event) {
    if (!event) return;
    PTHREAD_EVENT *ev = (PTHREAD_EVENT *)malloc(sizeof(PTHREAD_EVENT));
    if (!ev) return;
    pthread_mutex_init(&ev->mutex, NULL);
    pthread_cond_init(&ev->cond, NULL);
    ev->signaled = false;  // FIXED: Consistent field name
    event->pData = ev;  // FIXED: Use pData field
}

static void stub_SetEvent(EVENT *event) {
    if (!event) return;
    PTHREAD_EVENT *ev = (PTHREAD_EVENT *)event->pData;  // FIXED: Use pData field
    if (ev) {
        pthread_mutex_lock(&ev->mutex);
        ev->signaled = true;
        pthread_cond_broadcast(&ev->cond);
        pthread_mutex_unlock(&ev->mutex);
    }
}

static void stub_ResetEvent(EVENT *event) {
    if (!event) return;
    PTHREAD_EVENT *ev = (PTHREAD_EVENT *)event->pData;  // FIXED: Use pData field
    if (ev) {
        pthread_mutex_lock(&ev->mutex);
        ev->signaled = false;
        pthread_mutex_unlock(&ev->mutex);
    }
}

static bool stub_WaitEvent(EVENT *event, UINT timeout) {
    if (!event) return false;
    PTHREAD_EVENT *ev = (PTHREAD_EVENT *)event->pData;  // FIXED: Use pData field
    if (!ev) return false;
    
    pthread_mutex_lock(&ev->mutex);
    
    if (timeout == 0xFFFFFFFF) {
        // Infinite wait
        while (!ev->signaled) {
            pthread_cond_wait(&ev->cond, &ev->mutex);
        }
        pthread_mutex_unlock(&ev->mutex);
        return true;
    } else {
        // Timed wait
        struct timespec ts;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        ts.tv_sec = tv.tv_sec + (timeout / 1000);
        ts.tv_nsec = (tv.tv_usec * 1000) + ((timeout % 1000) * 1000000);
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        
        while (!ev->signaled) {
            int ret = pthread_cond_timedwait(&ev->cond, &ev->mutex, &ts);
            if (ret == ETIMEDOUT) {
                pthread_mutex_unlock(&ev->mutex);
                return false;
            }
        }
        pthread_mutex_unlock(&ev->mutex);
        return true;
    }
}

static void stub_FreeEvent(EVENT *event) {
    if (!event) return;
    PTHREAD_EVENT *ev = (PTHREAD_EVENT *)event->pData;  // FIXED: Use pData field
    if (ev) {
        pthread_mutex_destroy(&ev->mutex);
        pthread_cond_destroy(&ev->cond);
        free(ev);  // pthread structures use malloc/free
        event->pData = NULL;
    }
}

static bool stub_WaitThread(THREAD *t) { 
    if (!t) return false;
    pthread_t *thread = (pthread_t *)t->pData;  // FIXED: Use t->pData
    if (thread) {
        pthread_join(*thread, NULL);
        return true;
    }
    return false;
}

static void stub_FreeThread(THREAD *t) {
    if (!t) return;
    printf("[stub_FreeThread] t=%p, pData=%p\n", t, t->pData);
    pthread_t *thread = (pthread_t *)t->pData;  // FIXED: Use t->pData
    if (thread) {
        free(thread);  // pthread_t was allocated with malloc
        t->pData = NULL;  // FIXED: Clear pData, not the THREAD pointer
    }
}

// Thread start wrapper that calls NoticeThreadInit after thread_proc
static void *thread_start_wrapper(void *param) {
    THREAD *t = (THREAD *)param;
    if (t && t->thread_proc) {
        t->thread_proc(t, t->param);
    }
    return NULL;
}

static bool stub_InitThread(THREAD *t) { 
    if (!t) return false;
    
    // Initialize reference counter only if not already set
    if (t->ref == NULL || (uintptr_t)t->ref < 0x10000) {
        t->ref = NewRef();
        if (t->ref == NULL) return false;
    }
    
    // Add a reference for the thread itself (like real UnixInitThread)
    AddRef(t->ref);
    
    pthread_t *thread = (pthread_t *)malloc(sizeof(pthread_t));
    if (!thread) return false;
    
    int ret = pthread_create(thread, NULL, thread_start_wrapper, t);
    if (ret != 0) {
        free(thread);
        return false;
    }
    
    t->pData = thread;
    return true;
}

static UINT stub_ThreadId(void) { 
    // On macOS pthread_t is a pointer, hash it to get a UINT
    return (UINT)((uintptr_t)pthread_self() & 0xFFFFFFFF);
}

// Real file I/O implementations using standard C functions
static void *stub_FileOpen(char *name, bool write_mode, bool read_lock) {
    if (!name) return NULL;
    const char *mode = write_mode ? "r+b" : "rb";
    FILE *fp = fopen(name, mode);
    return (void *)fp;
}

static void *stub_FileOpenW(wchar_t *name, bool write_mode, bool read_lock) {
    if (!name) return NULL;
    // Convert wchar_t to char (simplified - assumes ASCII path)
    char path[4096];
    size_t i;
    for (i = 0; i < 4095 && name[i]; i++) {
        path[i] = (char)name[i];
    }
    path[i] = '\0';
    return stub_FileOpen(path, write_mode, read_lock);
}

static void *stub_FileCreate(char *name) {
    if (!name) return NULL;
    FILE *fp = fopen(name, "w+b");
    return (void *)fp;
}

static void *stub_FileCreateW(wchar_t *name) {
    if (!name) return NULL;
    char path[4096];
    size_t i;
    for (i = 0; i < 4095 && name[i]; i++) {
        path[i] = (char)name[i];
    }
    path[i] = '\0';
    return stub_FileCreate(path);
}

static bool stub_FileWrite(void *pData, void *buf, UINT size) {
    if (!pData || !buf) return false;
    FILE *fp = (FILE *)pData;
    return fwrite(buf, 1, size, fp) == size;
}

static bool stub_FileRead(void *pData, void *buf, UINT size) {
    if (!pData || !buf) return false;
    FILE *fp = (FILE *)pData;
    return fread(buf, 1, size, fp) == size;
}

static void stub_FileClose(void *pData, bool no_flush) {
    if (pData) {
        if (!no_flush) fflush((FILE *)pData);
        fclose((FILE *)pData);
    }
}

static void stub_FileFlush(void *pData) {
    if (pData) fflush((FILE *)pData);
}

static UINT64 stub_FileSize(void *pData) {
    if (!pData) return 0;
    FILE *fp = (FILE *)pData;
    long current = ftell(fp);
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, current, SEEK_SET);
    return (UINT64)size;
}

static bool stub_FileSeek(void *pData, UINT mode, int offset) {
    if (!pData) return false;
    FILE *fp = (FILE *)pData;
    int whence = (mode == 0) ? SEEK_SET : (mode == 1) ? SEEK_CUR : SEEK_END;
    return fseek(fp, offset, whence) == 0;
}

static bool stub_FileDelete(char *name) {
    if (!name) return false;
    return unlink(name) == 0;
}

static bool stub_FileDeleteW(wchar_t *name) {
    if (!name) return false;
    char path[4096];
    size_t i;
    for (i = 0; i < 4095 && name[i]; i++) {
        path[i] = (char)name[i];
    }
    path[i] = '\0';
    return stub_FileDelete(path);
}

static bool stub_MakeDir(char *name) {
    if (!name) return false;
    return mkdir(name, 0755) == 0;
}

static bool stub_MakeDirW(wchar_t *name) {
    if (!name) return false;
    char path[4096];
    size_t i;
    for (i = 0; i < 4095 && name[i]; i++) {
        path[i] = (char)name[i];
    }
    path[i] = '\0';
    return stub_MakeDir(path);
}

static bool stub_DeleteDir(char *name) {
    if (!name) return false;
    return rmdir(name) == 0;
}

static bool stub_DeleteDirW(wchar_t *name) {
    if (!name) return false;
    char path[4096];
    size_t i;
    for (i = 0; i < 4095 && name[i]; i++) {
        path[i] = (char)name[i];
    }
    path[i] = '\0';
    return stub_DeleteDir(path);
}

static CALLSTACK_DATA *stub_GetCallStack(void) { return NULL; }
static bool stub_GetCallStackSymbolInfo(CALLSTACK_DATA *s) { return false; }

static bool stub_FileRename(char *old_name, char *new_name) {
    if (!old_name || !new_name) return false;
    return rename(old_name, new_name) == 0;
}

static bool stub_FileRenameW(wchar_t *old_name, wchar_t *new_name) {
    if (!old_name || !new_name) return false;
    char old_path[4096], new_path[4096];
    size_t i;
    for (i = 0; i < 4095 && old_name[i]; i++) {
        old_path[i] = (char)old_name[i];
    }
    old_path[i] = '\0';
    for (i = 0; i < 4095 && new_name[i]; i++) {
        new_path[i] = (char)new_name[i];
    }
    new_path[i] = '\0';
    return stub_FileRename(old_path, new_path);
}
static bool stub_Run(char *filename, char *arg, bool hide, bool wait) { return false; }
static bool stub_RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait) { return false; }
static bool stub_IsSupportedOs(void) { return true; }
static void stub_GetOsInfo(OS_INFO *info) { memset(info, 0, sizeof(OS_INFO)); }
static void stub_Alert(char *msg, char *caption) {}
static void stub_AlertW(wchar_t *msg, wchar_t *caption) {}
static char *stub_GetProductId(void) { return ""; }
static void stub_SetHighPriority(void) {}
static void stub_RestorePriority(void) {}
static void *stub_NewSingleInstance(char *instance_name) { return NULL; }
static void stub_FreeSingleInstance(void *data) {}
static void stub_GetMemInfo(MEMINFO *info) { memset(info, 0, sizeof(MEMINFO)); }
static void stub_Yield(void) { usleep(1000); }

// Unix dispatch table - returns static structure with stub functions
OS_DISPATCH_TABLE *UnixGetDispatchTable(void) {
    static OS_DISPATCH_TABLE t = {
        stub_Init,
        stub_Free,
        stub_MemoryAlloc,
        stub_MemoryReAlloc,
        stub_MemoryFree,
        stub_GetTick,
        stub_GetSystemTime,
        stub_Inc32,
        stub_Dec32,
        stub_Sleep,
        stub_NewLock,
        stub_Lock,
        stub_Unlock,
        stub_DeleteLock,
        stub_InitEvent,
        stub_SetEvent,
        stub_ResetEvent,
        stub_WaitEvent,
        stub_FreeEvent,
        stub_WaitThread,
        stub_FreeThread,
        stub_InitThread,
        stub_ThreadId,
        stub_FileOpen,
        stub_FileOpenW,
        stub_FileCreate,
        stub_FileCreateW,
        stub_FileWrite,
        stub_FileRead,
        stub_FileClose,
        stub_FileFlush,
        stub_FileSize,
        stub_FileSeek,
        stub_FileDelete,
        stub_FileDeleteW,
        stub_MakeDir,
        stub_MakeDirW,
        stub_DeleteDir,
        stub_DeleteDirW,
        stub_GetCallStack,
        stub_GetCallStackSymbolInfo,
        stub_FileRename,
        stub_FileRenameW,
        stub_Run,
        stub_RunW,
        stub_IsSupportedOs,
        stub_GetOsInfo,
        stub_Alert,
        stub_AlertW,
        stub_GetProductId,
        stub_SetHighPriority,
        stub_RestorePriority,
        stub_NewSingleInstance,
        stub_FreeSingleInstance,
        stub_GetMemInfo,
        stub_Yield,
    };
    return &t;
}

//============================================================================
// Other Unix utility stubs  
//============================================================================

void UnixDisableCoreDump(void) {}
void UnixSetResourceLimit(UINT id, UINT64 value) {}
void UnixSetHighOomScore(void) {}
void UnixSetThreadPriorityRealtime(void) {}
void UnixIgnoreSignalForThread(int sig) {}
void UnixSetEnableKernelEspProcessing(bool b) {}
void UnixCloseIO(void) {}
UINT UnixGetNumberOfCpuInner(void) { return 1; }
bool UnixIsInVm(void) { return false; }
UINT64 UnixGetHighresTickNano64(bool raw) { 
    // Use our Tick64 implementation scaled to nanoseconds
    return Tick64() * 1000000ULL;
}

// Directory/File stubs
bool UnixCheckExecAccessW(wchar_t *name) { (void)name; return false; }
void UnixGetCurrentDir(char *dir, UINT size) { if (dir && size) dir[0] = 0; }
void UnixGetCurrentDirW(wchar_t *dir, UINT size) { if (dir && size) dir[0] = 0; }
bool UnixGetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size) { (void)path; (void)free_size; (void)used_size; (void)total_size; return false; }
bool UnixGetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size) { (void)path; (void)free_size; (void)used_size; (void)total_size; return false; }
DIRLIST *UnixEnumDirExW(wchar_t *dirname, COMPARE *compare) { return NULL; }
TOKEN_LIST *UnixExec(char *cmd) { return NULL; }
void UnixExecSilent(char *cmd) {}

// VLan/TAP stubs (not needed for client)
void UnixVLanInit(void) {}
bool UnixVLanCreate(char *name, UCHAR *mac_address) { (void)name; (void)mac_address; return false; }
void UnixVLanDelete(char *name) { (void)name; }
void UnixVLanFree(void *vlan) { (void)vlan; }
PACKET_ADAPTER *VLanGetPacketAdapter(void) { return NULL; }
bool VLanPutPacket(VLAN *v, void *buf, UINT size) { (void)v; (void)buf; (void)size; return false; }
void FreeTap(void *tap) { (void)tap; }

// HTTP/URL stubs (minimal implementations)
bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer) { (void)data; (void)str; (void)is_post; (void)referrer; return false; }
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

// WPC (Windows Proxy Configuration) stubs - not used on Unix
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
