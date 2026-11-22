#include "anti_debug.h"
#include "sha256.h"
#include <psapi.h>
#include <string.h>

#define SKY_PROC_DEBUG_PORT            7
#define SKY_PROC_DEBUG_OBJECT_HANDLE  30
#define SKY_PROC_DEBUG_FLAGS          31
#define SKY_THREAD_HIDE_FROM_DEBUGGER 17

typedef LONG (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *PFN_NtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);

static PFN_NtQueryInformationProcess g_pfnNtQueryInformationProcess = NULL;
static PFN_NtSetInformationThread    g_pfnNtSetInformationThread = NULL;

static void ResolveNtdllExports(void) {
    if (g_pfnNtQueryInformationProcess && g_pfnNtSetInformationThread) return;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) hNtdll = LoadLibraryW(L"ntdll.dll");
    if (!hNtdll) return;

    if (!g_pfnNtQueryInformationProcess) {
        g_pfnNtQueryInformationProcess = (PFN_NtQueryInformationProcess)
            GetProcAddress(hNtdll, "NtQueryInformationProcess");
    }
    if (!g_pfnNtSetInformationThread) {
        g_pfnNtSetInformationThread = (PFN_NtSetInformationThread)
            GetProcAddress(hNtdll, "NtSetInformationThread");
    }
}

static BOOL g_initialized = FALSE;
static uint8_t g_initial_digest[SHA256_DIGEST_SIZE];
static BOOL g_digest_ready = FALSE;
static AntiDebugStatus g_last_status = {0};

static BOOL GetCodeSectionRange(uintptr_t* code_start, size_t* code_size) {
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) return FALSE;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)hModule;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);

    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)section[i].Name, ".text", 5) == 0 && section[i].Name[5] == '\0') {
            *code_start = (uintptr_t)hModule + section[i].VirtualAddress;
            *code_size = section[i].Misc.VirtualSize;
            return TRUE;
        }
    }

    return FALSE;
}

#define SKY_MAX_PROTECTED_SECTIONS 8

typedef struct {
    const char* name;
    uintptr_t   start;
    size_t      size;
} ProtectedSection;

static int CollectProtectedSections(ProtectedSection out[], int max) {
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) return 0;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)hModule;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return 0;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    int count = 0;

    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections && count < max; i++) {
        const char* name = (const char*)section[i].Name;

        if (section[i].Misc.VirtualSize == 0) continue;
        if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) continue;
        if (section[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) continue;

        if (strncmp(name, ".text", 5) == 0 && name[5] == '\0') {

        } else if (strncmp(name, ".rdata", 6) == 0 && name[6] == '\0') {

        } else if (strncmp(name, ".idata", 6) == 0 && name[6] == '\0') {

        } else if (strncmp(name, ".rsrc", 5) == 0 && name[5] == '\0') {

        } else {
            continue;
        }

        out[count].name  = name;
        out[count].start = (uintptr_t)hModule + section[i].VirtualAddress;
        out[count].size  = section[i].Misc.VirtualSize;
        count++;
    }

    return count;
}

static BOOL ComputeRuntimeDigest(uint8_t digest[SHA256_DIGEST_SIZE]) {
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) return FALSE;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)hModule;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    ProtectedSection sections[SKY_MAX_PROTECTED_SECTIONS];
    int count = CollectProtectedSections(sections, SKY_MAX_PROTECTED_SECTIONS);
    if (count <= 0) return FALSE;

    SHA256_CTX ctx;
    sha256_init(&ctx);

    size_t header_size = nt_headers->OptionalHeader.SizeOfHeaders;
    if (header_size > 0x10000) header_size = 0x10000;
    sha256_update(&ctx, (const uint8_t*)hModule, header_size);

    for (int i = 0; i < count; i++) {

        sha256_update(&ctx, (const uint8_t*)sections[i].name, strlen(sections[i].name));
        sha256_update(&ctx, (const uint8_t*)&sections[i].size, sizeof(sections[i].size));
        sha256_update(&ctx, (const uint8_t*)sections[i].start, sections[i].size);
    }

    sha256_final(&ctx, digest);
    return TRUE;
}

static BOOL CheckRuntimeIntegrity(void) {
    if (!g_digest_ready) return TRUE;

    uint8_t current[SHA256_DIGEST_SIZE];
    if (!ComputeRuntimeDigest(current)) return TRUE;

    return memcmp(current, g_initial_digest, SHA256_DIGEST_SIZE) == 0;
}

static uint32_t table[256] = {0};
static volatile LONG g_crc_table_initialized = 0;

static void InitCRC32Table(void) {
    if (InterlockedCompareExchange(&g_crc_table_initialized, 1, 1) == 1) {
        return;
    }
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
    InterlockedExchange(&g_crc_table_initialized, 1);
}

static uint32_t SimpleCRC32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    if (g_crc_table_initialized != 1) {
        InitCRC32Table();
    }
    for (size_t i = 0; i < len; i++) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

static BOOL CheckNtDebugInfo(void) {
    ResolveNtdllExports();
    if (!g_pfnNtQueryInformationProcess) return FALSE;

    ULONG ret_len = 0;

    ULONG_PTR debug_port = 0;
    if (g_pfnNtQueryInformationProcess(GetCurrentProcess(), SKY_PROC_DEBUG_PORT,
                                       &debug_port, sizeof(debug_port), &ret_len) == 0
        && debug_port != 0) {
        return TRUE;
    }

    HANDLE debug_object = NULL;
    if (g_pfnNtQueryInformationProcess(GetCurrentProcess(), SKY_PROC_DEBUG_OBJECT_HANDLE,
                                       &debug_object, sizeof(debug_object), &ret_len) == 0
        && debug_object != NULL) {
        return TRUE;
    }

    ULONG debug_flags = 1;
    if (g_pfnNtQueryInformationProcess(GetCurrentProcess(), SKY_PROC_DEBUG_FLAGS,
                                       &debug_flags, sizeof(debug_flags), &ret_len) == 0
        && debug_flags == 0) {
        return TRUE;
    }

    return FALSE;
}

static BOOL CheckHardwareBreakpoints(void) {
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) return FALSE;

    return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
}

static BOOL IsReadableCodeAddress(const void* p) {
    MEMORY_BASIC_INFORMATION mbi;

    if (!p) return FALSE;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return FALSE;

    switch (mbi.Protect & 0xFF) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return TRUE;
        default:
            return FALSE;
    }
}

static BOOL CheckNtdllEntryInt3(void) {
    static const char* kWatch[] = {
        "DbgUiRemoteBreakin",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "NtCreateThreadEx",
        "NtQueryObject"
    };
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    int i;

    if (!hNtdll) return FALSE;

    for (i = 0; i < (int)(sizeof(kWatch) / sizeof(kWatch[0])); i++) {
        const unsigned char* fn = (const unsigned char*)GetProcAddress(hNtdll, kWatch[i]);
        if (!fn) continue;
        if (!IsReadableCodeAddress(fn)) continue;
        if (fn[0] == 0xCC) return TRUE;
    }

    return FALSE;
}

static BOOL CheckEntryInt3(void) {
    const unsigned char* watch[] = {
        (const unsigned char*)AntiDebug_CheckDebugger,
        (const unsigned char*)AntiDebug_CheckCodeIntegrity,
        (const unsigned char*)AntiDebug_Scan,
        (const unsigned char*)AntiDebug_CalculateCodeChecksum,
        (const unsigned char*)AntiDebug_Init,
    };

    for (size_t i = 0; i < sizeof(watch) / sizeof(watch[0]); i++) {
        if (watch[i] && watch[i][0] == 0xCC) return TRUE;
    }
    return FALSE;
}

static void HideThreadFromDebugger(void) {
    ResolveNtdllExports();
    if (g_pfnNtSetInformationThread) {
        g_pfnNtSetInformationThread(GetCurrentThread(), SKY_THREAD_HIDE_FROM_DEBUGGER, NULL, 0);
    }
}

BOOL AntiDebug_CheckDebugger(void) {
    if (IsDebuggerPresent()) {
        return TRUE;
    }

    BOOL is_remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_remote) && is_remote) {
        return TRUE;
    }

    return FALSE;
}

BOOL AntiDebug_CheckPEBDebugger(void) {

    return IsDebuggerPresent();
}

BOOL AntiDebug_CheckRemoteThread(int* suspicious_thread_count) {

    if (suspicious_thread_count) {
        *suspicious_thread_count = 0;
    }
    return FALSE;
}

BOOL AntiDebug_CheckModuleInjection(char suspicious_modules[][MAX_MODULE_NAME], int max_modules) {

    HMODULE hProcess = GetCurrentProcess();
    HMODULE hModules[256];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        return FALSE;
    }

    int module_count = cbNeeded / sizeof(HMODULE);
    if (module_count > 256) module_count = 256;
    int suspicious_found = 0;

    for (int i = 0; i < module_count && suspicious_found < max_modules; i++) {
        wchar_t module_name[MAX_PATH];
        if (GetModuleBaseNameW(hProcess, hModules[i], module_name, MAX_PATH)) {
            char lower_name[MAX_PATH];
            int len = WideCharToMultiByte(CP_UTF8, 0, module_name, -1, NULL, 0, NULL, NULL);
            if (len > 0 && len < MAX_PATH) {
                WideCharToMultiByte(CP_UTF8, 0, module_name, -1, lower_name, len, NULL, NULL);
            } else {
                lower_name[0] = '\0';
            }

            if (strstr(lower_name, "frida") ||
                strstr(lower_name, "substrate") ||
                strstr(lower_name, "detours")) {

                if (suspicious_modules) {
                    strncpy(suspicious_modules[suspicious_found], lower_name, MAX_MODULE_NAME - 1);
                    suspicious_modules[suspicious_found][MAX_MODULE_NAME - 1] = '\0';
                }
                suspicious_found++;
            }
        }
    }

    return suspicious_found > 0;
}

uint32_t AntiDebug_CalculateCodeChecksum(void) {
    uintptr_t code_start = 0;
    size_t code_size = 0;

    if (!GetCodeSectionRange(&code_start, &code_size)) {
        return 0;
    }

    return SimpleCRC32((const uint8_t*)code_start, code_size);
}

BOOL AntiDebug_CheckCodeIntegrity(uint32_t original_checksum) {
    if (original_checksum != 0) {
        return AntiDebug_CalculateCodeChecksum() == original_checksum;
    }

    return CheckRuntimeIntegrity();
}

BOOL AntiDebug_ProtectCodeSection(void) {

    return TRUE;
}

BOOL AntiDebug_CheckReverseTools(void) {

    return FALSE;
}

BOOL AntiDebug_Init(void) {
    if (g_initialized) return TRUE;

    InitCRC32Table();

    ResolveNtdllExports();
    if (!AntiDebug_CheckDebugger() && !CheckNtDebugInfo()) {
        HideThreadFromDebugger();
    }

    g_digest_ready = ComputeRuntimeDigest(g_initial_digest);
    g_initialized = TRUE;
    return TRUE;
}

int AntiDebug_Scan(AntiDebugResult* result, int max_results) {
    if (!g_initialized) {
        AntiDebug_Init();
    }

    int threat_found = ANTI_OK;
    int result_index = 0;

    memset(&g_last_status, 0, sizeof(g_last_status));
    g_last_status.is_protected = TRUE;
    g_last_status.integrity_ok = TRUE;

    if (AntiDebug_CheckDebugger() || CheckNtDebugInfo() ||
        CheckHardwareBreakpoints() || CheckNtdllEntryInt3()) {
        threat_found = ANTI_DEBUGGER_ATTACHED;
        g_last_status.debug_detected = TRUE;

        if (result && result_index < max_results) {
            result[result_index].threat_type = ANTI_DEBUGGER_ATTACHED;
            strcpy(result[result_index].description, "检测到调试器已附加");
            result_index++;
        }
    }

    if (!AntiDebug_CheckCodeIntegrity(0)) {
        threat_found = ANTI_CODE_MODIFIED;
        g_last_status.integrity_ok = FALSE;

        if (result && result_index < max_results) {
            result[result_index].threat_type = ANTI_CODE_MODIFIED;
            strcpy(result[result_index].description, "代码段/只读数据/资源已被修改");
            result_index++;
        }
    }

    if (CheckEntryInt3()) {

        if (threat_found != ANTI_DEBUGGER_ATTACHED) {
            threat_found = ANTI_CODE_MODIFIED;
        }
        g_last_status.integrity_ok = FALSE;

        if (result && result_index < max_results) {
            result[result_index].threat_type = ANTI_CODE_MODIFIED;
            strcpy(result[result_index].description, "关键函数入口被写入断点");
            result_index++;
        }
    }

    g_last_status.threat_count = result_index;
    return threat_found;
}

int AntiDebug_ScanDebuggerOnly(void) {
    if (!g_initialized) {
        AntiDebug_Init();
    }

    if (AntiDebug_CheckDebugger() || CheckNtDebugInfo() ||
        CheckHardwareBreakpoints() || CheckNtdllEntryInt3()) {
        g_last_status.debug_detected = TRUE;
        return ANTI_DEBUGGER_ATTACHED;
    }
    if (CheckEntryInt3()) {
        g_last_status.integrity_ok = FALSE;
        return ANTI_CODE_MODIFIED;
    }
    return ANTI_OK;
}

void AntiDebug_GetStatus(AntiDebugStatus* status) {
    if (status) {
        *status = g_last_status;
    }
}

BOOL AntiDebug_StartPeriodicScan(DWORD interval_ms) {

    UNREFERENCED_PARAMETER(interval_ms);
    return TRUE;
}

BOOL AntiDebug_StopPeriodicScan(void) {
    return TRUE;
}

void AntiDebug_Cleanup(void) {
    g_initialized = FALSE;
    g_digest_ready = FALSE;
    memset(g_initial_digest, 0, sizeof(g_initial_digest));
}
