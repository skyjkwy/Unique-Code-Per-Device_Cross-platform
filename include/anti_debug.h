#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <windows.h>
#include <stdint.h>

#define ANTI_OK 0

#define ANTI_DEBUGGER_ATTACHED 1

#define ANTI_REMOTE_THREAD 2

#define ANTI_SUSPICIOUS_MODULE 3

#define ANTI_CODE_MODIFIED 4

#define ANTI_REVERSE_TOOL 5

#define ANTI_PEB_TAMPERED 6

#define MAX_MODULE_NAME 256

#define MAX_SUSPICIOUS_MODULES 50

typedef struct {
    int threat_type;
    char module_name[MAX_MODULE_NAME];
    uintptr_t address;
    char description[256];
} AntiDebugResult;

typedef struct {
    BOOL is_protected;
    BOOL debug_detected;
    BOOL injection_detected;
    BOOL integrity_ok;
    int  threat_count;
} AntiDebugStatus;

BOOL AntiDebug_Init(void);

int AntiDebug_Scan(AntiDebugResult *result, int max_results);

int AntiDebug_ScanDebuggerOnly(void);

void AntiDebug_GetStatus(AntiDebugStatus *status);

BOOL AntiDebug_CheckDebugger(void);

BOOL AntiDebug_CheckPEBDebugger(void);

BOOL AntiDebug_CheckRemoteThread(int *suspicious_thread_count);

BOOL AntiDebug_CheckModuleInjection(char suspicious_modules[][MAX_MODULE_NAME], int max_modules);

BOOL AntiDebug_CheckCodeIntegrity(uint32_t original_checksum);

BOOL AntiDebug_CheckReverseTools(void);

BOOL AntiDebug_ProtectCodeSection(void);

uint32_t AntiDebug_CalculateCodeChecksum(void);

BOOL AntiDebug_StartPeriodicScan(DWORD interval_ms);

BOOL AntiDebug_StopPeriodicScan(void);

void AntiDebug_Cleanup(void);

#endif
