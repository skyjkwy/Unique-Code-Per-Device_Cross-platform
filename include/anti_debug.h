#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include "platform.h"

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
    lic_bool is_protected;
    lic_bool debug_detected;
    lic_bool injection_detected;
    lic_bool integrity_ok;
    int  threat_count;
} AntiDebugStatus;

#ifdef __cplusplus
extern "C" {
#endif

lic_bool AntiDebug_Init(void);

int AntiDebug_Scan(AntiDebugResult *result, int max_results);

int AntiDebug_ScanDebuggerOnly(void);

void AntiDebug_GetStatus(AntiDebugStatus *status);

lic_bool AntiDebug_CheckDebugger(void);

lic_bool AntiDebug_CheckPEBDebugger(void);

lic_bool AntiDebug_CheckRemoteThread(int *suspicious_thread_count);

lic_bool AntiDebug_CheckModuleInjection(char suspicious_modules[][MAX_MODULE_NAME], int max_modules);

lic_bool AntiDebug_CheckCodeIntegrity(uint32_t original_checksum);

lic_bool AntiDebug_CheckReverseTools(void);

lic_bool AntiDebug_ProtectCodeSection(void);

uint32_t AntiDebug_CalculateCodeChecksum(void);

lic_bool AntiDebug_StartPeriodicScan(uint32_t interval_ms);

lic_bool AntiDebug_StopPeriodicScan(void);

void AntiDebug_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
