#include "anti_debug.h"

#include <string.h>

lic_bool AntiDebug_Init(void) { return TRUE; }

int AntiDebug_Scan(AntiDebugResult *result, int max_results) {
    (void)result;
    (void)max_results;
    return 0;
}

int AntiDebug_ScanDebuggerOnly(void) { return 0; }

void AntiDebug_GetStatus(AntiDebugStatus *status) {
    if (!status) return;
    memset(status, 0, sizeof(*status));
    status->is_protected = TRUE;
    status->integrity_ok = TRUE;
}

lic_bool AntiDebug_CheckDebugger(void) { return FALSE; }

lic_bool AntiDebug_CheckPEBDebugger(void) { return FALSE; }

lic_bool AntiDebug_CheckRemoteThread(int *suspicious_thread_count) {
    if (suspicious_thread_count) *suspicious_thread_count = 0;
    return FALSE;
}

lic_bool AntiDebug_CheckModuleInjection(char suspicious_modules[][MAX_MODULE_NAME],
                                        int max_modules) {
    (void)suspicious_modules;
    (void)max_modules;
    return FALSE;
}

lic_bool AntiDebug_CheckCodeIntegrity(uint32_t original_checksum) {
    (void)original_checksum;
    return TRUE;
}

lic_bool AntiDebug_CheckReverseTools(void) { return FALSE; }

lic_bool AntiDebug_ProtectCodeSection(void) { return TRUE; }

uint32_t AntiDebug_CalculateCodeChecksum(void) { return 0; }

lic_bool AntiDebug_StartPeriodicScan(uint32_t interval_ms) {
    (void)interval_ms;
    return TRUE;
}

lic_bool AntiDebug_StopPeriodicScan(void) { return TRUE; }

void AntiDebug_Cleanup(void) {}
