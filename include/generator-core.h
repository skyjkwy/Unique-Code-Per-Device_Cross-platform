#ifndef GENERATOR_CORE_H
#define GENERATOR_CORE_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IDI_ICON1           101
#define IDC_MACHINE_CODE    1001
#define IDC_ACTIVATION_CODE 1002
#define IDC_BUTTON_GENERATE 1003
#define IDC_BUTTON_COPY     1004
#define IDC_STATUS          1005
#define IDC_USERNAME        1006
#define IDC_EMAIL           1007
#define IDC_YEARS           1008
#define IDC_MONTHS          1009
#define IDC_DAYS_EDIT       1010
#define IDC_HOURS           1011
#define IDC_MINUTES         1012
#define IDC_SECONDS         1013

#define IDT_TIMER_REALTIME  1

#define NTP_RESYNC_INTERVAL 300

#define COLOR_PRIMARY           RGB(0, 120, 212)
#define COLOR_PRIMARY_PRESSED   RGB(0, 90, 158)
#define COLOR_SECONDARY_BG      RGB(255, 255, 255)
#define COLOR_SECONDARY_BORDER  RGB(204, 204, 204)
#define COLOR_SECONDARY_PRESSED RGB(243, 242, 241)
#define COLOR_TEXT_DARK         RGB(51, 51, 51)
#define COLOR_TEXT_WHITE        RGB(255, 255, 255)
#define COLOR_TEXT_STATUS       RGB(128, 128, 128)
#define COLOR_OUTPUT_BG         RGB(220, 220, 220)

#define COLOR_DANGER            RGB(196, 43, 28)
#define COLOR_DANGER_PRESSED    RGB(160, 16, 13)

#define COLOR_GENERATE          RGB(16, 137, 62)
#define COLOR_GENERATE_PRESSED  RGB(16, 110, 45)
#define COLOR_COPY              RGB(0, 138, 160)
#define COLOR_COPY_PRESSED      RGB(0, 110, 128)

#define GEN_BTN_NO_BORDER       CLR_INVALID

extern HWND hWnd;
extern HWND hEditMachineCode;
extern HWND hEditActivationCode;
extern HWND hEditUsername;
extern HWND hEditEmail;
extern HWND hEditYears;
extern HWND hEditMonths;
extern HWND hEditDaysEdit;
extern HWND hEditHours;
extern HWND hEditMinutes;
extern HWND hEditSeconds;
extern HWND hButtonGenerate;
extern HWND hButtonCopy;
extern HWND hStaticStatus;

extern uint32_t g_verified_time;
extern int64_t  g_time_offset;
extern uint32_t g_last_ntp_sync_local;
extern WCHAR    g_current_status[512];

extern HFONT  g_hFontTitle;
extern HFONT  g_hFontLabel;
extern HFONT  g_hFontInput;
extern HFONT  g_hFontSmallInput;
extern HFONT  g_hFontStatus;
extern HFONT  g_hFontButton;
extern HBRUSH g_hBrushOutput;

void CreateControls(HWND hwnd);
void UpdateStatus(const WCHAR *text);

void Generator_EnableStatusPopups(BOOL enable);
void RefreshNtpTime(void);
uint32_t GetRealTimeVerified(void);
void CheckAndResyncNtp(void);

void Generator_SetTitleExtra(const WCHAR *extra);

void Generator_CenterOnScreen(HWND hwnd);

void Generator_DrawFlatButtonEx(const DRAWITEMSTRUCT *dis, COLORREF bg, COLORREF bgDown,
                                COLORREF textColor, COLORREF borderColor);

void OnGenerateActivationCode(void);
void OnCopyActivationCode(void);

BOOL Generator_ReadGenerateRequest(char *machineNorm, size_t machineCap,
                                   char *user, size_t userCap,
                                   char *email, size_t emailCap,
                                   uint64_t *outSeconds);

void Generator_ShowActivationCode(const char *utf8Code, uint64_t totalSeconds, uint32_t expire);

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#ifdef __cplusplus
}
#endif

#endif
