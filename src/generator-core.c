#include "generator-core.h"
#include "license.h"
#include "ntp_client.h"
#include "anti_debug.h"
#include "generator-version.h"
#include <stdio.h>
#include <wchar.h>
#include <time.h>

HWND hWnd = NULL;
HWND hEditMachineCode = NULL;
HWND hEditActivationCode = NULL;
HWND hEditUsername = NULL;
HWND hEditEmail = NULL;
HWND hEditYears = NULL;
HWND hEditMonths = NULL;
HWND hEditDaysEdit = NULL;
HWND hEditHours = NULL;
HWND hEditMinutes = NULL;
HWND hEditSeconds = NULL;
HWND hButtonGenerate = NULL;
HWND hButtonCopy = NULL;
HWND hStaticStatus = NULL;

uint32_t g_verified_time = 0;
int64_t  g_time_offset = 0;
uint32_t g_last_ntp_sync_local = 0;
WCHAR    g_current_status[512] = { 0 };

HFONT  g_hFontTitle = NULL;
HFONT  g_hFontLabel = NULL;
HFONT  g_hFontInput = NULL;
HFONT  g_hFontSmallInput = NULL;
HFONT  g_hFontStatus = NULL;
HFONT  g_hFontButton = NULL;
HBRUSH g_hBrushOutput = NULL;

static void ApplyWindowTitle(HWND hwnd);
static void StartNtpQueryAsync(void);

static BOOL IsValidEmail(const char *email) {
    if (!email || strlen(email) == 0) return TRUE;
    const char *at = strchr(email, '@');
    if (!at || at == email) return FALSE;
    const char *last_at = strrchr(email, '@');
    if (at != last_at) return FALSE;
    const char *domain = at + 1;
    if (strlen(domain) == 0) return FALSE;
    const char *dot = strrchr(domain, '.');
    if (!dot || dot == domain || strlen(dot + 1) == 0) return FALSE;
    if (domain[0] == '.' || domain[strlen(domain) - 1] == '.') return FALSE;
    return TRUE;
}

void CreateControls(HWND hwnd) {
    g_hFontTitle = CreateFontW(-MulDiv(14, 96, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
    g_hFontLabel = CreateFontW(-MulDiv(11, 96, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
    g_hFontInput = CreateFontW(-MulDiv(20, 96, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
    g_hFontSmallInput = CreateFontW(-MulDiv(16, 96, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
    g_hFontStatus = CreateFontW(-MulDiv(10, 96, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
    g_hFontButton = CreateFontW(-MulDiv(11, 96, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    g_hBrushOutput = CreateSolidBrush(COLOR_OUTPUT_BG);

    HWND hStaticTitle = CreateWindowW(L"STATIC", L"激活码生成器", WS_VISIBLE | WS_CHILD | SS_CENTER,
                                      24, 20, 1052, 28, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticTitle, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);

    HWND hStaticMachine = CreateWindowW(L"STATIC", L"机器码:", WS_VISIBLE | WS_CHILD,
                                        24, 64, 84, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticMachine, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditMachineCode = CreateWindowW(L"EDIT", L"",
                                     WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL,
                                     120, 56, 932, 36, hwnd, (HMENU)IDC_MACHINE_CODE, NULL, NULL);
    SendMessageW(hEditMachineCode, WM_SETFONT, (WPARAM)g_hFontInput, TRUE);

    HWND hStaticUsername = CreateWindowW(L"STATIC", L"用户名:", WS_VISIBLE | WS_CHILD,
                                         24, 112, 84, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticUsername, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditUsername = CreateWindowW(L"EDIT", L"",
                                  WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL,
                                  120, 104, 932, 36, hwnd, (HMENU)IDC_USERNAME, NULL, NULL);
    SendMessageW(hEditUsername, WM_SETFONT, (WPARAM)g_hFontInput, TRUE);

    HWND hStaticEmail = CreateWindowW(L"STATIC", L"邮箱:", WS_VISIBLE | WS_CHILD,
                                      24, 160, 84, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticEmail, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditEmail = CreateWindowW(L"EDIT", L"",
                               WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL,
                               120, 152, 932, 36, hwnd, (HMENU)IDC_EMAIL, NULL, NULL);
    SendMessageW(hEditEmail, WM_SETFONT, (WPARAM)g_hFontInput, TRUE);

    HWND hStaticTime = CreateWindowW(L"STATIC", L"授权时间:", WS_VISIBLE | WS_CHILD,
                                     24, 208, 84, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticTime, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditYears = CreateWindowW(L"EDIT", L"",
                                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL | ES_NUMBER,
                                120, 204, 90, 36, hwnd, (HMENU)IDC_YEARS, NULL, NULL);
    SendMessageW(hEditYears, WM_SETFONT, (WPARAM)g_hFontSmallInput, TRUE);

    HWND hStaticYears = CreateWindowW(L"STATIC", L"年", WS_VISIBLE | WS_CHILD,
                                      216, 208, 24, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticYears, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditMonths = CreateWindowW(L"EDIT", L"",
                                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL | ES_NUMBER,
                                244, 204, 80, 36, hwnd, (HMENU)IDC_MONTHS, NULL, NULL);
    SendMessageW(hEditMonths, WM_SETFONT, (WPARAM)g_hFontSmallInput, TRUE);

    HWND hStaticMonths = CreateWindowW(L"STATIC", L"月", WS_VISIBLE | WS_CHILD,
                                       328, 208, 24, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticMonths, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditDaysEdit = CreateWindowW(L"EDIT", L"",
                                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL | ES_NUMBER,
                                356, 204, 80, 36, hwnd, (HMENU)IDC_DAYS_EDIT, NULL, NULL);
    SendMessageW(hEditDaysEdit, WM_SETFONT, (WPARAM)g_hFontSmallInput, TRUE);

    HWND hStaticDays = CreateWindowW(L"STATIC", L"日", WS_VISIBLE | WS_CHILD,
                                      440, 208, 24, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticDays, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditHours = CreateWindowW(L"EDIT", L"",
                                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL | ES_NUMBER,
                                468, 204, 80, 36, hwnd, (HMENU)IDC_HOURS, NULL, NULL);
    SendMessageW(hEditHours, WM_SETFONT, (WPARAM)g_hFontSmallInput, TRUE);

    HWND hStaticHours = CreateWindowW(L"STATIC", L"时", WS_VISIBLE | WS_CHILD,
                                      552, 208, 24, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticHours, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditMinutes = CreateWindowW(L"EDIT", L"",
                                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL | ES_NUMBER,
                                580, 204, 80, 36, hwnd, (HMENU)IDC_MINUTES, NULL, NULL);
    SendMessageW(hEditMinutes, WM_SETFONT, (WPARAM)g_hFontSmallInput, TRUE);

    HWND hStaticMinutes = CreateWindowW(L"STATIC", L"分", WS_VISIBLE | WS_CHILD,
                                      664, 208, 24, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticMinutes, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditSeconds = CreateWindowW(L"EDIT", L"",
                                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_CENTER | ES_AUTOHSCROLL | ES_NUMBER,
                                692, 204, 80, 36, hwnd, (HMENU)IDC_SECONDS, NULL, NULL);
    SendMessageW(hEditSeconds, WM_SETFONT, (WPARAM)g_hFontSmallInput, TRUE);

    HWND hStaticSeconds = CreateWindowW(L"STATIC", L"秒", WS_VISIBLE | WS_CHILD,
                                      776, 208, 24, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticSeconds, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hButtonGenerate = CreateWindowW(L"BUTTON", L"生成激活码",
                                    WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                                    120, 264, 932, 36, hwnd, (HMENU)IDC_BUTTON_GENERATE, NULL, NULL);
    SendMessageW(hButtonGenerate, WM_SETFONT, (WPARAM)g_hFontButton, TRUE);

    HWND hStaticActivation = CreateWindowW(L"STATIC", L"激活码:", WS_VISIBLE | WS_CHILD,
                                           24, 312, 84, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticActivation, WM_SETFONT, (WPARAM)g_hFontLabel, TRUE);

    hEditActivationCode = CreateWindowW(L"EDIT", L"",
                                        WS_VISIBLE | WS_CHILD | ES_READONLY | ES_CENTER | ES_AUTOHSCROLL,
                                        120, 304, 932, 36, hwnd, (HMENU)IDC_ACTIVATION_CODE, NULL, NULL);
    SendMessageW(hEditActivationCode, WM_SETFONT, (WPARAM)g_hFontInput, TRUE);

    hButtonCopy = CreateWindowW(L"BUTTON", L"复制激活码",
                                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                                120, 352, 932, 36, hwnd, (HMENU)IDC_BUTTON_COPY, NULL, NULL);
    SendMessageW(hButtonCopy, WM_SETFONT, (WPARAM)g_hFontButton, TRUE);

    hStaticStatus = CreateWindowW(L"STATIC", L"状态: 等待输入", WS_VISIBLE | WS_CHILD,
                                  24, 408, 1052, 20, hwnd, (HMENU)IDC_STATUS, NULL, NULL);
    SendMessageW(hStaticStatus, WM_SETFONT, (WPARAM)g_hFontStatus, TRUE);

    HWND hStaticInfo = CreateWindowW(L"STATIC", L"输入机器码、用户名、邮箱和授权时间(留空或全0=永久)，点击生成激活码",
                                     WS_VISIBLE | WS_CHILD, 24, 436, 1052, 20, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticInfo, WM_SETFONT, (WPARAM)g_hFontStatus, TRUE);

    UpdateStatus(L"状态: 等待输入");
    ApplyWindowTitle(hwnd);
    StartNtpQueryAsync();
    SetTimer(hwnd, IDT_TIMER_REALTIME, 1000, NULL);
}

void UpdateStatus(const WCHAR *text) {
    if (text) wcscpy_s(g_current_status, 512, text);
    SetWindowTextW(hStaticStatus, text);
}

static WCHAR g_szTitleExtra[192] = L"";

void Generator_SetTitleExtra(const WCHAR *extra)
{
    if (!extra) { g_szTitleExtra[0] = L'\0'; return; }
    _snwprintf_s(g_szTitleExtra, ARRAYSIZE(g_szTitleExtra), _TRUNCATE, L"%s", extra);
}

static void VerifiedTimeText(WCHAR *out, size_t cch)
{
    char szTime[64] = { 0 };

    out[0] = L'\0';
    if (g_last_ntp_sync_local == 0) {
        _snwprintf_s(out, cch, _TRUNCATE, L"同步中...");
        return;
    }
    FormatExpireTime(g_verified_time, szTime, sizeof(szTime));
    MultiByteToWideChar(CP_UTF8, 0, szTime, -1, out, (int)cch);
    if (!out[0]) _snwprintf_s(out, cch, _TRUNCATE, L"未知");
}

static void ApplyWindowTitle(HWND hwnd)
{
    WCHAR wTitle[400];
    WCHAR wTime[80];

    if (!hwnd) return;
    VerifiedTimeText(wTime, ARRAYSIZE(wTime));
    _snwprintf_s(wTitle, ARRAYSIZE(wTitle), _TRUNCATE,
                 L"激活码生成器%s - v%d.%d.%d.%d | 可信时间 %s",
                 g_szTitleExtra,
                 GEN_VERSION_MAJOR, GEN_VERSION_MINOR,
                 GEN_VERSION_BUILD, GEN_VERSION_REVISION,
                 (g_last_ntp_sync_local == 0) ? L"同步中..." : wTime);
    SetWindowTextW(hwnd, wTitle);
}

#define WM_APP_NTP_DONE (WM_APP + 60)
#define NTP_RETRY_SECONDS 5

static volatile LONG g_ntpInFlight = 0;
static uint32_t      g_ntpResult   = 0;
static uint32_t      g_ntpStartLocal = 0;
static uint32_t      g_ntpRttSeconds = 0;
static uint32_t      g_ntpRetryAt    = 0;

static DWORD WINAPI NtpThreadProc(LPVOID param)
{
    LARGE_INTEGER freq, t0, t1;
    uint32_t ntp = 0;
    BOOL ok;

    (void)param;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    ok = GetNtpTime(&ntp);
    QueryPerformanceCounter(&t1);

    if (ok && freq.QuadPart > 0) {

        __int64 rtt = (t1.QuadPart - t0.QuadPart) / freq.QuadPart;
        g_ntpRttSeconds = (uint32_t)(rtt / 2);
        g_ntpResult = ntp;
    }
    PostMessageW(hWnd, WM_APP_NTP_DONE, (WPARAM)(ok ? 1 : 0), 0);
    return 0;
}

static void StartNtpQueryAsync(void)
{
    uint32_t now = (uint32_t)time(NULL);
    HANDLE th;

    if (g_ntpInFlight != 0) return;
    if (g_last_ntp_sync_local == 0) {
        if ((int32_t)(now - g_ntpRetryAt) < 0) return;
    } else if (now - g_last_ntp_sync_local < NTP_RESYNC_INTERVAL) {
        return;
    }

    g_ntpStartLocal = now;
    th = CreateThread(NULL, 0, NtpThreadProc, NULL, 0, NULL);
    if (!th) return;
    InterlockedExchange(&g_ntpInFlight, 1);
    CloseHandle(th);
}

void RefreshNtpTime() {
    uint32_t ntp_time = 0;
    uint32_t local_time = (uint32_t)time(NULL);
    if (GetNtpTime(&ntp_time)) {
        g_time_offset = (int64_t)ntp_time - (int64_t)local_time;
        g_last_ntp_sync_local = local_time;
        g_verified_time = ntp_time;
    }
}

uint32_t GetRealTimeVerified() {
    uint32_t local_time = (uint32_t)time(NULL);
    int64_t real_time = (int64_t)local_time + g_time_offset;
    if (real_time > 0 && real_time < 0xFFFFFFFF) {
        g_verified_time = (uint32_t)real_time;
    }
    return g_verified_time;
}

void CheckAndResyncNtp() {
    StartNtpQueryAsync();
}

void Generator_CenterOnScreen(HWND hwnd)
{
    RECT rc, wa;
    int x, y;

    if (!hwnd || !GetWindowRect(hwnd, &rc)) return;

    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0)) {
        wa.left = 0;
        wa.top = 0;
        wa.right = GetSystemMetrics(SM_CXSCREEN);
        wa.bottom = GetSystemMetrics(SM_CYSCREEN);
    }

    x = wa.left + ((wa.right - wa.left) - (rc.right - rc.left)) / 2;
    y = wa.top  + ((wa.bottom - wa.top) - (rc.bottom - rc.top)) / 2;
    if (x < wa.left) x = wa.left;
    if (y < wa.top)  y = wa.top;

    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

static void GetEditTextA(HWND hEdit, char *buf, int max_len) {
    WCHAR wbuf[256] = { 0 };
    GetWindowTextW(hEdit, wbuf, 256);
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, max_len, NULL, NULL);
}

static int GetEditInt(HWND hEdit) {
    WCHAR wbuf[32] = { 0 };
    GetWindowTextW(hEdit, wbuf, 32);
    return _wtoi(wbuf);
}

BOOL Generator_ReadGenerateRequest(char *machineNorm, size_t machineCap,
                                   char *user, size_t userCap,
                                   char *email, size_t emailCap,
                                   uint64_t *outSeconds) {
    char raw_machine_input[200] = { 0 };
    int years, months, days, hours, minutes, seconds;
    LicenseTime license_time;

    GetEditTextA(hEditMachineCode, raw_machine_input, sizeof(raw_machine_input));
    GetEditTextA(hEditUsername, user, (int)userCap);
    GetEditTextA(hEditEmail, email, (int)emailCap);

    years = GetEditInt(hEditYears);
    months = GetEditInt(hEditMonths);
    days = GetEditInt(hEditDaysEdit);
    hours = GetEditInt(hEditHours);
    minutes = GetEditInt(hEditMinutes);
    seconds = GetEditInt(hEditSeconds);

    if (strlen(raw_machine_input) == 0) { UpdateStatus(L"状态: 请输入机器码"); return FALSE; }
    if (!NormalizeMachineCode(raw_machine_input, machineNorm, machineCap)) {
        UpdateStatus(L"状态: 机器码格式无效（请检查输入内容）"); return FALSE;
    }
    if (machineNorm[0] == '\0') { UpdateStatus(L"状态: 请输入机器码"); return FALSE; }
    if (!IsValidEmail(email)) { UpdateStatus(L"状态: 邮箱格式不正确"); return FALSE; }

    if (years < 0) years = 0;
    if (months < 0) months = 0;
    if (days < 0) days = 0;
    if (hours < 0) hours = 0;
    if (minutes < 0) minutes = 0;
    if (seconds < 0) seconds = 0;

    license_time.years = years;
    license_time.months = months;
    license_time.days = days;
    license_time.hours = hours;
    license_time.minutes = minutes;
    license_time.seconds = seconds;
    *outSeconds = LicenseTimeToSeconds(&license_time);
    return TRUE;
}

static BOOL g_statusPopups = FALSE;

void Generator_EnableStatusPopups(BOOL enable)
{
    g_statusPopups = enable;
}

static void StatusPopup(UINT icon, const WCHAR *caption, const WCHAR *text)
{
    if (g_statusPopups && hWnd != NULL && text != NULL && text[0]) {
        MessageBoxW(hWnd, text, caption, MB_OK | icon);
    }
}

void Generator_ShowActivationCode(const char *utf8Code, uint64_t totalSeconds, uint32_t expire) {
    int wlen;
    WCHAR wdisplay[ACTIVATION_CODE_LEN + 1];

    wlen = MultiByteToWideChar(CP_UTF8, 0, utf8Code, -1, NULL, 0);
    if (wlen <= 0 || wlen > (int)ARRAYSIZE(wdisplay)) {
        UpdateStatus(L"状态: 激活码内容异常");
        StatusPopup(MB_ICONERROR, L"未生成激活码",
                    L"签出来的激活码内容不对（长度或编码异常），没有显示到界面上。\n\n"
                    L"这张码不要用 —— 请核对私钥与公钥是否配对、生成时间是否有效。");
        return;
    }
    MultiByteToWideChar(CP_UTF8, 0, utf8Code, -1, wdisplay, wlen);
    SetWindowTextW(hEditActivationCode, wdisplay);

    if (totalSeconds > 0) {
        char duration_buf[128] = { 0 };
        char expire_buf[64] = { 0 };
        WCHAR wduration[128] = { 0 };
        WCHAR wexpire[64] = { 0 };
        WCHAR wstatus[512];

        FormatTotalSeconds(totalSeconds, duration_buf, sizeof(duration_buf));
        FormatExpireTime(expire, expire_buf, sizeof(expire_buf));
        MultiByteToWideChar(CP_UTF8, 0, duration_buf, -1, wduration, 128);
        MultiByteToWideChar(CP_UTF8, 0, expire_buf, -1, wexpire, 64);
        swprintf(wstatus, 512, L"状态: 激活码生成成功，授权时长: %s，过期时间: %s", wduration, wexpire);
        UpdateStatus(wstatus);
        StatusPopup(MB_ICONINFORMATION, L"激活码已生成", wstatus);
    } else {
        UpdateStatus(L"状态: 激活码生成成功(永久授权)");
        StatusPopup(MB_ICONINFORMATION, L"激活码已生成",
                    L"激活码生成成功（永久授权）。");
    }
}

void OnGenerateActivationCode() {
    char machine_code[200] = { 0 };
    char username[USERNAME_LEN] = { 0 };
    char email[EMAIL_LEN] = { 0 };
    char activation_code[ACTIVATION_CODE_LEN] = { 0 };
    uint64_t total_seconds = 0;
    uint32_t expire = 0;

    if (!Generator_ReadGenerateRequest(machine_code, sizeof(machine_code),
                                       username, sizeof(username),
                                       email, sizeof(email), &total_seconds)) {
        return;
    }

    if (GenerateActivationCode(machine_code, total_seconds, username, email,
                               activation_code, sizeof(activation_code), g_verified_time)) {
        if (total_seconds > 0) {

            expire = (uint32_t)((uint64_t)g_verified_time + total_seconds);
        }
        Generator_ShowActivationCode(activation_code, total_seconds, expire);
    } else {
        UpdateStatus(L"状态: 生成激活码失败");

        StatusPopup(MB_ICONERROR, L"未生成激活码",
                    L"本地签名失败，没有生成激活码。\n\n"
                    L"离线版是用编译进二进制的私钥本地签的，常见原因：\n"
                    L"  · 这个构建没编进私钥（build.bat 的 generator 段缺 ecdsa_sign.c 或 "
                    L"ECDSA_SIGN_ENABLED）\n"
                    L"  · 内嵌的私钥与公钥不配对\n"
                    L"  · 系统加密库调用被拦（杀软 / 受限账户）\n\n"
                    L"换联网版 generator-web.exe 走服务端签发可以绕开这个问题。");
    }
}

void OnCopyActivationCode() {
    WCHAR wcode[ACTIVATION_CODE_LEN * 2] = { 0 };
    GetWindowTextW(hEditActivationCode, wcode, ACTIVATION_CODE_LEN * 2);
    if (wcslen(wcode) == 0) { UpdateStatus(L"状态: 激活码为空"); return; }

    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, (wcslen(wcode) + 1) * sizeof(WCHAR));
        if (hMem != NULL) {
            WCHAR *pData = (WCHAR *)GlobalLock(hMem);
            if (pData != NULL) {
                wcscpy(pData, wcode);
                GlobalUnlock(hMem);
                if (SetClipboardData(CF_UNICODETEXT, hMem)) {
                    UpdateStatus(L"状态: 激活码已复制到剪贴板");
                } else { GlobalFree(hMem); UpdateStatus(L"状态: 复制失败"); }
            } else { GlobalFree(hMem); UpdateStatus(L"状态: 复制失败"); }
        } else { UpdateStatus(L"状态: 内存分配失败"); }
        CloseClipboard();
    } else { UpdateStatus(L"状态: 无法打开剪贴板"); }
}

void Generator_DrawFlatButtonEx(const DRAWITEMSTRUCT *dis, COLORREF bg, COLORREF bgDown,
                                COLORREF textColor, COLORREF borderColor)
{
    WCHAR btnText[64] = { 0 };
    BOOL pressed;
    HBRUSH hBrush;
    HFONT hOldFont;
    RECT rcText;

    if (dis == NULL || dis->hDC == NULL) return;
    GetWindowTextW(dis->hwndItem, btnText, (int)ARRAYSIZE(btnText));
    pressed = (dis->itemState & ODS_SELECTED) != 0;

    hBrush = CreateSolidBrush(pressed ? bgDown : bg);
    FillRect(dis->hDC, &dis->rcItem, hBrush);
    DeleteObject(hBrush);

    if (borderColor != GEN_BTN_NO_BORDER) {
        HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
        HPEN hOldPen = (HPEN)SelectObject(dis->hDC, hPen);
        HBRUSH hOldBrush = (HBRUSH)SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));
        Rectangle(dis->hDC, dis->rcItem.left, dis->rcItem.top, dis->rcItem.right, dis->rcItem.bottom);
        SelectObject(dis->hDC, hOldPen);
        SelectObject(dis->hDC, hOldBrush);
        DeleteObject(hPen);
    }

    SetTextColor(dis->hDC, textColor);
    SetBkMode(dis->hDC, TRANSPARENT);
    hOldFont = (HFONT)SelectObject(dis->hDC, g_hFontButton);
    rcText = dis->rcItem;
    DrawTextW(dis->hDC, btnText, -1, &rcText, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dis->hDC, hOldFont);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            CreateControls(hwnd);
            AntiDebug_Init();
            AntiDebug_StartPeriodicScan(5000);
            break;

        case WM_TIMER:
            if (wParam == IDT_TIMER_REALTIME) {
                g_verified_time = GetRealTimeVerified();
                StartNtpQueryAsync();
                ApplyWindowTitle(hwnd);
            }
            break;

        case WM_APP_NTP_DONE: {
            uint32_t now = (uint32_t)time(NULL);

            InterlockedExchange(&g_ntpInFlight, 0);
            if (wParam == 1) {

                g_time_offset = (int64_t)g_ntpResult
                              - (int64_t)(g_ntpStartLocal + g_ntpRttSeconds);
                g_last_ntp_sync_local = now;
                g_verified_time = GetRealTimeVerified();
            } else {
                g_ntpRetryAt = now + NTP_RETRY_SECONDS;
            }
            ApplyWindowTitle(hwnd);
            return 0;
        }

        case WM_CTLCOLOREDIT: {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, COLOR_TEXT_DARK);
            SetBkColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, OPAQUE);
            return (LRESULT)GetStockObject(WHITE_BRUSH);
        }

        case WM_CTLCOLORSTATIC: {
            HDC hdc = (HDC)wParam;
            HWND hCtrl = (HWND)lParam;
            if (hCtrl == hEditActivationCode) {
                SetTextColor(hdc, COLOR_TEXT_DARK);
                SetBkColor(hdc, COLOR_OUTPUT_BG);
                SetBkMode(hdc, OPAQUE);
                return (LRESULT)g_hBrushOutput;
            } else if (hCtrl == hStaticStatus) {
                SetTextColor(hdc, COLOR_TEXT_STATUS);
                SetBkColor(hdc, RGB(255, 255, 255));
                SetBkMode(hdc, OPAQUE);
                return (LRESULT)GetStockObject(WHITE_BRUSH);
            } else {
                SetTextColor(hdc, COLOR_TEXT_DARK);
                SetBkMode(hdc, TRANSPARENT);
                return (LRESULT)GetStockObject(WHITE_BRUSH);
            }
        }

        case WM_CTLCOLORDLG:
        case WM_CTLCOLORBTN:
            SetBkColor((HDC)wParam, RGB(255, 255, 255));
            SetBkMode((HDC)wParam, OPAQUE);
            return (LRESULT)GetStockObject(WHITE_BRUSH);

        case WM_DRAWITEM: {
            DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lParam;
            if (dis == NULL) break;

            if (dis->CtlID == IDC_BUTTON_GENERATE) {
                Generator_DrawFlatButtonEx(dis, COLOR_GENERATE, COLOR_GENERATE_PRESSED,
                                           COLOR_TEXT_WHITE, GEN_BTN_NO_BORDER);
            } else if (dis->CtlID == IDC_BUTTON_COPY) {
                Generator_DrawFlatButtonEx(dis, COLOR_COPY, COLOR_COPY_PRESSED,
                                           COLOR_TEXT_WHITE, GEN_BTN_NO_BORDER);
            }
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_BUTTON_GENERATE: OnGenerateActivationCode(); break;
                case IDC_BUTTON_COPY: OnCopyActivationCode(); break;
            }
            break;

        case WM_DESTROY:
            KillTimer(hwnd, IDT_TIMER_REALTIME);
            AntiDebug_Cleanup();
            if (g_hFontTitle) DeleteObject(g_hFontTitle);
            if (g_hFontLabel) DeleteObject(g_hFontLabel);
            if (g_hFontInput) DeleteObject(g_hFontInput);
            if (g_hFontSmallInput) DeleteObject(g_hFontSmallInput);
            if (g_hFontStatus) DeleteObject(g_hFontStatus);
            if (g_hFontButton) DeleteObject(g_hFontButton);
            if (g_hBrushOutput) DeleteObject(g_hBrushOutput);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
