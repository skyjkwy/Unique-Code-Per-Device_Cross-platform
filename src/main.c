#include <windows.h>

#include <stdio.h>

#include <wchar.h>

#include "license.h"

#include "ntp_client.h"

#include "anti_debug.h"

#define IDI_ICON1 101

#define IDC_MACHINE_CODE 1001

#define IDC_ACTIVATION_CODE 1002

#define IDC_BUTTON_ACTIVATE 1003

#define IDC_BUTTON_GENERATE 1004

#define IDC_STATUS 1005

#define IDC_USERNAME 1006

#define IDC_EMAIL 1007

#define IDC_BUTTON_REACTIVATE 1008

#define IDT_TIMER_UPDATE 1

#define IDT_TIMER_REALTIME 2

#define NTP_RESYNC_INTERVAL 300

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

HWND hWnd;

HWND hEditMachineCode;

HWND hEditActivationCode;

HWND hEditUsername;

HWND hEditEmail;

HWND hButtonActivate;

HWND hButtonGenerate;

HWND hButtonReactivate;

HWND hStaticStatus;

static WNDPROC g_pfnOrigEditUser = NULL;
static WNDPROC g_pfnOrigEditEmail = NULL;
static WNDPROC g_pfnOrigEditCode = NULL;

static void PaintEditOwnFrame(HWND hEdit)
{
    RECT rc;
    GetClientRect(hEdit, &rc);
    HDC hdc = GetDC(hEdit);
    HBRUSH hbr = CreateSolidBrush(RGB(100, 100, 100));
    RECT rcTop    = { 0, 0, rc.right, 1 };
    RECT rcBottom = { 0, rc.bottom - 1, rc.right, rc.bottom };
    RECT rcLeft   = { 0, 0, 1, rc.bottom };
    RECT rcRight  = { rc.right - 1, 0, rc.right, rc.bottom };
    FillRect(hdc, &rcTop, hbr);
    FillRect(hdc, &rcBottom, hbr);
    FillRect(hdc, &rcLeft, hbr);
    FillRect(hdc, &rcRight, hbr);
    DeleteObject(hbr);
    ReleaseDC(hEdit, hdc);
}

static LRESULT CALLBACK BorderEditProc(HWND hEdit, UINT message, WPARAM wParam, LPARAM lParam)
{
    WNDPROC pfnOrig = NULL;
    if (hEdit == hEditUsername) pfnOrig = g_pfnOrigEditUser;
    else if (hEdit == hEditEmail) pfnOrig = g_pfnOrigEditEmail;
    else if (hEdit == hEditActivationCode) pfnOrig = g_pfnOrigEditCode;

    if (message == WM_PAINT) {
        LRESULT lResult = CallWindowProcW(pfnOrig, hEdit, message, wParam, lParam);
        PaintEditOwnFrame(hEdit);
        return lResult;
    }
    if (message == WM_DESTROY) {
        SetWindowLongPtrW(hEdit, GWLP_WNDPROC, (LONG_PTR)pfnOrig);
        return CallWindowProcW(pfnOrig, hEdit, message, wParam, lParam);
    }
    return CallWindowProcW(pfnOrig, hEdit, message, wParam, lParam);
}

static void SubclassBorderEdit(HWND hEdit, WNDPROC *pSaveOrig)
{
    *pSaveOrig = (WNDPROC)SetWindowLongPtrW(hEdit, GWLP_WNDPROC, (LONG_PTR)BorderEditProc);
}

char g_machine_code[MACHINE_CODE_LEN];

BOOL g_is_activated = FALSE;

uint32_t g_verified_time = 0;

int64_t g_time_offset = 0;

uint32_t g_last_ntp_sync_local = 0;

WCHAR g_current_status[512] = {0};

HFONT g_hFont = NULL;
HFONT g_hFontTitle = NULL;
HFONT g_hFontEdit = NULL;
HFONT g_hFontMachine = NULL;
HFONT g_hFontStatus = NULL;

HBRUSH g_hbrMachineBg = NULL;

HWND g_hStaticTitle = NULL;

HWND g_hStaticInfo = NULL;

uint32_t g_last_ntp_attempt = 0;
uint32_t g_ntp_backoff = 0;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

void UpdateStatus(const WCHAR *text);

void UpdateStatusWithTime(const WCHAR *status_text);

void RefreshStatusDisplay();

void DrawFlatButton(DRAWITEMSTRUCT *dis);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {

    const WCHAR CLASS_NAME[] = L"LicenseActivationClass";

    WNDCLASSEXW wc = {0};

    wc.cbSize = sizeof(WNDCLASSEXW);

    wc.lpfnWndProc = WindowProc;

    wc.hInstance = hInstance;

    wc.lpszClassName = CLASS_NAME;

    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);

    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON1));

    wc.hIconSm = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON1));

    RegisterClassExW(&wc);

    hWnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"一机一码授权系统",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 1040, 720,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (hWnd == NULL) {
        return 0;
    }

    ShowWindow(hWnd, nCmdShow);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {

        TranslateMessage(&msg);

        DispatchMessageW(&msg);
    }

    return 0;
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
    uint32_t local_time = (uint32_t)time(NULL);

    BOOL need_sync = FALSE;
    if (g_last_ntp_sync_local == 0) {
        need_sync = TRUE;
    } else if (local_time - g_last_ntp_sync_local >= NTP_RESYNC_INTERVAL) {
        need_sync = TRUE;
    }

    if (!need_sync) return;

    if (g_ntp_backoff > 0 && g_last_ntp_attempt > 0) {
        if (local_time - g_last_ntp_attempt < g_ntp_backoff) {
            return;
        }
    }

    g_last_ntp_attempt = local_time;
    uint32_t prev_sync = g_last_ntp_sync_local;

    RefreshNtpTime();

    if (g_last_ntp_sync_local != prev_sync) {

        g_ntp_backoff = 0;
    } else {

        if (g_ntp_backoff == 0) {
            g_ntp_backoff = 1;
        } else {
            g_ntp_backoff *= 2;
            if (g_ntp_backoff > 60) g_ntp_backoff = 60;
        }
    }
}

void CreateControls(HWND hwnd) {

    HDC hScreenDC = GetDC(hwnd);
    int dpiY = GetDeviceCaps(hScreenDC, LOGPIXELSY);
    ReleaseDC(hwnd, hScreenDC);

    g_hFont = CreateFontW(-MulDiv(11, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                          DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                          CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    g_hFontTitle = CreateFontW(-MulDiv(16, dpiY, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    g_hFontEdit = CreateFontW(-MulDiv(20, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    g_hFontMachine = CreateFontW(-MulDiv(12, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    g_hFontStatus = CreateFontW(-MulDiv(10, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    g_hbrMachineBg = CreateSolidBrush(RGB(220, 220, 220));

    g_hStaticTitle = CreateWindowW(L"STATIC", L"一机一码授权系统", WS_VISIBLE | WS_CHILD | SS_CENTER,
                                   32, 40, 960, 36, hwnd, NULL, NULL, NULL);
    SendMessageW(g_hStaticTitle, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);

    HWND hStaticMachine = CreateWindowW(L"STATIC", L"机器码:", WS_VISIBLE | WS_CHILD | SS_RIGHT,
                                        32, 108, 96, 44, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticMachine, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    hEditMachineCode = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY | ES_CENTER,
                                     132, 108, 860, 44, hwnd, (HMENU)IDC_MACHINE_CODE, NULL, NULL);
    SendMessageW(hEditMachineCode, WM_SETFONT, (WPARAM)g_hFontMachine, TRUE);

    hButtonGenerate = CreateWindowW(L"BUTTON", L"复制机器码", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                                    392, 172, 240, 40, hwnd, (HMENU)IDC_BUTTON_GENERATE, NULL, NULL);
    SendMessageW(hButtonGenerate, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    HWND hStaticUsername = CreateWindowW(L"STATIC", L"用户名:", WS_VISIBLE | WS_CHILD | SS_RIGHT,
                                         32, 256, 96, 50, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticUsername, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    hEditUsername = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_CENTER | ES_AUTOHSCROLL,
                                  132, 256, 860, 50, hwnd, (HMENU)IDC_USERNAME, NULL, NULL);
    SendMessageW(hEditUsername, WM_SETFONT, (WPARAM)g_hFontEdit, TRUE);
    SubclassBorderEdit(hEditUsername, &g_pfnOrigEditUser);

    HWND hStaticEmail = CreateWindowW(L"STATIC", L"邮箱:", WS_VISIBLE | WS_CHILD | SS_RIGHT,
                                      32, 334, 96, 50, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticEmail, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    hEditEmail = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_CENTER | ES_AUTOHSCROLL,
                               132, 334, 860, 50, hwnd, (HMENU)IDC_EMAIL, NULL, NULL);
    SendMessageW(hEditEmail, WM_SETFONT, (WPARAM)g_hFontEdit, TRUE);
    SubclassBorderEdit(hEditEmail, &g_pfnOrigEditEmail);

    HWND hStaticActivation = CreateWindowW(L"STATIC", L"激活码:", WS_VISIBLE | WS_CHILD | SS_RIGHT,
                                           32, 412, 96, 50, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticActivation, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    hEditActivationCode = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_CENTER | ES_AUTOHSCROLL,
                                        132, 412, 860, 50, hwnd, (HMENU)IDC_ACTIVATION_CODE, NULL, NULL);
    SendMessageW(hEditActivationCode, WM_SETFONT, (WPARAM)g_hFontEdit, TRUE);
    SubclassBorderEdit(hEditActivationCode, &g_pfnOrigEditCode);

    hButtonActivate = CreateWindowW(L"BUTTON", L"验证激活", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                                    162, 490, 340, 46, hwnd, (HMENU)IDC_BUTTON_ACTIVATE, NULL, NULL);
    SendMessageW(hButtonActivate, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    hButtonReactivate = CreateWindowW(L"BUTTON", L"重新激活", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                                      522, 490, 340, 46, hwnd, (HMENU)IDC_BUTTON_REACTIVATE, NULL, NULL);
    SendMessageW(hButtonReactivate, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    ShowWindow(hButtonReactivate, SW_HIDE);

    hStaticStatus = CreateWindowW(L"STATIC", L"状态: 未激活", WS_VISIBLE | WS_CHILD,
                                  32, 564, 960, 24, hwnd, (HMENU)IDC_STATUS, NULL, NULL);
    SendMessageW(hStaticStatus, WM_SETFONT, (WPARAM)g_hFontStatus, TRUE);

    g_hStaticInfo = CreateWindowW(L"STATIC", L"请复制机器码，联系开发者获取激活码",
                                  WS_VISIBLE | WS_CHILD, 32, 602, 960, 22, hwnd, NULL, NULL, NULL);
    SendMessageW(g_hStaticInfo, WM_SETFONT, (WPARAM)g_hFontStatus, TRUE);

    GenerateMachineCode(g_machine_code, sizeof(g_machine_code));

    char display_mc[MACHINE_CODE_LEN] = {0};
    if (!ObfuscateMachineCode(g_machine_code, display_mc, sizeof(display_mc))) {

        strncpy_s(display_mc, sizeof(display_mc), g_machine_code, _TRUNCATE);
    }
    int wlen = MultiByteToWideChar(CP_UTF8, 0, display_mc, -1, NULL, 0);
    WCHAR wdisplay[MACHINE_CODE_LEN + 1] = {0};
    if (wlen > 0) {
        MultiByteToWideChar(CP_UTF8, 0, display_mc, -1, wdisplay, wlen);
    }
    SetWindowTextW(hEditMachineCode, wdisplay);

    RefreshNtpTime();

    g_verified_time = GetRealTimeVerified();

    UpdateStatusWithTime(L"状态: 等待激活");

    SetTimer(hwnd, IDT_TIMER_REALTIME, 1000, NULL);

    uint32_t verified_time = 0;
    int time_source = 0;

    if (!VerifyTimeIntegrityWithTime(g_machine_code, g_verified_time, &verified_time, &time_source)) {

        g_verified_time = verified_time;

        char verified_time_buf[64] = {0};
        FormatExpireTime(verified_time, verified_time_buf, sizeof(verified_time_buf));

        WCHAR wtime[64] = {0};
        MultiByteToWideChar(CP_UTF8, 0, verified_time_buf, -1, wtime, 64);

        WCHAR wstatus[512];
        swprintf(wstatus, 512, L"状态: 检测到系统时间异常，授权已锁定! 可信时间: %s", wtime);
        UpdateStatus(wstatus);

        SetWindowTextW(hEditUsername, L"");
        SetWindowTextW(hEditEmail, L"");
        SetWindowTextW(hEditActivationCode, L"");

        ShowWindow(hButtonReactivate, SW_SHOW);
        EnableWindow(hButtonActivate, FALSE);
        EnableWindow(hEditActivationCode, FALSE);
        EnableWindow(hEditUsername, FALSE);
        EnableWindow(hEditEmail, FALSE);
        return;
    }

    g_verified_time = verified_time;

    uint32_t expire_time = 0;
    char loaded_username[USERNAME_LEN] = {0};
    char loaded_email[EMAIL_LEN] = {0};

    if (LoadActivationStatus(g_machine_code, &expire_time, loaded_username, loaded_email)) {

        if (IsLicenseExpired(expire_time, g_verified_time)) {

            UpdateStatus(L"状态: 授权已过期，请重新激活");

            SetWindowTextW(hEditUsername, L"");
            SetWindowTextW(hEditEmail, L"");
            SetWindowTextW(hEditActivationCode, L"");

            ShowWindow(hButtonReactivate, SW_SHOW);
            EnableWindow(hButtonActivate, FALSE);
            EnableWindow(hEditActivationCode, FALSE);
            EnableWindow(hEditUsername, FALSE);
            EnableWindow(hEditEmail, FALSE);

        } else {

            g_is_activated = TRUE;

            UpdateLastSeenTime(g_verified_time);

            int remaining = GetRemainingDays(expire_time, g_verified_time);
            char expire_buf[64] = {0};
            FormatExpireTime(expire_time, expire_buf, sizeof(expire_buf));

            WCHAR wusername[USERNAME_LEN] = {0};
            MultiByteToWideChar(CP_UTF8, 0, loaded_username, -1, wusername, USERNAME_LEN);

            WCHAR wexpire[64] = {0};
            MultiByteToWideChar(CP_UTF8, 0, expire_buf, -1, wexpire, 64);

            WCHAR wstatus[512];
            if (remaining >= 0) {
                swprintf(wstatus, 512, L"状态: 已激活，用户: %s，剩余: %d天，过期: %s",
                         wusername, remaining, wexpire);
            } else {
                swprintf(wstatus, 512, L"状态: 已激活(永久)，用户: %s",
                         wusername);
            }
            UpdateStatusWithTime(wstatus);

            EnableWindow(hButtonActivate, FALSE);
            EnableWindow(hEditActivationCode, FALSE);
            EnableWindow(hEditUsername, FALSE);
            EnableWindow(hEditEmail, FALSE);

            WCHAR wuser[USERNAME_LEN] = {0};
            MultiByteToWideChar(CP_UTF8, 0, loaded_username, -1, wuser, USERNAME_LEN);
            SetWindowTextW(hEditUsername, wuser);

            WCHAR wemail[EMAIL_LEN] = {0};
            MultiByteToWideChar(CP_UTF8, 0, loaded_email, -1, wemail, EMAIL_LEN);
            SetWindowTextW(hEditEmail, wemail);

            SetTimer(hwnd, IDT_TIMER_UPDATE, 60000, NULL);

            SetTimer(hwnd, IDT_TIMER_REALTIME, 1000, NULL);
        }
    }
}

void UpdateStatus(const WCHAR *text) {

    if (text) wcscpy_s(g_current_status, 512, text);

    SetWindowTextW(hStaticStatus, text);
}

void UpdateStatusWithTime(const WCHAR *status_text) {

    if (status_text) wcscpy_s(g_current_status, 512, status_text);

    char time_buf[64] = {0};
    FormatExpireTime(g_verified_time, time_buf, sizeof(time_buf));

    WCHAR wtime[64] = {0};
    MultiByteToWideChar(CP_UTF8, 0, time_buf, -1, wtime, 64);

    WCHAR wstatus[512];
    swprintf(wstatus, 512, L"%s 可信时间: %s", status_text ? status_text : g_current_status, wtime);
    SetWindowTextW(hStaticStatus, wstatus);
}

void RefreshStatusDisplay() {

    if (wcslen(g_current_status) > 0) {

        char time_buf[64] = {0};
        FormatExpireTime(g_verified_time, time_buf, sizeof(time_buf));

        WCHAR wtime[64] = {0};
        MultiByteToWideChar(CP_UTF8, 0, time_buf, -1, wtime, 64);

        WCHAR wstatus[512];
        swprintf(wstatus, 512, L"%s 可信时间: %s", g_current_status, wtime);
        SetWindowTextW(hStaticStatus, wstatus);
    }
}

static void GetEditTextA(HWND hEdit, char *buf, int max_len) {
    WCHAR wbuf[256] = {0};

    if (GetWindowTextW(hEdit, wbuf, 256) == 0) {
        buf[0] = '\0';
        return;
    }

    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, max_len, NULL, NULL);
}

void OnGenerateMachineCode() {

    if (strlen(g_machine_code) == 0) {
        UpdateStatus(L"状态: 机器码为空");
        return;
    }

    char obf_mc[MACHINE_CODE_LEN] = {0};
    if (!ObfuscateMachineCode(g_machine_code, obf_mc, sizeof(obf_mc))) {
        strncpy_s(obf_mc, sizeof(obf_mc), g_machine_code, _TRUNCATE);
    }
    WCHAR wcode[MACHINE_CODE_LEN + 1] = {0};
    MultiByteToWideChar(CP_UTF8, 0, obf_mc, -1, wcode, MACHINE_CODE_LEN);

    if (OpenClipboard(NULL)) {

        EmptyClipboard();

        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, (wcslen(wcode) + 1) * sizeof(WCHAR));
        if (hMem != NULL) {

            WCHAR *pData = (WCHAR *)GlobalLock(hMem);
            if (pData != NULL) {

                wcscpy(pData, wcode);

                GlobalUnlock(hMem);

                if (SetClipboardData(CF_UNICODETEXT, hMem)) {
                    UpdateStatus(L"状态: 机器码已复制到剪贴板");
                } else {

                    GlobalFree(hMem);
                    UpdateStatus(L"状态: 复制失败");
                }
            } else {

                GlobalFree(hMem);
                UpdateStatus(L"状态: 复制失败");
            }
        } else {

            UpdateStatus(L"状态: 内存分配失败");
        }

        CloseClipboard();
    } else {

        UpdateStatus(L"状态: 无法打开剪贴板");
    }
}

void OnReactivate() {

    g_is_activated = FALSE;

    KillTimer(hWnd, IDT_TIMER_UPDATE);
    KillTimer(hWnd, IDT_TIMER_REALTIME);

    ClearActivationStatus();

    SetWindowTextW(hEditUsername, L"");
    SetWindowTextW(hEditEmail, L"");
    SetWindowTextW(hEditActivationCode, L"");

    EnableWindow(hButtonActivate, TRUE);
    EnableWindow(hEditActivationCode, TRUE);
    EnableWindow(hEditUsername, TRUE);
    EnableWindow(hEditEmail, TRUE);

    ShowWindow(hButtonReactivate, SW_HIDE);

    UpdateStatus(L"状态: 已重置授权，请重新输入信息并激活");
}

void OnActivate() {

    g_verified_time = GetRealTimeVerified();

    WCHAR wactivation[200] = {0};
    GetWindowTextW(hEditActivationCode, wactivation, 200);

    char activation_code[200] = {0};
    WideCharToMultiByte(CP_UTF8, 0, wactivation, -1, activation_code, 200, NULL, NULL);

    if (strlen(activation_code) == 0) {
        UpdateStatus(L"状态: 请输入激活码");
        return;
    }

    if (strlen(g_machine_code) == 0) {
        UpdateStatus(L"状态: 请先生成机器码");
        return;
    }

    char username[USERNAME_LEN] = {0};
    char email[EMAIL_LEN] = {0};

    GetEditTextA(hEditUsername, username, sizeof(username));
    GetEditTextA(hEditEmail, email, sizeof(email));

    if (strlen(username) == 0) {
        UpdateStatus(L"状态: 请输入用户名");
        return;
    }

    if (!IsValidEmail(email)) {
        UpdateStatus(L"状态: 邮箱格式不正确");
        return;
    }

    uint32_t expire_time = 0;
    char code_seq[CODE_SEQ_LEN + 1] = {0};
    int result = ValidateActivationCode(g_machine_code, username, email, activation_code, &expire_time, g_verified_time, code_seq);

    if (result != ACT_VALID) {
        switch (result) {
            case ACT_USED:

                UpdateStatus(L"状态: 该激活码已被使用，无法重复激活");
                break;
            case ACT_EXPIRED_FUTURE:

                UpdateStatus(L"状态: 激活码已过期或时间异常");
                break;
            case ACT_INVALID:

                UpdateStatus(L"状态: 激活码无效");
                break;
            case ACT_TIME_TAMPERED:

                UpdateStatus(L"状态: 检测到时间篡改，请重新激活");
                break;
            default:

                UpdateStatus(L"状态: 激活码无效");
                break;
        }
        return;
    }

    if (SaveActivationStatus(TRUE, g_machine_code, expire_time, username, email, code_seq, g_verified_time)) {

        g_is_activated = TRUE;

        UpdateLastSeenTime(g_verified_time);

        InitializeTimeProtection(g_machine_code, g_verified_time);

        char expire_buf[64] = {0};
        FormatExpireTime(expire_time, expire_buf, sizeof(expire_buf));

        WCHAR wusername[USERNAME_LEN] = {0};
        MultiByteToWideChar(CP_UTF8, 0, username, -1, wusername, USERNAME_LEN);

        WCHAR wexpire[64] = {0};
        MultiByteToWideChar(CP_UTF8, 0, expire_buf, -1, wexpire, 64);

        WCHAR wstatus[512];
        if (expire_time > 0) {

            int remaining = GetRemainingDays(expire_time, g_verified_time);
            swprintf(wstatus, 512, L"状态: 激活成功! 用户: %s，剩余: %d天，过期: %s",
                     wusername, remaining, wexpire);
        } else {

            swprintf(wstatus, 512, L"状态: 激活成功(永久授权)! 用户: %s", wusername);
        }
        UpdateStatusWithTime(wstatus);

        EnableWindow(hButtonActivate, FALSE);
        EnableWindow(hEditActivationCode, FALSE);
        EnableWindow(hEditUsername, FALSE);
        EnableWindow(hEditEmail, FALSE);

        SetTimer(hWnd, IDT_TIMER_UPDATE, 60000, NULL);
        SetTimer(hWnd, IDT_TIMER_REALTIME, 1000, NULL);
    } else {

        UpdateStatus(L"状态: 激活成功，但保存失败");
    }
}

void DrawFlatButton(DRAWITEMSTRUCT *dis) {
    UINT id = dis->CtlID;
    BOOL pressed = (dis->itemState & ODS_SELECTED) != 0;
    BOOL disabled = (dis->itemState & ODS_DISABLED) != 0;

    int type;
    if (id == IDC_BUTTON_ACTIVATE) {
        type = 0;
    } else if (id == IDC_BUTTON_REACTIVATE) {
        type = 2;
    } else {
        type = 1;
    }

    COLORREF bg, fg, border;
    if (disabled) {
        bg = RGB(243, 243, 243); fg = RGB(160, 160, 160); border = RGB(225, 225, 225);
    } else if (pressed) {
        switch (type) {
            case 0:  bg = RGB(0, 90, 158);    fg = RGB(255, 255, 255); border = bg;            break;
            case 2:  bg = RGB(161, 52, 56);   fg = RGB(255, 255, 255); border = bg;            break;
            default: bg = RGB(225, 225, 225); fg = RGB(51, 51, 51);    border = RGB(200, 200, 200); break;
        }
    } else {
        switch (type) {
            case 0:  bg = RGB(0, 120, 212);   fg = RGB(255, 255, 255); border = bg;            break;
            case 2:  bg = RGB(209, 52, 56);   fg = RGB(255, 255, 255); border = bg;            break;
            default: bg = RGB(255, 255, 255); fg = RGB(51, 51, 51);    border = RGB(204, 204, 204); break;
        }
    }

    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;

    HBRUSH hbr = CreateSolidBrush(bg);
    FillRect(hdc, &rc, hbr);
    DeleteObject(hbr);

    HPEN hpen = CreatePen(PS_SOLID, 1, border);
    HPEN oldpen = (HPEN)SelectObject(hdc, hpen);
    HBRUSH oldbr = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, oldpen);
    SelectObject(hdc, oldbr);
    DeleteObject(hpen);

    WCHAR text_buf[64] = {0};
    GetWindowTextW(dis->hwndItem, text_buf, 64);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, fg);
    HFONT oldfont = (HFONT)SelectObject(hdc, g_hFont);
    DrawTextW(hdc, text_buf, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldfont);

    if (dis->itemState & ODS_FOCUS) {
        RECT frc = rc;
        InflateRect(&frc, -3, -3);
        DrawFocusRect(hdc, &frc);
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {

        case WM_CREATE:

            CreateControls(hwnd);

            {
                HICON hIcon = LoadIconW((HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE),
                                        MAKEINTRESOURCEW(IDI_ICON1));
                if (hIcon) {
                    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
                    SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                }
            }

            AntiDebug_Init();

            AntiDebug_StartPeriodicScan(5000);
            break;

        case WM_TIMER:
            if (wParam == IDT_TIMER_REALTIME) {

                g_verified_time = GetRealTimeVerified();

                RefreshStatusDisplay();

                CheckAndResyncNtp();
            }
            else if (wParam == IDT_TIMER_UPDATE && g_is_activated) {

                RefreshNtpTime();

                g_verified_time = GetRealTimeVerified();

                uint32_t verify_time = 0;
                int verify_source = 0;
                BOOL time_valid = VerifyTimeIntegrity(g_machine_code, &verify_time, &verify_source);

                if (verify_time > g_verified_time) {
                    g_verified_time = verify_time;
                }

                UpdateLastSeenTime(g_verified_time);

                if (!time_valid) {

                    KillTimer(hwnd, IDT_TIMER_UPDATE);
                    KillTimer(hwnd, IDT_TIMER_REALTIME);

                    g_is_activated = FALSE;

                    ClearActivationStatus();

                    UpdateStatus(L"状态: 检测到时间异常，授权已锁定!");

                    SetWindowTextW(hEditUsername, L"");
                    SetWindowTextW(hEditEmail, L"");
                    SetWindowTextW(hEditActivationCode, L"");

                    ShowWindow(hButtonReactivate, SW_SHOW);
                    EnableWindow(hButtonActivate, FALSE);
                    EnableWindow(hEditActivationCode, FALSE);
                    EnableWindow(hEditUsername, FALSE);
                    EnableWindow(hEditEmail, FALSE);
                    break;
                }

                uint32_t expire_time = 0;
                char loaded_username[USERNAME_LEN] = {0};

                if (LoadActivationStatus(g_machine_code, &expire_time, loaded_username, NULL)) {

                    if (IsLicenseExpired(expire_time, g_verified_time)) {

                        KillTimer(hwnd, IDT_TIMER_UPDATE);
                        KillTimer(hwnd, IDT_TIMER_REALTIME);
                        g_is_activated = FALSE;
                        UpdateStatus(L"状态: 授权已过期，请重新激活");

                        SetWindowTextW(hEditUsername, L"");
                        SetWindowTextW(hEditEmail, L"");
                        SetWindowTextW(hEditActivationCode, L"");

                        ShowWindow(hButtonReactivate, SW_SHOW);
                        EnableWindow(hButtonActivate, FALSE);
                        EnableWindow(hEditActivationCode, FALSE);
                        EnableWindow(hEditUsername, FALSE);
                        EnableWindow(hEditEmail, FALSE);
                    } else {

                        int remaining = GetRemainingDays(expire_time, g_verified_time);
                        char expire_buf[64] = {0};
                        FormatExpireTime(expire_time, expire_buf, sizeof(expire_buf));

                        WCHAR wusername[USERNAME_LEN] = {0};
                        MultiByteToWideChar(CP_UTF8, 0, loaded_username, -1, wusername, USERNAME_LEN);

                        WCHAR wexpire[64] = {0};
                        MultiByteToWideChar(CP_UTF8, 0, expire_buf, -1, wexpire, 64);

                        WCHAR wstatus[512];
                        if (remaining >= 0) {
                            swprintf(wstatus, 512, L"状态: 已激活，用户: %s，剩余: %d天，过期: %s",
                                     wusername, remaining, wexpire);
                        } else {
                            swprintf(wstatus, 512, L"状态: 已激活(永久)，用户: %s",
                                     wusername);
                        }
                        UpdateStatusWithTime(wstatus);
                    }
                }
            }
            break;

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORDLG: {
            HDC hdc = (HDC)wParam;
            HWND hCtl = (HWND)lParam;

            if (hCtl == hEditMachineCode) {
                SetBkColor(hdc, RGB(220, 220, 220));
                SetBkMode(hdc, OPAQUE);
                SetTextColor(hdc, RGB(51, 51, 51));
                return (LRESULT)g_hbrMachineBg;
            }
            SetBkMode(hdc, TRANSPARENT);
            if (hCtl == g_hStaticTitle) {

                SetTextColor(hdc, RGB(0, 120, 212));
            } else if (hCtl == hStaticStatus || hCtl == g_hStaticInfo) {

                SetTextColor(hdc, RGB(102, 102, 102));
            } else {

                SetTextColor(hdc, RGB(51, 51, 51));
            }

            return (LRESULT)GetStockObject(WHITE_BRUSH);
        }

        case WM_CTLCOLOREDIT: {
            HDC hdc = (HDC)wParam;
            HWND hCtl = (HWND)lParam;
            if (hCtl == hEditMachineCode) {
                SetBkColor(hdc, RGB(220, 220, 220));
                SetBkMode(hdc, OPAQUE);
                SetTextColor(hdc, RGB(51, 51, 51));
                return (LRESULT)g_hbrMachineBg;
            }
            SetBkColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, OPAQUE);
            SetTextColor(hdc, RGB(51, 51, 51));
            return (LRESULT)GetStockObject(WHITE_BRUSH);
        }

        case WM_CTLCOLORBTN:
            return (LRESULT)GetStockObject(WHITE_BRUSH);

        case WM_DRAWITEM: {
            DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lParam;
            if (dis->CtlType == ODT_BUTTON) {
                DrawFlatButton(dis);
                return TRUE;
            }
            break;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            HPEN hpen = CreatePen(PS_SOLID, 1, RGB(230, 230, 230));
            HPEN oldpen = (HPEN)SelectObject(hdc, hpen);

            MoveToEx(hdc, 24, 60, NULL);   LineTo(hdc, rc.right - 24, 60);
            MoveToEx(hdc, 24, 162, NULL);  LineTo(hdc, rc.right - 24, 162);
            MoveToEx(hdc, 24, 354, NULL);  LineTo(hdc, rc.right - 24, 354);
            SelectObject(hdc, oldpen);
            DeleteObject(hpen);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_BUTTON_GENERATE:

                    OnGenerateMachineCode();
                    break;

                case IDC_BUTTON_ACTIVATE:

                    OnActivate();
                    break;

                case IDC_BUTTON_REACTIVATE:

                    OnReactivate();
                    break;
            }
            break;

        case WM_DESTROY:

            KillTimer(hwnd, IDT_TIMER_UPDATE);
            KillTimer(hwnd, IDT_TIMER_REALTIME);

            AntiDebug_StopPeriodicScan();
            AntiDebug_Cleanup();

            if (g_hbrMachineBg) {
                DeleteObject(g_hbrMachineBg);
                g_hbrMachineBg = NULL;
            }
            if (g_hFont) {
                DeleteObject(g_hFont);
                g_hFont = NULL;
            }
            if (g_hFontTitle) {
                DeleteObject(g_hFontTitle);
                g_hFontTitle = NULL;
            }
            if (g_hFontEdit) {
                DeleteObject(g_hFontEdit);
                g_hFontEdit = NULL;
            }
            if (g_hFontMachine) {
                DeleteObject(g_hFontMachine);
                g_hFontMachine = NULL;
            }
            if (g_hFontStatus) {
                DeleteObject(g_hFontStatus);
                g_hFontStatus = NULL;
            }

            PostQuitMessage(0);
            break;

        default:

            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }

    return 0;
}
