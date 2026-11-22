#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <time.h>
#include <stdlib.h>
#include "ecdsa.h"
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

#define IDI_ICON1           101
#define IDC_KEY_DISPLAY     1001
#define IDC_BUTTON_GENERATE 1002
#define IDC_BUTTON_COPY     1003
#define IDC_BUTTON_SAVE     1004
#define IDC_STATUS          1005
#define IDC_BUTTON_KEYPAIR  1006

#define COLOR_PRIMARY         RGB(0, 120, 212)
#define COLOR_PRIMARY_PRESSED RGB(0, 90, 158)
#define COLOR_TEXT_DARK       RGB(51, 51, 51)
#define COLOR_TEXT_GRAY       RGB(120, 120, 120)
#define COLOR_TEXT_WHITE      RGB(255, 255, 255)
#define COLOR_BORDER          RGB(200, 200, 200)
#define COLOR_READONLY_BG     RGB(245, 245, 245)
#define COLOR_BTN_HOVER       RGB(240, 240, 240)

HWND hWnd;
HWND hEditKey;
HWND hButtonGenerate;
HWND hButtonCopy;
HWND hButtonSave;
HWND hButtonKeyPair;
HWND hStaticStatus;

static HFONT hFontTitle = NULL;
static HFONT hFontLabel = NULL;
static HFONT hFontContent = NULL;
static HFONT hFontStatus = NULL;
static HFONT hFontButton = NULL;

static HBRUSH hBrushReadOnly = NULL;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

void InitRandomGenerator(void);

void GenerateRandomKey(char *key, size_t length);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    const WCHAR CLASS_NAME[] = L"KeyGeneratorClass";

    InitRandomGenerator();

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
        L"密钥生成器",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 450,
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

void CreateControls(HWND hwnd) {

    HDC hScreenDC = GetDC(NULL);
    int dpiY = GetDeviceCaps(hScreenDC, LOGPIXELSY);
    ReleaseDC(NULL, hScreenDC);

    hFontTitle = CreateFontW(-MulDiv(14, dpiY, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    hFontLabel = CreateFontW(-MulDiv(11, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    hFontContent = CreateFontW(-MulDiv(11, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    hFontStatus = CreateFontW(-MulDiv(10, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    hFontButton = CreateFontW(-MulDiv(11, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");

    hBrushReadOnly = CreateSolidBrush(COLOR_READONLY_BG);

    HWND hStaticTitle = CreateWindowW(L"STATIC", L"密钥生成器", WS_VISIBLE | WS_CHILD | SS_CENTER,
                                      24, 24, 752, 32, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);

    HWND hStaticKey = CreateWindowW(L"STATIC", L"生成的密钥:", WS_VISIBLE | WS_CHILD,
                                    24, 72, 200, 22, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticKey, WM_SETFONT, (WPARAM)hFontLabel, TRUE);

    hEditKey = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY | ES_CENTER | ES_AUTOHSCROLL,
                             24, 102, 752, 36, hwnd, (HMENU)IDC_KEY_DISPLAY, NULL, NULL);
    SendMessageW(hEditKey, WM_SETFONT, (WPARAM)hFontContent, TRUE);

    hButtonGenerate = CreateWindowW(L"BUTTON", L"生成密钥", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW,
                                    24, 158, 240, 36, hwnd, (HMENU)IDC_BUTTON_GENERATE, NULL, NULL);
    SendMessageW(hButtonGenerate, WM_SETFONT, (WPARAM)hFontButton, TRUE);

    hButtonCopy = CreateWindowW(L"BUTTON", L"复制密钥", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW,
                                280, 158, 240, 36, hwnd, (HMENU)IDC_BUTTON_COPY, NULL, NULL);
    SendMessageW(hButtonCopy, WM_SETFONT, (WPARAM)hFontButton, TRUE);

    hButtonSave = CreateWindowW(L"BUTTON", L"保存到文件", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW,
                                536, 158, 240, 36, hwnd, (HMENU)IDC_BUTTON_SAVE, NULL, NULL);
    SendMessageW(hButtonSave, WM_SETFONT, (WPARAM)hFontButton, TRUE);

    hButtonKeyPair = CreateWindowW(L"BUTTON", L"生成密钥对 (ECDSA P-256)", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW,
                                   24, 210, 752, 36, hwnd, (HMENU)IDC_BUTTON_KEYPAIR, NULL, NULL);
    SendMessageW(hButtonKeyPair, WM_SETFONT, (WPARAM)hFontButton, TRUE);

    hStaticStatus = CreateWindowW(L"STATIC", L"状态: 就绪", WS_VISIBLE | WS_CHILD,
                                  24, 262, 752, 22, hwnd, (HMENU)IDC_STATUS, NULL, NULL);
    SendMessageW(hStaticStatus, WM_SETFONT, (WPARAM)hFontStatus, TRUE);

    HWND hStaticInfo = CreateWindowW(L"STATIC", L"「生成密钥」用于在线授权 API_SECRET；「生成密钥对」输出 sky.bin(私钥) + sky_share.bin(公钥)",
                                     WS_VISIBLE | WS_CHILD, 24, 300, 752, 22, hwnd, NULL, NULL, NULL);
    SendMessageW(hStaticInfo, WM_SETFONT, (WPARAM)hFontLabel, TRUE);

}

void UpdateStatus(const WCHAR *text) {
    SetWindowTextW(hStaticStatus, text);
}

static int g_rand_initialized = 0;

void InitRandomGenerator(void) {
    if (!g_rand_initialized) {

        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        srand((unsigned int)(counter.LowPart ^ GetCurrentProcessId() ^ GetCurrentThreadId()));
        g_rand_initialized = 1;
    }
}

void GenerateRandomKey(char *key, size_t length) {

    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const int charset_len = 62;

    InitRandomGenerator();

    for (size_t i = 0; i < length - 1; i++) {
        key[i] = charset[rand() % charset_len];
    }
    key[length - 1] = '\0';
}

void OnGenerateKey() {

    EnableWindow(hButtonGenerate, FALSE);
    UpdateStatus(L"状态: 生成中...");

    InvalidateRect(hWnd, NULL, TRUE);
    UpdateWindow(hWnd);

    char key[65];
    GenerateRandomKey(key, sizeof(key));

    int wlen = MultiByteToWideChar(CP_UTF8, 0, key, -1, NULL, 0);
    WCHAR wkey[65];
    MultiByteToWideChar(CP_UTF8, 0, key, -1, wkey, wlen);
    SetWindowTextW(hEditKey, wkey);

    UpdateStatus(L"状态: 密钥生成成功");

    EnableWindow(hButtonGenerate, TRUE);
}

void OnCopyKey() {
    WCHAR wkey[65] = {0};
    GetWindowTextW(hEditKey, wkey, 65);

    if (wcslen(wkey) == 0) {
        UpdateStatus(L"状态: 请先生成密钥");
        return;
    }

    if (OpenClipboard(NULL)) {
        EmptyClipboard();

        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, (wcslen(wkey) + 1) * sizeof(WCHAR));
        if (hMem != NULL) {
            WCHAR *pData = (WCHAR *)GlobalLock(hMem);
            if (pData != NULL) {
                wcscpy(pData, wkey);
                GlobalUnlock(hMem);

                if (SetClipboardData(CF_UNICODETEXT, hMem)) {
                    UpdateStatus(L"状态: 密钥已复制到剪贴板");
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

void OnSaveKey() {
    WCHAR wkey[65] = {0};
    GetWindowTextW(hEditKey, wkey, 65);

    if (wcslen(wkey) == 0) {
        UpdateStatus(L"状态: 请先生成密钥");
        return;
    }

    OPENFILENAMEW ofn = {0};
    WCHAR szFile[MAX_PATH] = {0};

    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"文本文件 (*.txt)\0*.txt\0所有文件 (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn) == TRUE) {
        char key[65] = {0};
        WideCharToMultiByte(CP_UTF8, 0, wkey, -1, key, 65, NULL, NULL);

        FILE *fp = _wfopen(ofn.lpstrFile, L"w");
        if (fp) {
            fprintf(fp, "#define SECRET_KEY \"%s\"\n", key);
            fclose(fp);

            UpdateStatus(L"状态: 密钥已保存");
        } else {
            UpdateStatus(L"状态: 保存失败");
        }
    }
}

void OnGenerateKeyPair(void) {
    EnableWindow(hButtonKeyPair, FALSE);
    UpdateStatus(L"状态: 正在生成 ECDSA P-256 密钥对...");
    InvalidateRect(hWnd, NULL, TRUE);
    UpdateWindow(hWnd);

    BROWSEINFOW bi = {0};
    bi.hwndOwner = hWnd;
    bi.lpszTitle = L"选择密钥对保存目录";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) {
        EnableWindow(hButtonKeyPair, TRUE);
        UpdateStatus(L"状态: 已取消");
        return;
    }

    wchar_t dir_path[MAX_PATH];
    SHGetPathFromIDListW(pidl, dir_path);
    CoTaskMemFree(pidl);

    size_t len = wcslen(dir_path);
    if (len > 0 && dir_path[len - 1] != L'\\') {
        dir_path[len] = L'\\';
        dir_path[len + 1] = L'\0';
    }

    wchar_t priv_path[MAX_PATH], pub_path[MAX_PATH];
    _snwprintf_s(priv_path, MAX_PATH, _TRUNCATE, L"%ssky.bin", dir_path);
    _snwprintf_s(pub_path, MAX_PATH, _TRUNCATE, L"%ssky_share.bin", dir_path);

    if (ECDSA_GenerateKeyPair(priv_path, pub_path)) {
        WCHAR msg[512];
        _snwprintf_s(msg, 512, _TRUNCATE,
                     L"密钥对生成成功！\n\n私钥: %s\n公钥: %s\n\n请将 sky_share.bin 的 72 字节填入 key.c 的 EMBEDDED_PUBLIC_KEY 数组，重新编译程序。",
                     priv_path, pub_path);
        MessageBoxW(hWnd, msg, L"密钥对生成成功", MB_OK | MB_ICONINFORMATION);
        UpdateStatus(L"状态: 密钥对生成成功");
    } else {
        MessageBoxW(hWnd, L"密钥对生成失败，请检查系统是否支持 ECDSA P-256。", L"错误", MB_OK | MB_ICONERROR);
        UpdateStatus(L"状态: 密钥对生成失败");
    }

    EnableWindow(hButtonKeyPair, TRUE);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            CreateControls(hwnd);
            break;

        case WM_CTLCOLORSTATIC: {
            HDC hdc = (HDC)wParam;
            HWND hCtl = (HWND)lParam;

            if (hCtl == hEditKey) {

                SetBkColor(hdc, COLOR_READONLY_BG);
                SetTextColor(hdc, COLOR_TEXT_DARK);
                SetBkMode(hdc, OPAQUE);
                return (LRESULT)hBrushReadOnly;
            } else if (hCtl == hStaticStatus) {

                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, COLOR_TEXT_GRAY);
                return (LRESULT)GetStockObject(WHITE_BRUSH);
            } else {

                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, COLOR_TEXT_DARK);
                return (LRESULT)GetStockObject(WHITE_BRUSH);
            }
        }

        case WM_CTLCOLOREDIT:
            SetBkColor((HDC)wParam, RGB(255, 255, 255));
            SetTextColor((HDC)wParam, COLOR_TEXT_DARK);
            SetBkMode((HDC)wParam, OPAQUE);
            return (LRESULT)GetStockObject(WHITE_BRUSH);

        case WM_CTLCOLORDLG:
        case WM_CTLCOLORBTN:
            return (LRESULT)GetStockObject(WHITE_BRUSH);

        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
            if (pDIS->CtlType != ODT_BUTTON) break;

            WCHAR szText[64] = {0};
            GetWindowTextW(pDIS->hwndItem, szText, 64);

            BOOL bPrimary = (pDIS->CtlID == IDC_BUTTON_GENERATE || pDIS->CtlID == IDC_BUTTON_KEYPAIR);
            BOOL bDisabled = (pDIS->itemState & ODS_DISABLED) ? TRUE : FALSE;
            BOOL bSelected = (pDIS->itemState & ODS_SELECTED) ? TRUE : FALSE;

            COLORREF bgClr, textClr;
            if (bDisabled) {

                bgClr = bPrimary ? RGB(160, 200, 230) : RGB(240, 240, 240);
                textClr = RGB(160, 160, 160);
            } else if (bPrimary) {

                bgClr = bSelected ? COLOR_PRIMARY_PRESSED : COLOR_PRIMARY;
                textClr = COLOR_TEXT_WHITE;
            } else {

                bgClr = bSelected ? COLOR_BTN_HOVER : RGB(255, 255, 255);
                textClr = COLOR_TEXT_DARK;
            }

            HBRUSH hBrush = CreateSolidBrush(bgClr);
            FillRect(pDIS->hDC, &pDIS->rcItem, hBrush);
            DeleteObject(hBrush);

            if (!bPrimary) {
                HPEN hPen = CreatePen(PS_SOLID, 1, COLOR_BORDER);
                HPEN hOldPen = (HPEN)SelectObject(pDIS->hDC, hPen);
                HBRUSH hOldBrush = (HBRUSH)SelectObject(pDIS->hDC, GetStockObject(NULL_BRUSH));
                Rectangle(pDIS->hDC, pDIS->rcItem.left, pDIS->rcItem.top,
                          pDIS->rcItem.right, pDIS->rcItem.bottom);
                SelectObject(pDIS->hDC, hOldPen);
                SelectObject(pDIS->hDC, hOldBrush);
                DeleteObject(hPen);
            }

            SetTextColor(pDIS->hDC, textClr);
            SetBkMode(pDIS->hDC, TRANSPARENT);
            HFONT hOldFont = (HFONT)SelectObject(pDIS->hDC, hFontButton);
            DrawTextW(pDIS->hDC, szText, -1, &pDIS->rcItem,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(pDIS->hDC, hOldFont);

            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_BUTTON_GENERATE:
                    OnGenerateKey();
                    break;

                case IDC_BUTTON_COPY:
                    OnCopyKey();
                    break;

                case IDC_BUTTON_SAVE:
                    OnSaveKey();
                    break;

                case IDC_BUTTON_KEYPAIR:
                    OnGenerateKeyPair();
                    break;
            }
            break;

        case WM_DESTROY:

            if (hFontTitle) DeleteObject(hFontTitle);
            if (hFontLabel) DeleteObject(hFontLabel);
            if (hFontContent) DeleteObject(hFontContent);
            if (hFontStatus) DeleteObject(hFontStatus);
            if (hFontButton) DeleteObject(hFontButton);
            if (hBrushReadOnly) DeleteObject(hBrushReadOnly);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }

    return 0;
}