#include "generator-core.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    const WCHAR CLASS_NAME[] = L"ActivationGeneratorClass";

    WNDCLASSEXW wc = { 0 };
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON1));
    wc.hIconSm       = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON1));

    RegisterClassExW(&wc);

    hWnd = CreateWindowExW(
        0, CLASS_NAME, L"激活码生成器",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 1100, 650,
        NULL, NULL, hInstance, NULL
    );

    if (hWnd == NULL) return 0;

    Generator_EnableStatusPopups(TRUE);

    Generator_CenterOnScreen(hWnd);

    ShowWindow(hWnd, nCmdShow);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}
