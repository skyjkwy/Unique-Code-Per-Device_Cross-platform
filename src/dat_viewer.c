#include <windows.h>
#include <richedit.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>

#define IDC_BUTTON_OPEN    1001
#define IDC_EDIT_DISPLAY   1002
#define IDC_RADIO_HEX      1003
#define IDC_RADIO_AUTO     1004
#define IDC_BUTTON_REFRESH 1005
#define IDC_BUTTON_CLEAR   1006
#define IDC_STATIC_TITLE   1007
#define IDC_STATIC_HINT    1008
#define IDI_ICON1          101

#define FILE_ENCRYPT_MAGIC "LICE"
#define FILE_ENCRYPT_VERSION 0x01
#define FILE_KEY1_LEN 16
#define FILE_KEY2_LEN 16
#define FILE_KEY3_LEN 8
#define FILE_ENCRYPT_HEADER_SIZE 13

static const uint8_t FILE_KEY1_DAT[] = {
    0xA3, 0x5F, 0xB7, 0xD9, 0xC1, 0x8E, 0x24, 0xF6,
    0x3D, 0x72, 0x0B, 0x98, 0x5E, 0x4A, 0x1C, 0x6F
};

static const uint8_t FILE_KEY2_DAT[] = {
    0x8B, 0x42, 0xE5, 0x17, 0x9F, 0xD3, 0xA8, 0x36,
    0xC4, 0x5E, 0x71, 0x09, 0xB2, 0x6D, 0xF8, 0xAC
};

static const uint8_t FILE_KEY3_DAT[] = {
    0x3F, 0x92, 0xC7, 0xE8, 0x51, 0x06, 0xAD, 0xB4
};

#define COLOR_ACCENT       RGB(0, 120, 212)
#define COLOR_ACCENT_DOWN  RGB(0, 95, 184)
#define COLOR_TEXT_DARK    RGB(32, 32, 32)
#define COLOR_TEXT_SECOND  RGB(110, 110, 110)
#define COLOR_EDIT_BG      RGB(245, 245, 245)
#define COLOR_EDIT_TEXT    RGB(51, 51, 51)
#define COLOR_BORDER       RGB(200, 200, 200)
#define COLOR_BORDER_DOWN  RGB(120, 120, 120)

#define USERNAME_LEN 64
#define EMAIL_LEN 64
#define SHA256_DIGEST_SIZE 32
#define CODE_SEQ_LEN 8
#define BASE_FILE_SIZE 169

HWND hWnd;
HWND hButtonOpen;
HWND hButtonRefresh;
HWND hButtonClear;
HWND hEditDisplay;
HWND hRadioHex;
HWND hRadioAuto;
HWND hStaticTitle;
HWND hStaticHint;
HFONT hFont;
HFONT hTitleFont;
HFONT hLabelFont;
HFONT hBtnFont;
HBRUSH hBgBrush;
HBRUSH hEditBrush;

WCHAR g_szFile[MAX_PATH] = L"";
int g_view_mode = 0;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    const WCHAR CLASS_NAME[] = L"DatViewerClass";

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
        L"DAT 文件查看器 (支持所有 .dat 文件)",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 650,
        NULL, NULL, hInstance, NULL
    );

    if (hWnd == NULL) return 0;

    ShowWindow(hWnd, nCmdShow);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}

static void FormatTimeStr(uint32_t timestamp, char *buf, size_t max_len) {
    if (timestamp == 0) {
        strncpy(buf, "永久授权 (0)", max_len - 1);
        buf[max_len - 1] = '\0';
        return;
    }
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (tm_info) {
        strftime(buf, max_len, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(buf, max_len, "%u", timestamp);
    }
}

static void FormatRemainingTime(uint64_t remaining_seconds, char *buf, size_t max_len) {
    if (remaining_seconds == 0) {
        strncpy(buf, "已过期", max_len - 1);
        buf[max_len - 1] = '\0';
        return;
    }

    int years = 0, months = 0, days = 0, hours = 0, minutes = 0, seconds = 0;

    years = (int)(remaining_seconds / (365LL * 24 * 3600));
    remaining_seconds -= (uint64_t)years * 365LL * 24 * 3600;

    months = (int)(remaining_seconds / (30LL * 24 * 3600));
    remaining_seconds -= (uint64_t)months * 30LL * 24 * 3600;

    days = (int)(remaining_seconds / (24LL * 3600));
    remaining_seconds -= (uint64_t)days * 24LL * 3600;

    hours = (int)(remaining_seconds / 3600);
    remaining_seconds -= (uint64_t)hours * 3600;

    minutes = (int)(remaining_seconds / 60);

    seconds = (int)(remaining_seconds % 60);

    int show_count = (years > 0) + (months > 0) + (days > 0) + (hours > 0) + (minutes > 0) + (seconds > 0);

    if (show_count <= 2) {

        snprintf(buf, max_len, "%d时%d分%d秒", hours, minutes, seconds);
        if (days > 0) {
            snprintf(buf, max_len, "%d天%d时%d分%d秒", days, hours, minutes, seconds);
        }
        if (months > 0 || years > 0) {
            snprintf(buf, max_len, "%d年%d月%d天%d时%d分%d秒", years, months, days, hours, minutes, seconds);
        }
    } else if (years > 0 || months > 0) {

        snprintf(buf, max_len, "%d年%d月%d天%d时%d分%d秒", years, months, days, hours, minutes, seconds);
    } else if (days > 0) {

        snprintf(buf, max_len, "%d天%d时%d分%d秒", days, hours, minutes, seconds);
    } else {

        snprintf(buf, max_len, "%d时%d分%d秒", hours, minutes, seconds);
    }
}

static void HexStr(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        snprintf(out + i * 2, 3, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

static int IsPrintable(uint8_t b) {
    return (b >= 0x20 && b <= 0x7E);
}

static size_t BuildHexView(const uint8_t *data, size_t len, WCHAR *out, size_t out_max) {
    if (out_max == 0) return 0;

    size_t pos = 0;
    size_t bytes_per_line = 16;

    int written = swprintf(out + pos, out_max - pos,
        L"偏移地址     00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII\r\n"
        L"------------------------------------------------------------------------\r\n");
    if (written > 0) pos += (size_t)written;
    else return pos;

    for (size_t offset = 0; offset < len; offset += bytes_per_line) {
        if (pos >= out_max - 256) break;

        size_t line_len = (len - offset < bytes_per_line) ? (len - offset) : bytes_per_line;

        written = swprintf(out + pos, out_max - pos, L"%08X   ", (unsigned int)offset);
        if (written > 0) pos += (size_t)written;
        else break;

        for (size_t i = 0; i < bytes_per_line && pos < out_max - 512; i++) {
            if (i < line_len) {
                written = swprintf(out + pos, out_max - pos, L"%02X ", data[offset + i]);
                if (written > 0) pos += (size_t)written;
                else break;
            } else {
                written = swprintf(out + pos, out_max - pos, L"   ");
                if (written > 0) pos += (size_t)written;
                else break;
            }
            if (i == 7 && pos < out_max - 128) {
                written = swprintf(out + pos, out_max - pos, L" ");
                if (written > 0) pos += (size_t)written;
            }
        }

        if (pos < out_max - 128) {
            written = swprintf(out + pos, out_max - pos, L"  ");
            if (written > 0) pos += (size_t)written;
        }

        for (size_t i = 0; i < line_len && pos < out_max - 256; i++) {
            uint8_t b = data[offset + i];
            if (IsPrintable(b)) {
                written = swprintf(out + pos, out_max - pos, L"%c", (WCHAR)b);
                if (written > 0) pos += (size_t)written;
            } else {
                written = swprintf(out + pos, out_max - pos, L".");
                if (written > 0) pos += (size_t)written;
            }
        }

        if (pos < out_max - 128) {
            written = swprintf(out + pos, out_max - pos, L"\r\n");
            if (written > 0) pos += (size_t)written;
        } else {
            break;
        }
    }

    if (pos < out_max - 256) {
        written = swprintf(out + pos, out_max - pos,
            L"\r\n------------------------------------------------------------------------\r\n"
            L"文件大小: %zu 字节 (0x%zX)\r\n", len, len);
        if (written > 0) pos += (size_t)written;
    }

    return pos;
}

static void GenerateKeyStream(uint8_t *output, size_t length, const uint8_t *key3, uint32_t seed) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) {
        S[i] = (uint8_t)i;
    }

    uint32_t j = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t seed_part = (seed >> (i % 4 * 8)) & 0xFF;
        j = (j + S[i] + key3[i % 8] + seed_part) & 0xFF;
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    uint32_t idx_i = 0, idx_j = 0;
    for (size_t n = 0; n < length; n++) {
        idx_i = (idx_i + 1) & 0xFF;
        idx_j = (idx_j + S[idx_i]) & 0xFF;

        uint8_t temp = S[idx_i];
        S[idx_i] = S[idx_j];
        S[idx_j] = temp;

        output[n] = S[(S[idx_i] + S[idx_j]) & 0xFF];
    }
}

static void DecryptDataView(uint8_t *data, size_t length, uint32_t seed) {
    uint8_t *keystream = (uint8_t *)malloc(length);
    if (!keystream) return;

    GenerateKeyStream(keystream, length, FILE_KEY3_DAT, seed);
    for (size_t i = 0; i < length; i++) {
        data[i] ^= keystream[i];
    }

    for (size_t i = length; i > 0; i--) {
        data[i - 1] ^= FILE_KEY2_DAT[(i - 1) % FILE_KEY2_LEN];
    }

    for (size_t i = 0; i < length; i++) {
        data[i] ^= FILE_KEY1_DAT[i % FILE_KEY1_LEN];
    }

    free(keystream);
}

static uint8_t* DecryptFileData(const uint8_t *file_data, long file_size, size_t *out_size) {

    if (file_size >= FILE_ENCRYPT_HEADER_SIZE &&
        memcmp(file_data, FILE_ENCRYPT_MAGIC, 4) == 0 &&
        file_data[4] == FILE_ENCRYPT_VERSION) {

        uint32_t seed = 0;
        uint32_t original_length = 0;

        memcpy(&seed, file_data + 5, 4);
        memcpy(&original_length, file_data + 9, 4);

        if (file_size != (long)(FILE_ENCRYPT_HEADER_SIZE + original_length)) {
            return NULL;
        }

        uint8_t *decrypted = (uint8_t *)malloc(original_length);
        if (!decrypted) return NULL;

        memcpy(decrypted, file_data + FILE_ENCRYPT_HEADER_SIZE, original_length);
        DecryptDataView(decrypted, original_length, seed);

        *out_size = original_length;
        return decrypted;
    } else {

        uint8_t *copy = (uint8_t *)malloc(file_size);
        if (!copy) return NULL;
        memcpy(copy, file_data, file_size);
        *out_size = file_size;
        return copy;
    }
}

static int IsLicenseDat(const uint8_t *data, size_t len) {
    if (len < BASE_FILE_SIZE) return 0;
    uint8_t status = data[0];
    if (status != 0 && status != 1) return 0;
    long used_size = (long)len - BASE_FILE_SIZE;
    if (used_size % CODE_SEQ_LEN != 0) return 0;
    return 1;
}

static size_t BuildLicenseView(const uint8_t *data, size_t len, WCHAR *out, size_t out_max) {
    if (out_max == 0) return 0;

    uint8_t status = data[0];
    uint32_t expire_time = *(uint32_t*)(data + 1);
    uint32_t last_seen_time = *(uint32_t*)(data + 5);
    const char *username = (const char*)(data + 9);
    const char *email = (const char*)(data + 73);
    const uint8_t *digest = data + 137;
    const char *used_codes = (const char*)(data + BASE_FILE_SIZE);

    size_t used_section_size = len - BASE_FILE_SIZE;
    int total_codes = (int)(used_section_size / CODE_SEQ_LEN);
    int used_count = 0;
    for (int i = 0; i < total_codes; i++) {
        if (used_codes[i * CODE_SEQ_LEN] != '\0') used_count++;
    }

    char expire_buf[64] = {0};
    char last_seen_buf[64] = {0};
    FormatTimeStr(expire_time, expire_buf, sizeof(expire_buf));
    FormatTimeStr(last_seen_time, last_seen_buf, sizeof(last_seen_buf));

    char digest_hex[SHA256_DIGEST_SIZE * 2 + 1] = {0};
    HexStr(digest, SHA256_DIGEST_SIZE, digest_hex);

    time_t now = time(NULL);
    int expired = (expire_time > 0 && (uint32_t)now > expire_time) ? 1 : 0;
    uint64_t remaining_seconds = 0;
    if (expire_time > 0) {
        int64_t diff = (int64_t)expire_time - (int64_t)now;
        remaining_seconds = (diff > 0) ? (uint64_t)diff : 0;
    }
    int rolled_back = ((uint32_t)now < last_seen_time && last_seen_time > 0) ? 1 : 0;

    WCHAR wusername[USERNAME_LEN * 2] = {0};
    MultiByteToWideChar(CP_UTF8, 0, username, -1, wusername, USERNAME_LEN * 2);
    WCHAR wemail[EMAIL_LEN * 2] = {0};
    MultiByteToWideChar(CP_UTF8, 0, email, -1, wemail, EMAIL_LEN * 2);

    char remaining_buf[128] = {0};
    if (expire_time > 0) {
        if (expired) {
            strncpy(remaining_buf, "已过期", sizeof(remaining_buf) - 1);
        } else {
            FormatRemainingTime(remaining_seconds, remaining_buf, sizeof(remaining_buf));
        }
    }

    size_t pos = 0;
    int written = swprintf(out + pos, out_max - pos,
        L"======= license-SkyBox.dat 智能解析 =======\r\n\r\n"
        L"[000] 激活状态 (1 byte): 0x%02X  %s\r\n"
        L"[001] 过期时间 (4 bytes): 0x%08X (%u)  →  %S\r\n"
        L"      状态: %s",
        status, (status == 1) ? L"已激活" : L"未激活",
        expire_time, expire_time, expire_buf,
        expired ? L"已过期" : (expire_time == 0 ? L"永久授权" : L"有效"));
    if (written > 0) pos += (size_t)written;
    else return pos;

    if (expire_time > 0 && pos < out_max - 256) {
        WCHAR wremaining[128] = {0};
        MultiByteToWideChar(CP_UTF8, 0, remaining_buf, -1, wremaining, 128);
        written = swprintf(out + pos, out_max - pos, L"，剩余 %s", wremaining);
        if (written > 0) pos += (size_t)written;
    }

    if (pos < out_max - 512) {
        written = swprintf(out + pos, out_max - pos,
            L"\r\n[005] 最后运行 (4 bytes): 0x%08X (%u)  →  %S\r\n"
            L"      时间回拨: %s\r\n"
            L"[009] 用户名 (64 bytes): %s\r\n"
            L"[073] 邮箱 (64 bytes):   %s\r\n"
            L"[137] 机器码哈希 (32 bytes):\r\n"
            L"      %S\r\n"
            L"[169] 已用激活码 (动态长度): 共 %d 个\r\n",
            last_seen_time, last_seen_time, last_seen_buf,
            rolled_back ? L"检测到回拨!" : L"正常",
            wusername[0] ? wusername : L"(空)",
            wemail[0] ? wemail : L"(空)",
            digest_hex, used_count);
        if (written > 0) pos += (size_t)written;
    }

    for (int i = 0; i < total_codes && pos < out_max - 256; i++) {
        char seq[CODE_SEQ_LEN + 1] = {0};
        memcpy(seq, used_codes + i * CODE_SEQ_LEN, CODE_SEQ_LEN);
        if (seq[0] != '\0') {
            WCHAR wseq[CODE_SEQ_LEN + 1] = {0};
            MultiByteToWideChar(CP_UTF8, 0, seq, -1, wseq, CODE_SEQ_LEN + 1);
            written = swprintf(out + pos, out_max - pos, L"      [%03d] %s\r\n", i + 1, wseq);
            if (written > 0) pos += (size_t)written;
        }
    }
    if (used_count == 0 && pos < out_max - 128) {
        written = swprintf(out + pos, out_max - pos, L"      (暂无记录)\r\n");
        if (written > 0) pos += (size_t)written;
    }

    if (pos < out_max - 256) {
        written = swprintf(out + pos, out_max - pos,
            L"\r\n======= 文件结构 =======\r\n"
            L"偏移   大小   字段\r\n"
            L"0        1   激活状态\r\n"
            L"1        4   过期时间\r\n"
            L"5        4   最后运行时间\r\n"
            L"9       64   用户名\r\n"
            L"73      64   邮箱\r\n"
            L"137     32   机器码哈希\r\n"
            L"169      N   已用激活码列表 (动态增长, 每个8字节)\r\n"
            L"总计: %zu 字节 (基础169 + 已用列表%zu)\r\n",
            len, used_section_size);
        if (written > 0) pos += (size_t)written;
    }

    return pos;
}

void RefreshDisplay() {
    if (wcslen(g_szFile) == 0) {
        SetWindowTextW(hEditDisplay, L"请点击\"打开文件\"按钮选择 .dat 文件");
        return;
    }

    FILE *fp = NULL;
    _wfopen_s(&fp, g_szFile, L"rb");
    if (!fp) {
        SetWindowTextW(hEditDisplay, L"无法打开文件!");
        return;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(fp);
        SetWindowTextW(hEditDisplay, L"文件为空!");
        return;
    }

    size_t read_size = (file_size > 1024 * 1024) ? (1024 * 1024) : (size_t)file_size;
    uint8_t *raw_data = (uint8_t*)malloc(read_size);
    if (!raw_data) {
        fclose(fp);
        SetWindowTextW(hEditDisplay, L"内存分配失败!");
        return;
    }
    fread(raw_data, 1, read_size, fp);
    fclose(fp);

    size_t decrypted_size = 0;
    uint8_t *decrypted_data = DecryptFileData(raw_data, file_size, &decrypted_size);

    int is_encrypted = (decrypted_size > 0 && decrypted_size != (size_t)file_size &&
                       memcmp(raw_data, FILE_ENCRYPT_MAGIC, 4) == 0);

    uint8_t *parse_data = is_encrypted ? decrypted_data : raw_data;
    size_t parse_size = is_encrypted ? decrypted_size : file_size;

    const size_t BUF_SIZE = 262144;
    WCHAR *display = (WCHAR*)malloc(sizeof(WCHAR) * BUF_SIZE);
    if (!display) {
        free(raw_data);
        if (decrypted_data != raw_data) free(decrypted_data);
        SetWindowTextW(hEditDisplay, L"内存分配失败!");
        return;
    }
    display[0] = L'\0';

    size_t pos = 0;
    int remaining = (int)(BUF_SIZE - pos);
    if (remaining > 0) {
        int written = swprintf(display + pos, remaining,
            L"文件: %s\r\n"
            L"原始大小: %ld 字节 (0x%lX)\r\n",
            g_szFile, file_size, file_size);
        if (written > 0) pos += (size_t)written;
    }

    remaining = (int)(BUF_SIZE - pos);
    if (remaining > 0) {
        if (is_encrypted) {
            int written = swprintf(display + pos, remaining,
                L"文件状态: [已加密 ✓] (自动解密)\r\n"
                L"解密后大小: %zu 字节 (0x%zX)\r\n\r\n",
                decrypted_size, decrypted_size);
            if (written > 0) pos += (size_t)written;
        } else {
            int written = swprintf(display + pos, remaining,
                L"文件状态: 明文格式\r\n\r\n");
            if (written > 0) pos += (size_t)written;
        }
    }

    int is_license = IsLicenseDat(parse_data, parse_size);

    if (g_view_mode == 1) {
        if (is_encrypted) {
            remaining = (int)(BUF_SIZE - pos);
            if (remaining > 0) {
                int written = swprintf(display + pos, remaining,
                    L"======= 原始文件 (加密后) =======\r\n\r\n");
                if (written > 0) pos += (size_t)written;
            }
            remaining = (int)(BUF_SIZE - pos);
            if (remaining > 0) {
                pos += BuildHexView(raw_data, (size_t)file_size, display + pos, (size_t)remaining);
            }
            remaining = (int)(BUF_SIZE - pos);
            if (remaining > 0) {
                int written = swprintf(display + pos, remaining,
                    L"\r\n======= 解密后内容 =======\r\n\r\n");
                if (written > 0) pos += (size_t)written;
            }
        }
        remaining = (int)(BUF_SIZE - pos);
        if (remaining > 0) {
            pos += BuildHexView(parse_data, parse_size, display + pos, (size_t)remaining);
        }
    } else {
        if (is_license) {
            remaining = (int)(BUF_SIZE - pos);
            if (remaining > 0) {
                pos += BuildLicenseView(parse_data, parse_size, display + pos, (size_t)remaining);
            }
            remaining = (int)(BUF_SIZE - pos);
            if (remaining > 0) {
                int written = swprintf(display + pos, remaining,
                    L"\r\n======= 文件十六进制视图 =======\r\n\r\n");
                if (written > 0) pos += (size_t)written;
            }
            remaining = (int)(BUF_SIZE - pos);
            if (remaining > 0) {
                pos += BuildHexView(parse_data, parse_size, display + pos, (size_t)remaining);
            }
        } else {
            remaining = (int)(BUF_SIZE - pos);
            if (remaining > 0) {
                int written = swprintf(display + pos, remaining,
                    L"(未知格式，以十六进制显示)\r\n\r\n");
                if (written > 0) pos += (size_t)written;
            }
            remaining = (int)(BUF_SIZE - pos);
            if (remaining > 0) {
                pos += BuildHexView(parse_data, parse_size, display + pos, (size_t)remaining);
            }
        }
    }

    display[pos] = L'\0';
    SetWindowTextW(hEditDisplay, display);
    SendMessageW(hEditDisplay, EM_SETSEL, 0, 0);
    SendMessageW(hEditDisplay, EM_SCROLLCARET, 0, 0);
    free(display);
    free(raw_data);
    if (decrypted_data != raw_data) free(decrypted_data);
}

void OnOpenFile() {
    OPENFILENAMEW ofn = {0};
    WCHAR szFile[MAX_PATH] = L"";

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"DAT 文件 (*.dat)\0*.dat\0所有文件 (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrInitialDir = L".";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (!GetOpenFileNameW(&ofn)) return;

    wcscpy(g_szFile, szFile);
    RefreshDisplay();
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {

            hBgBrush = CreateSolidBrush(RGB(255, 255, 255));
            hEditBrush = CreateSolidBrush(COLOR_EDIT_BG);

            hTitleFont = CreateFontW(-18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
            hLabelFont = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
            hBtnFont = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
            hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Courier New");

            hStaticTitle = CreateWindowW(L"STATIC", L"DAT 文件查看器",
                WS_VISIBLE | WS_CHILD | SS_LEFT,
                24, 18, 600, 30, hwnd, (HMENU)IDC_STATIC_TITLE, NULL, NULL);
            SendMessageW(hStaticTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

            hStaticHint = CreateWindowW(L"STATIC", L"支持 license-SkyBox.dat 智能解析与十六进制查看",
                WS_VISIBLE | WS_CHILD | SS_LEFT,
                24, 54, 600, 18, hwnd, (HMENU)IDC_STATIC_HINT, NULL, NULL);
            SendMessageW(hStaticHint, WM_SETFONT, (WPARAM)hLabelFont, TRUE);

            hButtonOpen = CreateWindowW(L"BUTTON", L"打开文件",
                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                24, 88, 120, 36, hwnd, (HMENU)IDC_BUTTON_OPEN, NULL, NULL);

            hButtonRefresh = CreateWindowW(L"BUTTON", L"刷新",
                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                156, 88, 90, 36, hwnd, (HMENU)IDC_BUTTON_REFRESH, NULL, NULL);

            hButtonClear = CreateWindowW(L"BUTTON", L"清空",
                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                258, 88, 90, 36, hwnd, (HMENU)IDC_BUTTON_CLEAR, NULL, NULL);

            hRadioAuto = CreateWindowW(L"BUTTON", L"自动解析",
                WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                372, 94, 100, 24, hwnd, (HMENU)IDC_RADIO_AUTO, NULL, NULL);
            SendMessageW(hRadioAuto, WM_SETFONT, (WPARAM)hLabelFont, TRUE);
            SendMessageW(hRadioAuto, BM_SETCHECK, BST_CHECKED, 0);

            hRadioHex = CreateWindowW(L"BUTTON", L"十六进制",
                WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                482, 94, 100, 24, hwnd, (HMENU)IDC_RADIO_HEX, NULL, NULL);
            SendMessageW(hRadioHex, WM_SETFONT, (WPARAM)hLabelFont, TRUE);

            LoadLibraryW(L"Msftedit.dll");
            hEditDisplay = CreateWindowExW(0, L"RichEdit50W", L"请点击\"打开文件\"按钮选择 .dat 文件",
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
                WS_VSCROLL | WS_HSCROLL | ES_READONLY,
                24, 136, 836, 460, hwnd, (HMENU)IDC_EDIT_DISPLAY, NULL, NULL);
            SendMessageW(hEditDisplay, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessageW(hEditDisplay, EM_SETREADONLY, TRUE, 0);
            SendMessageW(hEditDisplay, EM_SETLIMITTEXT, 0, 0);
            SendMessageW(hEditDisplay, EM_SETBKGNDCOLOR, 0, (LPARAM)COLOR_EDIT_BG);
            break;
        }

        case WM_CTLCOLORSTATIC: {

            HDC hdc = (HDC)wParam;
            HWND hCtrl = (HWND)lParam;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, COLOR_TEXT_SECOND);
            if (hCtrl == hStaticTitle) {
                SetTextColor(hdc, COLOR_TEXT_DARK);
            }
            return (LRESULT)hBgBrush;
        }

        case WM_CTLCOLOREDIT: {

            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, COLOR_EDIT_BG);
            SetTextColor(hdc, COLOR_EDIT_TEXT);
            SetBkMode(hdc, OPAQUE);
            return (LRESULT)hEditBrush;
        }

        case WM_CTLCOLORDLG:
        case WM_CTLCOLORBTN:
            return (LRESULT)hBgBrush;

        case WM_DRAWITEM: {

            LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
            if (!dis || dis->CtlType != ODT_BUTTON) break;
            HWND hCtrl = dis->hwndItem;
            WCHAR szText[64] = {0};
            GetWindowTextW(hCtrl, szText, 64);
            RECT rc = dis->rcItem;
            BOOL bDown = (dis->itemState & ODS_SELECTED) ? TRUE : FALSE;
            BOOL bPrimary = (hCtrl == hButtonOpen) ? TRUE : FALSE;

            if (bPrimary) {
                COLORREF cr = bDown ? COLOR_ACCENT_DOWN : COLOR_ACCENT;
                HBRUSH br = CreateSolidBrush(cr);
                FillRect(dis->hDC, &rc, br);
                DeleteObject(br);
                SetTextColor(dis->hDC, RGB(255, 255, 255));
            } else {
                HBRUSH br = CreateSolidBrush(RGB(255, 255, 255));
                FillRect(dis->hDC, &rc, br);
                DeleteObject(br);
                HPEN pen = CreatePen(PS_SOLID, 1, bDown ? COLOR_BORDER_DOWN : COLOR_BORDER);
                HGDIOBJ oldPen = SelectObject(dis->hDC, pen);
                HGDIOBJ oldBr = SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));
                Rectangle(dis->hDC, rc.left, rc.top, rc.right, rc.bottom);
                SelectObject(dis->hDC, oldPen);
                SelectObject(dis->hDC, oldBr);
                DeleteObject(pen);
                SetTextColor(dis->hDC, COLOR_TEXT_DARK);
            }
            SetBkMode(dis->hDC, TRANSPARENT);
            HGDIOBJ oldFont = SelectObject(dis->hDC, hBtnFont);
            DrawTextW(dis->hDC, szText, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(dis->hDC, oldFont);
            return TRUE;
        }

        case WM_COMMAND: {
            WORD id = LOWORD(wParam);
            WORD cmd = HIWORD(wParam);
            if (id == IDC_BUTTON_OPEN) {
                OnOpenFile();
            } else if (id == IDC_BUTTON_REFRESH) {
                RefreshDisplay();
            } else if (id == IDC_BUTTON_CLEAR) {
                g_szFile[0] = L'\0';
                SetWindowTextW(hEditDisplay, L"已清空。请点击\"打开文件\"按钮选择 .dat 文件");
            } else if (id == IDC_RADIO_AUTO && cmd == BN_CLICKED) {
                g_view_mode = 0;
                RefreshDisplay();
            } else if (id == IDC_RADIO_HEX && cmd == BN_CLICKED) {
                g_view_mode = 1;
                RefreshDisplay();
            }
            break;
        }

        case WM_DESTROY:
            DeleteObject(hFont);
            DeleteObject(hTitleFont);
            DeleteObject(hLabelFont);
            DeleteObject(hBtnFont);
            DeleteObject(hBgBrush);
            DeleteObject(hEditBrush);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
