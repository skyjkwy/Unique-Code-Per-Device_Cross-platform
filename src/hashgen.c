#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pe_digest.h"

static void GuardFromMacro(const char *macro, char *out, size_t cap) {
    size_t i = 0, o = 0;
    for (; macro[i] && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)macro[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!ok && c >= 'a' && c <= 'z') ok = 1;
        out[o++] = ok ? (char)((c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c) : '_';
    }

    if (o + 3 < cap) {
        out[o++] = '_';
        out[o++] = 'H';
        out[o] = '\0';
    } else if (o < cap) {
        out[o] = '\0';
    }
}

static void FileMacroFrom(const char *macro, char *out, size_t cap) {
    static const char *kSuffix = "_CODE_SHA256";
    size_t len = strlen(macro);
    size_t slen = strlen(kSuffix);

    if (len >= slen && strcmp(macro + (len - slen), kSuffix) == 0) {
        size_t head = len - slen;
        if (head + 12 < cap) {
            memcpy(out, macro, head);
            memcpy(out + head, "_FILE_SHA256", 12);
            out[head + 12] = '\0';
        } else {
            out[0] = '\0';
        }
        return;
    }

    if (len + 12 < cap) {
        memcpy(out, macro, len);
        memcpy(out + len, "_FILE_SHA256", 13);
    } else {
        out[0] = '\0';
    }
}

int main(int argc, char *argv[]) {
    const char *pe_path = NULL;
    const char *header_path = NULL;
    const char *macro_name = NULL;
    char file_macro[160];
    char guard[192];
    FILE *fp = NULL;
    long file_size = 0;
    uint8_t *file_data = NULL;
    char text_hex[PE_DIGEST_HEX_LEN + 1];
    char file_hex[PE_DIGEST_HEX_LEN + 1];
    FILE *hfp = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: hashgen <pe_path> [header_path] [macro_name]\n");
        return 1;
    }

    pe_path = argv[1];
    header_path = argc > 2 ? argv[2] : "include/dll_hash.h";
    macro_name = argc > 3 ? argv[3] : "LICENSE_DLL_CODE_SHA256";

    GuardFromMacro(macro_name, guard, sizeof(guard));
    FileMacroFrom(macro_name, file_macro, sizeof(file_macro));
    if (file_macro[0] == '\0') {
        fprintf(stderr, "Macro name too long: %s\n", macro_name);
        return 1;
    }

    fp = fopen(pe_path, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open %s\n", pe_path);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (file_size <= 0) {
        fprintf(stderr, "Empty or unreadable file: %s\n", pe_path);
        fclose(fp);
        return 1;
    }

    file_data = (uint8_t *)malloc((size_t)file_size);
    if (!file_data) {
        fclose(fp);
        return 1;
    }
    if (fread(file_data, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "Short read: %s\n", pe_path);
        free(file_data);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    if (!PeComputeTextDigest(file_data, (size_t)file_size, text_hex)) {
        fprintf(stderr, "Not a valid PE (no .text): %s\n", pe_path);
        free(file_data);
        return 1;
    }
    if (!PeComputeStructDigest(file_data, (size_t)file_size, file_hex)) {
        fprintf(stderr, "Cannot compute file structure digest: %s\n", pe_path);
        free(file_data);
        return 1;
    }

    printf("Code(.text) SHA256:    %s\n", text_hex);
    printf("File structure SHA256: %s\n", file_hex);
    PeDescribeSections(file_data, (size_t)file_size);

    free(file_data);
    file_data = NULL;

    hfp = fopen(header_path, "w");
    if (!hfp) {
        fprintf(stderr, "Cannot open %s for writing\n", header_path);
        return 1;
    }

    fprintf(hfp,
        "#ifndef %s\n"
        "#define %s\n"
        "\n"
        "#define %s \"%s\"\n"
        "#define %s \"%s\"\n"
        "\n"
        "#endif\n",
        guard, guard,
        macro_name, text_hex,
        file_macro, file_hex);

    fclose(hfp);
    return 0;
}
