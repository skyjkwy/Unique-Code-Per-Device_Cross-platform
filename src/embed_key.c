#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <input.bin> <output.h> <array_name> <guard_name>\n", argv[0]);
        return 1;
    }

    const char *in_path = argv[1];
    const char *out_path = argv[2];
    const char *array_name = argv[3];
    const char *guard_name = argv[4];

    FILE *fin = fopen(in_path, "rb");
    if (!fin) {
        fprintf(stderr, "Error: cannot open %s\n", in_path);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 4096) {
        fprintf(stderr, "Error: invalid file size (%ld bytes)\n", file_size);
        fclose(fin);
        return 1;
    }

    unsigned char *buf = (unsigned char *)malloc(file_size);
    if (!buf) {
        fprintf(stderr, "Error: memory allocation failed\n");
        fclose(fin);
        return 1;
    }

    size_t rd = fread(buf, 1, file_size, fin);
    fclose(fin);

    if ((long)rd != file_size) {
        fprintf(stderr, "Error: incomplete read\n");
        free(buf);
        return 1;
    }

    FILE *fout = fopen(out_path, "w");
    if (!fout) {
        fprintf(stderr, "Error: cannot create %s\n", out_path);
        free(buf);
        return 1;
    }

    fprintf(fout, "#ifndef %s\n", guard_name);
    fprintf(fout, "#define %s\n\n", guard_name);
    fprintf(fout, "#include <stdint.h>\n\n");
    fprintf(fout, "static const uint8_t %s[] = {\n", array_name);

    for (long i = 0; i < file_size; i++) {
        if (i % 8 == 0) fprintf(fout, "    ");
        fprintf(fout, "0x%02X", buf[i]);
        if (i < file_size - 1) fprintf(fout, ",");
        if (i % 8 == 7 || i == file_size - 1) fprintf(fout, "\n");
        else fprintf(fout, " ");
    }

    fprintf(fout, "};\n\n");
    fprintf(fout, "#endif\n");

    fclose(fout);
    free(buf);

    printf("Generated %s (%ld bytes)\n", out_path, file_size);
    return 0;
}
