#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (needlelen > haystacklen || needlelen == 0) return NULL;
    if (haystacklen == 0) return NULL;
    for (size_t i = 0; i <= haystacklen - needlelen; i++)
        if (memcmp((const char *)haystack + i, needle, needlelen) == 0)
            return (void *)((const char *)haystack + i);
    return NULL;
}

typedef struct {
    unsigned char signature[16];
    int signature_len;
    char* file_type;
    char* file_extension;
    char* contains_string;
    char* old_format_type;
} FileSignature;

FileSignature signatures[] = {
    {{0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x33, 0x67, 0x70, 0x34}, 12, "3GP", ".3gp", NULL, NULL},
    {{0x52, 0x49, 0x46, 0x46}, 4, "AVI", ".avi", NULL, NULL},
    {{0x42, 0x4D}, 2, "BMP", ".bmp", NULL, NULL},
    {{0xFF, 0xD8, 0xFF, 0xE0}, 4, "JPG", ".jpg", NULL, NULL},
    {{0x4D, 0x5A}, 2, "EXE", ".exe", NULL, NULL},
    {{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, "XLS (Old)", ".xls", NULL, "xls"},
    {{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, "DOC (Old)", ".doc", NULL, "doc"},
    {{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 8, "PPT (Old)", ".ppt", NULL, "ppt"},
    {{0x50, 0x4B, 0x03, 0x04}, 4, "DOCX", ".docx", "word/", NULL},
    {{0x50, 0x4B, 0x03, 0x04}, 4, "XLSX", ".xlsx", "xl/", NULL},
    {{0x50, 0x4B, 0x03, 0x04}, 4, "PPTX", ".pptx", "ppt/", NULL},
    {{0x25, 0x50, 0x44, 0x46, 0x2D}, 5, "PDF", ".pdf", NULL, NULL},
    {{0xFF, 0xFB}, 2, "MP3", ".mp3", NULL, NULL},
    {{0xFF, 0xF3}, 2, "MP3", ".mp3", NULL, NULL},
    {{0x49, 0x44, 0x33}, 3, "MP3", ".mp3", NULL, NULL},
    {{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34, 0x32}, 12, "MP4", ".mp4", NULL, NULL},
    {{0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D}, 12, "MP4", ".mp4", NULL, NULL},
    {{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 8, "PNG", ".png", NULL, NULL},
    {{0x1F, 0x8B, 0x08}, 3, "TAR.GZ", ".tar.gz", NULL, NULL}
};
int num_signatures = sizeof(signatures) / sizeof(signatures[0]);

void decrypt(unsigned char* ciphertext, unsigned char* plaintext, int length, int shift) {
    for (int i = 0; i < length; i++)
        plaintext[i] = (unsigned char)(((int)ciphertext[i] - shift + 256) % 256);
}

FileSignature* signature(unsigned char* content, int length) {
    size_t search_limit = length > 4096 ? 4096 : length;
    for (int i = 0; i < num_signatures; i++) {
        if (length >= signatures[i].signature_len &&
            memcmp(content, signatures[i].signature, signatures[i].signature_len) == 0) {
            if (signatures[i].old_format_type != NULL) {
                if (strcmp(signatures[i].old_format_type, "xls") == 0) {
                    if (length > 8 && content[8] == 0x09 && content[9] == 0x08) return &signatures[i];
                } else if (strcmp(signatures[i].old_format_type, "doc") == 0) {
                    if (length > 8 && content[8] == 0x00 && content[9] == 0x46 && content[10] == 0x49 && content[11] == 0x4C) return &signatures[i];
                } else if (strcmp(signatures[i].old_format_type, "ppt") == 0) {
                    if (length > 8 && content[8] == 0x00 && content[9] == 0x6E && content[10] == 0x1E && content[11] == 0xF0) return &signatures[i];
                }
            } else if (signatures[i].contains_string == NULL) {
                return &signatures[i];
            } else {
                void* found = memmem(content, search_limit,
                                     signatures[i].contains_string, strlen(signatures[i].contains_string));
                if (found != NULL) return &signatures[i];
            }
        }
    }
    return NULL;
}

int main() {
    char filename[256];
    FILE *file;
    unsigned char *encrypted_content;
    long file_size;
    char output_filename[512];

    printf("Enter the name of the encrypted file: ");
    if (fgets(filename, sizeof(filename), stdin) == NULL) {
        fprintf(stderr, "Invalid filename.\n");
        return 1;
    }
    size_t len = strlen(filename);
    if (len > 0 && filename[len - 1] == '\n') filename[len - 1] = '\0';

    file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    encrypted_content = (unsigned char*)malloc(file_size);
    if (encrypted_content == NULL) {
        perror("Memory error");
        fclose(file);
        return 1;
    }

    if (fread(encrypted_content, 1, file_size, file) != file_size) {
        perror("File reading error");
        free(encrypted_content);
        fclose(file);
        return 1;
    }
    fclose(file);

    char *last_dot = strrchr(filename, '.');
    char base_filename[256];
    if (last_dot != NULL) {
        strncpy(base_filename, filename, last_dot - filename);
        base_filename[last_dot - filename] = '\0';
    } else {
        strcpy(base_filename, filename);
    }

    for (int shift = 0; shift < 256; shift++) {
        printf("Trying shift: %d\n", shift);

        unsigned char *decrypted_content = (unsigned char*)malloc(file_size);
        if (decrypted_content == NULL) {
            perror("Allocating memory error");
            free(encrypted_content);
            return 1;
        }

        decrypt(encrypted_content, decrypted_content, file_size, shift);

        FileSignature* detected_signature = signature(decrypted_content, file_size);

        if (detected_signature != NULL) {
            printf("\nDecryption completed\n");
            printf("Shift value %d\n", shift);
            printf("File type: %s\n", detected_signature->file_type);

            snprintf(output_filename, sizeof(output_filename), "decrypted_%s%s", base_filename, detected_signature->file_extension);

            FILE *outfile = fopen(output_filename, "wb");
            if (outfile != NULL) {
                if (fwrite(decrypted_content, 1, file_size, outfile) == file_size) {
                    printf("Content saved to '%s'\n", output_filename);
                } else {
                    perror("Error writing");
                }
                fclose(outfile);
            } else {
                perror("Error opening file");
            }

            free(decrypted_content);
            free(encrypted_content);
            printf("Press any key to exit\n");
            getchar();
            return 0;
        }
        free(decrypted_content);
    }

    printf("\nCould not decrypt\n");

    free(encrypted_content);
    printf("Press any key to exit\n");
    getchar();
    return 0;
}