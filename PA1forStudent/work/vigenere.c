#include <stdio.h>

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

void encrypt(const char *ciphertext, const char *original_key, char *plaintext) {
    int i, j;
    
    int original_key_len = strlen(original_key);
    char *valid_key = malloc(original_key_len + 1);
    int valid_key_len = 0;
    for (i = 0; i < original_key_len; i++) {
        if (isalpha(original_key[i])) {
            valid_key[valid_key_len++] = tolower(original_key[i]);
        }
    }
    valid_key[valid_key_len] = '\0';

    if (valid_key_len == 0) {
        strcpy(plaintext, ciphertext);
        free(valid_key);
        return;
    }

    int ciphertext_len = strlen(ciphertext);

    for (i = 0, j = 0; i < ciphertext_len; i++) {
        char c_char = ciphertext[i];

        if (isalpha(c_char)) {
            char key_char = valid_key[j % valid_key_len];
            char cipher_char_lower = tolower(c_char);

            int cipher_val = cipher_char_lower - 'a';
            int key_val = key_char - 'a';

            int plain_val = (cipher_val + key_val + 26) % 26;
            
            plaintext[i] = plain_val + 'a';

            j++;
        
        } else {
            plaintext[i] = c_char;
        }
    }
    plaintext[i] = '\0';
    free(valid_key);
}

void decrypt(const char *ciphertext, const char *original_key, char *plaintext) {
    int i, j;

    int original_key_len = strlen(original_key);
    char *valid_key = malloc(original_key_len + 1);
    int valid_key_len = 0;
    for (i = 0; i < original_key_len; i++) {
        if (isalpha(original_key[i])) {
            valid_key[valid_key_len++] = tolower(original_key[i]);
        }
    }
    valid_key[valid_key_len] = '\0';

    if (valid_key_len == 0) {
        strcpy(plaintext, ciphertext);
        free(valid_key);
        return;
    }

    int ciphertext_len = strlen(ciphertext);

    for (i = 0, j = 0; i < ciphertext_len; i++) {
        char c_char = ciphertext[i];

        if (isalpha(c_char)) {
            char key_char = valid_key[j % valid_key_len];
            char cipher_char_lower = tolower(c_char);

            int cipher_val = cipher_char_lower - 'a';
            int key_val = key_char - 'a';

            int plain_val = (cipher_val - key_val + 26) % 26;
            
            plaintext[i] = plain_val + 'a';

            j++;
        
        } else {
            plaintext[i] = c_char;
        }
    }
    plaintext[i] = '\0';
    free(valid_key);
}


int main() {
    // 과제 설명에 나온 예시
    char plaintext1[] = "abcdefgh";
    char key1[] = "uailab";
    char ciphertext1[100];
    char ciphertext100[100];
    encrypt(plaintext1, key1, ciphertext1);
    printf("Plaintext:  %s\n", plaintext1);
    printf("Key:        %s\n", key1);
    printf("Ciphertext: %s\n\n", ciphertext1); // 예상 결과: ubkoegah
    decrypt(ciphertext1,key1, ciphertext100);
    printf("decription: %s\n", ciphertext100);

    // 과제 요구사항을 포함한 복합적인 예시
    char plaintext2[] = "Computer Networks, PA1!";
    char key2[] = "CSE351";
    char ciphertext2[100];
    encrypt(plaintext2, key2, ciphertext2);
    printf("Plaintext:  %s\n", plaintext2);
    printf("Key:        %s\n", key2);
    printf("Ciphertext: %s\n", ciphertext2);

    return 0;
}
