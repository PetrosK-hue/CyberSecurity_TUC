#include <stdio.h>
#include "simple_crypto.h"
int main()
{
    char str[100], key[100];
    // One Time Pad Cipher
    printf("[OTP] input: ");
    scanf("%s", str);
    printf("[OTP] encrypted: %s", OTP_encryption(str));
    printf("\n[OTP] decrypted %s", OTP_decryption(OTP_encryption(str)));
    // Caesars Cipher
    printf("\n[Caesars] input: ");
    scanf("%s", str);
    printf("[Caesars] key: 4 ");
    printf("\n[Caesars] encrypted: %s", Caesars_encryption(str));
    printf("\n[Caesars] decrypted: %s", Caesars_decryption(Caesars_encryption(str)));

    // Vigenere's Cipher
    printf("\n[Vigenere] input: ");
    scanf("%s", str);
    printf("[Vigenere] key: ");
    scanf("%s", key);
    printf("[Vigenere] encrypted: %s", Vigenere_encryption(str, key));
    printf("\n[Vigenere] decrypted: %s\n", Vigenere_decryption(Vigenere_encryption(str, key),key));

    return 0;
}