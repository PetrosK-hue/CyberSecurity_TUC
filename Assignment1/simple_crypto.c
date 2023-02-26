#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
char key[100];

char *OTP_encryption(char str[])
{
    //Programiz Function on removing special Charachters
    for (int i = 0, j; str[i] != '\0'; ++i) {
      //Programiz Function on removing not alphabetics
      // enter the loop if the character is not an alphabet
      // and not the null character
      while (!(str[i] >= 'a' && str[i] <= 'z') && !(str[i] >= 'A' && str[i] <= 'Z') && !(str[i] == '\0')) {
         for (j = i; str[j] != '\0'; ++j) {

            // if jth element of line is not an alphabet,
            // assign the value of (j+1)th element to the jth element
            str[j] = str[j + 1];
         }
         str[j] = '\0';
      }
    }
    for (int i = 0; i < strlen(str); i++)
    {
        char randomData;
        FILE *fp;
        fp = fopen("/dev/urandom", "r");
        ssize_t result = fread(&randomData, sizeof(randomData), 1, fp);
        if (result > 0)
        {
            key[i] = randomData;
            while ((key[i] > 126 || key[i] < 33))
            {
                key[i] = randomData;
                result = fread(&randomData, sizeof(randomData), 1, fp);
            }
        }
    }
    char *encrypted_str = (char *)malloc(sizeof(str));
    for (int i = 0; i < strlen(str); i++)
    {
        encrypted_str[i] = (char)(key[i] ^ str[i]);
        encrypted_str[i] = (encrypted_str[i] % 126) + 33;
    }
    return encrypted_str;
}

char *OTP_decryption(char *str)
{
    char *decrypted_str = (char *)malloc(sizeof(str));

    for (int i = 0; i < strlen(str); i++)
    {
        decrypted_str[i] = (char *)(str[i] - 33 ^ key[i]);
    }
    return decrypted_str;
}

char *Caesars_encryption(char *str)
{
    //Programiz Function on removing special Charachters
    for (int i = 0, j; str[i] != '\0'; ++i) {
      //Programiz Function on removing not alphabetics
      // enter the loop if the character is not an alphabet
      // and not the null character
      while (!(str[i] >= 'a' && str[i] <= 'z') && !(str[i] >= 'A' && str[i] <= 'Z') && !(str[i] == '\0')) {
         for (j = i; str[j] != '\0'; ++j) {

            // if jth element of line is not an alphabet,
            // assign the value of (j+1)th element to the jth element
            str[j] = str[j + 1];
         }
         str[j] = '\0';
      }
    }
    char *encrypted_str = (char *)malloc(sizeof(str));
    for (int i = 0; i < strlen(str); i++)
    {
        int tmp = str[i] + 4;
        if (tmp > 122)
            encrypted_str[i] = 47 + tmp - 122;
        else if (tmp > 90 && tmp < 97)
            encrypted_str[i] = 96 + tmp - 90;
        else if (tmp > 57 && tmp < 65)
            encrypted_str[i] = 64 + tmp - 57;
        else
            encrypted_str[i] = tmp;
    }
    return encrypted_str;
}

char *Caesars_decryption(char *str)
{
    char *decrypted_str = (char *)malloc(sizeof(str));
    for (int i = 0; i < strlen(str); i++)
    {
        int tmp = str[i] - 4;
        if (tmp < 48)
            decrypted_str[i] = 123 - abs(tmp - 48);
        else if (tmp < 97 && tmp > 90)
            decrypted_str[i] = 91 - abs(tmp - 97);
        else if (tmp < 65 && tmp > 57)
            decrypted_str[i] = 58 - abs(tmp - 65);
        else
            decrypted_str[i] = tmp;
    }
    return decrypted_str;
}

char *Vigenere_encryption(char *str, char *lemon)
{
    char *encrpypted_str = (char *)malloc(sizeof(str));
    char *extended_key = (char *)malloc(sizeof(str));
    int i, j = 0;
    for (i = 0; i < strlen(str); ++i)
    {
        if (j == strlen(lemon))
            j = 0;
        extended_key[i] = lemon[j];
        j++;
    }
    // extended_key[i] = '\0';
    //  encryption
    for (i = 0; i < strlen(str); ++i)
    {
        encrpypted_str[i] = (str[i] + extended_key[i]) % 26 + 65;
    }
    // encrpypted_str[i] = '\0';
    return encrpypted_str;
}

char *Vigenere_decryption(char *str, char *lemon)
{
    char *decrpypted_str = (char *)malloc(sizeof(str));
    char *extended_key = (char *)malloc(sizeof(str));
    int i, j = 0;
    for (i = 0; i < strlen(str); ++i)
    {
        if (j == strlen(lemon))
            j = 0;
        extended_key[i] = lemon[j];
        j++;
    }
    printf("\n[Vigenere] Extended key: %s", extended_key);
    // extended_key[i] = '\0';
    //  decryption
    for (i = 0; i < strlen(str); i++)
    {
        decrpypted_str[i] = (str[i] - extended_key[i] + 26) % 26 + 65;
    }
    return decrpypted_str;
}
