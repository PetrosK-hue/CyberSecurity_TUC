#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

char *OTP_encryption(char str[]);
char *OTP_decryption(char *str);
char *Caesars_encryption(char *str);
char *Caesars_decryption(char *str);
char *Vigenere_encryption(char *str, char *lemon);
char *Vigenere_decryption(char *str, char *lemon);


#endif