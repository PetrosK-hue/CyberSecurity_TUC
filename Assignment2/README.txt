###################################################################

[ASSIGNMENT 2] EVP_API TOOLKIT (using OPENSSL)
        KATSIBAS PETROS(2016030038)

###################################################################

## TASK A
### Key Derivation Function (KDF)

In this function we generate a key according to the given password. The key is 
symmetric to the user-defined string. In order to accomplish this, we used an existing 
function, which is located in OpenSSL librady and called:

EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md, const unsigned char *salt, 
                const unsigned char *data, int datal, int count,
                unsigned char *key, unsigned char *iv);

As we can see from parameters of this function, we need an AES block cipher as EVP_CIPHER
and  a SHA1() cryptographic hash function as EVP_MD. Based on the bitmode( 128 or 256) we run
either EVP_aes_128_ecb() or EVP_aes_256_ecb(). The salt is not needed so is replaced by NULL
and count is 1 as default.

## TASK B
### Data Encryption

For the task B, we call functions based on the given key and the bit mode(128 or 256).
Specifically, EVP_EncryptInit_ex(), EVP_EncryptUpdate(), EVP_EncryptFinal_ex() are at our 
encryption routine for a successful encyption of a file.

## TASK C
### Data Decryption

The fucntion C, as the name reveals, decrypts a cipher text according, also, to a key and 
bitmode. OpenSSL has already implemented fucntions for this task. Our sequence is a creation
a cipher content {EVP_CIPHER_CTX_new()} and decryption as we update this CTX with given file
{EVP_DecryptInit_ex() with bitmode 128 or 256, EVP_DecryptUpdate() and finally, EVP_DecryptFinal_ex() }

## TASK D
### Data Signing (CMAC)
The purpose of this function is to produce a CMAC (Cipher-based Message Authentication Code).
The CMAC is basically a code that we use for extra protection in our messages and works
as said in assignment. The functions which belongs to this routine are CMAC_Init() with 
the correct bitmode, CMAC_Update(), CMAC_Final().

## TASK E
### Data Verification (CMAC)
This function takes two unsigned char arrays and compare them with strcmp, nothing 
too special. The output of this function( TRUE or FALSE) is whether or not the produced CMAC and 
the CMAC obtained from the received message are equal.



## TASK F
### Using the tool
( 1 ) successful encryption
./assign_2 -i encryptme_256.txt -o decryptme_256.txt -p TUC2016030038 -b 256 -e

( 2 ) successful decryption
./assign_2 -i hpy414_decryptme_128.txt -o hpy414_encryptme_128.txt -p hpy414 -b 128 -d

( 3 )signed the file with success
./assign_2 -i signme_128.txt -o verifyme_128.txt -p TUC2016030038 -b 128 -s

( 4 ) Veryfication of files
a) 128 bits
./assign_2 -i hpy414_verifyme_128.txt -o hry414_verifyme_128_D.txt -p hry414 -b 128 -v
b) 256 bits
./assign_2 -i hpy414_verifyme_256.txt -o hry414_verifyme_256_D.txt -p hry414 -b 256 -v
  Both files' Verification is FALSE.
