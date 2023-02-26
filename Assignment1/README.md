###################################################################

[ASSIGNMENT 1] OTP/CAESAR'S/VIGENERE'S CIPHERS 
        KATSIBAS PETROS(2016030038)

###################################################################

MAKE FILE:
### $gcc -g simple_crypto.c -c
### $gcc demoprogram.c -c
### $gcc simple_crypto.o demoprogram.o -o demoprogram
-----------------------------------------------------------
#### $make
#### $./demoprogram 
-----------------------------------------------------------

## [OTP] ONE TIME PAD CIPHER
Simple cryptographic tool implemented in C using a random generated key(different per run) and "XOR-ing" each char of user's input string.
For the generation of the random key we were asked:
1) To save the key, so decryption takes place.
2) To use /dev/random, that uses Linux Library by opening file as implemented in simple_crypto.c

In order to prevent our program to generate and calculate unprintable ASCII charachters, we limited our key to be within 33 and 126 and for XOR we recalculated each char with modulo and addition of 33(maximum and minimum printable ASCII charachters).
We also used a implementation by Programmiz to prenent our user's input to include special charachters beyond aA-zZ and 0-9 by swapping-removing them.(I tried with C-functions isdigit() and isalpha() but i couldn't make it work properly.)

## CAESAR'S CIPHER
Caesar's cipher is also a simple cryptographic tool that takes a buffer (String) and displace by 4(in our case) each charachter.
Again, we prevent both user's input from including special chars as in OTP cipher and encrypted result from including un-printable ASCII chars.

## VIGENERE'S CIPHER
Vinegere's cipher is a TOUPPER() cipher (only CAPS) and corresponds a alphabetic letter subject to charachters of user's input and secret key. To function properly, we have to extend our charachter-key to the same length of our input. Then, we add extended key with our string and we 'mod' our result. The last step is to add ASCII[65] so we have a A-Z shift.

### OUR RESULTS (AS ASKED)
#### [OTP] input: secret 
#### [OTP] encrypted: vWN|NR  
#### [OTP] decrypted secret
#### [Caesars] input: hello
#### [Caesars] key: 4 
#### [Caesars] encrypted: lipps
#### [Caesars] decrypted: hello
#### [Vigenere] input: ATTACKATDAWN
#### [Vigenere] key: LEMON
#### [Vigenere] encrypted: LXFOPVEFRNHR
#### [Vigenere] Extended key: LEMONLEMONLE
#### [Vigenere] decrypted: ATTACKATDAWN

( gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0 )

