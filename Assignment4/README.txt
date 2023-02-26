###################################################################

[ASSIGNMENT 4] Asymmetric Encryption Tool in C
        KATSIBAS PETROS(2016030038)

###################################################################
MAKE FILE:

    make all            # gcc project
    make clean          # Clean Task files and executable demo.
    make keygen         # Generation of keys.
    make taskD          # Run the whole TASK D with the given files and keys.
    make taskD1         # Run the taskD1 Encrypt "hpy414_encryptme_pub.txt" using the hpy414_public.key.
    make taskD2         # Run the taskD2 Decrypt “hpy414_decryptme_pub.txt” using the hpy414_public.key.
    make taskD3         # Run the taskD3 Encrypt “hpy414_encryptme_priv.txt” using the hpy414_private.key.
    make taskD4         # Run the taskD4 Decrypt “hpy414_decryptme_priv.txt” using the hpy414_private.key.

(*All output files are located in Results folder. )

## Summary

Successful implementation of every assignment's Task. Generation of the prime
pool and return with the function sieve_of_eratosthenes one random prime from 
the prime pool each time the function is called (TASK A), implementation of 
read and write functions in order to read and write size_t and 
char types for input - output and key. (Task B and C) and ,finally, Successfully encrypted 
and decrypted all files( Task D).
