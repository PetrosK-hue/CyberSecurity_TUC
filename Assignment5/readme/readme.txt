###################################################################

[ASSIGNMENT 5] Implementation of a Basic RANSOMWARE in C
        KATSIBAS PETROS(2016030038)

###################################################################

###################################################################
MAKE FILE:

    make all            # gcc project
    make clean          # Clean .txt files and executable demos.
COMMANDS:

    ./ransomware.sh -n <num_files>  # Creates a X .txt files.
    ./ransomware.sh -e              # Encrypts all .txt files.
    ./ransomware.sh -d              # Decrypts all .encrypt files.

    ./acmonitor -v (1)              # Prints all files-log entries created
                                    in last 20 minutes.
    ./acmonitor -e                  # Prints all .encrypted files.

## Summary 

In this assignment we were asked to develop a Ransomware in Bash script and 
to enrich the Access Control Monitor in order to detect it.

###Ransomware

Using COMMANDS above, ransomware creates a X number of files.tzt using our previous
test_aclog.c. In this way, we are able to capture this action in our logging_tool 
with the proper access_type=0. Another function of ransomware is to encrypt using 
the given openssl function all .txt files in our directory. Last operation is decryption
of all .encrypt files , again using given function of openssl library.

(/* Ransomware uses as default directory the directory that includes the bash script*/)

### Acmonitor

Then we enriched our implemented acmonitor.c with two more operations.
First function prints all files that have created in the last 20 minutes by using the 
information included in our logging_tool ( parsing time variables of entries).
Second function prints all encrypted files as their extension includes .encypt and by fopen64(),
used in openssl, the files are, also, captured in our logging_tool.


gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
    
