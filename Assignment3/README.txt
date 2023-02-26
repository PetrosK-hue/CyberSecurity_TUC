###################################################################

[ASSIGNMENT 3] Access Control Logging Tool
        KATSIBAS PETROS(2016030038)

###################################################################
MAKE FILE:
### $gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 
### $gcc acmonitor.c -o acmonitor
### $gcc test_aclog.c -o test_aclog
### LD_PRELOAD=./logger.so ./test_aclog
-----------------------------------------------------------
#### $make all
#### $make run
-----------------------------------------------------------

We successfully overwrote fopen and fwrite functions using "LD_PRELOAD" library, as said.
We fill our 'logging_file' with all 7 fields( UID,File name, Date,Timestamp, Access  type, Is-action-denied  flag, File  fingerprint) for every log had took place. We, also, follow the instructiosn for step 2( Access Control Log Monitoring tool ) and we create the log monitoring tool, "acmonitor.c" with the appropriate printing functions. Step 3 of assignment is about testing 
the above steps with functions 'list_file_modifications' and 'list_unauthorized_accesses' .

( gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0 )

