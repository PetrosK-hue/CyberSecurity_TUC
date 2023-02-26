all: logger acmonitor test_aclog

logger: logger.c
	gcc -g -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor
	#sudo chown root logger.so
	#sudo chmod 4577 logger.so

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog
	#sudo chown root logger.so
	#sudo chmod 4577 logger.so

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog
	#sudo chown root logger.so
	#sudo chmod 4577 logger.so
clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -f *.encrypt
	rm -f *.txt

