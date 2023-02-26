CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = main.o rsa.o utils.o
LIBMATH = -lm 

TARGET = assign_4
TUC_AM = TUC2016030038

FILESPATH = ../files/
OUTPUTFILESPATH = ../results/

TASKD1FILE = hpy414_encryptme_pub.txt
TASKD2FILE = hpy414_decryptme_pub.txt
TASKD3FILE = hpy414_encryptme_priv.txt
TASKD4FILE = hpy414_decryptme_priv.txt

PUBLICKEY = hpy414_public.key
PRIVATEKEY = hpy414_private.key

TASKD1OUT = $(TUC_AM)_encrypted_pub.txt
TASKD2OUT = $(TUC_AM)_decrypted_pub.txt
TASKD3OUT = $(TUC_AM)_encrypted_priv.txt
TASKD4OUT = $(TUC_AM)_decrypted_priv.txt


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) $(DBG) -o $(TARGET) $(OBJFILES) $(LIBMATH)


keygen:
	./$(TARGET) -g $(GD)
taskD1:
	./$(TARGET) -i  $(FILESPATH)$(TASKD1FILE) -o $(OUTPUTFILESPATH)$(TASKD1OUT) -k  $(FILESPATH)$(PUBLICKEY) -e
taskD2:
	./$(TARGET) -i  $(FILESPATH)$(TASKD2FILE) -o $(OUTPUTFILESPATH)$(TASKD2OUT) -k  $(FILESPATH)$(PUBLICKEY) -d
taskD3:
	./$(TARGET) -i  $(FILESPATH)$(TASKD3FILE) -o $(OUTPUTFILESPATH)$(TASKD3OUT) -k  $(FILESPATH)$(PRIVATEKEY) -e
taskD4:
	./$(TARGET) -i  $(FILESPATH)$(TASKD4FILE) -o $(OUTPUTFILESPATH)$(TASKD4OUT) -k  $(FILESPATH)$(PRIVATEKEY) -d

taskD: taskD1 taskD2 taskD3 taskD4

clean:
	rm -f $(TARGET) *.o
	rm -rf $(OUTPUTFILESPATH)*
