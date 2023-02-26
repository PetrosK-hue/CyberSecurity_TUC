#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16

/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t);
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *,
			unsigned char *, int);
int decrypt(unsigned char *, int, unsigned char *, unsigned char *,
			unsigned char *, int);
int gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);
int concat(unsigned char *, int, unsigned char *, int, unsigned char *);
void get_encrypted_message (unsigned char * plaintext,int plaintext_len, unsigned char * chunk,int chunk_length, unsigned char * new_cmac,int new_cmac_length);

/* TODO Declare your function prototypes here... */

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else
	{
		for (i = 0; i < len; i++)
		{
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}
/*
 * Prints the input as string
 */
void print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else
	{
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}
/*Read file*/

int read_file(char *input_file, unsigned char *plaintext)
{
	int size = 0;
	FILE *fp = fopen(input_file, "rb");

	// Return if could not open file
	if (fp == NULL)
	{
		return 0;
	}
	do
	{
		plaintext[size] = fgetc(fp);

		if (feof(fp))
		{
			break;
		}
		size++;
	} while (1);

	fclose(fp);
	return size;
}
void write_file(char *output_file, unsigned char *ciphertext, int ciphertext_length)
{

	FILE *fpointer = fopen(output_file, "w");
	for (int i = 0; i < ciphertext_length; i++)
	{
		fputc(ciphertext[i], fpointer);
	}

	fclose(fpointer);
}

/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void usage(void)
{
	printf(
		"\n"
		"Usage:\n"
		"    assign_2 -i in_file -o out_file -p passwd -b bits"
		" [-d | -e | -s | -v]\n"
		"    assign_2 -h\n");
	printf(
		"\n"
		"Options:\n"
		" -i    path    Path to input file\n"
		" -o    path    Path to output file\n"
		" -p    psswd   Password for key generation\n"
		" -b    bits    Bit mode (128 or 256 only)\n"
		" -d            Decrypt input and store results to output\n"
		" -e            Encrypt input and store results to output\n"
		" -s            Encrypt+sign input and store results to output\n"
		" -v            Decrypt+verify input and store results to output\n"
		" -h            This help message\n");
	exit(EXIT_FAILURE);
}

/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void check_args(char *input_file, char *output_file, unsigned char *password,
				int bit_mode, int op_mode)
{
	if (!input_file)
	{
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file)
	{
		printf("Error: No output file!\n");
		usage();
	}

	if (!password)
	{
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256))
	{
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1)
	{
		printf("Error: No mode\n");
		usage();
	}
}

/*
 * Generates a key using a password
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
			int bit_mode)
{
	if (bit_mode == 128)
	{
		EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha1(), NULL, password, strlen((const char *)password), 1, key, iv);
	}
	else if (bit_mode == 256)
	{
		EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), NULL, password, strlen((const char *)password), 1, key, iv);
	}
}

/*
 * Encrypts the data
 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
			unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{

	/* TODO Task B */
	int ciphertext_len;
	EVP_CIPHER_CTX *ctx;
	int len;

	/* Create and initialise the context */
	ctx = EVP_CIPHER_CTX_new();

	if (bit_mode == 128)
	{
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
	}
	else if (bit_mode == 256)
	{
		EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
	}

	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
	ciphertext_len = len;

	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
			unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len, len;

	plaintext_len = 0;
	EVP_CIPHER_CTX *ctx;

	/*TODO Task C */
	/* Create and initialise the context */
	ctx = EVP_CIPHER_CTX_new();

	if (bit_mode == 128)
	{
		EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
	}
	else if (bit_mode == 256)
	{
		EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
	}

	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

	plaintext_len = len;

	// Finalise the decryption.

	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

/*
 * Generates a CMAC
 */
int gen_cmac(unsigned char *data, size_t data_len, unsigned char *key,
			 unsigned char *cmac, int bit_mode)
{
	/* TODO Task D */
	size_t mactlen;

	CMAC_CTX *ctx = CMAC_CTX_new();
	if (bit_mode == 128)
	{
		CMAC_Init(ctx, key, bit_mode/8, EVP_aes_128_ecb(), NULL);
	}
	else if (bit_mode == 256)
	{

		CMAC_Init(ctx, key, bit_mode/8, EVP_aes_256_ecb(), NULL);
	}
	CMAC_Update(ctx, data, sizeof(data));

	CMAC_Final(ctx, cmac, &mactlen);

	CMAC_CTX_free(ctx);
	return strlen((char *)(cmac));
}
// Copying N bytes Function
int concat(unsigned char *a, int cmac_length, unsigned char *b, int ciphertext_length, unsigned char *concat)
{
	int lena = cmac_length;
	int lenb = ciphertext_length;
	
	memcpy(concat, a, lena);
	memcpy(concat + lena, b, lenb + 1);
	return lena + lenb;
}

/*
 * Verifies a CMAC
 */
void get_encrypted_message(unsigned char *plaintext, int plaintext_len, unsigned char *chunk, int chunk_length, unsigned char *new_cmac, int new_cmac_length)
{

	int j = 0;
	for (int i = 0; i < plaintext_len; i++)
	{
		if (i <= plaintext_len - BLOCK_SIZE - 1)
		{
			chunk[i] = plaintext[i];
		}
		else if (i > plaintext_len - BLOCK_SIZE - 1)
		{
			new_cmac[j] = plaintext[i];
			j = j + 1;
		}
	}
}
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;

	/* TODO Task E */
	verify = strcmp((const char *)cmac1, (const char *)cmac2);
	if (verify == 0)
	{
		printf("TRUE\n");
	}
	else if (verify != 1)
	{
		printf("FALSE\n");
	}

	return verify;
}

/* TODO Develop your functions here... */

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int main(int argc, char **argv)
{
	int opt;				 /* used for command line arguments */
	int bit_mode;			 /* defines the key-size 128 or 256 */
	int op_mode;			 /* operation mode */
	char *input_file;		 /* path to the input file */
	char *output_file;		 /* path to the output file */
	unsigned char *password; /* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;

	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1)
	{
		switch (opt)
		{
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	/* TODO Develop the logic of your tool here... */

	/* encrypt */
	if (op_mode == 0)
	{
		unsigned char *plaintext = (unsigned char *)malloc(sizeof(unsigned char) * 4096);
		/* Read input file containing plaintext and store to plaintext length*/
		int plaintext_len = read_file(input_file, plaintext);
		/*malloc for key*/
		unsigned char *key;
		/* Operate on the data according to the mode */
		key = (unsigned char *)malloc(sizeof(unsigned char) * bit_mode);
		/*Call key gen*/
		keygen(password, key, NULL, bit_mode);

		/* encrypt */
		/*malloc for cipher text*/
		unsigned char *ciphertext;
		ciphertext = (unsigned char *)malloc(sizeof(unsigned char) * plaintext_len + BLOCK_SIZE);
		/*Call encrypt*/
		int ciphertext_length = encrypt(plaintext, plaintext_len, key, NULL, ciphertext, bit_mode);
		/*Write output file containing the cipher/encrypted message */
		write_file(output_file, ciphertext, ciphertext_length);
		/* Free the three mallocs*/
		free(plaintext);
		free(key);
		free(ciphertext);
	}
	/* decrypt */
	else if (op_mode == 1)
	{
		/*Read input file containing cipher/encrypted message */
		unsigned char *ciphertext = (unsigned char *)malloc(sizeof(unsigned char) * 4096);
		int ciphertext_len = read_file(input_file, ciphertext);
		/*Malloc for key*/
		unsigned char *key = (unsigned char *)malloc(sizeof(unsigned char) * bit_mode);
		keygen(password, key, NULL, bit_mode);
		/*Malloc plaintext */
		unsigned char *plaintext = malloc(sizeof(unsigned char) * ciphertext_len + BLOCK_SIZE);
		/*Call decrypt*/
		int plaintext_len = decrypt(ciphertext, ciphertext_len, key, NULL, plaintext, bit_mode);
		/*write plaintext to output file*/
		write_file(output_file, plaintext, plaintext_len);
		free(ciphertext);
		free(key);
		free(plaintext);
	}
	/* sign */
	else if (op_mode == 2)
	{
		/*malloc the plaintext*/
		unsigned char *data = (unsigned char *)malloc(sizeof(unsigned char) * 4096);
		/* Read input file containing plaintext and store to plaintext length*/
		int data_len = read_file(input_file, data);
		/*Key generation*/
		/*malloc for key*/
		unsigned char *key = (unsigned char *)malloc(sizeof(unsigned char) * bit_mode);
		/*Call key gen*/
		keygen(password, key, NULL, bit_mode);
		/*Mallloc cmac*/
		unsigned char *cmac = (unsigned char *)malloc(sizeof(unsigned char) * data_len + BLOCK_SIZE);
		/*Create cmac encrypted*/
		int cmac_length = gen_cmac(data, data_len, key, cmac, bit_mode);
		/*malloc for cipher text*/
		unsigned char *ciphertext;
		ciphertext = (unsigned char *)malloc(sizeof(unsigned char) * data_len + BLOCK_SIZE);
		/*Call encrypt*/
		int ciphertext_length = encrypt(data, data_len, key, NULL, ciphertext, bit_mode);
		/*Malloc size for con*/
		unsigned char *con = (unsigned char *)malloc(sizeof(unsigned char) * (cmac_length + ciphertext_length));
		/*Call concat function*/
		int concat_lenth = concat(ciphertext, ciphertext_length, cmac, cmac_length, con);
		/*write to file */
		write_file(output_file, con, concat_lenth);
		free(data);
		free(key);
		free(cmac);
		free(ciphertext);
		free(con);
	}
	/* verify */
	else if (op_mode == 3)
	{
		/*malloc the plaintext*/
		unsigned char *data = (unsigned char *)malloc(sizeof(unsigned char) * 4096);
		/* Read input file containing plaintext and store to plaintext length*/
		int data_len = read_file(input_file, data);
		/*Malloc size for chunk*/
		int chunk_length = 0;
		int new_cmac_length = 0;
		unsigned char *chunk = NULL;
		unsigned char *new_cmac = NULL;

		chunk = (unsigned char *)malloc(sizeof(unsigned char) * (data_len - 16));
		chunk_length = data_len - 16;
		new_cmac = (unsigned char *)malloc(sizeof(unsigned char) * (16));
		new_cmac_length = 16;

		get_encrypted_message(data, data_len, chunk, chunk_length, new_cmac, new_cmac_length);
		/*malloc for key*/
		unsigned char *key = (unsigned char *)malloc(sizeof(unsigned char) * bit_mode);
		/*Call key gen*/
		keygen(password, key, NULL, bit_mode);

		unsigned char *plaintext = malloc(sizeof(unsigned char) * chunk_length + BLOCK_SIZE);
		int plaintext_len = decrypt(chunk, chunk_length, key, NULL, plaintext, bit_mode);

		unsigned char *cmac = (unsigned char *)malloc(sizeof(unsigned char) * plaintext_len + BLOCK_SIZE + 1);
		/*Create cmac encrypted*/
		gen_cmac(plaintext, plaintext_len, key, cmac, bit_mode);
		// Verify
		if (verify_cmac(cmac, new_cmac) == 0)
		{
			write_file(output_file, plaintext, plaintext_len);
		}

		free(data);
		free(chunk);
		free(key);
		free(new_cmac);
		free(plaintext);
		free(cmac);
	}
	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	/* END */
	return 0;
}

