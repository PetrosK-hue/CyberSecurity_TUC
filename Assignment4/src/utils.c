#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
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
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}

/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
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

/*
 * Prints the usage message
 */
void usage(void)
{
	printf(
		"\n"
		"Usage:\n"
		"    assign_3 -g \n"
		"    assign_3 -i in_file -o out_file -k key_file [-d | -e]\n"
		"    assign_3 -h\n");
	printf(
		"\n"
		"Options:\n"
		" -i    path    Path to input file\n"
		" -o    path    Path to output file\n"
		" -k    path    Path to key file\n"
		" -d            Decrypt input and store results to output\n"
		" -e            Encrypt input and store results to output\n"
		" -g            Generates a keypair and saves to 2 files\n"
		" -h            This help message\n");
	exit(EXIT_FAILURE);
}

/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void check_args(char *input_file, char *output_file, char *key_file, int op_mode)
{
	if ((!input_file) && (op_mode != 2))
	{
		printf("Error: No input file!\n");
		usage();
	}

	if ((!output_file) && (op_mode != 2))
	{
		printf("Error: No output file!\n");
		usage();
	}

	if ((!key_file) && (op_mode != 2))
	{
		printf("Error: No user key!\n");
		usage();
	}

	if (op_mode == -1)
	{
		printf("Error: No mode\n");
		usage();
	}
}

unsigned char *read_file(char *input_file)
{
	FILE *fp;
	unsigned char *buffer = NULL;
	size_t len;

	fp = fopen(input_file, "rb+");
	if (fp == NULL)
	{
		// abort if file cannot be opened
		printf("Cannot open file..OUPS\n");
		exit(-1);
	}
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buffer = (unsigned char *)calloc(len, sizeof(unsigned char));
	if (NULL == buffer)
	{
		exit(1);
	}

	if (fread(buffer, 1, len, fp))
	{
		fclose(fp);
		return buffer;

		free(buffer);
		buffer = NULL;
	}
	else
	{
		//read failure & exit
		exit(1);
	}
}

int get_file_length(char *input_file)
{
	FILE *fp;
	size_t len;

	fp = fopen(input_file, "rb+");
	if (fp == NULL)
	{
		// abort if file cannot be opened
		printf("Cannot open file..OUPSLENGTH");
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	fclose(fp);

	return len;
}

void write_to_file(char *output_file, size_t a, size_t b)
{
	FILE *fp = fopen(output_file, "wb+");

	if (fp == NULL)
	{
		printf("Cannot open file..WRI\n");
		exit(1);
	}
	// Write key
	fwrite(&a, sizeof(size_t), 1, fp);
	// fseek(fp, 0, SEEK_END);
	fwrite(&b, sizeof(size_t), 1, fp);

	// Close File
	fclose(fp);
	fp = NULL;
}

void write_cipher_to_file(char *output_file, unsigned char *ciphertext, int ciphertext_len)
{

	FILE *fp = fopen(output_file, "wb+");

	if (fp == NULL)
	{
		printf("Cannot open...WRITE cipher\n");
		exit(1);
	}

	fwrite(ciphertext, 1, ciphertext_len, fp);
	// Close File
	fclose(fp);
	fp = NULL;
}

void write_plaintext_to_file(char *output_file, unsigned char *plaintext, int plaintext_len)
{

	FILE *fp = fopen(output_file, "wb+");
	if (fp == NULL)
	{
		printf("Cannot open file..Plaint\n");
		exit(1);
	}

	// Write Buffer
	fwrite(plaintext, 1, plaintext_len, fp);
	// Close File
	fclose(fp);
	fp = NULL;
}
