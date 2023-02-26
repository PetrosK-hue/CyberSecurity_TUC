#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <assert.h>

#define MD5_HASH 32
int get_number_of_lines(FILE *);
char *read_line(FILE *);
int user_id_exists_in_array(int, int *, int);
int filename_exists_in_array(char *, char filenames[][10], int);
int string_ends_with(char *str, char *suffix);

void list_unauthorized_accesses(FILE *log);
void list_file_modifications(FILE *log, char *file_to_scan);

void print_files_created(FILE *log, int files_created);
void print_files_encrypted(FILE *log);

struct entry
{

	int uid;		   /* user id (positive integer) */
	int access_type;   /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file;		   /* filename (string) */
	char *fingerprint; /* file fingerprint */
	char *path;
	/* add here other fields if necessary */
	struct tm tm;
};
void parse_data(FILE *log, struct entry **entries, int lines);

void usage(void)
{
	printf(
		"\n"
		"usage:\n"
		"\t./acmonitor \n"
		"Options:\n"
		"-m, Prints malicious users\n"
		"-i <filename>, Prints table of users that modified "
		"the file <filename> and the number of modifications\n"
		"-v <number of files>, Prints the total number of files\n"
		"created in the last 20 minutes\n"
		"-e, Prints all the files that were encrypted by the ransomware\n"
		"-h, Help message\n\n");

	exit(1);
}

void list_unauthorized_accesses(FILE *log)
{
	/* add your code here */
	// Get logfile number of lines
	int lines;
	lines = get_number_of_lines(log);

	// Declare array of entries
	// struct entry entry[lines];
	struct entry *entries = malloc(sizeof(struct entry) * lines);
	// Parse logfile data to struct
	parse_data(log, &entries, lines);

	// Find and print malicious users
	int denied_access_counter = 0;
	int user_id = 0;
	int i, j;

	int *malicious_users = malloc(lines * sizeof *malicious_users); // Array to store checked malicious users
	memset(malicious_users, 0x00, lines);
	char filenames[lines][10]; // Array to store checked filenames
	memset(filenames, 0, sizeof(filenames[0][0]) * lines * 10);
	int events_recorded_flag = 0; // To decide if security events occured
	printf("-----   Malicious Users:   -----.\n");
	for (j = 0; j < lines; j++)
	{
		user_id = entries[j].uid;
		for (i = 0; i < lines; i++)
		{
			if ((entries[i].action_denied == 1) && (user_id == entries[i].uid) && (filename_exists_in_array(entries[i].file, filenames, lines) == 0))
			{
				strcpy(filenames[i], entries[i].file);
				denied_access_counter = denied_access_counter + 1;
			}
		}

		if ((denied_access_counter > 7) && (user_id_exists_in_array(user_id, malicious_users, lines) == 0))
		{
			malicious_users[j] = user_id;
			events_recorded_flag = 1;
			printf("  Malicious User [%d] caught accessing [%d] files \n", user_id, denied_access_counter);
		}

		memset(filenames, 0, sizeof(filenames[0][0]) * lines * 10);
		denied_access_counter = 0;
	}
	if (events_recorded_flag == 0)
	{
		printf(" No Malicious Users Found! \n");
	}
	free(entries);
	free(malicious_users);
	return;
}

void list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */

	// Get logfile number of lines
	int lines;
	lines = get_number_of_lines(log);

	// Declare array of entries
	// struct entry entry[lines];
	struct entry *entries = malloc(sizeof(struct entry) * lines);

	// Parse logfile data to struct
	parse_data(log, &entries, lines);

	// Find users that modified the given file
	int user_id = 0;

	int i, j;

	int *users = malloc(lines * sizeof *users);
	memset(users, 0x00, lines);

	int modification_counter = 0;

	int prev_action_denied;

	char curr_fingerprint[33];
	memset(&curr_fingerprint, 0x00, 33);

	char prev_fingerprint[33];
	memset(&prev_fingerprint, 0x00, 33);

	printf("    FILE: %18s Modifications.       \n", file_to_scan);
	printf("|   User ID     |   Number of Modifications  |\n");
	printf("----------------------------------------------------");

	int print_flag = 0;

	for (j = 0; j < lines; j++)
	{
		user_id = entries[j].uid;

		for (i = 0; i < lines; i++)
		{
			if (((strcmp(entries[i].file, file_to_scan)) == 0) && (entries[i].action_denied == 0) && (user_id == entries[i].uid))
			{
				strcpy(curr_fingerprint, entries[i].fingerprint);

				if ((strcmp(curr_fingerprint, prev_fingerprint) != 0) && (entries[i].access_type == 2))
				{
					modification_counter = modification_counter + 1;
				}

				strcpy(prev_fingerprint, curr_fingerprint);
			}
		}
		if (user_id_exists_in_array(user_id, users, lines) == 0)
		{
			users[j] = user_id;

			if (modification_counter > 0)
			{
				print_flag = 1;
				printf("|   %d     |    %d       |\n", user_id, modification_counter);
				printf("----------------------------------------------------");
			}

			if (modification_counter == 0)
			{
				print_flag = print_flag + 1;

				if (print_flag == 1)
				{
					printf("No user modified this file.\n");
				}
			}
		}
		modification_counter = 0;
	}
	int file_exists = 0;
	for (i = 0; i < lines; i++)
	{
		if (strcmp(file_to_scan, entries[i].file) == 0)
		{
			file_exists = 1;

			break;
		}
	}
	if (file_exists == 0)
		printf("File does not exist\n");

	free(entries);
	free(users);
	return;
}

void print_files_created(FILE *log, int files_created)
{
	// Get logfile number of lines
	int lines;
	lines = get_number_of_lines(log);
	// Declare array of entries
	// struct entry entry[lines];
	struct entry *entries = malloc(sizeof(struct entry) * lines);

	// Parse logfile data to struct
	parse_data(log, &entries, lines);

	int files_created_counter = 0;

	time_t t = time(NULL);
	struct tm tm2;
	tm2 = *localtime(&t);
	for (int i = 0; i < lines; i++)
	{
		// Valid Creation
		if ((entries[i].access_type == 0) && (entries[i].action_denied == 0))
		{
			// Current month and year case
			if ((entries[i].tm.tm_mon == (tm2.tm_mon + 1)) && (entries[i].tm.tm_year == (tm2.tm_year + 1900)))
			{	//same day
				if (entries[i].tm.tm_mday == tm2.tm_mday)
				{	//same hour
					if (entries[i].tm.tm_hour == tm2.tm_hour)
					{
						if ((tm2.tm_min - entries[i].tm.tm_min >= 0) && (tm2.tm_min - entries[i].tm.tm_min <= 20))
						{
							files_created_counter = files_created_counter + 1;
						}
					}
					//different hour 
					else if (entries[i].tm.tm_hour == tm2.tm_hour - 1)
					{
						if (((-59 <= tm2.tm_min - entries[i].tm.tm_min) && (tm2.tm_min - entries[i].tm.tm_min <= -40)) || (tm2.tm_min - entries[i].tm.tm_min == 0))
						{
							files_created_counter = files_created_counter + 1;
						}
					}
				}
				// mid-night case
				else if (entries[i].tm.tm_mday == tm2.tm_mday - 1)
				{
					if (tm2.tm_hour == entries[i].tm.tm_hour - 23)
					{
						if (((-59 <= tm2.tm_min - entries[i].tm.tm_min) && (tm2.tm_min - entries[i].tm.tm_min <= -40)) || (tm2.tm_min - entries[i].tm.tm_min == 0))
						{
							files_created_counter = files_created_counter + 1;
						}
					}
				}
			}
		}
	}
	if (files_created_counter >= files_created)
		printf(" %d files were created in the last 20 minutes \n", files_created_counter);

	else
		printf("No file created in the last 20 minutes \n");
}

void print_files_encrypted(FILE *log)
{
	// Get logfile number of lines
	int lines;
	lines = get_number_of_lines(log);

	// Declare array of entries
	// struct entry entry[lines];
	struct entry *entries = malloc(sizeof(struct entry) * lines);

	// Parse logfile data to struct
	parse_data(log, &entries, lines);
	int i;

	int encrypted_files_counter = 0;

	for (i = 0; i < lines - 2; i++)
	{

		if ((string_ends_with(entries[i].file, "encrypt")) && (entries[i].access_type == 2))
		{
			encrypted_files_counter = encrypted_files_counter + 1;
			printf(" %s \n", entries[i].path);
		}
	}

	if (encrypted_files_counter == 0)
		printf("No files encrypted!\n");

	free(entries);
	return;
}

int main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL)
	{
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:v:em")) != -1)
	{
		switch (ch)
		{
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'v':
			print_files_created(log, atoi(optarg));
			break;
		case 'e':
			print_files_encrypted(log);
			break;
		default:
			usage();
		}
	}
	/* add your code here */

	fclose(log);
	argc -= optind;
	argv += optind;

	return 0;
}

int get_number_of_lines(FILE *fp)
{
	int lines = 0;
	char c;

	for (c = getc(fp); c != EOF; c = getc(fp))
	{
		if (c == '\n')
		{
			lines = lines + 1;
		}
	}

	rewind(fp);

	return lines;
}

char *read_line(FILE *fp)
{

	char *line_buffer = NULL;
	size_t len = 0;
	ssize_t read;

	if (fp == NULL)
	{
		exit(EXIT_FAILURE);
	}

	getline(&line_buffer, &len, fp);

	return line_buffer;
}

int user_id_exists_in_array(int user_id, int *malicious_users, int lines)
{
	int i;
	for (i = 0; i < lines; i++)
	{
		if (malicious_users[i] == user_id)
		{
			return 1;
		}
	}
	return 0;
}

int filename_exists_in_array(char *filename, char filenames[][10], int lines)
{
	int i;

	for (i = 0; i < lines; i++)
	{
		if (strcmp(filenames[i], filename) == 0)
		{
			return 1;
		}
	}

	return 0;
}
// Find .ecrypt files.
int string_ends_with(char *fileName, char *extension)
{
	if (strlen(fileName) > strlen(extension) + 2)
	{
		char ext[256];
		sprintf(ext, ".%s", extension);
		return strcmp(fileName + strlen(fileName) - strlen(ext), ext) == 0 ? 1 : 0;
	}
	return 0;
}
// Using our logging_tool information.
void parse_data(FILE *log, struct entry **entries, int lines)
{
	char *line_buffer;

	int i;

	for (i = 0; i < lines; i++)
	{
		line_buffer = read_line(log);

		char *temp;

		// Parse uid
		(*entries)[i].uid = atoi(strsep(&line_buffer, "\t"));

		// Parse path
		(*entries)[i].path = strsep(&line_buffer, "\t");

		// Parse filename
		(*entries)[i].file = basename((*entries)[i].path);

		// Parse date
		temp = strsep(&line_buffer, "\t");

		// Split date to integers
		(*entries)[i].tm.tm_mday = atoi(strsep(&temp, "/"));
		(*entries)[i].tm.tm_mon = atoi(strsep(&temp, "/"));
		(*entries)[i].tm.tm_year = atoi(strsep(&temp, "/"));

		// Parse time
		temp = strsep(&line_buffer, "\t");

		// Split time to integers
		(*entries)[i].tm.tm_hour = atoi(strsep(&temp, ":"));
		(*entries)[i].tm.tm_min = atoi(strsep(&temp, ":"));
		(*entries)[i].tm.tm_sec = atoi(strsep(&temp, ":"));

		// Parse access type
		(*entries)[i].access_type = atoi(strsep(&line_buffer, "\t"));

		// Parse action denied flag
		(*entries)[i].action_denied = atoi(strsep(&line_buffer, "\t"));

		// Parse fingerprint
		(*entries)[i].fingerprint = strsep(&line_buffer, "\t");
	}
}