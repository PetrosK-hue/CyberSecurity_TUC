#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MD5_HASH 32

struct entry
{

	int uid;		   /* user id (positive integer) */
	int access_type;   /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file;		   /* filename (string) */
	char *fingerprint; /* file fingerprint */
};

struct access
{
	int data;
	int key;
	struct access *accnext;
};
struct access *headacc = NULL;
struct access *acccurrent = NULL;

// show list
void printAccessList()
{
	struct access *acc = headacc;
	printf("List of all Accesses:\n");

	// start from the beginning
	while (acc != NULL)
	{
		printf("User ID: %d | Times: %d\n", acc->key, acc->data);
		acc = acc->accnext;
	}
}

// insert link at the first location
void insertAccessFirst(int key, int data)
{
	// create a link
	struct access *link = (struct access *)malloc(sizeof(struct access));

	link->key = key;
	link->data = data;

	// point it to old first node
	link->accnext = headacc;

	// point first to new first node
	headacc = link;
}

// find a link with given key
struct access *findAccess(int key)
{

	// start from head
	struct access *current_acc = headacc;

	// if empty
	if (headacc == NULL)
	{
		return NULL;
	}

	// slide list
	while (current_acc->key != key)
	{

		// if last node
		if (current_acc->accnext == NULL)
		{
			return NULL;
		}
		else
		{
			// next link
			current_acc = current_acc->accnext;
		}
	}
	// if data found, return the current Link
	return current_acc;
}
// delete a link with given key
struct access *deleteAccess(int key)
{

	// start from head
	struct access *current_acc = headacc;
	struct access *previous_acc = NULL;

	// if empty
	if (headacc == NULL)
	{
		return NULL;
	}
	// slide list
	while (current_acc->key != key)
	{

		// if last node
		if (current_acc->accnext == NULL)
		{
			return NULL;
		}
		else
		{
			// save to current link
			previous_acc = current_acc;
			// go to next link
			current_acc = current_acc->accnext;
		}
	}

	// found a match, update the link
	if (current_acc == headacc)
	{
		// change first to point to next link
		headacc = headacc->accnext;
	}
	else
	{
		// bypass the current link
		previous_acc->accnext = current_acc->accnext;
	}

	return current_acc;
}
// ---------- MALICIOUS USERS ----------------
/* Linked list that contains potential malicious users */
struct node
{
	int data;
	int key;
	char files[8][FILENAME_MAX];
	struct node *next;
};

struct node *head = NULL;
struct node *current = NULL;

// display the list
void printList()
{
	struct node *ptr = head;
	printf("Malicious Users:\n");
	// start from the beginning
	while (ptr != NULL)
	{
		if (ptr->data > 7)
			printf("%d\n", ptr->key);
		ptr = ptr->next;
	}
}

// delete a link with given key
struct node *delete_node(int key)
{

	// start from the first link
	struct node *current = head;
	struct node *previous = NULL;

	// if list is empty
	if (head == NULL)
	{
		return NULL;
	}

	// navigate through list
	while (current->key != key)
	{

		// if it is last node
		if (current->next == NULL)
		{
			return NULL;
		}
		else
		{
			// store reference to current link
			previous = current;
			// move to next link
			current = current->next;
		}
	}

	// found a match, update the link
	if (current == head)
	{
		// change first to point to next link
		head = head->next;
	}
	else
	{
		// bypass the current link
		previous->next = current->next;
	}

	return current;
}
// insert link at the first location
void insertFirst(int key, int data, char *file)
{
	// create a link
	struct node *link = (struct node *)malloc(sizeof(struct node));

	link->key = key;
	link->data = data;
	memcpy(link->files[0], file, FILENAME_MAX);

	// point it to old first node
	link->next = head;

	// point first to new first node
	head = link;
}
void insertList(int key, int data, char *file)
{
	// create a link
	struct node *link = (struct node *)malloc(sizeof(struct node));

	if (data < 9)
	{
		link = delete_node(key);

		link->key = key;
		link->data = data;
		memcpy(link->files[data], file, FILENAME_MAX);

		// point it to old first node
		link->next = head;

		// point first to new first node
		head = link;
	}
}
// find a link with given key
struct node *find(int key)
{

	// start from the first link
	struct node *current = head;

	// if list is empty
	if (head == NULL)
	{
		return NULL;
	}

	// navigate through list
	while (current->key != key)
	{

		// if it is last node
		if (current->next == NULL)
		{
			return NULL;
		}
		else
		{
			// go to next link
			current = current->next;
		}
	}

	// if data found, return the current Link
	return current;
}

void usage(void)
{
	printf(
		"\n"
		"usage:\n"
		"\t./monitor \n"
		"Options:\n"
		"-m, Prints malicious users\n"
		"-i <filename>, Prints table of users that modified "
		"the file <filename> and the number of modifications\n"
		"-h, Help message\n\n");

	exit(1);
}

void list_unauthorized_accesses(FILE *log)
{

	/* add your code here */
	/* Read file line by line */
	char *line = NULL;
	char path[0xFFF];
	size_t len = 0;
	ssize_t read;
	int uid, is_action_denied, denied_times, file_in_list;
	file_in_list = 0;
	if (log == NULL)
		exit(EXIT_FAILURE);
	while ((read = getline(&line, &len, log)) != -1)
	{
		/* Split line and get uid and action-denied-flag */
		uid = atoi(strtok(line, " "));
		memcpy(path, strtok(NULL, " "), FILENAME_MAX);
		for (int i = 1; i < 7; i++)
			strtok(NULL, " "); // We don't care for these elements
		is_action_denied = atoi(strtok(NULL, " "));
		/* Check if uid is already on the list */
		if (is_action_denied == 1)
		{
			struct node *foundLink = find(uid);
			if (foundLink == NULL)
			{
				denied_times = 1;
				insertFirst(uid, denied_times, path); // Insert uid with 1 denied time
			}
			else
			{
				denied_times = foundLink->data; // Save current denied times
				for (int i = 0; i < 8; i++)
				{
					if (strcmp(foundLink->files[i], " ") && !strcmp(path, foundLink->files[i]))
					{
						file_in_list = 1;
					}
				}
				if (file_in_list == 0)
					insertList(uid, denied_times + 1, path);
			}
		}
	}
	printList();

	if (line)
		free(line);
	return;
}

void list_file_modifications(FILE *log, char *file_to_scan)
{
	/* add your code here */
	char *line, *file_name = NULL;
	char hash[MD5_HASH];
	char prev_hash[MD5_HASH];
	char path[0xFFF];
	size_t len = 0;
	ssize_t read;
	int uid, is_action_denied, accessed, file_mode;

	if (log == NULL)
		exit(EXIT_FAILURE);

	while ((read = getline(&line, &len, log)) != -1)
	{
		/* Split line and get uid and action-denied-flag */
		uid = atoi(strtok(line, " "));
		memcpy(path, strtok(NULL, " "), FILENAME_MAX);
		for (int i = 1; i < 6; i++)
			strtok(NULL, " "); // We don't care for these elements
		file_mode = atoi(strtok(NULL, " "));
		is_action_denied = atoi(strtok(NULL, " "));
		memcpy(hash, strtok(NULL, " "), MD5_HASH);
		/* If hash is changed and is_action_denied == 0 */
		if (strncmp(hash, prev_hash, MD5_HASH) && file_mode == 3 && !is_action_denied && !strcmp(file_to_scan, path))
		{
			memcpy(prev_hash, hash, MD5_HASH);
			/* Add to users list */
			struct node *foundLink = findAccess(uid);
			if (foundLink == NULL)
			{
				accessed = 1;
				insertAccessFirst(uid, accessed); // Insert uid with 1 denied time
			}
			else
			{
				accessed = foundLink->data;			  // Save current denied times
				deleteAccess(uid);					  // Delete Older Access
				insertAccessFirst(uid, accessed + 1); // Insert Element with updated denied times
			}
		}
	}
	printAccessList();

	if (line)
		free(line);

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

	while ((ch = getopt(argc, argv, "hi:m")) != -1)
	{
		switch (ch)
		{
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
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
