#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	FILE *fp = fopen(argv[1], "r");
	//if (fp == NULL){
	//	printf("file does not exist\n");
	//	exit(1);
	//}
	printf("this is file pointer name %s\n", argv[1]);
	int count = 4;
	char pcapArray[5][50];
	char line[100];
	char *word[10];
	int number[5];
	char * p;
	int x = 0;
	for (int i = 0; i < 4; i++){
		fgets(line, 100, fp);
		//line[strlen(line) - 1] = '\0';
		printf("this is line %s", line);
		strcpy(pcapArray[i], line);
		//strcpy(pcapArray[i], line);
		p = strtok(line, ":\n ");
		while(p != NULL){
			//printf("This is p %s\n", p);
			word[x] = p;
			printf("This is count of x %d \n", x);
			printf("Word sub I %s\n", word[x]);
			p = strtok(NULL, ":\n ");
			//number[x] = (int) p;
			x++;
		}
		if(strcmp(word[0], "Version")){
			printf("True");
		}

		
		//printf("This is array line %s\n", pcapArray[i]);
		//printf("This is word %s\n", word[x]);
		//printf("THis is number %d\n", number[i]);
	}
	fgets(line, 100, fp);
	printf("Line string --> %s", line);
	char key[100];
	char value[100];
	sscanf(line, "%s : %[^\n]s", key, value);
	printf("key value pair '%s'  '%s'", key, value);	
	
	//printf("This is character c %c", c);
}
