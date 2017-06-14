#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "PcapStructs.h"

#define HTON2(x) ((x >> 8) | (x << 8))
int main(int argc, char *argv[])
{
	FILE *fp = fopen(argv[1], "r");
	FILE *fp1 = fopen("sample.pcap", "w");
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
	int type;

	//save the value to the structure
	//char * magicNumber = "d4 c3 b2 a1";
	//printf("this is magic number ----> %s", magicNumber);
	//GETS FIRST FOUR LINES OF THE TXT FILE
	for (int i = 0; i < 4; i++){
		fgets(line, 100, fp);
		//line[strlen(line) - 1] = '\0';
		//printf("this is line %s", line);
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
	//	if(strcmp(word[0], "Version")){
	//		printf("True");
	//	}

		
		//printf("This is array line %s\n", pcapArray[i]);
		//printf("This is word %s\n", word[x]);
		//printf("THis is number %d\n", number[i]);
	}
	//printf("This is word[0] %s\n", pcapArray[0]);
	
	fgets(line, 100, fp);
	printf("Line string --> %s", line);
	char key[100];
	char value[100];
	char garbage[100];
	char buffer[20] ={'\0'};
	sscanf(pcapArray[0], "%s : %[^\n]s\n", garbage, buffer);
	//printf("This is version %s\n", buffer);
	//int version = atoi(buffer);
	//printf("ATOI version number ---> %x\n", version);
	sscanf(line, "%s : %[^\n]s\n", key, value);
	//sscanf(line, "%s : %s", key, value);
	//printf("key value pair %s  %s\n", key, value);
	//printf("%d\n", strlen(key));
	//printf("%d", strlen("Latitude"));
	// type of payload
	if(key[0] == 'M'){
		type = 0x10;
		
	}
	else if(key[0] == 'L'){
		type = 0x13;
	}
	//else if(key[0] ==               //for  command payload packet	
	else if(key[0] == 'N'){
		type = 0x11;
	}else{
		type = 0x12;
	}

	TOPHEADER fileHeader = (const TOPHEADER) {0};
	fileHeader.magicNumber = 0xa1b2c3d4;
	fileHeader.majorVersion = 0x0002;
	fileHeader.minorVersion = 0x0004;
	fileHeader.thisZone = 0x00000000;
	fileHeader.timestampAcc = 0x00000000;
	fileHeader.captureLength = 0x00000001;
	fileHeader.linklayerType = 0x00000001;
	//printf("This is fileheader %lx", fileHeader.magicNumber);
	//printf("This is fp1 %d", ftell(fp1));
	
	fwrite(&fileHeader, 1, sizeof(fileHeader), fp1);

	PACKETHEADER packet;
	packet.unixEpoch = 0x582b59dc;
	packet.usFromEpoch = 0x000701d2; 
	packet.lengthDataCaptured = 0x00000042; //for hello world
	packet.untruncatedPacketLength = 0x00000042; //these values will need to change later
	fwrite(&packet, 1, sizeof(packet), fp1);
	
	ETHERNET ethernet;
	ethernet.destMac[0] = 0xFFFF;
	ethernet.destMac[1] = 0x0000;
	ethernet.destMac[2] = 0x0000;
	ethernet.sMac[0] = 0x0000;
	ethernet.sMac[1] = 0x0000;
	ethernet.sMac[2] = 0x0000;
	ethernet.ethernetType = 0x0008;
	fwrite(&ethernet, 1, sizeof(ethernet), fp1);
	
	IPHEADER ipv4;
	ipv4.versionAndIHL = 0x45;
	ipv4.dscpAndECN = 0x00;
	ipv4.iptotalLength = 0x0000;
	ipv4.Identification = 0x0000;
	ipv4.flagstoFragmentoffset = 0x0000;
	ipv4.ttltoProtocol = 0x0000;
	ipv4.headerChecksum = 0x0000;
	ipv4.sourceIP = 0x00000000;
	ipv4.destIP = 0x00000000;
	fwrite(&ipv4, 1, sizeof(ipv4), fp1);

	UDP udp;
	udp.sourcePort = 0xeeee;
	udp.destPort = 0xa70e;
	udp.Length = 0x0000; //change later to real length
	udp.checksum = 0x0000;
	fwrite(&udp, 1, sizeof(udp), fp1);

	ZERG zergHeader;
	zergHeader.versionToType = type;
	printf("This is word %s\n", word[0]);
	//uint32_t sequenceNumber = atoi(word[3]);
	//printf("SequnceNum %d", sequenceNumber);
	//printf("Check\n");
	//buffer = {'\0'}
	sscanf(pcapArray[1], "%s : %[^\n]s\n", garbage, buffer); //sequence sscanf
	int sequence = atoi(buffer); 
	sscanf(pcapArray[2], "%s : %[^\n]s\n", garbage, buffer); //source ID sscanf
	//printf("This should be source buffer %s\n", buffer);
	uint16_t sourceID = HTON2(atoi(buffer));
	//printf("This is converted sourceID  %d", sourceID);
	//zergHeader = HTON2(atoi(buffer));
	sscanf(pcapArray[3], "%s : %[^\n]s\n", garbage, buffer);
	uint16_t destID = HTON2(atoi(buffer));
	
	//printf("Sequnce  %x and destid %x\n", sequence, destID);
	zergHeader.totalLength[0] = 0x00;
	zergHeader.totalLength[1] = 0x00;
	zergHeader.totalLength[2] = 0x00;
	zergHeader.sourceZergID = sourceID;
	zergHeader.destinationZergID = destID;
	uint8_t s1 = (sequence & 0xFF000000) >> 24; 
	uint8_t s2 = (sequence & 0xFF0000) >> 16;
	uint8_t s3 = (sequence & 0xFF00) >> 8;
	uint8_t s4 = sequence & 0xFF;

	zergHeader.sequenceID[0] = s1;
	zergHeader.sequenceID[1] = s2;
	zergHeader.sequenceID[2] = s3;
	zergHeader.sequenceID[3] = s4;	
	printf("sequence 1 %d, sequence 4 %d\n", s3, s4);
	//fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
	
	
	//printf("This is character c %c", c);
	// switch case statement for different payload types
	switch(type)
	{
		case 0x10:
			;
			char * messagePayload;
			messagePayload = (char *) malloc ((strlen(value) + 1) * sizeof(char));
			messagePayload[strlen(value) + 1] = '\0';
			int totalLength = strlen(value) + 12;
			uint8_t tLen1 = (totalLength & 0xFF0000) >> 16;
			uint8_t tLen2 = (totalLength & 0xFF00) >> 8;
			uint8_t tLen3 = (totalLength & 0xFF) ;
			zergHeader.totalLength[0] = tLen1;
			zergHeader.totalLength[1] = tLen2;
			zergHeader.totalLength[2] = tLen3;
			strcpy(messagePayload, value);
			fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
			fwrite(messagePayload, 1, strlen(value), fp1);
			break;
		//case 0x11:
		
		//case 0x12:
	
		//case 0x13:
	}

}
