#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "PcapStructs.h"

#define HTON2(x) ((x >> 8) | (x << 8))

int ZergType(char * name);

union Data{
	int i;
	float f;
};

union Data64{
	double f;
	uint8_t i;
};

int main(int argc, char *argv[])
{
	FILE *fp = fopen(argv[1], "r");
	FILE *fp1 = fopen(argv[2], "w");
	if(argc > 3){
		printf("To many arguments");
		exit(1);
	}
	if (fp == NULL){
		printf("file does not exist\n");
		exit(1);
	}
	
	int count = 4;
	char pcapArray[5][50];
	char line[100], fifthLine[100];
	char *word[10];
	int number[5];
	char * p;
	int x = 0;
	int type;

	//GETS FIRST FOUR LINES OF THE TXT FILE
	for (int i = 0; i < 4; i++){
		fgets(line, 100, fp);
		strcpy(pcapArray[i], line);
		p = strtok(line, ":\n ");
		
	}
	fgets(fifthLine, 100, fp);
	char key[100];
	char value[100];
	char garbage[100];
	char buffer[20] ={'\0'};
	sscanf(pcapArray[0], "%s : %[^\n]s\n", garbage, buffer);
	sscanf(fifthLine, "%s : %[^\n]s\n", key, value);  // 5th line of the code
	if(key[0] == 'M'){
		type = 0x10;
		
	}
	else if(key[0] == 'L'){
		type = 0x13;
	}
	               //for  command payload packet	
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
	sscanf(pcapArray[1], "%s : %[^\n]s\n", garbage, buffer); //sequence sscanf
	int sequence = atoi(buffer); 
	sscanf(pcapArray[2], "%s : %[^\n]s\n", garbage, buffer); //source ID sscanf
	//printf("This should be source buffer %s\n", buffer);
	uint16_t sourceID = HTON2(atoi(buffer));
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
	
	
	int StatusPayloadLength = 0;
	int totalLength = 0;
	uint8_t tLen1 = 0, tLen2 = 0, tLen3 = 0;
	char * messagePayload;
	STATUSPAYLOAD status;
	union Data FloatToBin;  //union declaration
	union Data64 data64;
	char buffer1[20] = {'\0'};
	float bufferF = 0.0;
	int bufferA, bufferB;
	uint16_t bufferUint;
	COMMAND	command;
	uint8_t parameter2[4]; 
	uint16_t parameter1;
	switch(type)
	{
		case 0x10:
			;
			messagePayload = (char *) malloc ((strlen(value) + 1) * sizeof(char));
			messagePayload[strlen(value) + 1] = '\0';
			totalLength = strlen(value) + 12;
			tLen1 = (totalLength & 0xFF0000) >> 16;
			tLen2 = (totalLength & 0xFF00) >> 8;
			tLen3 = (totalLength & 0xFF);
			zergHeader.totalLength[0] = tLen1;
			zergHeader.totalLength[1] = tLen2;
			zergHeader.totalLength[2] = tLen3;
			strcpy(messagePayload, value);
			fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
			fwrite(messagePayload, 1, strlen(value), fp1);
			break;
		case 0x11:
			;
			StatusPayloadLength = strlen(value) + 12;
			totalLength = StatusPayloadLength + 12;
			tLen1 = (totalLength & 0xFF0000) >> 16;
			tLen2 = (totalLength & 0xFF00) >> 8;
			tLen3 = (totalLength & 0xFF);
			messagePayload = (char *) malloc ((strlen(value) + 1) * sizeof(char));
			messagePayload[strlen(value) + 1] = '\0';
			strcpy(messagePayload, value);
			zergHeader.totalLength[0] = tLen1;
			zergHeader.totalLength[1] = tLen2;
			zergHeader.totalLength[2] = tLen3;
			sscanf(fifthLine, "%s : %d/%d", garbage, &bufferA, &bufferB);
			uint8_t hp1 = (bufferA & 0xFF0000) >> 16;
			uint8_t hp2 = (bufferA & 0xFF00) >> 8;
			uint8_t hp3 = (bufferA & 0xFF);
			status.hitPoints[0] = hp1;
			status.hitPoints[1] = hp2;
			status.hitPoints[2] = hp3;
			uint8_t mhp1 = (bufferB & 0xFF0000) >> 16;
			uint8_t mhp2 = (bufferB & 0xFF00) >> 8;
			uint8_t mhp3 = (bufferB & 0xFF);
			status.maxHitPoints[0] = mhp1;
			status.maxHitPoints[1] = mhp2;
			status.maxHitPoints[2] = mhp3;
			fgets(line, 100, fp); //Get zerg name fgets
			sscanf(line, "%s : %[^\n]s\n", garbage, buffer);
			
			status.statusType = ZergType(buffer);
			fgets(line, 100, fp); //armor FGETS
			sscanf(line, "%s : %d\n", garbage, &bufferA);
			status.armor = bufferA;

			fgets(line, 100, fp);
			sscanf(line, "%s : %fm/s", garbage, &bufferF);
			FloatToBin.f = bufferF;
			uint8_t speed1 = (FloatToBin.i >> 24);
			uint8_t speed2 = (FloatToBin.i >> 16);
			uint8_t speed3 = (FloatToBin.i >> 8);
			uint8_t speed4 = (FloatToBin.i & 0xFF);
			status.speed[0] = speed1;
			status.speed[1] = speed2;
			status.speed[2] = speed3;
			status.speed[3] = speed4;
			fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
			fwrite(&status, 1, sizeof(status), fp1);
			fwrite(messagePayload, 1, strlen(value), fp1);
			break;
			
		case 0x12:
			;
			uint8_t param1, param2, param3, param4;
			uint16_t commandNum = 0;
			if(strcmp(key, "GET_STATUS") == 0){  //commandnum = 0
				commandNum = 0;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 2;
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				fwrite(&command, 1, sizeof(command), fp1); 
				
				
			}
			else if(strcmp(key, "GOTO") == 0){  // commandNum = 1
				commandNum = 1;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 8;
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				sscanf(fifthLine, "%s %f %hu", garbage, &bufferF, &bufferUint );
				FloatToBin.f = bufferF;
				param1 = (FloatToBin.i & 0xFF000000) >> 24;
				param2 = (FloatToBin.i & 0xFF0000) >> 16;
				param3 = (FloatToBin.i & 0xFF00) >> 8;
				param4 = (FloatToBin.i & 0xFF);
				parameter2[0] = param1;
				parameter2[1] = param2;
				parameter2[2] = param3;
				parameter2[3] = param4;
				parameter1 = HTON2(bufferUint);
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				fwrite(&command, 1, sizeof(command), fp1);
				fwrite(&parameter1, 1, sizeof(parameter1), fp1);
				fwrite(&parameter2, 1, sizeof(parameter2), fp1);
			}
			else if(strcmp(key, "GET_GPS") == 0){ // commandNum = 2
				commandNum = 2;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 2;
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				fwrite(&command, 1, sizeof(command), fp1);
				
			}
			else if(strcmp(key, "RESERVED") == 0){  // commandNum = 3
				commandNum = 3;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 8;
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				fwrite(&command, 1, sizeof(command), fp1);
			}
			else if(strcmp(key, "RETURN") == 0){  //commandNum = 4
				commandNum = 4;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 2;
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				fwrite(&command, 1, sizeof(command), fp1);

			}
			else if(strcmp(key, "SET_GROUP") == 0){  // commandNum = 5
				commandNum = 5;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 8;
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				//fgets(line, 100, fp);
				sscanf(fifthLine, "%s %f %s", garbage, &bufferF, buffer);
				if(strcmp(buffer, "ADD") == 0){
					bufferUint = 1;
				}else{
					bufferUint = 0;
				}
				parameter1 = HTON2(bufferUint);
				FloatToBin.f = bufferF;
				param1 = (FloatToBin.i & 0xFF000000) >> 24;
				param2 = (FloatToBin.i & 0xFF0000) >> 16;
				param3 = (FloatToBin.i & 0xFF00) >> 8;
				param4 = (FloatToBin.i & 0xFF);
				parameter2[0] = param1;
				parameter2[1] = param2;
				parameter2[2] = param3;
				parameter2[3] = param4;
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				fwrite(&command, 1, sizeof(command), fp1);
				fwrite(&parameter1, 1, sizeof(parameter1), fp1);
				fwrite(&parameter2, 1, sizeof(parameter2), fp1); 
				
			}
			else if(strcmp(key, "STOP") == 0){  //commandNum = 6
				commandNum = 6;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 2;
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				fwrite(&command, 1, sizeof(command), fp1);
			}else{  // commandNum = 7
				commandNum = 7;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 2;  
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				//fgets(line, 100, fp);
				sscanf(fifthLine, "%s %f", garbage, &bufferF);
				FloatToBin.f = bufferF;
				param1 = (FloatToBin.i & 0xFF000000) >> 24;
				param2 = (FloatToBin.i & 0xFF0000) >> 16;
				param3 = (FloatToBin.i & 0xFF00) >> 8;
				param4 = (FloatToBin.i & 0xFF);
				parameter2[0] = param1;
				parameter2[1] = param2;
				parameter2[2] = param3;
				parameter2[3] = param4;
				parameter1 = 0;
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				fwrite(&command, 1, sizeof(command), fp1);
				fwrite(&parameter1, 1, sizeof(parameter1), fp1);
				fwrite(&parameter2, 1, sizeof(parameter2), fp1);
				
			}
			break;
		case 0x13:
				;
				uint64_t buffer64;
				commandNum = 8;
				command.commandField = HTON2(commandNum);
				totalLength = 12 + 8;
				tLen1 = (totalLength & 0xFF0000) >> 16;
				tLen2 = (totalLength & 0xFF00) >> 8;
				tLen3 = (totalLength & 0xFF);
				zergHeader.totalLength[0] = tLen1;
				zergHeader.totalLength[1] = tLen2;
				zergHeader.totalLength[2] = tLen3;
				parameter1 = 0;
				char latitude[30];
				sscanf(fifthLine, "%s : %s", garbage, latitude);

				char longitude[30];
				fgets(line, 100, fp);
				sscanf(line, "%s : %s", garbage, longitude);
				
				char altitude[30];
				fgets(line, 100, fp);
				sscanf(line, "%s : %s", garbage, altitude);

				char bearing[30];
				fgets(line, 100, fp);
				sscanf(line, "%s : %s", garbage, bearing);
	
				char speed[10];
				fgets(line, 100, fp);
				sscanf(line, "%s : %s", garbage, speed);

				char accuracy[10];
				fgets(line, 100, fp);
				sscanf(line, "%s : %s", garbage, accuracy);
			
				//buffer64 = atof(latitude);
				//FloatToBin.f = buffer64;
				fwrite(&zergHeader, 1, sizeof(zergHeader), fp1);
				//fwrite(&command, 1, sizeof(command), fp1);
				//fwrite(&parameter1, 1, sizeof(parameter1), fp1);
				//fwrite(&parameter2, 1, sizeof(parameter2), fp1);
				break;
	}
}

int ZergType(char * name)
{
	int type = 0;
	if(strcmp(name, "Overmind") == 0){
		type = 0;
	}
	else if(strcmp(name, "Larva") == 0){
		type = 1;
	}
	else if(strcmp(name, "Cerebrate") == 0){
		type = 2;
	}
	else if(strcmp(name, "Overlord") == 0){
		type = 3;
	}
	else if(strcmp(name, "Queen") == 0){
		type = 4;
	}
	else if(strcmp(name, "Drone") == 0){
		type = 5;
	}
	else if(strcmp(name, "Zergling") == 0){
		type = 6;
	}
	else if(strcmp(name, "Lurker") == 0){
		type = 7;
	}
	else if(strcmp(name, "Broodling") == 0){
		type = 8;
	}
	else if(strcmp(name, "Hydralisk") == 0){
		type = 9;
	}
	else if(strcmp(name, "Guardian") == 0){
		type = 10;
	}
	else if(strcmp(name, "Scourge") == 0){
		type = 11;
	}
	else if(strcmp(name, "Ultralisk") == 0){
		type = 12;
	}
	else if(strcmp(name, "Mutalisk") == 0){
		type = 13;
	}
	else if(strcmp(name, "Defiler") == 0){
		type = 14;
	}else{
		type = 15;
	}
	return(type);
}
