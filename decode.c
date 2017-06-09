#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define NTOH2(x) (((x << 8) & 65280) + (x >> 8))
#define NTOH3(x) ((int) x[0] << 16) | ((int) (x[1]) << 8) | ((int) (x[2]))
#define NTOH4(x) ((int) x[0] << 24) | ((int) (x[1]) << 16) | ((int) (x[2]) <<  8) | ((int) (x[3]))

char * zergBreed(int breedType);
long unsigned swap32(long unsigned val);
char * commandOption(int instruction);

typedef struct PcapFileHeader {
	uint32_t magicNumber;  // File_Type_ID
	uint16_t majorVersion; // Major_Version
	uint16_t minorVersion;  // Minor_Version
	uint32_t thisZone;  // GMT Offset
	uint32_t timestampAcc;  // Accuracy Delta
	uint32_t captureLength; // Maximum Length of a Capture
	uint32_t linklayerType;   //Link Layer Type


} TOPHEADER; 

typedef struct PcapPacketHeader {
	uint32_t unixEpoch;
	uint32_t usFromEpoch;
	uint32_t lengthDataCaptured;
	uint32_t untruncatedPacketLength;
} PACKETHEADER;

typedef struct EthernetFrame {
	uint16_t destMac[3];
	uint16_t sMac[3];
	uint16_t ethernetType; 
	
} ETHERNET;

typedef struct ipv4Header {
	uint8_t versionAndIHL;
	uint8_t dscpAndECN;
	uint16_t iptotalLength;
	uint16_t Identification;
	uint16_t flagstoFragmentoffset;
	uint16_t ttltoProtocol;
	uint16_t headerChecksum;
	uint32_t sourceIP;
	uint32_t destIP;
} IPHEADER;

typedef struct udpHeader {
	uint16_t sourcePort;
	uint16_t destPort;
	uint16_t Length; 
	uint16_t checksum;
}UDP;

typedef struct zergPacketHeader {
	uint8_t versionToType;
	uint8_t totalLength[3];
	uint16_t sourceZergID;
	uint16_t destinationZergID;
	//uint32_t sequenceID;  try to do it in an array instead conversino
	uint8_t sequenceID[4];
}ZERG;

typedef struct statusPayload { 
	uint8_t hitPoints[3];
	uint8_t armor;
	uint8_t maxHitPoints[3];
	uint8_t statusType;
	uint8_t speed[4];
}STATUSPAYLOAD;

typedef struct commandPayload {
	uint16_t commandField;
} COMMAND;



void main(int argc, char *argv[])
{
	TOPHEADER fileHeader;
	FILE *fp = fopen(argv[1], "r");
	if (fp == NULL){
		printf("file does not exist\n");
		exit(1);
	}
	fread(&fileHeader, sizeof(fileHeader), 1, fp);

	PACKETHEADER packet;
	fread(&packet, sizeof(packet), 1, fp);


	ETHERNET ether;
	fread(&ether, sizeof(ether), 1, fp);
	int len = ftell(fp);

	IPHEADER ip;
	int version;
	int ihl;
	uint8_t mask = 1;
	fread(&ip, sizeof(ip), 1, fp);
	ihl = ip.versionAndIHL & 0x0F;
	version =  ip.versionAndIHL >> 4;
	int ipLength = NTOH2(ip.iptotalLength);

	UDP udp;
	fread(&udp, sizeof(udp), 1, fp);

	ZERG zerg;
	fread(&zerg, sizeof(zerg), 1, fp);


	int zergSourceID = NTOH2(zerg.sourceZergID);
	int zergDestinationID = NTOH2(zerg.destinationZergID);
	int zergLength  = NTOH3(zerg.totalLength);
	int sequence = 	NTOH4(zerg.sequenceID);
	int messageLength = zergLength - 12;
	printf("Message length of zerg message %d\n", messageLength);
	int type = zerg.versionToType & 0xF;  // This is type of message
	int zergVersion = zerg.versionToType >> 4;  // This is version
	printf("Version: %d\n", zergVersion);

	STATUSPAYLOAD status;
	//if message type = 0  it is a message and can do this
	// This is the message payload branch
	printf("Sequence: %d\n", sequence);
	printf("From: %d\n", zergSourceID);
	printf("To: %d\n", zergDestinationID);
	printf("Ip total length %d\n", ipLength);
	//char * payloadLength = (char*) malloc((
	char * messagePayload;
	messagePayload = (char*) malloc((messageLength + 1) * sizeof(char));
	messagePayload[messageLength] = '\0';
	
	COMMAND command;
	uint16_t parameter1;
	uint8_t parameter2[4];

//	parameter1 = NTOH2(parameter1);
//	parameter2 = NTOH4(parameter2);
//	int space = 2;
	switch(type)
	{
		case 0:  //regular payload
			;
			//char * messagePayload; 
			//messagePayload = (char*) malloc((messageLength + 1) * sizeof(char));
			fread(messagePayload, messageLength, 1, fp);
			//messagePayload[messageLength] = '\0';
			//printf("From: %d\n", zergSourceID);
			//printf("To: %d\n", zergDestinationID);
			printf("%s\n", messagePayload);
			break;
		case 1:   //status payload
			;
			fread(&status, sizeof(status), 1, fp);
			fread(messagePayload, messageLength, 1, fp);
			printf("Status Type is %d\n", status.statusType);
			int statusType = status.statusType; 
			int speed = NTOH4(status.speed);
			int hitPoints = NTOH3(status.hitPoints);
			int maxhp = NTOH3(status.maxHitPoints);
			printf("Name    :%s\n", messagePayload); 
			printf("Hp      :%d/%d\n", hitPoints, maxhp);
			char * breed = zergBreed(statusType);
			printf("Name    :%s\n",  breed);
			printf("Armor   :%d\n", status.armor);
			printf("Speed   :%x\n", speed);
			break;
			//printf("name is: :%s", messagePayload);
		case 2: //command payload
			;
			fread(&command, sizeof(command), 1, fp);
			int commandNum = NTOH2(command.commandField);
			char * commandWord = commandOption(commandNum);
			printf("%s", commandWord);
			if(commandNum %2 == 0){
			// Command payload only 2 bytes instead of 8
				;

			}else{
				fread(&parameter1, sizeof(parameter1), 1, fp);
				fread(&parameter2, sizeof(parameter2), 1, fp);
				parameter1 = NTOH2(parameter1);
				int nParameter2 = NTOH4(parameter2);
				if(commandNum == 1){  //GOTO COMMAND
					printf("   %x  %d\n",  nParameter2, parameter1);
				}
				else if (commandNum == 3){ //RESERVED
					; // do nothing
				}
				else if (commandNum == 5){  
					if(parameter1 != 0){ //SETGROUP
						//True statement and should be ADD OR SUBTRACT
						printf("   %d ADD\n", nParameter2);
					}else{
						printf("   %x SUBTRACT\n", nParameter2);
					}
				
				}else{  //REPEAT COMMAND
					printf("   %d\n", nParameter2);
				}
			}
			break;
	}
	//free(messagePayload);
	fclose(fp);
	//free(messagePayload)
}



long unsigned swap32(long unsigned val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}


char * zergBreed(int breedType)
{
	char * word = {'\0'};
	switch(breedType)
	{
		case 0: 
			word = "Overmind";
			break;
		case 1:
			word = "Larva";
			break;
		case 2:
			word = "Cerebrate";
			break;
		case 3:
			word = "Overlord";
			break;
		case 4:
			word = "Queen";
			break;
		case 5:
			word = "Drone";
			break;
		case 6:
			word = "Zergling";
			break;
		case 7:
			word = "Lurker";
			break;
		case 8:
			word  = "Broodling";
			break;
		case 9:
			word = "Hydralisk";
			break;
		case 10:
			word = "Guardian";
			break;
		case 11:
			word = "Scourge";
			break;
		case 12:
			word = "Ultralisk";
			break;
		case 13:
			word = "Mutalisk";
			break;
		case 14:
			word = "Defiler";
			break;
		case 15:
			word = "Devourer";
			break;
	}
	return(word);
}

char * commandOption(int instruction){
	char * word = {'\0'};
	switch(instruction)
	{
		case 0:
			word = "GET_STATUS";
			break;
		case 1:
			word = "GOTO";
			break;
		case 2:
			word = "GET_GPS";
			break;
		case 3:
			word = "RESERVED";
			break;
		case 4:
			word = "RETURN";
			break;
		case 5:
			word = "SET_GROUP";
			break;
		case 6:
			word = "STOP";
			break;
		case 7:
			word = "REPEAT";
			break;
	}
	return(word);
}
