#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define NTOH2(x) (((x << 8) & 65280) + (x >> 8))
#define NTOH3(x) ((int) x[0] << 16) | ((int) (x[1]) << 8) | ((int) (x[2]))
#define NTOH4(x) ((int) x[0] << 24) | ((int) (x[1]) << 16) | ((int) (x[2]) <<  8) | ((int) (x[3]))

long unsigned swap32(long unsigned val);

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



void main(int argc, char *argv[])
{
	TOPHEADER fileHeader;
	FILE *fp = fopen(argv[1], "r");
	if (fp == NULL){
		printf("file does not exist");
		exit(1);
	}
	fread(&fileHeader, sizeof(fileHeader), 1, fp);
//	printf("%x\n", fileHeader.magicNumber);
//	printf("%x\n", fileHeader.majorVersion);
//	printf("Link Layer Type -----> %x\n", fileHeader.linklayerType);
//	printf("This is fp of file header %ld\n", ftell(fp));	

	PACKETHEADER packet;
//	printf("This is size of packet header %ld", sizeof(packet));
	fread(&packet, sizeof(packet), 1, fp);
//	printf("Length Data captured ---- > %x\n", packet.lengthDataCaptured);
	
	ETHERNET ether;
//	printf("File pointer of ethernet %ld\n", ftell(fp));
//	printf("size of ethernet %ld", sizeof(ether));
	fread(&ether, sizeof(ether), 1, fp);
//	printf("Ethernet Type -----> %x\n", ether.ethernetType);
	int len = ftell(fp);
//	printf("place in code ---> %d", len);

//	printf("location of ip header pointer %ld", ftell(fp));
	IPHEADER ip;
	int version;
	int ihl;
	uint8_t mask = 1;
	fread(&ip, sizeof(ip), 1, fp);
	ihl = ip.versionAndIHL & 0x0F;
	version =  ip.versionAndIHL >> 4;
//	printf("This is ihl\n");
//	printf("THis is  IHL ---> %d", ihl);
//	printf("This is version ---> %d", version);
	putchar('\n');
//	printf("Ip version and IHL ----> %x\n", ip.versionAndIHL);
//	printf("Ip total length ----> %x\n", ip.iptotalLength);
//	printf("THis is filepointer at ipheader %ld\n", ftell(fp));
//	printf("offsets of version and IHL %ld\n", (long) offsetof(IPHEADER, versionAndIHL));
//	printf("Offsets of dscp and ECN %ld\n", (long) offsetof(IPHEADER, dscpAndECN));
//	printf("offsets of ip total length %ld\n", (long) offsetof(IPHEADER, iptotalLength));
//	printf("offsets of identification %ld\n", (long) offsetof(IPHEADER, Identification));
//	printf("offsets of flags to fragment %ld\n", (long) offsetof(IPHEADER, flagstoFragmentoffset));
//	printf("offsets of source ip address %ld\n", (long) offsetof(IPHEADER, sourceIP));

	UDP udp;
//	printf("This is size of udp %ld\n", sizeof(udp));
//	printf("FP location %ld\n", ftell(fp));
	fread(&udp, sizeof(udp), 1, fp);
//	printf("FP location %ld\n", ftell(fp));
//	printf("UDP dest port ----> %x\n", udp.destPort);
//	printf("udp length -----> %x\n", udp.Length);


	ZERG zerg;
//	printf("fp at end of UDP is at %ld\n", ftell(fp));
//	printf("Size of Zerg %ld\n", sizeof(zerg));
	fread(&zerg, sizeof(zerg), 1, fp);
//	printf("fp after you read zerg is at %ld\n", ftell(fp));
//	printf("Version and type of ZERG \n");
//	printf("%x\n", zerg.versionToType);
//	printf("Total length: ");
//	printf("THis is source--->%x\n", zerg.sourceZergID);
//	printf("This is destination ----> %x\n", zerg.destinationZergID);
//	printf("This is file pointer before message----> %ld\n", ftell(fp));
	
//	printf("This is zerg total 0 %d, zerg at 1 %d, zerg at 2 %d", zerg.totalLength[0], zerg.totalLength[1], zerg.totalLength[2]);
	int zergSourceID = NTOH2(zerg.sourceZergID);
	int zergDestinationID = NTOH2(zerg.destinationZergID);
	int zergLength  = NTOH3(zerg.totalLength);
	int sequence = 	NTOH4(zerg.sequenceID);
	int messageLength = zergLength - 12;
	
	int type = zerg.versionToType & 0xF;  // This is type of message
	int zergVersion = zerg.versionToType >> 4;  // This is version
	printf("Version: %d\n", zergVersion);

	//if message type = 0  it is a message and can do this
	// This is the message payload branch
	switch(type)
	{
		case 0:
			;
			char * messagePayload; 
			messagePayload = (char*) malloc((messageLength + 1) * sizeof(char));
			fread(messagePayload, messageLength, 1, fp);
			messagePayload[messageLength] = '\0';
			printf("Sequence: %d\n", sequence);
			printf("From: %d\n", zergSourceID);
			printf("To: %d\n", zergDestinationID);
			//printf("Sequence: %d\n", sequence);
			printf("%s\n", messagePayload);
	}	 
	fclose(fp);
}



long unsigned swap32(long unsigned val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}
