#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


long unsigned swap32(long unsigned val);

typedef struct PcapFileHeader {
	uint32_t magicNumber;  // File_Type_ID
	uint16_t majorVersion; // Major_Version
	uint16_t minorVersion;  // Minor_Version
	uint32_t thisZone;  // GMT Offset
	unsigned long timestampAcc;  // Accuracy Delta
	unsigned long captureLength; // Maximum Length of a Capture
	unsigned long linklayerType;   //Link Layer Type
	uint64_t gmtoffsetToAccuracyDelta;
	uint32_t maxLengthCapture;

} TOPHEADER; 

typedef struct PcapPacketHeader {
	unsigned long unixEpoch;
	unsigned long usFromEpoch;
	unsigned long lengthDataCaptured;
	unsigned long untruncatedPacketLength;
	uint64_t unixepochusfromEPOCH;
} PACKETHEADER;

typedef struct EthernetFrame {
	unsigned long destMac1;
	unsigned short destMac2;
	unsigned long sMac1;
	unsigned short sMac2;
	unsigned short ethernetType;
	// fseek for another 16 bytes  
	
} ETHERNET;

typedef struct ipv4Header {
	uint8_t versionAndIHL;
	uint8_t dscpAndECN;
	uint16_t iptotalLength;
	uint64_t IdtoHeaderChecksum;
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
	uint16_t totalLength; 
	uint8_t totalLength1;
	uint16_t destinationZergID;
	uint16_t sourceZergID;
	uint32_t sequenceID;
	uint32_t payload;
}ZERG; 


void main()
{
	//printf("lu", sizeof(TOPHEADER);
	TOPHEADER fileHeader;
	FILE *fp = fopen("/home/jvoigt/share/capstone_1/pcaps/hello.pcap", "r");
	if (!fp)
		printf("File, doesn't exist");
	fread(&(fileHeader.magicNumber), 4, 1, fp);
	printf("%x\n", fileHeader.magicNumber); // need to reverse endianness
	
	fread(&(fileHeader.majorVersion), 2, 1, fp);
	printf("%x\n", fileHeader.majorVersion); // need to reverse endianess

	fread(&(fileHeader.minorVersion), 2, 1, fp);
	//printf("%x\n", fileHeader.minorVersion);
	fread(&(fileHeader.gmtoffsetToAccuracyDelta), 8, 1, fp);
	fread(&(fileHeader.maxLengthCapture), 4, 1, fp);
	fread(&(fileHeader.linklayerType), 4, 1, fp);
	printf("Link Layer Type -----> %lx\n", fileHeader.linklayerType);
	
	PACKETHEADER packet;
	fread(&(packet.unixepochusfromEPOCH), 8, 1, fp);
	fread(&(packet.lengthDataCaptured), 4, 1, fp);
	printf("Length Data captured ---- > %lx\n", packet.lengthDataCaptured);
	fread(&(packet.untruncatedPacketLength), 4, 1, fp); 
	
	ETHERNET ether;
	fread(&(ether.destMac1), 4, 1, fp);
	fread(&(ether.destMac2), 2, 1, fp);
	fread(&(ether.sMac1), 2, 1, fp);
	fread(&(ether.sMac2), 4, 1, fp);
	fread(&(ether.ethernetType), 2, 1, fp);
	printf("Ethernet Type -----> %x\n", ether.ethernetType);
//	fseek(fp ,2, SEEK_CUR);
	int len = ftell(fp);
	printf("place in code ---> %d", len);

	IPHEADER ip;
	int version[4];
	int ihl[4];
	uint8_t mask = 1;
	fread(&(ip.versionAndIHL), 1, 1, fp);
	for(int i = 0; i < 8; i++){
		if (i < 4){
			ihl[i] = ip.versionAndIHL & mask;
			mask <<= 1;
		}else{
			version[i-4] = ip.versionAndIHL & mask;
			mask <<= 1;
		}
	}
	printf("This is version\n");
	for(int i = 0; i < 4; i++){
		printf("%d", version[i]);
	}
	putchar('\n');
	printf("Ip version and IHL ----> %x\n", ip.versionAndIHL);
	fread(&(ip.dscpAndECN), 1, 1, fp);
	fread(&(ip.iptotalLength), 2, 1, fp);
	printf("Ip total length ----> %x\n", ip.iptotalLength);
	fread(&(ip.IdtoHeaderChecksum), 8, 1, fp);
	fread(&(ip.sourceIP), 4, 1, fp);
	fread(&(ip.destIP), 4, 1, fp);

	UDP udp;
	fread(&(udp.sourcePort), 2, 1, fp);
	fread(&(udp.destPort), 2, 1, fp);
	printf("UDP dest port ----> %x\n", udp.destPort);
	fread(&(udp.Length), 2, 1, fp);
	printf("udp length -----> %x\n", udp.Length);
	fread(&(udp.checksum), 2, 1, fp);

	ZERG zerg;
	fread(&(zerg.versionToType), 1, 1, fp);
	printf("Version and type\n");
	printf("%x\n", zerg.versionToType);
	fread(&(zerg.totalLength), 2, 1, fp);
	fread(&(zerg.totalLength1), 1, 1, fp);
	printf("Total length: ");
	printf("%x\n", zerg.totalLength1);
	fread(&(zerg.sourceZergID), 2, 1, fp);
	printf("%x\n", zerg.sourceZergID);
	fread(&(zerg.destinationZergID), 2, 1, fp);
	printf("%x\n", zerg.destinationZergID);
	fread(&(zerg.sequenceID), 4, 1, fp);
	fread(&(zerg.payload), 4, 1, fp);
	printf("%x\n", zerg.payload);
	fclose(fp);
}



long unsigned swap32(long unsigned val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}
