// Online C compiler to run C program online
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//original source from: https://github.com/NatteeSetobol/Etern-blue-Windows-7-Checker/blob/6db4d227566dd2bad02e8c780acb6748a55c9602/main.cpp

typedef unsigned short ushort;
typedef unsigned char uchar;

struct __attribute__((__packed__))net_bios
{
	uint32_t length;
};

struct __attribute__((__packed__))smb_header
{
	unsigned char protocol[4];
	unsigned char command;
	uint32_t smbError;
	unsigned char flag;
	ushort flag2;
	ushort PIDHigh;
	unsigned char securityFeature[8];
	ushort reserves;
	ushort tid;
	ushort pid;
	ushort uid;
	ushort mid;
};

struct __attribute__((__packed__)) Trans_Response
{
	unsigned char wordCount;
	ushort totalParameterCount;
	ushort totalDataCount;
	ushort maxParameterCount;
	ushort maxDataCount;
	unsigned char maxSetupCount;
	unsigned char reserved;
	ushort flags;
	uint32_t timeout;
	ushort reserved2;
	ushort parameterCount;
	ushort parameterOffset;
	ushort dataCount;
	ushort dataOffset;
	unsigned char setupCount;
	unsigned char reserved3;
	ushort unknown;
	ushort byteCount;
};

ushort  BigToLittleEndian(ushort bigEndian)
{
	uint32_t toUInt32 = 0;
	ushort result = 0;

	toUInt32 = (uint32_t) bigEndian;
	
	result =  (ushort) ( (uint32_t) (BigToLittleEndian(toUInt32) >> 16));

	return result; 
}

void hexDump(char *desc, void *addr, int len) 
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}


int main() {
    struct smb_header smbHeader = {};
	struct net_bios netBios = {};
	struct Trans_Response transResp = {};
	uint32_t packetTotalSize = 0;
	unsigned char packet[4178];
	struct net_bios *recv_netBios = NULL;
	struct smb_header *recv_smbHeader = NULL;
	uint32_t recvPacketSize = 0;
	void *recvPacket = NULL;
	uint32_t result = 0;
	ushort newMID = 0;

	smbHeader.protocol[0] = 0xFF;
	smbHeader.protocol[1] = 'S';
	smbHeader.protocol[2] = 'M';
	smbHeader.protocol[3] = 'B';

	smbHeader.command = 0x26;
	smbHeader.smbError = 0;
	smbHeader.flag = 0x18;
	smbHeader.flag2 = 0xc007;
	smbHeader.PIDHigh = 0;
	smbHeader.reserves = 0;
	smbHeader.tid = 0x0008;
	smbHeader.pid = 0xFFFE;
	smbHeader.uid = 0x0008;
	smbHeader.mid = 0xFFFF;

	transResp.wordCount = 0x0f;
	transResp.totalParameterCount = 0x00;
	transResp.totalDataCount  = 0x00;
	transResp.maxParameterCount = 0xffff;
	transResp.maxDataCount = 2048;
	transResp.maxSetupCount = 0x02;
	transResp.reserved = 0x00;
	transResp.flags = 0x00;
	transResp.timeout = 0xffffffff;
	transResp.reserved2 = 0x0000;
	transResp.parameterCount = 0x0;
	transResp.parameterOffset = 0x0;
	transResp.dataCount = 0;
	transResp.dataOffset = 0;
	transResp.setupCount = 1;
	transResp.reserved3 = 0;
	transResp.unknown = 0x23;
	transResp.byteCount = 0;


	packetTotalSize = sizeof(smbHeader) + sizeof(transResp);
	netBios.length = BigToLittleEndian(packetTotalSize);

	//packet = MemoryRaw(packetTotalSize+sizeof(netBios) );

	memcpy(packet,(void*) &netBios,sizeof(netBios));
	memcpy(packet+sizeof(netBios),(void*) &smbHeader,sizeof(smbHeader));
	memcpy(packet+sizeof(netBios)+sizeof(smbHeader),&transResp,sizeof(transResp));
	hexdump(packet, 4178, 0);
	
    return 0;
}
