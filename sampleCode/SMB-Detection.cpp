//Original link: https://www.cxyzjd.com/article/fanwenbo/5790201

/*
Copyright statement: This article is the original article of the blogger and follows the CC 4.0 BY-SA copyright agreement. Please attach the link to the original source and this statement for reprinting.
Link to this article: https://blog.csdn.net/fanwenbo/article/details/5790201
*/

/*In the SMB protocol, during their conversation, Microsoft gave the specific version of the operating system in some special domains. This information can be used to monitor the Windows operating system.
Specifically, look at the following code, which defines the structure of some SMB protocols*/

// SMB.h: interface for the CSMB class.
//
//

#include <winsock2.h>
typedef unsigned char UCHAR; // 8 unsigned bits
typedef unsigned short USHORT; // 16 unsigned bits
typedef unsigned long ULONG; // 32 unsigned bits

#pragma pack (1)

typedef struct netbiosHeader
{
UCHAR Type; // Type of the packet
UCHAR Flags; // Flags
USHORT Length; // Count of data bytes (netbios header not included)
} NETBIOSHEADER,*PNETBIOSHEADER;

//4
//
///
///     SMB HEADER
///
//
typedef struct NegoRequestHead
{
UCHAR Protocol[4]; // Contains 0xFF,'SMB'
UCHAR Command; // Command code
union
{
   struct
   {
    UCHAR ErrorClass; // Error class
    UCHAR Reserved; // Reserved for future use
    USHORT Error; // Error code
   } DosError;
   ULONG Status; // 32-bit error code
} Status;
UCHAR Flags; // Flags
USHORT Flags2; // More flags
union
{
   USHORT Pad[6]; // Ensure section is 12 bytes long
   struct
   {
    USHORT PidHigh; // High part of PID
    ULONG Unused; // Not used
    ULONG Unused2;
   } Extra;
}pad;
USHORT Tid; // Tree identifier
USHORT Pid; // Caller's process id
USHORT Uid; // Unauthenticated user id
USHORT Mid; // multiplex id
// UCHAR WordCount; // Count of parameter words
// USHORT* ParameterWords; // The parameter words
// USHORT ByteCount; // Count of bytes
// UCHAR* Buffer; // The bytes
}NEGOREQUESTHEAD,*PNEGOREQUESTHEAD;
//32
//**************************************************************
//**********************END*************************************

 

 


//
///
///     SMB REQUEST HEADER
///
//
/*
struct RequestHead
{
UCHAR WordCount; //Count of parameter words = 0
USHORT ByteCount; //Count of data bytes
struct {
UCHAR BufferFormat; //0x02 -- Dialect
UCHAR DialectName[]; //ASCII null-terminated string
} Dialects[];
};  
*/
//**************************************************************
//**********************END*************************************


// Echo SMB HEADER

struct EchoSMBHeader
{
UCHAR WordCount; //Count of parameter words = 17
USHORT DialectIndex; //Index of selected dialect
UCHAR SecurityMode; //Security mode:
// bit 0: 0 = share, 1 = user
// bit 1: 1 = encrypt passwords
USHORT MaxMpxCount; //Max pending multiplexed requests
USHORT MaxNumberVcs; //Max VCs between client and server
ULONG MaxBufferSize; //Max transmit buffer size
ULONG MaxRawSize; //Maximum raw buffer size
ULONG SessionKey; //Unique token identifying this session
ULONG Capabilities; //Server capabilities
ULONG SystemTimeLow; //System (UTC) time of the server (low).
ULONG SystemTimeHigh; //System (UTC) time of the server (high).
USHORT ServerTimeZone; //Time zone of server (min from UTC)
UCHAR EncryptionKeyLength;// Length of encryption key.
USHORT ByteCount; //Count of data bytes
//UCHAR EncryptionKey[]; The challenge encryption key
//UCHAR OemDomainName[]; The name of the domain (in OEM chars)
}; //37

//REQUEST DATA HEADER
struct RequestData
{
UCHAR WordCount; //Count of parameter words = 13
UCHAR AndXCommand; //Secondary (X) command; 0xFF = none
UCHAR AndXReserved;// Reserved (must be 0)
USHORT AndXOffset; //Offset to next command WordCount
USHORT MaxBufferSize; //Client's maximum buffer size
USHORT MaxMpxCount; //Actual maximum multiplexed pending requests
USHORT VcNumber; //0=first (only),nonzero=additional VC number
ULONG SessionKey; //Session key (valid iff VcNumber != 0)
USHORT CaseInsensitivePasswordLength; //Account password size, ANSI
USHORT CaseSensitivePasswordLength; //Account password size, Unicode
ULONG Reserved; //must be 0
ULONG Capabilities; //Client capabilities
USHORT ByteCount; //Count of data bytes; min = 0
// UCHAR CaseInsensitivePassword[]; Account Password, ANSI
// UCHAR CaseSensitivePassword[]; Account Password, Unicode
// STRING AccountName[]; Account Name, Unicode
// STRING PrimaryDomain[]; Client's primary domain, Unicode
// STRING NativeOS[]; Client's native operating system, Unicode
// STRING NativeLanMan[]; Client's native LAN Manager type, Unicode
};
//29

//DATA Each
struct EchoData
{
UCHAR WordCount; //Count of parameter words = 3
UCHAR AndXCommand; //Secondary (X) command; 0xFF = none
UCHAR AndXReserved; //Reserved (must be 0)
USHORT AndXOffset; //Offset to next command WordCount
USHORT Action; //Request mode: bit0 = logged in as GUEST
USHORT ByteCount; //Count of data bytes
// STRING NativeOS[]; //Server's native operating system
// STRING NativeLanMan[]; Server's native LAN Manager type
// STRING PrimaryDomain[]; Server's primary domain
}; //9


class CSMB  
{
private:
CString szComputerName;
CString szIP;
WSADATA wsaData;
struct sockaddr_in name;
struct sockaddr_in local;

void Convert(char* buf);
ULONG sessionKey;
UCHAR securityMode;
int   s;

public:  
bool InitSocket();
int SendNBSS();
bool RecvNBSS();
int SendNegotiate();
bool RecvNegotiate();
int SendSesssetupX();
bool RecvSesssetupX();
HANDLE hEvent;

CSMB(CString strIP,CString szComuputerName);
virtual ~CSMB();
CString szNativeOS;
CString szNativeLM;
CString szDomain;
void DoSMBScan();
DWORD static BeginScan(LPVOID smb1);
};

#endif // !defined(AFX_SMB_H__29408F98_890D_4CE5_A284_55985EA816AF__INCLUDED_)

 

 

In the specific SMB protocol, we need the following steps:
1) Initialize the Socket
2) Send Netbios information
3) SMB negotiation process
4) Send the process of establishing a handshake

// SMB.cpp: implementation of the CSMB class.
//
//

#include "stdafx.h"
#include <windows.h>
#include "NetScan.h"
#include "SMB.h"

#define SMB_PORT 139

#include <winsock2.h>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//
// Construction/Destruction
//
#define PC_NETWORK_PROGRAM_10 "/x02PC NETWORK PROGRAM 1.0/0"
#define MICROSOFT_NETWORKS_103 "/x02MICROSOFT NETWORKS 1.03/0"
#define MICROSOFT_NETWORKS_30     "/x02MICROSOFT NETWORKS 3.0/0"
#define LANMAN10      "/x02LANMAN1.0/0"
#define LM12       "/x02LM1.2X002/0"
#define SANBA       "/x02SAMBA/0"
#define NTLM012       "/x02NT LM 0.12/0"
#define NTLANMAN10      "/x02NT LANMAN 1.0/0"

#define DOMAIN      "WORKGROUP/0"
#define NATIVEOS     "Unix/0"
#define NATIVELANMAN    "Samba/0"


CSMB::CSMB(CString strIP,CString strComputerName)
{
this->szComputerName = strComputerName;
szIP = strIP;
szDomain = _T("");
szNativeOS = _T("");
szNativeLM = _T("");
hEvent = CreateEvent(NULL,true,false,NULL);
}

bool CSMB::InitSocket()
{
if(WSAStartup(MAKEWORD(2,2),&wsaData) !=0)
    return false;

s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

DWORD nIP = inet_addr(szIP);
ZeroMemory((PVOID)&name,sizeof(name));
name.sin_family = AF_INET;
name.sin_port = htons(SMB_PORT);
name.sin_addr.S_un.S_addr = nIP;

// local.sin_family = AF_INET;
// local.sin_port = ANY;
// local.sin_addr.S_un = INADDR_ANY;

if(s == INVALID_SOCKET)
    return false;
return true;
}

int CSMB::SendNBSS()
{
int iRet = connect(s,(struct sockaddr*)&name,sizeof(name));

if(iRet == -1)
    return 0;

unsigned char buf[1024] = {0};
buf[0] = 0x81; //0x81 corresponds to a NETBIOS session request. This code is used when the client sends its NETBIOS name to the server.
         //0x82 corresponds to a NETBIOS session response. This code uses
         //0x00 to correspond to a session message when the server approves the NETBIOS session to the client . This code is always used in SMB sessions.

buf[1] = 0;      // always 0

buf[2] = 0x00;
buf[3] = 0x48;

buf[4] = 0x20;

Convert((char*)&buf[5]);

iRet = send(s,(char*)buf,72,0);
return iRet;
}

bool CSMB::RecvNBSS()
{
unsigned char buf[1024] = {0};
int len = 1024;

fd_set fread;
fd_set ferror;
FD_ZERO(&fread);
FD_ZERO(&ferror);


FD_SET(s, &fread);
FD_SET(s, &ferror);

struct timeval timeout;
timeout.tv_sec = 5;
timeout.tv_usec = 0;


if(select(0,&fread,NULL, &ferror,&timeout) >0)
{
    if(FD_ISSET(s,&fread))
    {
     int iRet = recv(s,(char*) buf , len,0);
    }
if(buf[0] == 0x82)
{
    return true;
}
else
    return false;
}
return false;
}

int CSMB::SendNegotiate()
{
int iRet ;
int len = 0;
unsigned char buf[1024] = {0} ;
// Constructor Netbios Header
NETBIOSHEADER nHeader ;
nHeader.Flags = 0x00;
nHeader.Type = 0x00;
nHeader.Length = htons(0x00a4);

// constructor SMB Header
NEGOREQUESTHEAD negoRequestHead;
ZeroMemory ((LPVOID) & negoRequestHead, 32);
strcpy ((char *) & negoRequestHead.Protocol [1], (char *) "SMB");

negoRequestHead.Protocol [0] = 0xFF;
negoRequestHead.Command = 0x72;

// ZeroMemory ((LPVOID) negoRequestHead.Status.Status, sizeof (negoRequestHead.Status));

negoRequestHead.Flags = 0x00;
negoRequestHead.Flags2 = 0x00;

// ZeroMemory ((LPVOID) negoRequestHead.pad.Pad, sizeof (negoRequestHead.pad));

negoRequestHead.Tid = 0x0000;
negoRequestHead.Pid = htons (GetCurrentProcessId ());
negoRequestHead.Uid = 0x0000;
negoRequestHead.Mid = negoRequestHead.Pid + 100;
// Constructor Request Header
//negoRequestHead.WordCount = 0x00;
//negoRequestHead.ByteCount = htons (0x81);

int i =0;
memcpy((void*)&buf[i],(void*)&nHeader,sizeof(nHeader));
i = i + sizeof(nHeader);
memcpy((void*) &buf[i], (void*) &negoRequestHead,32);
i = i +    32;

buf[i++] = 0x00;
buf[i++] = 0x81;
buf[i++] = 0x00;

memcpy((void*) &buf[i],(void*)PC_NETWORK_PROGRAM_10, 24);
i = i + 24;
memcpy((void*) &buf[i],(void*)MICROSOFT_NETWORKS_103, 25);
i= i+ 25;
memcpy((void*) &buf[i],(void*)MICROSOFT_NETWORKS_30, 24);
i = i+ 24;
memcpy((void*) &buf[i],(void*)LANMAN10, 11);
i = i + 11;
memcpy((void*) &buf[i],(void*)LM12, 11);
i = i + 11;
memcpy((void*) &buf[i],(void*)SANBA, 7);
i = i + 7;
memcpy((void*) &buf[i],(void*)NTLM012, 12);
i = i + 12;
memcpy((void*) &buf[i],(void*)NTLANMAN10, 15);
i = i + 15;

iRet = send(s,(char*)buf,i,0);
return iRet;
}

bool CSMB::RecvNegotiate()
{
unsigned char buf[1024] = {0};
int len = 1024;

fd_set fread;
fd_set ferror;
FD_ZERO(&fread);
FD_ZERO(&ferror);

FD_SET(s, &fread);
FD_SET(s, &ferror);

struct timeval timeout;
timeout.tv_sec = 5;
timeout.tv_usec = 0;
int iRet =0;

if(select(0,&fread,NULL, &ferror,&timeout) >0)
{
    if(FD_ISSET(s,&fread))
    {
      iRet= recv(s,(char*) buf , len,0);
    }
    else
     return false;
}
else
    return false;

NETBIOSHEADER nHeader;
NEGOREQUESTHEAD neGequestHead;
struct EchoSMBHeader data;

if(iRet < sizeof(nHeader) + 32 + 37)
{
    return false;
}

memcpy((void*)&nHeader,buf,sizeof(nHeader));
int i = sizeof(nHeader);
memcpy((void*)&negoRequestHead,(void*)&buf[i],32);
i = i + 32;
memcpy((void*)&data, (void*)&buf[i],37);
i = i + 37;

char EncryptionKey[17] = {0};
memcpy((void*)&EncryptionKey,&buf[i], 16);
i = i+ 16;
securityMode = data.SecurityMode;

sessionKey = data.SessionKey;

return true;
}

int CSMB::SendSesssetupX()
{
int iRet ;
int len = 0;
unsigned char buf[1024] = {0} ;
// Constructor Netbios Header
NETBIOSHEADER nHeader ;
nHeader.Flags = 0x00;
nHeader.Type = 0x00;
nHeader.Length = htons(0x54);

// constructor SMB Header
NEGOREQUESTHEAD negoRequestHead;
ZeroMemory ((LPVOID) & negoRequestHead, 32);

strcpy ((char *) & negoRequestHead.Protocol [1], (char *) "SMB");
negoRequestHead.Protocol [0] = 0xFF;
negoRequestHead.Command = 0x73;

// ZeroMemory ((LPVOID) & negoRequestHead.Status.Status, sizeof (negoRequestHead.Status));

negoRequestHead.Flags = 0x08;
negoRequestHead.Flags2 = htons (0x0001);

// ZeroMemory ((LPVOID) negoRequestHead.pad.Pad, sizeof (negoRequestHead.pad));
negoRequestHead.Tid = 0x0000;
negoRequestHead.Pid = htons (GetCurrentProcessId ());
negoRequestHead.Uid = 0x0000;
negoRequestHead.Mid = negoRequestHead.Pid + 100;
// negoRequestHead.WordCount = 0x00;
// negoRequestHead.ByteCount =
// Constructor Request Header
struct RequestData data;
ZeroMemory ((void *) & data, 29);

data.WordCount = 0x0d;
data.AndXCommand = 0xFF;
data.AndXReserved = 0x00;
data.AndXOffset = 0x00;
data.MaxBufferSize = 0xffff;
data.MaxMpxCount = 0x0002;
data.VcNumber = negoRequestHead.Pid;
data.SessionKey = sessionKey;
data.CaseInsensitivePasswordLength =0x0001;
data.CaseSensitivePasswordLength = 0x0000;
data.Reserved = 0x00;
data.Capabilities = 0x00;
data.ByteCount = htons(0x1700);
int i =0;
memcpy((void*)&buf[i],(void*)&nHeader,sizeof(nHeader));
i = i + sizeof(nHeader);
memcpy((void*) &buf[i], (void*) &negoRequestHead, 32);
i = i + 32;
memcpy((void*) &buf[i],(void*) &data, 29);
i = i + 29;
buf[i++] = 0x00;
buf[i++] = 0x00;
memcpy((void*) &buf[i],(void*)DOMAIN, 10);
i = i + 10;
memcpy((void*) &buf[i],(void*)NATIVEOS, 5);
i= i+ 5;
memcpy((void*) &buf[i],(void*)NATIVELANMAN, 6);
i = i+ 6;

iRet = send(s,(char*)buf,i,0);
return iRet;
}


void CSMB::Convert(char* buf)
{
char temp[16] = {0x20};

strcpy(temp, szComputerName);

//temp[szComputerName.GetLength()] = 0x20;
FillMemory((LPVOID)&temp[szComputerName.GetLength()], 16-szComputerName.GetLength(), 0x20);
int i=0;

for(i=0; i< 16; i++)
{  
    char c = temp[i];
  
    int j = c/16;
    int k = c%16;
    buf[2*i] = j + 'A';
    buf[2*i+1] = k + 'A';
}
buf[32] = 0x00;
buf[33] = 0x20;

for(i=17; i<33;i++)
{
    buf[i*2] = 'C';
    buf[i*2 + 1] = 'A';
}
buf[66] = 0;
}

bool CSMB::RecvSesssetupX()
{
unsigned char buf[1024] = {0};
int len = 1024;

fd_set fread;
fd_set ferror;
FD_ZERO(&fread);
FD_ZERO(&ferror);

FD_SET(s, &fread);
FD_SET(s, &ferror);

struct timeval timeout;
timeout.tv_sec = 5;
timeout.tv_usec = 0;
int iRet =0;

if(select(0,&fread,NULL, &ferror,&timeout) >0)
{
    if(FD_ISSET(s,&fread))
    {
      iRet= recv(s,(char*) buf , len,0);
    }
    else
     return false;
}
else
    return false;

NETBIOSHEADER nHeader;
NEGOREQUESTHEAD neGequestHead;
struct EchoData data;

if(iRet < sizeof(nHeader) + 32 + 9)
{
    return false;
}

closesocket(s);

memcpy((void*)&nHeader,buf,sizeof(nHeader));
int i = sizeof(nHeader);
memcpy((void*)&negoRequestHead, &buf[i],32);
i = i + 32;
memcpy((void*)&data, &buf[i],9);
i = i + 9;

char NativeOs[256] = {0};

strcpy(NativeOs,(char*)&buf[i]);

i = i + strlen(NativeOs) + 1;
char NativeLanMan[256] = {0};
strcpy(NativeLanMan,(char*)&buf[i]);
i = i + strlen(NativeLanMan) + 1;
char Domain[256] = {0};
strcpy(Domain,(char*)&buf[i]);

this->szNativeLM = NativeLanMan;
this->szNativeOS = NativeOs;
this->szDomain = Domain;
return true;
}

void CSMB::DoSMBScan()
{
if(!InitSocket())
    return ;

int iRet = SendNBSS();
if(iRet <= 0)
    return ;
if(!RecvNBSS())
    return ;

iRet = SendNegotiate();
if(iRet <=0)
    return ;

if(!RecvNegotiate())
    return ;
iRet = SendSesssetupX();
if(iRet <=0)
    return ;

RecvSesssetupX();

// ResetEvent(hEvent);
return ;
}

/*
void CSMB::DoSMBScan()
{
DWORD IDThread;

// CWinThread temp ;
// temp.CreateThread(0,0);

HANDLE    hThread = ::CreateThread(NULL, // no security attributes
           0,                             // use default stack size
           (LPTHREAD_START_ROUTINE)BeginScan, // thread function
           this,                      // no thread function argument
           0,                         // use default creation flags
           &IDThread);                // returns thread identifier
::ResumeThread(hThread);
DWORD dwMilliseconds    = 15000;
// SetEvent(hEvent);
DWORD dRet = WaitForSingleObject(hEvent, dwMilliseconds);

if(dRet == WAIT_TIMEOUT)
{
    ::ExitThread(1);
    Sleep(2000);
}

}
*/
DWORD CSMB::BeginScan(LPVOID smb1)
{
// SetEvent(smb->hEvent);
CSMB *smb = (CSMB*) smb1;
if(!smb->InitSocket())
    return 1;

int iRet = smb->SendNBSS();
if(iRet <= 0)
    return 1;
if(!smb->RecvNBSS())
    return 1;

iRet = smb->SendNegotiate();
if(iRet <=0)
    return 1;

if(!smb->RecvNegotiate())
    return 1;
iRet = smb->SendSesssetupX();
if(iRet <=0)
    return 1;

smb->RecvSesssetupX();

SetEvent(smb->hEvent);
return 1;
}

//CSMB::~CSMB()
//{

 // shutdown(this->s, 1); WSACleanup(); } Due to space issues, there is no way to put the entire project in, so I have to paste the header file and CPP file here. I hope to be helpful! ! !
