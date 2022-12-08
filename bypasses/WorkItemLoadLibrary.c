/* WorkItemLoadLibrary.c by @rad9800
 * Credit goes to:
 * - Peter Winter-Smith (@peterwintrsmith)
 * - Proofpoint threatinsight team for their detailed analysis
 *
 * Loads a DLL by queuing a work item (RtlQueueWorkItem/) with
 * the address of LoadLibraryW and a pointer to the buffer
 *
 */
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#define IMPORTAPI( DLLFILE, FUNCNAME, RETTYPE, ...)\
typedef RETTYPE( WINAPI* type##FUNCNAME )( __VA_ARGS__ );\
type##FUNCNAME FUNCNAME = (type##FUNCNAME)GetProcAddress((LoadLibraryW(DLLFILE), GetModuleHandleW(DLLFILE)), #FUNCNAME);

HMODULE getModuleHandle(LPCWSTR libraryName)
{
	const LIST_ENTRY* head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;

	while (next != head)
	{
		LDR_DATA_TABLE_ENTRY* entry =
			CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		const UNICODE_STRING* basename = (UNICODE_STRING*)((BYTE*)&entry->FullDllName
			+ sizeof(UNICODE_STRING));

		if (_wcsicmp(libraryName, basename->Buffer) == 0)
		{
			return entry->DllBase;
		}

		next = next->Flink;
	}
	return NULL;
}

HMODULE queueLoadLibrary(WCHAR* libraryName, BOOL swtch)
{
	IMPORTAPI(L"NTDLL.dll", NtWaitForSingleObject, NTSTATUS, HANDLE, BOOLEAN, PLARGE_INTEGER);



	if (swtch)
	{
		IMPORTAPI(L"NTDLL.dll", RtlQueueWorkItem, NTSTATUS, PVOID, PVOID, ULONG);

		if (NT_SUCCESS(RtlQueueWorkItem(&LoadLibraryW, (PVOID)libraryName, WT_EXECUTEDEFAULT)))
		{
			LARGE_INTEGER timeout;
			timeout.QuadPart = -500000;
			NtWaitForSingleObject(NtCurrentProcess(), FALSE, &timeout);
		}
	}
	else
	{
		IMPORTAPI(L"NTDLL.dll", RtlRegisterWait, NTSTATUS, PHANDLE, HANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG);
		HANDLE newWaitObject;
		HANDLE eventObject = CreateEventW(NULL, FALSE, FALSE, NULL);

		if (NT_SUCCESS(RtlRegisterWait(&newWaitObject, eventObject, LoadLibraryW, (PVOID)libraryName, 0, WT_EXECUTEDEFAULT)))
		{
			WaitForSingleObject(eventObject, 500);
		}
	}

	return getModuleHandle(libraryName);

}

int main()
{
	WCHAR libraryName[] = L"DBGHELP.dll";
	HMODULE moduleHandle = queueLoadLibrary(libraryName, TRUE);

	printf("0x%p", moduleHandle);
}
