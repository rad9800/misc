/****************************************************************************************
 * ClearVeh.c by @rad9800
 * Credit goes to:
 * - @peterwintrsmith/@modexpblog (mdsec)
 *
 * 1. Find the LdrpVectorHandlerList by registering a dummy VEH and walking the doubly
 *	linked list until we find a pointer in the NTDLL .data section
 * 2. We use this as our head of our DLL and save the current VEH (so we can later
 *	restore them)
 * 3. RemoveVectoredExceptionHandler(pointer)
 * 4. Do whatever - trigger those patch guards ?? (you may want to add your own VEH)
 * 5. Restore the saved exception handlers (stored in an array) with
 *	AddVectoredExceptionHandler(0, DecodePointer(array[].VectoredHandler)
 * 6. Profit??
 *
  ****************************************************************************************/

#include <Windows.h>
#include <winternl.h>
#include <stdio.h> // printf


typedef struct _VECTXCPT_CALLOUT_ENTRY {
	LIST_ENTRY Links;
	PVOID reserved[2];
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;

LONG WINAPI dummyExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	return 0;
}

BOOL getNtdllSectionVa(PCSTR sectionName, PVOID* sectionVa, DWORD* sectionSz)
{
	const LIST_ENTRY* head = 
		&NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
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

				if (_stricmp(section->Name, sectionName) == 0) {

					*sectionVa = (PVOID)((ULONG_PTR)entry->DllBase
						+ section->VirtualAddress);
					*sectionSz = section->Misc.VirtualSize;

					return TRUE;
				}
			}

		}
		next = next->Flink;
	}
	return FALSE;
}

PVOID findLdrpVectorHandlerList()
{
	BOOL found = FALSE;

	//
	// Register a fake handler
	//
	PVOID dummyHandler = AddVectoredExceptionHandler(0, &dummyExceptionHandler);

	if (dummyHandler == NULL)
		return NULL;

	PLIST_ENTRY next = ((PLIST_ENTRY)dummyHandler)->Flink;

	PVOID sectionVa;
	DWORD sectionSz;
	//
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	//
	if (getNtdllSectionVa(".data", &sectionVa, &sectionSz))
	{
		while ((PVOID)next != dummyHandler)
		{
			if ((PVOID)next >= sectionVa && 
				(PVOID)next <= (PVOID)((ULONG_PTR)sectionVa + sectionSz))
				break;

			if ((PVOID)next >= sectionVa &&
				(PVOID)next <= (PVOID*)sectionVa + sectionSz)
			{
				found = TRUE;
				break;
			}

			next = next->Flink;
		}
	}

	//
	// Cleanup after ourselves..
	//
	RemoveVectoredExceptionHandler(dummyHandler);

	return found ? next : NULL;
}

int main()
{

	PVECTXCPT_CALLOUT_ENTRY vehHandles[64];
	PLIST_ENTRY next;

	PVOID LdrpVectorHandlerList;
	unsigned vehCounter = 0;

	LdrpVectorHandlerList = findLdrpVectorHandlerList();
	next = ((PLIST_ENTRY)LdrpVectorHandlerList)->Flink;

	printf("LdrpVectorHandlerList:\t0x%p\n", LdrpVectorHandlerList);

	for (; next != LdrpVectorHandlerList && vehCounter < 64; 
		vehCounter++, next = next->Flink)
	{
		printf("Registered Handler:\t0x%p -> ", next);
		vehHandles[vehCounter] = (PVECTXCPT_CALLOUT_ENTRY)next;
		printf("0x%p\n", DecodePointer(vehHandles[vehCounter]->VectoredHandler));
	}

	for (unsigned i = 0; i < vehCounter; i++)
	{
		printf("Removing VEH[%d]:\t0x%p -> ", i, vehHandles[i]);
		printf("0x%p\n", DecodePointer(vehHandles[i]->VectoredHandler));
		RemoveVectoredExceptionHandler(vehHandles[i]);
	}


	//
	// Re-register the saved exception handlers
	//
	for (unsigned i = 0; i < vehCounter; i++)
	{
		printf("Restoring VEH[%d]:\t0x%p\n", i, 
			DecodePointer(vehHandles[i]->VectoredHandler));
		AddVectoredExceptionHandler(0, 
			DecodePointer(vehHandles[i]->VectoredHandler));
	}

	//
	// Observe our re-registered handlers
	//
	for (next = ((PLIST_ENTRY)LdrpVectorHandlerList)->Flink; 
		next != LdrpVectorHandlerList; next = next->Flink)
	{
		printf("Checking Handler:\t0x%p\n", 
			DecodePointer(((PVECTXCPT_CALLOUT_ENTRY)next)->VectoredHandler));
	}

	return 0;
}
