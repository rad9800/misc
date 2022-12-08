/* FourWorkItemParams.c by @rad9800
 * Credit goes to:
 * - Peter Winter-Smith (@peterwintrsmith)
 * - C5pider (for Ekko) 
 * Get a clean call stack using RtlRegisterWait (or RtlQueueWorkItem if you'd like)
 * for any function with up to 4 parameters
 */
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#define IMPORTAPI( DLLFILE, FUNCNAME, RETTYPE, ...)\
typedef RETTYPE( WINAPI* type##FUNCNAME )( __VA_ARGS__ );\
type##FUNCNAME FUNCNAME = (type##FUNCNAME)GetProcAddress((LoadLibraryW(DLLFILE), GetModuleHandleW(DLLFILE)), #FUNCNAME);

void workItemWrapper(PVOID functionAddr, DWORD64 firstArg, DWORD64 secondArg, DWORD64 thirdArg, DWORD64 fourthArg)
{
	IMPORTAPI(L"NTDLL.dll", RtlRegisterWait, NTSTATUS, PHANDLE, HANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG);
	IMPORTAPI(L"NTDLL.dll", NtContinue, NTSTATUS, PCONTEXT, BOOLEAN);

	HANDLE newWaitObject;
	HANDLE eventObject = CreateEventW(NULL, FALSE, FALSE, NULL);
	NTSTATUS status;
	CONTEXT contextThread;

	//
	// Capture our original context
	//

	status = RtlRegisterWait(&newWaitObject, eventObject, RtlCaptureContext, &contextThread, 0, WT_EXECUTEONLYONCE | WT_EXECUTEDEFAULT);
	if (!NT_SUCCESS(status))
		return;
	WaitForSingleObject(eventObject, 500);


	//
	// Setup our stack 
	//
	
	contextThread.Rsp -= 8;
	contextThread.Rip = functionAddr;
	contextThread.Rcx = firstArg;
	contextThread.Rdx = secondArg;
	contextThread.R8 = thirdArg;
	contextThread.R9 = fourthArg;

	status = RtlRegisterWait(&newWaitObject, eventObject, NtContinue, &contextThread, 0, WT_EXECUTEONLYONCE | WT_EXECUTEDEFAULT);
	if (!NT_SUCCESS(status))
		return;

	WaitForSingleObject(eventObject, 500);
}


int main()
{
	CONTEXT captureMe = { .ContextFlags = CONTEXT_ALL };

	workItemWrapper(GetThreadContext, GetCurrentThread(), &captureMe, NULL, NULL);

	printf("Rip: 0x%p\n", captureMe.Rip);
}
