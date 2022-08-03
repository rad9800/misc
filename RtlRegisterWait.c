#include <Windows.h>
#include <stdio.h>

/*++
Credit to: 
@5pider for Ekko 
* (https://github.com/Cracked5pider/Ekko)
@domchell for How I Met Your Beacon 
@peterwintrsmith
* (https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/)
--*/

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#define IMPORTAPI( DLLFILE, FUNCNAME, RETTYPE, ...)\
typedef RETTYPE( WINAPI* type##FUNCNAME )( __VA_ARGS__ );\
type##FUNCNAME FUNCNAME = (type##FUNCNAME)GetProcAddress((LoadLibraryW(DLLFILE), GetModuleHandleW(DLLFILE)), #FUNCNAME);



typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} UNICODE_STRING;

void CreateTimer( DWORD SleepTime )
{
    IMPORTAPI( L"NTDLL.dll", RtlRegisterWait, NTSTATUS,
        PHANDLE NewWaitObject, HANDLE Object, WAITORTIMERCALLBACKFUNC Callback,
        PVOID Context, ULONG Milliseconds, ULONG Flags );

    CONTEXT CtxThread = { 0 };

    CONTEXT RopProtRW = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopDelay = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRX = { 0 };
    CONTEXT RopSetEvt = { 0 };

    HANDLE hEvent;
    HANDLE hNewWaitObject;
    PVOID   ImageBase = NULL;
    DWORD   ImageSize = 0;
    DWORD   OldProtect = 0;

    // Can be randomly generated
    CHAR    KeyBuf[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
    UNICODE_STRING Key = { 0 };
    UNICODE_STRING Img = { 0 };

    PVOID   NtContinue = NULL;
    PVOID   SysFunc032 = NULL;

    hEvent = CreateEventW( 0, 0, 0, 0 );

    NtContinue = GetProcAddress( GetModuleHandleA( "Ntdll" ), "NtContinue" );
    SysFunc032 = GetProcAddress( LoadLibraryA( "Advapi32" ), "SystemFunction032" );

    ImageBase = GetModuleHandleA( NULL );
    ImageSize = ((PIMAGE_NT_HEADERS)((DWORD64)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    Key.Buffer = KeyBuf;
    Key.Length = Key.MaximumLength = 16;

    Img.Buffer = ImageBase;
    Img.Length = Img.MaximumLength = ImageSize;

    if( NT_SUCCESS( RtlRegisterWait( &hNewWaitObject, hEvent, RtlCaptureContext, &CtxThread, 0, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD ) ) )
    {
        WaitForSingleObject( hEvent, 0x32 );

        memcpy( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopDelay, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopMemDec, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopProtRX, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopSetEvt, &CtxThread, sizeof( CONTEXT ) );

        // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        RopProtRW.Rsp -= 8;
        RopProtRW.Rip = VirtualProtect;
        RopProtRW.Rcx = ImageBase;
        RopProtRW.Rdx = ImageSize;
        RopProtRW.R8 = PAGE_READWRITE;
        RopProtRW.R9 = &OldProtect;

        // SystemFunction032( &Key, &Img );
        RopMemEnc.Rsp -= 8;
        RopMemEnc.Rip = SysFunc032;
        RopMemEnc.Rcx = &Img;
        RopMemEnc.Rdx = &Key;

        // WaitForSingleObject( hTargetHdl, SleepTime );
        RopDelay.Rsp -= 8;
        RopDelay.Rip = WaitForSingleObject;
        RopDelay.Rcx = NtCurrentProcess();
        RopDelay.Rdx = SleepTime;

        // SystemFunction032( &Key, &Img );
        RopMemDec.Rsp -= 8;
        RopMemDec.Rip = SysFunc032;
        RopMemDec.Rcx = &Img;
        RopMemDec.Rdx = &Key;

        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX.Rsp -= 8;
        RopProtRX.Rip = VirtualProtect;
        RopProtRX.Rcx = ImageBase;
        RopProtRX.Rdx = ImageSize;
        RopProtRX.R8 = PAGE_EXECUTE_READWRITE;
        RopProtRX.R9 = &OldProtect;

        // SetEvent( hEvent );
        RopSetEvt.Rsp -= 8;
        RopSetEvt.Rip = SetEvent;
        RopSetEvt.Rcx = hEvent;

        RtlRegisterWait( &hNewWaitObject, hEvent, NtContinue, &RopProtRW, 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
        RtlRegisterWait( &hNewWaitObject, hEvent, NtContinue, &RopMemEnc, 200, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
        RtlRegisterWait( &hNewWaitObject, hEvent, NtContinue, &RopDelay, 300, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
        RtlRegisterWait( &hNewWaitObject, hEvent, NtContinue, &RopMemDec, 400, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
        RtlRegisterWait( &hNewWaitObject, hEvent, NtContinue, &RopProtRX, 500, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
        RtlRegisterWait( &hNewWaitObject, hEvent, NtContinue, &RopSetEvt, 600, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );


        WaitForSingleObject( hEvent, INFINITE );
    }
}


int main()
{
    do {
        printf( "Starting.\n" );
        // Start Sleep Obfuscation
        CreateTimer( 4 * 1000 );
        printf( "Looping.\n" );
    }
    while( TRUE );

}
