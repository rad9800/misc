//////////////////////////////////////////////////////////////////////////////////////////
// RtlFreeHeapHook.c (uses HWBP.c)
// PoC demonstrating hooking kernel32.HeapFree -> ntdll.RtlFreeHeap with a HWBP as seen in
// the NightHawk C2. 
// Credits:
// - Peter Winter-Smith (@peterwintrsmith)
//////////////////////////////////////////////////////////////////////////////////////////
#include <Windows.h>
#include <tlhelp32.h>

#include <stdio.h> // strcpy_s

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Macros                                      */
//////////////////////////////////////////////////////////////////////////////////////////

#define MALLOC( size ) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define FREE( adr ) HeapFree(GetProcessHeap(), 0, adr)

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Typedefs                                    */
//////////////////////////////////////////////////////////////////////////////////////////

/*
 * All callback functions must match this prototype.
 */
typedef void (WINAPI* exception_callback)(PEXCEPTION_POINTERS);

struct descriptor_entry
{
    /* Data */
    uintptr_t adr;
    unsigned pos;
    DWORD tid;
    BOOL dis;
    exception_callback fun;


    struct descriptor_entry* next, * prev;
};

//////////////////////////////////////////////////////////////////////////////////////////
/*                                       Globals                                        */
//////////////////////////////////////////////////////////////////////////////////////////

CRITICAL_SECTION g_critical_section;
struct descriptor_entry* head = NULL;

//////////////////////////////////////////////////////////////////////////////////////////
/*                                 Function Definitions                                 */
//////////////////////////////////////////////////////////////////////////////////////////

/*
 * Function: set_hardware_breakpoint
 * ---------------------------------
 *  sets/removes a hardware breakpoint in the specified debug register for a specific
 *    function address
 *
 *    tid: thread id
 *    address: address of function to point a debug register towards
 *    pos: Dr[0-3]
 *    init: TRUE (Sets)/FALSE (Removes)
 */
void
set_hardware_breakpoint(
    const DWORD tid,
    const uintptr_t address,
    const UINT pos,
    const BOOL init
)
{
    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE thd;

    if (tid == GetCurrentThreadId())
    {
        thd = GetCurrentThread();
    }
    else
    {
        thd = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    }

    GetThreadContext(thd, &context);

    if (init)
    {
        (&context.Dr0)[pos] = address;
        context.Dr7 &= ~(3ull << (16 + 4 * pos));
        context.Dr7 &= ~(3ull << (18 + 4 * pos));
        context.Dr7 |= 1ull << (2 * pos);
    }
    else
    {
        if ((&context.Dr0)[pos] == address)
        {
            context.Dr7 &= ~(1ull << (2 * pos));
            (&context.Dr0)[pos] = 0ull;
        }
    }

    SetThreadContext(thd, &context);

    if (thd != INVALID_HANDLE_VALUE) CloseHandle(thd);
}

/*
 * Function: set_hardware_breakpoint
 * ---------------------------------
 *  sets/removes a hardware breakpoint in the specified debug register for a specific
 *    function address
 *
 *    address: address of function to point a debug register towards
 *    pos: Dr[0-3]
 *    init: TRUE (Sets)/FALSE (Removes)
 *    tid: Thread ID (0 if to set on all threads)
 */
void
set_hardware_breakpoints(
    const uintptr_t address,
    const UINT pos,
    const BOOL init,
    const DWORD tid
)
{
    const DWORD pid = GetCurrentProcessId();
    const HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };

        if (Thread32First(h, &te)) {
            do {
                if ((te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID)) && te.th32OwnerProcessID == pid) {
                    if (tid != 0 && tid != te.th32ThreadID) {
                        continue;
                    }
                    set_hardware_breakpoint(
                        te.th32ThreadID,
                        address,
                        pos,
                        init
                    );

                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }
}

/* DLL related functions */

/*
 * Function: insert_descriptor_entry
 * ---------------------------------
 * Instantiates a hardware hook at the supplied address.
 *
 *    adr: address to hook
 *    pos: Dr[0-3]
 *    fun: callback function matching the exception_callback signature
 *    tid: Thread ID (if is 0, will apply hook to all threads)
 *    dis: Disable DR during callback (allows you to call original function)
 */
void insert_descriptor_entry(
    const uintptr_t adr,
    const unsigned pos,
    const exception_callback fun,
    const DWORD tid,
    const BOOL dis
)
{
    struct descriptor_entry* new = MALLOC(sizeof(struct descriptor_entry));
    const unsigned idx = pos % 4;

    EnterCriticalSection(&g_critical_section);

    new->adr = adr;
    new->pos = idx;
    new->tid = tid;
    new->fun = fun;
    new->dis = TRUE;

    new->next = head;

    new->prev = NULL;

    if (head != NULL)
        head->prev = new;

    head = new;

    LeaveCriticalSection(&g_critical_section);

    set_hardware_breakpoints(
        adr,
        idx,
        TRUE,
        tid
    );
}

/*
 * Function: insert_descriptor_entry
 * ---------------------------------
 *  Removes the hardware breakpoint entry
 *
 *    adr: address to hook
 *    tid: Thread ID (if is 0, will apply hook to all threads)
 *         N.B. the tid must match the originally applied value
 *
 */
void delete_descriptor_entry(
    const uintptr_t adr,
    const DWORD tid
)
{
    struct descriptor_entry* temp;
    PVOID temp2 = NULL;

    unsigned pos = 0;
    BOOL found = FALSE;

    EnterCriticalSection(&g_critical_section);

    temp = head;

    while (temp != NULL)
    {
        if (temp->adr == adr &&
            temp->tid == tid)
        {
            found = TRUE;

            pos = temp->pos;
            if (head == temp)
                head = temp->next;

            if (temp->next != NULL)
                temp->next->prev = temp->prev;

            if (temp->prev != NULL)
                temp->prev->next = temp->next;

            // save so we can free later
            temp2 = temp;
        }

        temp = temp->next;
    }

    LeaveCriticalSection(&g_critical_section);

    if (found)
    {
        set_hardware_breakpoints(
            adr,
            pos,
            FALSE,
            tid
        );

        if (temp2) FREE(temp2);
    }
}

DWORD get_heap_allocation_size(PVOID allocatedMemory)
{
    HANDLE process_heaps[64] = { 0 };
    const DWORD heap_counter = GetProcessHeaps(64, process_heaps);
    BOOL found = FALSE;

    for (unsigned i = 0; i < heap_counter; i++)
    {
        PROCESS_HEAP_ENTRY heapEntry = { .lpData = NULL };

        if (!HeapLock(process_heaps[i]))
            break;

        while (HeapWalk(process_heaps[i], &heapEntry))
        {
            //
            // We are only interested in "busy" allocated memory chunks 
            //
            if (heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
            {
                if (allocatedMemory == heapEntry.lpData) {
                    found = TRUE;
                    break;
                }
            }
        }

        if (!HeapUnlock(process_heaps[i]))
            //
            // This is really bad..
            //
            break;

        if (found) return heapEntry.cbData;
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                      Exception Handler                               */
//////////////////////////////////////////////////////////////////////////////////////////
/*
 * Function: exception_handler
 * -----------------------------------------
 *  hardware breakpoint exception handler required to deal with set debug registers.
 *  initiated by hardware_engine_init and removed by hardware_engine_stop
 *
 */
LONG WINAPI exception_handler(
    PEXCEPTION_POINTERS ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        struct descriptor_entry* temp;
        BOOL resolved = FALSE;

        EnterCriticalSection(&g_critical_section);
        temp = head;
        while (temp != NULL)
        {
            if (temp->adr == ExceptionInfo->ContextRecord->Rip)
            {
                if (temp->tid != 0 && temp->tid != GetCurrentThreadId())
                    continue;
                //
                // We have found our node, now check if we need to disable current Dr
                //
                if (temp->dis)
                {
                    set_hardware_breakpoint(
                        GetCurrentThreadId(),
                        temp->adr,
                        temp->pos,
                        FALSE
                    );
                }

                temp->fun(ExceptionInfo);

                //
                // re-enable dr for our current thread
                //
                if (temp->dis)
                {
                    set_hardware_breakpoint(
                        GetCurrentThreadId(),
                        temp->adr,
                        temp->pos,
                        TRUE
                    );
                }

                resolved = TRUE;
            }

            temp = temp->next;
        }
        LeaveCriticalSection(&g_critical_section);

        if (resolved)
        {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * Function: hardware_engine_init
 * ------------------------------
 *  initializes the VEH and critical section
 *
 * returns: handler to the exception handler (can be removed with
 *          RemoveVectoredExceptionHandler.
 */
PVOID
hardware_engine_init(
    void
)
{
    const PVOID handler = AddVectoredExceptionHandler(1, exception_handler);
    InitializeCriticalSection(&g_critical_section);

    return handler;
}

/*
 * Function: hardware_engine_stop
 * ------------------------------
 *  Disables all currently set hardware breakpoints, and
 *  clears all the descriptor entries.
 *
 */
void
hardware_engine_stop(
    PVOID handler
)
{
    struct descriptor_entry* temp;

    EnterCriticalSection(&g_critical_section);

    temp = head;
    while (temp != NULL)
    {
        delete_descriptor_entry(temp->adr, temp->tid);
        temp = temp->next;
    }

    LeaveCriticalSection(&g_critical_section);

    if (handler != NULL) RemoveVectoredExceptionHandler(handler);

    DeleteCriticalSection(&g_critical_section);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                       Callbacks                                      */
//////////////////////////////////////////////////////////////////////////////////////////

void heap_free_memset(const PEXCEPTION_POINTERS ExceptionInfo)
{
    const DWORD size = HeapSize(ExceptionInfo->ContextRecord->Rcx, 
						  ExceptionInfo->ContextRecord->Rdx, 
						  ExceptionInfo->ContextRecord->R8);
    if (size)
    {
        memset(ExceptionInfo->ContextRecord->R8, 0, size);
    }
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Entry                                       */
//////////////////////////////////////////////////////////////////////////////////////////

int main()
{
    const PVOID handler = hardware_engine_init();

    //
    // 0 - all threads / GetCurrentThreadId() 
    //
    insert_descriptor_entry(HeapFree, 0, heap_free_memset, 0, FALSE);

    PVOID memory = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
    strcpy_s(memory, 0x1000, "Confidential C2 Information: 10.1.33.7");

    HeapFree(GetProcessHeap(), 0, memory);

    delete_descriptor_entry(HeapFree, 0);

    getchar();

    hardware_engine_stop(handler);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          EOF                                         */
//////////////////////////////////////////////////////////////////////////////////////////
