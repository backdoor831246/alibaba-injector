#include "globals.hh"
#include "syscalls.h"
#include "xorstr.hpp"
#include <string>
#include <tlhelp32.h>
#include <vector>
#include <windows.h>

// #define DISABLE_OUTPUT
#if defined(DISABLE_OUTPUT)
#define ILog(text, ...)
#else
#define ILog(text, ...)                                                        \
  do {                                                                         \
    char buf[512];                                                             \
    sprintf_s(buf, text, __VA_ARGS__);                                         \
    globals.log_lines.push_back(buf);                                          \
  } while (0)
#endif

namespace Console {
void SetColor(WORD color) {
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
void Red()    { SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY); }
void Green()  { SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
void Yellow() { SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
void White()  { SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }
} // namespace Console

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
typedef BOOL(WINAPI *f_RtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

WORD GetSSN(const char *szStubName) {
  HMODULE hNtdll = GetModuleHandleA(_xor_("ntdll.dll").c_str());
  if (!hNtdll) return 0;
  FARPROC pFunc = GetProcAddress(hNtdll, szStubName);
  if (!pFunc) return 0;
  BYTE *pByte = (BYTE *)pFunc;
  for (int i = 0; i < 32; i++) {
    if (pByte[i] == 0x4C && pByte[i+1] == 0x8B && pByte[i+2] == 0xD1 && pByte[i+3] == 0xB8)
      return *(WORD *)(pByte + i + 4);
  }
  return 0;
}

ULONG64 GetIndirectSyscallAddr(const char *szStubName) {
  HMODULE hNtdll = GetModuleHandleA(_xor_("ntdll.dll").c_str());
  if (!hNtdll) return 0;
  FARPROC pFunc = GetProcAddress(hNtdll, szStubName);
  if (!pFunc) return 0;
  BYTE *pByte = (BYTE *)pFunc;
  for (int i = 0; i < 32; i++) {
    if (pByte[i] == 0x0F && pByte[i+1] == 0x05)
      return (ULONG64)&pByte[i];
  }
  return 0;
}

struct Syscalls {
  WORD    NtAllocate;
  WORD    NtProtect;
  WORD    NtWrite;
  WORD    NtCreateThread;
  WORD    NtOpenProcess;
  WORD    NtReadMemory;
  WORD    NtFreeMemory;

  ULONG64 AddrNtAllocate;
  ULONG64 AddrNtProtect;
  ULONG64 AddrNtWrite;
  ULONG64 AddrNtCreateThread;
  ULONG64 AddrNtOpenProcess;
  ULONG64 AddrNtReadMemory;
  ULONG64 AddrNtFreeMemory;

  bool Init() {
    NtAllocate     = GetSSN(_xor_("ZwAllocateVirtualMemory").c_str());
    NtProtect      = GetSSN(_xor_("NtProtectVirtualMemory").c_str());
    NtWrite        = GetSSN(_xor_("NtWriteVirtualMemory").c_str());
    NtCreateThread = GetSSN(_xor_("NtCreateThreadEx").c_str());
    NtOpenProcess  = GetSSN(_xor_("NtOpenProcess").c_str());
    NtReadMemory   = GetSSN(_xor_("NtReadVirtualMemory").c_str());
    NtFreeMemory   = GetSSN(_xor_("NtFreeVirtualMemory").c_str());

    AddrNtAllocate     = GetIndirectSyscallAddr(_xor_("ZwAllocateVirtualMemory").c_str());
    AddrNtProtect      = GetIndirectSyscallAddr(_xor_("NtProtectVirtualMemory").c_str());
    AddrNtWrite        = GetIndirectSyscallAddr(_xor_("NtWriteVirtualMemory").c_str());
    AddrNtCreateThread = GetIndirectSyscallAddr(_xor_("NtCreateThreadEx").c_str());
    AddrNtOpenProcess  = GetIndirectSyscallAddr(_xor_("NtOpenProcess").c_str());
    AddrNtReadMemory   = GetIndirectSyscallAddr(_xor_("NtReadVirtualMemory").c_str());
    AddrNtFreeMemory   = GetIndirectSyscallAddr(_xor_("NtFreeVirtualMemory").c_str());

    return NtAllocate && NtProtect && NtWrite && NtCreateThread &&
           NtOpenProcess && NtReadMemory && NtFreeMemory &&
           AddrNtAllocate && AddrNtProtect && AddrNtWrite &&
           AddrNtCreateThread && AddrNtOpenProcess &&
           AddrNtReadMemory && AddrNtFreeMemory;
  }
} g_Syscalls;

// Helper: NtFreeVirtualMemory instead of VirtualFreeEx
static void SysFreeRemote(HANDLE hProc, PVOID pAddr) {
  SIZE_T regionSize = 0;
  GetSyscall(g_Syscalls.NtFreeMemory);
  GetSyscallAddr(g_Syscalls.AddrNtFreeMemory);
  sysNtFreeVirtualMemory(hProc, &pAddr, &regionSize, MEM_RELEASE);
}

typedef HMODULE(WINAPI *f_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *f_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI *f_DLL_ENTRY_POINT)(HMODULE, DWORD, LPVOID);
typedef VOID(NTAPI *PIMAGE_TLS_CALLBACK)(PVOID, DWORD, PVOID);

struct MANUAL_MAPPING_DATA {
  PVOID pbase;
  f_LoadLibraryA   pLoadLibraryA;
  f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
  f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
  HINSTANCE hMod;
  DWORD     fdwReasonParam;
  LPVOID    reservedParam;
  bool      SEHSupport;
  typedef BOOL(WINAPI *f_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
  f_VirtualProtect pVirtualProtect;
};

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

/////////////////////////////////////////////////////
// Shellcode
/////////////////////////////////////////////////////
#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall Shellcode(MANUAL_MAPPING_DATA *pData) {
  if (!pData) {
    pData->hMod = (HINSTANCE)0x404040;
    return;
  }

  BYTE *pBase = (BYTE *)pData->pbase;
  auto *pDos  = (IMAGE_DOS_HEADER *)pBase;
  auto *pNt   = (IMAGE_NT_HEADERS *)(pBase + pDos->e_lfanew);
  auto *pOpt  = &pNt->OptionalHeader;

  auto _LoadLibraryA   = pData->pLoadLibraryA;
  auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
  auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif

  BYTE *LocationDelta = pBase - pOpt->ImageBase;
  if (LocationDelta) {
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
      auto *pReloc = (IMAGE_BASE_RELOCATION *)(pBase +
          pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
      const auto *pRelocEnd = (IMAGE_BASE_RELOCATION *)((uintptr_t)pReloc +
          pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
      while (pReloc < pRelocEnd && pReloc->SizeOfBlock) {
        UINT  count    = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *pRelInfo = (WORD *)(pReloc + 1);
        for (UINT i = 0; i < count; ++i, ++pRelInfo) {
          if (RELOC_FLAG(*pRelInfo)) {
            UINT_PTR *pPatch = (UINT_PTR *)(pBase + pReloc->VirtualAddress + (*pRelInfo & 0xFFF));
            *pPatch += (UINT_PTR)LocationDelta;
          }
        }
        pReloc = (IMAGE_BASE_RELOCATION *)((BYTE *)pReloc + pReloc->SizeOfBlock);
      }
    }
  }

  if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
    auto *pImport = (IMAGE_IMPORT_DESCRIPTOR *)(pBase +
        pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (pImport->Name) {
      char      *szMod  = (char *)(pBase + pImport->Name);
      HINSTANCE  hDll   = _LoadLibraryA(szMod);
      ULONG_PTR *pThunk = (ULONG_PTR *)(pBase + pImport->OriginalFirstThunk);
      ULONG_PTR *pFunc  = (ULONG_PTR *)(pBase + pImport->FirstThunk);
      if (!pImport->OriginalFirstThunk) pThunk = pFunc;
      for (; *pThunk; ++pThunk, ++pFunc) {
        if (IMAGE_SNAP_BY_ORDINAL(*pThunk))
          *pFunc = (ULONG_PTR)_GetProcAddress(hDll, (char *)(*pThunk & 0xFFFF));
        else {
          auto *pIBN = (IMAGE_IMPORT_BY_NAME *)(pBase + *pThunk);
          *pFunc = (ULONG_PTR)_GetProcAddress(hDll, pIBN->Name);
        }
      }
      ++pImport;
    }
  }

  if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size) {
    struct DELAY_DESC {
      DWORD grAttrs, rvaDLLName, rvaHmod, rvaIAT,
            rvaINT, rvaBoundIAT, rvaUnloadIAT, dwTimeStamp;
    };
    auto *pDelay = (DELAY_DESC *)(pBase +
        pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    while (pDelay->rvaDLLName) {
      HINSTANCE hDll = _LoadLibraryA((char *)(pBase + pDelay->rvaDLLName));
      if (hDll) {
        ULONG_PTR *pThunk = (ULONG_PTR *)(pBase + pDelay->rvaINT);
        ULONG_PTR *pFunc  = (ULONG_PTR *)(pBase + pDelay->rvaIAT);
        for (; *pThunk; ++pThunk, ++pFunc) {
          if (IMAGE_SNAP_BY_ORDINAL(*pThunk))
            *pFunc = (ULONG_PTR)_GetProcAddress(hDll, (char *)(*pThunk & 0xFFFF));
          else {
            auto *pIBN = (IMAGE_IMPORT_BY_NAME *)(pBase + *pThunk);
            *pFunc = (ULONG_PTR)_GetProcAddress(hDll, pIBN->Name);
          }
        }
      }
      ++pDelay;
    }
  }

  if (pData->pVirtualProtect) {
    auto *pSec  = IMAGE_FIRST_SECTION(pNt);
    auto *pFile = &pNt->FileHeader;
    for (UINT i = 0; i < pFile->NumberOfSections; ++i, ++pSec) {
      if (!pSec->Misc.VirtualSize) continue;
      DWORD newProt = PAGE_READONLY;
      if (pSec->Characteristics & IMAGE_SCN_MEM_WRITE)
        newProt = PAGE_READWRITE;
      else if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        newProt = PAGE_EXECUTE_READ;
      DWORD oldProt = 0;
      pData->pVirtualProtect(pBase + pSec->VirtualAddress,
                             pSec->Misc.VirtualSize, newProt, &oldProt);
    }
    DWORD old;
    pData->pVirtualProtect(pBase, pOpt->SizeOfHeaders, PAGE_READONLY, &old);
  }

  if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
    auto *pTLS = (IMAGE_TLS_DIRECTORY *)(pBase +
        pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    auto *pCallback = (PIMAGE_TLS_CALLBACK *)(pTLS->AddressOfCallBacks);
    for (; pCallback && *pCallback; ++pCallback)
      (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
  }

  BOOL ExceptionSupportFailed = FALSE;
#ifdef _WIN64
  if (pData->SEHSupport) {
    auto &excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (excep.Size) {
      if (!_RtlAddFunctionTable(
              (IMAGE_RUNTIME_FUNCTION_ENTRY *)(pBase + excep.VirtualAddress),
              excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
              (DWORD64)pBase))
        ExceptionSupportFailed = TRUE;
    }
  }
#endif

  if (pOpt->AddressOfEntryPoint) {
    auto _DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);
    _DllMain((HMODULE)pBase, pData->fdwReasonParam, pData->reservedParam);
  }

  if (ExceptionSupportFailed)
    pData->hMod = (HINSTANCE)0x505050;
  else
    pData->hMod = (HINSTANCE)pBase;
}
#pragma optimize("", on)
#pragma runtime_checks("", restore)

__declspec(noinline) void ShellcodeEnd() {}

bool IsElevated() {
  BOOL elevated = FALSE;
  HANDLE hToken = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    TOKEN_ELEVATION te;
    DWORD dwSize = 0;
    if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &dwSize))
      elevated = te.TokenIsElevated;
    CloseHandle(hToken);
  }
  return elevated;
}

bool ManualMapDll(HANDLE hProc, BYTE *pSrcData, SIZE_T FileSize,
                  bool ClearHeader = true, bool ClearNonNeededSections = true,
                  bool AdjustProtections = true,
                  bool SEHExceptionSupport = true) {
  if (((IMAGE_DOS_HEADER *)pSrcData)->e_magic != 0x5A4D) {
    ILog(_xor_("[!] Invalid PE file\n").c_str());
    return false;
  }

  auto *pNt   = (IMAGE_NT_HEADERS *)(pSrcData + ((IMAGE_DOS_HEADER *)pSrcData)->e_lfanew);
  auto *pOpt  = &pNt->OptionalHeader;
  auto *pFile = &pNt->FileHeader;

  if (pFile->Machine != CURRENT_ARCH) {
    ILog(_xor_("[!] x86/x64 mismatch\n").c_str());
    return false;
  }

  PVOID pTargetBase = nullptr;
  SIZE_T regionSize = pOpt->SizeOfImage;
  GetSyscall(g_Syscalls.NtAllocate);
  GetSyscallAddr(g_Syscalls.AddrNtAllocate);
  NTSTATUS status = sysZwAllocateVirtualMemory(hProc, &pTargetBase, 0, &regionSize,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (status != 0 || !pTargetBase) {
    ILog(_xor_("[!] VirtualAllocEx syscall failed: 0x%X").c_str(), status);
    return false;
  }
  ILog(_xor_("[+] Allocated remote image base: 0x%p").c_str(), pTargetBase);

  SIZE_T bytesWritten = 0;
  GetSyscall(g_Syscalls.NtWrite);
  GetSyscallAddr(g_Syscalls.AddrNtWrite);
  status = sysNtWriteVirtualMemory(hProc, pTargetBase, pSrcData, 0x1000, &bytesWritten);
  if (status != 0) {
    ILog(_xor_("[!] Failed to write headers. Status: 0x%X").c_str(), status);
    SysFreeRemote(hProc, pTargetBase);
    return false;
  }
  ILog(_xor_("[+] Written PE headers.").c_str());

  auto *pSection = IMAGE_FIRST_SECTION(pNt);
  for (UINT i = 0; i < pFile->NumberOfSections; ++i, ++pSection) {
    if (!pSection->SizeOfRawData) continue;
    GetSyscall(g_Syscalls.NtWrite);
    GetSyscallAddr(g_Syscalls.AddrNtWrite);
    status = sysNtWriteVirtualMemory(hProc,
        (BYTE *)pTargetBase + pSection->VirtualAddress,
        pSrcData + pSection->PointerToRawData,
        pSection->SizeOfRawData, &bytesWritten);
    if (status != 0) {
      ILog(_xor_("[!] Failed to write section %s. Status: 0x%X").c_str(), (char *)pSection->Name, status);
      SysFreeRemote(hProc, pTargetBase);
      return false;
    }
  }
  ILog(_xor_("[+] Written PE sections.").c_str());

  MANUAL_MAPPING_DATA data = {};
  data.pbase           = pTargetBase;
  data.pLoadLibraryA   = LoadLibraryA;
  data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
  data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else
  SEHExceptionSupport = false;
#endif
  data.fdwReasonParam  = DLL_PROCESS_ATTACH;
  data.reservedParam   = nullptr;
  data.SEHSupport      = SEHExceptionSupport;
  data.pVirtualProtect = VirtualProtect;

  PVOID pMappingData = nullptr;
  SIZE_T mappingSize = sizeof(MANUAL_MAPPING_DATA);
  GetSyscall(g_Syscalls.NtAllocate);
  GetSyscallAddr(g_Syscalls.AddrNtAllocate);
  status = sysZwAllocateVirtualMemory(hProc, &pMappingData, 0, &mappingSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (status != 0 || !pMappingData) {
    ILog(_xor_("[!] Failed to alloc params. Status: 0x%X").c_str(), status);
    SysFreeRemote(hProc, pTargetBase);
    return false;
  }
  GetSyscall(g_Syscalls.NtWrite);
  GetSyscallAddr(g_Syscalls.AddrNtWrite);
  status = sysNtWriteVirtualMemory(hProc, pMappingData, &data, sizeof(data), &bytesWritten);
  if (status != 0) {
    ILog(_xor_("[!] Failed to write params. Status: 0x%X").c_str(), status);
    SysFreeRemote(hProc, pTargetBase);
    SysFreeRemote(hProc, pMappingData);
    return false;
  }
  ILog(_xor_("[+] Mapped injector params.").c_str());

  PVOID pShellcode = nullptr;
  SIZE_T shellSize = 0x1000;
  GetSyscall(g_Syscalls.NtAllocate);
  GetSyscallAddr(g_Syscalls.AddrNtAllocate);
  status = sysZwAllocateVirtualMemory(hProc, &pShellcode, 0, &shellSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (status != 0 || !pShellcode) {
    ILog(_xor_("[!] Failed to alloc shellcode. Status: 0x%X").c_str(), status);
    SysFreeRemote(hProc, pTargetBase);
    SysFreeRemote(hProc, pMappingData);
    return false;
  }

  GetSyscall(g_Syscalls.NtWrite);
  GetSyscallAddr(g_Syscalls.AddrNtWrite);
  status = sysNtWriteVirtualMemory(hProc, pShellcode, (PVOID)Shellcode, 0x1000, &bytesWritten);
  if (status != 0) {
    ILog(_xor_("[!] Failed to write shellcode. Status: 0x%X").c_str(), status);
    SysFreeRemote(hProc, pTargetBase);
    SysFreeRemote(hProc, pMappingData);
    SysFreeRemote(hProc, pShellcode);
    return false;
  }
  ILog(_xor_("[+] Mapped injector shellcode.").c_str());

  ULONG oldProtect;
  PVOID pShellcodeProt = pShellcode;
  SIZE_T protSize = 0x1000;
  GetSyscall(g_Syscalls.NtProtect);
  GetSyscallAddr(g_Syscalls.AddrNtProtect);
  sysNtProtectVirtualMemory(hProc, &pShellcodeProt, &protSize,
                            PAGE_EXECUTE_READ, &oldProtect);

  HANDLE hThread = nullptr;
  GetSyscall(g_Syscalls.NtCreateThread);
  GetSyscallAddr(g_Syscalls.AddrNtCreateThread);
  status = sysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc,
                               pShellcode, pMappingData, 0x04, 0, 0, 0, nullptr);
  if (status != 0 || !hThread) {
    ILog(_xor_("[!] Thread creation failed: 0x%X").c_str(), status);
    SysFreeRemote(hProc, pTargetBase);
    SysFreeRemote(hProc, pMappingData);
    SysFreeRemote(hProc, pShellcode);
    return false;
  }
  ILog(_xor_("[+] Remote thread spawned safely.").c_str());
  CloseHandle(hThread);

  // Polling: NtReadVirtualMemory instead of ReadProcessMemory
  HINSTANCE hCheck = nullptr;
  while (!hCheck) {
    DWORD exitCode = 0;
    GetExitCodeProcess(hProc, &exitCode);
    if (exitCode != STILL_ACTIVE) {
      ILog(_xor_("[!] Target crashed during shellcode execution (ExitCode: 0x%X)").c_str(), exitCode);
      SysFreeRemote(hProc, pTargetBase);
      SysFreeRemote(hProc, pMappingData);
      SysFreeRemote(hProc, pShellcode);
      return false;
    }

    MANUAL_MAPPING_DATA data_checked = {};
    SIZE_T bytesRead = 0;
    GetSyscall(g_Syscalls.NtReadMemory);
    GetSyscallAddr(g_Syscalls.AddrNtReadMemory);
    sysNtReadVirtualMemory(hProc, pMappingData, &data_checked, sizeof(data_checked), &bytesRead);
    hCheck = data_checked.hMod;

    if (hCheck == (HINSTANCE)0x404040) {
      ILog(_xor_("[!] Shellcode null error (pData was null internally)").c_str());
      SysFreeRemote(hProc, pTargetBase);
      SysFreeRemote(hProc, pMappingData);
      SysFreeRemote(hProc, pShellcode);
      return false;
    }
    if (hCheck == (HINSTANCE)0x505050) {
      ILog(_xor_("[!] Exception support failed").c_str());
      break;
    }
    Sleep(10);
  }
  ILog(_xor_("[+] Shellcode finished executing.").c_str());

  BYTE *emptyBuffer = (BYTE *)malloc(pOpt->SizeOfImage);
  if (emptyBuffer) {
    memset(emptyBuffer, 0, pOpt->SizeOfImage);

    if (ClearHeader) {
      GetSyscall(g_Syscalls.NtWrite);
      GetSyscallAddr(g_Syscalls.AddrNtWrite);
      sysNtWriteVirtualMemory(hProc, pTargetBase, emptyBuffer, 0x1000, &bytesWritten);
    }

    if (ClearNonNeededSections) {
      pSection = IMAGE_FIRST_SECTION(pNt);
      for (UINT i = 0; i < pFile->NumberOfSections; ++i, ++pSection) {
        if (!pSection->Misc.VirtualSize) continue;
        if (strcmp((char *)pSection->Name, _xor_(".reloc").c_str()) == 0 ||
            strcmp((char *)pSection->Name, _xor_(".rsrc").c_str())  == 0) {
          GetSyscall(g_Syscalls.NtWrite);
          GetSyscallAddr(g_Syscalls.AddrNtWrite);
          sysNtWriteVirtualMemory(hProc,
              (BYTE *)pTargetBase + pSection->VirtualAddress,
              emptyBuffer, pSection->Misc.VirtualSize, &bytesWritten);
        }
      }
    }

    free(emptyBuffer);
  }

  SysFreeRemote(hProc, pShellcode);
  SysFreeRemote(hProc, pMappingData);
  return true;
}

void RefreshProcessList() {
  globals.process_list.clear();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(snap, &pe)) {
      do {
        std::wstring wName = pe.szExeFile;
        std::string name;
        for (wchar_t c : wName) name += (char)c;
        globals.process_list.push_back({pe.th32ProcessID, name});
      } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
  }
}

bool DoInject() {
  static bool syscallsInit = false;
  if (!syscallsInit) {
    if (!g_Syscalls.Init()) {
      ILog(_xor_("[!] Failed to initialize syscalls\n").c_str());
      return false;
    }
    syscallsInit = true;
  }

  std::string dllPath = globals.dll_path;
  DWORD pid = 0;

  if (globals.selected_process_idx >= 0 &&
      globals.selected_process_idx < (int)globals.process_list.size()) {
    pid = globals.process_list[globals.selected_process_idx].pid;
  }

  if (dllPath.empty()) { ILog(_xor_("[!] DLL path is empty").c_str());   return false; }
  if (!pid)            { ILog(_xor_("[!] No process selected").c_str()); return false; }

  ILog(_xor_("[*] Target PID: %d").c_str(), pid);

  // NtOpenProcess вместо OpenProcess
  HANDLE hProc = nullptr;
  OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
  CLIENT_ID clientId        = {};
  clientId.UniqueProcess    = (HANDLE)(ULONG_PTR)pid;
  clientId.UniqueThread     = nullptr;

  ACCESS_MASK access = IsElevated()
      ? PROCESS_ALL_ACCESS
      : PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ;

  GetSyscall(g_Syscalls.NtOpenProcess);
  GetSyscallAddr(g_Syscalls.AddrNtOpenProcess);
  NTSTATUS status = sysNtOpenProcess(&hProc, access, &objAttr, &clientId);
  if (status != 0 || !hProc) {
    ILog(_xor_("[!] NtOpenProcess failed: 0x%X").c_str(), status);
    return false;
  }

  std::wstring wDllPath;
  for (char c : dllPath) wDllPath += (wchar_t)c;

  HANDLE hFile = CreateFileW(wDllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    ILog(_xor_("[!] CreateFileW failed: 0x%X").c_str(), GetLastError());
    CloseHandle(hProc);
    return false;
  }

  DWORD fileSize = GetFileSize(hFile, nullptr);
  if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
    ILog(_xor_("[!] Invalid file size").c_str());
    CloseHandle(hFile);
    CloseHandle(hProc);
    return false;
  }

  BYTE *buffer = (BYTE *)VirtualAlloc(nullptr, fileSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!buffer) {
    ILog(_xor_("[!] Local VirtualAlloc failed").c_str());
    CloseHandle(hFile);
    CloseHandle(hProc);
    return false;
  }

  DWORD bytesRead = 0;
  if (!ReadFile(hFile, buffer, fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
    ILog(_xor_("[!] ReadFile failed").c_str());
    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hFile);
    CloseHandle(hProc);
    return false;
  }
  CloseHandle(hFile);

  bool result = ManualMapDll(hProc, buffer, fileSize);
  VirtualFree(buffer, 0, MEM_RELEASE);
  CloseHandle(hProc);

  if (result) ILog(_xor_("[+] Injection successful!").c_str());
  else        ILog(_xor_("[!] Injection failed!").c_str());

  return result;
}
