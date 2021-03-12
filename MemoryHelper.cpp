#include "MemoryHelper.h"


std::optional<uint32_t> MemoryHelper::GetProcessId(std::wstring_view InProcessName)
{
	PROCESSENTRY32W PE32;
	PE32.dwSize = sizeof(PROCESSENTRY32W);
	void* hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(hSnapshot == INVALID_HANDLE_VALUE)
		return std::nullopt;
	Process32First(hSnapshot,&PE32);
	do
    {
        if(PE32.szExeFile == InProcessName)
            return static_cast<uint32_t>(PE32.th32ProcessID);
        
    } while(Process32Next(hSnapshot,&PE32));
	CloseHandle(hSnapshot);
	return std::nullopt;
}

std::optional<PROCESSENTRY32W> MemoryHelper::GetPE32(std::wstring_view InProcessName)
{
	PROCESSENTRY32W PE32;
	PE32.dwSize = sizeof(PROCESSENTRY32W);
	void* hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(hSnapshot == INVALID_HANDLE_VALUE)
		return std::nullopt;
	Process32First(hSnapshot,&PE32);
	do
    {
        if(PE32.szExeFile == InProcessName)
            return PE32;
        
    } while(Process32Next(hSnapshot,&PE32));
	CloseHandle(hSnapshot);
	return std::nullopt;
}

std::optional<uintptr_t> MemoryHelper::GetModuleAddress(std::wstring_view InModuleName,const uint32_t ProcessId)
{
	MODULEENTRY32W ME32;
    ME32.dwSize = sizeof(MODULEENTRY32);
    
    void* hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,ProcessId);
    if(hSnapshot == INVALID_HANDLE_VALUE)
        return -1;

    Module32Next(hSnapshot,&ME32);
    do
    {
        if(InModuleName == ME32.szModule)
        {
            return reinterpret_cast<uintptr_t>(ME32.modBaseAddr);
        }
    } while(Module32Next(hSnapshot,&ME32));

	return std::nullopt;
}

std::optional<MODULEENTRY32W> MemoryHelper::GetME32(std::wstring_view InModuleName, const uint32_t ProcessId)
{
	MODULEENTRY32W ME32;
    ME32.dwSize = sizeof(MODULEENTRY32);
    
    void* hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,ProcessId);
    if(hSnapshot == INVALID_HANDLE_VALUE)
        return std::nullopt;

    Module32Next(hSnapshot,&ME32);
    do
    {
        if(InModuleName == ME32.szModule)
        {
            return ME32;
        }
    } while(Module32Next(hSnapshot,&ME32));

	return std::nullopt;
}

bool MemoryHelper::EnableDebugPrivileges(void* ProcessHandle) noexcept
{
	void* hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
	
    const bool TokenSuccess = OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES, &hToken);
    const bool LUPVSuccess = LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool AdjustTokenValueSuccess = AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), nullptr, nullptr);
    CloseHandle(ProcessHandle);
    CloseHandle(hToken);
	if(GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return false;
	return TokenSuccess && LUPVSuccess && AdjustTokenValueSuccess;
}

std::optional<void*> MemoryHelper::OpenProcess(const uint32_t DesiredAccess, const bool InheritHandle, std::wstring_view InProcessName) noexcept
{
	PROCESSENTRY32W PE32;
	PE32.dwSize = sizeof(PROCESSENTRY32W);
	void* hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(hSnapshot == INVALID_HANDLE_VALUE)
		return std::nullopt;
	Process32First(hSnapshot,&PE32);
	do
    {
        if(PE32.szExeFile == InProcessName)
        {
        	void* hProcess = ::OpenProcess(DesiredAccess,InheritHandle,PE32.th32ProcessID);
        	if(hProcess == nullptr)
				return std::nullopt;
			return hProcess;
        }
        
    } while(Process32Next(hSnapshot,&PE32));
	CloseHandle(hSnapshot);
	return std::nullopt;
}

std::optional<void*> MemoryHelper::OpenProcess(const uint32_t DesiredAccess, const bool InheritHandle,
	const uint32_t InProcessId) noexcept
{
	void* hProcess = ::OpenProcess(DesiredAccess,InheritHandle,InProcessId);
	if(hProcess == nullptr)
		return std::nullopt;
	return hProcess;
}

