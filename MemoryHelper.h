#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOGDICAPMASKS
#define NOSYSMETRICS
#define NOMENUS
#define NOICONS
#define NOSYSCOMMANDS
#define NORASTEROPS
#define OEMRESOURCE
#define NOATOM
#define NOCLIPBOARD
#define NOCOLOR
#define NOCTLMGR
#define NODRAWTEXT
#define NOKERNEL
#define NONLS
#define NOMEMMGR
#define NOMETAFILE
#define NOOPENFILE
#define NOSCROLL
#define NOSERVICE
#define NOSOUND
#define NOTEXTMETRIC
#define NOWH
#define NOCOMM
#define NOKANJI
#define NOHELP
#define NOPROFILER
#define NODEFERWINDOWPOS
#define NOMCX
#define NORPC
#define NOPROXYSTUB
#define NOIMAGE
#define NOTAPE
#define NOMINMAX
#define STRICT

#include <Windows.h>
#include <optional>
#include <sstream>
#include <memory>
#include <TlHelp32.h>


class MemoryHelper final 
{
public:
	MemoryHelper(const MemoryHelper&) = delete;
	MemoryHelper& operator =(const MemoryHelper&) = delete;
	MemoryHelper() = default;

	[[nodiscard]] static std::optional<uint32_t> GetProcessId(std::wstring_view InProcessName);

	[[nodiscard]] static std::optional<PROCESSENTRY32W> GetPE32(std::wstring_view InProcessName);

	[[nodiscard]] static std::optional<uintptr_t> GetModuleAddress(std::wstring_view InModuleName,const uint32_t ProcessId);

	[[nodiscard]] static std::optional<MODULEENTRY32W> GetME32(std::wstring_view InModuleName,const uint32_t ProcessId);

	template<typename T>
	[[nodiscard]] static std::optional<T> Read(void* ProcessHandle, const uintptr_t Address) noexcept;

	template<typename T>
	static bool Write(void* ProcessHandle, const uintptr_t Address, const T& InValue) noexcept;

	static bool EnableDebugPrivileges(void* ProcessHandle) noexcept;
	
	//To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege privilege.
	[[nodiscard]]static std::optional<void*> OpenProcess(const uint32_t DesiredAccess, const bool InheritHandle, std::wstring_view InProcessName) noexcept;

	//To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege privilege.
	[[nodiscard]]static std::optional<void*> OpenProcess(const uint32_t DesiredAccess, const bool InheritHandle, const uint32_t InProcessId) noexcept;
};

template <typename T>
[[nodiscard]] std::optional<T> MemoryHelper::Read(void* ProcessHandle, const uintptr_t Address) noexcept
{
	T Buffer;
	DWORD PrevProtect;
	VirtualProtectEx(ProcessHandle,reinterpret_cast<void*>(Address),sizeof(T),PAGE_EXECUTE_READ,&PrevProtect);
	bool Success = ::ReadProcessMemory(ProcessHandle, reinterpret_cast<const void*>(Address),std::addressof(Buffer),sizeof(T),nullptr);
	VirtualProtectEx(ProcessHandle,reinterpret_cast<void*>(Address),sizeof(T),PrevProtect,nullptr);
	if(Success)
		return std::optional<T>(std::move(Buffer));
	return std::nullopt;
}

template <typename T>
bool MemoryHelper::Write(void* ProcessHandle,const uintptr_t Address, const T& InValue) noexcept
{
	DWORD PrevProtect;
	VirtualProtectEx(ProcessHandle,reinterpret_cast<void*>(Address),sizeof(T),PAGE_EXECUTE_READWRITE,&PrevProtect);
	bool Success = ::WriteProcessMemory(ProcessHandle,reinterpret_cast<void*>(Address),std::addressof(InValue),sizeof(T),nullptr);
	VirtualProtectEx(ProcessHandle,reinterpret_cast<void*>(Address),sizeof(T),PrevProtect,nullptr);
	return Success;
}
