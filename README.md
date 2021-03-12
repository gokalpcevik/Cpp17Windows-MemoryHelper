# Cpp17Windows-MemoryHelper
This is a simple class to read/write memory with Win32 API.

Example of usage(No error checking):
```cpp
struct Vec3
{
  float x,y,z;
};
/* Most functions return std::optional so we use the overloaded * operator to get the underlying values. 
  You can also do this:
  auto PiD = MemoryHelper::GetProcessId(L"some_process.exe");
  and then do *PiD or PiD.value()
*/
uint32_t PiD = *MemoryHelper::GetProcessId(L"some_process.exe");
uintptr_t MiD = *MemoryHelper::GetModuleAddress(L"some_module.dll",PiD);
void* handle = *MemoryHelper::OpenProcess(PROCESS_VM_READ,false,PiD);
Vec3 value = *MemoryHelper::Read<Vec3>(handle,MiD + 0xFFF69);
CloseHandle(handle);
```
For error checking, take a look at std::optional. Most functions return std::optional.
```cpp
std::optional<uint32_t> PiD = MemoryHelper::GetProcessId(L"some_process.exe"); 
if(PiD)
{
  // Do stuff
}
```
