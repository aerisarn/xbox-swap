#include "fmalloc.h"
#include "o1heap.h"

#include <io.h>
#include <sys/types.h>
#include <windows.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <string>
#include <vector>

#ifdef _XBOX_UWP
extern "C" {
WINBASEAPI
_Ret_maybenull_ PVOID WINAPI AddVectoredExceptionHandler(
    _In_ ULONG First, _In_ PVECTORED_EXCEPTION_HANDLER Handler);

WINBASEAPI
ULONG
WINAPI
RemoveVectoredExceptionHandler(_In_ PVOID Handle);
}
#endif

#ifdef _XBOX_UWP
#define MapFile MapViewOfFile3FromApp
#else
#define MapFile MapViewOfFile3
#endif

#ifdef _XBOX_UWP
#define VAlloc VirtualAlloc2FromApp
#else
#define VAlloc VirtualAlloc2
#endif

#if ULONG_MAX / 2 < LONG_MAX
#error `unsigned long` too narrow.  Need new approach.
#endif

unsigned long distance(long x, long y) {
  return (x > y) ? (unsigned long)x - (unsigned long)y
                 : (unsigned long)y - (unsigned long)x;
}

#define MAPFILE_MAX_LOADED_BYTES 536870912
#define MAPFILE_PAGE_SIZE 4096

HANDLE INVALID_MAPFILE = NULL;

LPVOID fmalloced_base = nullptr;
HANDLE swap_file;
std::vector<HANDLE> views;
std::vector<size_t> view_page_index;
std::vector<long> views_last_swap;
HANDLE exception_handler = NULL;
size_t pages = 0;

long time = 0;

CRITICAL_SECTION memory_critical_section;

static O1HeapInstance *instance = NULL;

#define DWORD_HI(x) (x >> 32)
#define DWORD_LO(x) ((x)&0xffffffff)

size_t inline get_view_to_map(void* address) {
	return ((unsigned long long)address - (unsigned long long)fmalloced_base) /
		MAPFILE_PAGE_SIZE;
}

size_t inline get_view_to_unmap() {
  size_t index = 0;
  long max_distance = 0;
  for (size_t v = 0; v < views_last_swap.size(); ++v) {
    long component_distance = distance(time, views_last_swap.at(v));
    if (component_distance > max_distance) {
      index = v;
      max_distance = component_distance;
    }
  }
  return index;
}

int fallocate(HANDLE hndl, long long int size_to_reserve) {
  if (size_to_reserve <= 0)
    return 0;

  LARGE_INTEGER minus_one = {0}, zero = {0};
  minus_one.QuadPart = -1;

  // Get the current file position
  LARGE_INTEGER old_pos = {0};
  if (!SetFilePointerEx(hndl, zero, &old_pos, FILE_CURRENT))
    return -1;

  // Move file position to the new end. These calls do NOT result in the actual
  // allocation of new blocks, but they must succeed.
  LARGE_INTEGER new_pos = {0};
  new_pos.QuadPart = size_to_reserve;
  if (!SetFilePointerEx(hndl, new_pos, NULL, FILE_END))
    return -1;
  if (!SetEndOfFile(hndl))
    return -1;

  if (!SetFilePointerEx(hndl, minus_one, NULL, FILE_END))
    return -1;
  char initializer_buf[1] = {1};
  DWORD written = 0;
  if (!WriteFile(hndl, initializer_buf, 1, &written, NULL))
    return -1;

  return 0;
}

void nemory_mapping_init(const char *files_prefix, size_t size);
void nemory_mapping_deinit();

/* init routine */
void fmalloc_init(const char *filepath, size_t max_size) {
  nemory_mapping_init(filepath, max_size);
  instance = o1heapInit(fmalloced_base, max_size);
  if (instance == NULL) {
    return;
  }

  if (!InitializeCriticalSectionAndSpinCount(&memory_critical_section,
                                             0x00000400)) {
    return;
  }
}

void *fmalloc(size_t size) {
  EnterCriticalSection(&memory_critical_section); // no time-out interval
  void *result = o1heapAllocate(instance, size);
  LeaveCriticalSection(&memory_critical_section);
  return result;
}

void ffree(void *addr) {
  EnterCriticalSection(&memory_critical_section); // no time-out interval
  o1heapFree(instance, addr);
  LeaveCriticalSection(&memory_critical_section);
}

void *frealloc(void *_Block, size_t _Size) {
  EnterCriticalSection(&memory_critical_section); // no time-out interval
  void *new_alloc = fmalloc(_Size);
  memcpy(new_alloc, _Block, _Size);
  ffree(_Block);
  LeaveCriticalSection(&memory_critical_section);
  return new_alloc;
}

XBOXFMALLOC_API void fmalloc_close() {
  instance = nullptr;
  nemory_mapping_deinit();
  DeleteCriticalSection(&memory_critical_section);
}

HANDLE open_map_file(const char* filepath, size_t max_size) {
	struct _stat64 st;
	std::wstring filepathw(filepath, filepath + strlen(filepath));
	if (_stat64(filepath, &st) < 0 || st.st_size < max_size) {
		// try to create it

		HANDLE hFile = CreateFileFromAppW(filepathw.c_str(),		// Name of the file
			(GENERIC_READ | GENERIC_WRITE),	// Open for writing
			0,								// Do not share
			NULL,							// Default security
			CREATE_ALWAYS,					// Overwrite existing
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
			NULL);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			return INVALID_MAPFILE;
		}

		if (fallocate(hFile, max_size) != 0) {
			return INVALID_MAPFILE;
		}

		CloseHandle(hFile);

		if (_stat64(filepath, &st) < 0) {
			return INVALID_MAPFILE;
		}
	}

	HANDLE hFile = CreateFileFromAppW(filepathw.c_str(),		// Name of the file
		(GENERIC_READ | GENERIC_WRITE),	// Open for writing
		0,								// Do not share
		NULL,							// Default security
		OPEN_EXISTING,					// Overwrite existing
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return INVALID_MAPFILE;
	}

	return hFile;
}

void close_map_file(HANDLE map_file) {
	CloseHandle(map_file);
}


// THE SHADOW!
// The handler is handled by process, so it's not thread safe
static LONG CALLBACK
ShadowExceptionHandler(PEXCEPTION_POINTERS exception_pointers) {
	void* addr =
		(void*)(exception_pointers->ExceptionRecord->ExceptionInformation[1]);

	size_t page_index = get_view_to_map(addr);

	if (page_index >= pages)
		return EXCEPTION_CONTINUE_SEARCH;

	//We got work to do. Lock
	EnterCriticalSection(&memory_critical_section);

	time += 1;

	size_t view_to_swap = time % views.size();
	HANDLE& swap_handle = views[view_to_swap];
	size_t swap_page_index = view_page_index[view_to_swap];

	OVERLAPPED write_address = { 0 };
	write_address.Pointer = (VOID*)((char*)0ull + swap_page_index * MAPFILE_PAGE_SIZE);
	DWORD written = 0;
	//Save content
	BOOL bResult = WriteFile(swap_file, swap_handle, MAPFILE_PAGE_SIZE, &written, &write_address);
	if (!bResult || written != MAPFILE_PAGE_SIZE)
	{
		int error = GetLastError();
		int debug = 0;
	}
	//Free old page
	bResult = VirtualFree(swap_handle, MAPFILE_PAGE_SIZE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
	if (!bResult)
	{
		int error = GetLastError();
		int debug = 0;
	}
	//Allocate new page
	swap_handle = VAlloc(
		GetCurrentProcess(),
		(char*)fmalloced_base + page_index * MAPFILE_PAGE_SIZE,
		MAPFILE_PAGE_SIZE,
		MEM_COMMIT | MEM_RESERVE | MEM_REPLACE_PLACEHOLDER,
		PAGE_READWRITE,
		nullptr,
		0
	);
	if (NULL == swap_handle)
	{
		int error = GetLastError();
		int debug = 0;
	}
	//Read page from file into memory
	OVERLAPPED read_address = { 0 };
	read_address.Pointer = (VOID*)((char*)0ull + page_index * MAPFILE_PAGE_SIZE);
	DWORD read = 0;
	bResult = ReadFile(swap_file, swap_handle, MAPFILE_PAGE_SIZE, &read, &read_address);
	if (!bResult || read != MAPFILE_PAGE_SIZE)
	{
		int error = GetLastError();
		int debug = 0;
	}
	view_page_index[view_to_swap] = page_index;

	LeaveCriticalSection(&memory_critical_section);

	return EXCEPTION_CONTINUE_EXECUTION;
}


void nemory_mapping_init(const char* files_prefix, size_t size) {
	swap_file = open_map_file(files_prefix, size);

	pages = (size / MAPFILE_PAGE_SIZE);

	// allocate the whole address space
	fmalloced_base =
		VAlloc(nullptr, nullptr, size,
			MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0);

	// split it in file pages
	for (size_t index = 0; index < pages - 1; ++index) {
		if (!VirtualFree((char*)fmalloced_base + index * MAPFILE_PAGE_SIZE,
			MAPFILE_PAGE_SIZE,
			MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
			int error = GetLastError();
			fmalloced_base = nullptr;
		};
	}

	size_t pages_to_load = MAPFILE_MAX_LOADED_BYTES / MAPFILE_PAGE_SIZE;
	views.resize(pages_to_load);
	view_page_index.resize(pages_to_load);
	views_last_swap.resize(pages_to_load, 0);

	for (size_t index = 0; index < pages_to_load; ++index) {
		views[index] = VAlloc(
			GetCurrentProcess(),
			(char*)fmalloced_base + index * MAPFILE_PAGE_SIZE,
			MAPFILE_PAGE_SIZE,
			MEM_COMMIT | MEM_RESERVE | MEM_REPLACE_PLACEHOLDER,
			PAGE_READWRITE,
			nullptr,
			0
		);
		if (views[index] == NULL)
		{
			int error = GetLastError();
			fmalloced_base = nullptr;
		}
		view_page_index[index] = index;
	}

	exception_handler =
		AddVectoredExceptionHandler(TRUE, &ShadowExceptionHandler);
}

void nemory_mapping_deinit() {
  RemoveVectoredExceptionHandler(exception_handler);

  exception_handler = NULL;

  for (size_t index = 0; index < views.size(); ++index) {
    UnmapViewOfFile(views.at(index));
  }

  VirtualFree(fmalloced_base, 0, MEM_RELEASE);
  fmalloced_base = nullptr;

  close_map_file(swap_file);
}
