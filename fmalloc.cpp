#include "fmalloc.h"
#include "o1heap.h"

#include <io.h>
#include <windows.h>
#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <vector>
#include <string>

#define MAPFILE_SIZE 1073741824ull

struct MapFileDescriptor
{
	int file_descriptor;
	HANDLE mapping_handle;
};

MapFileDescriptor INVALID_MAPFILE = { -1, NULL };

LPVOID fmalloced_base = nullptr;
std::vector<MapFileDescriptor> descriptors;
HANDLE view_handle = NULL;
HANDLE exception_handler = NULL;

static O1HeapInstance* instance = NULL;

#ifdef __USE_FILE_OFFSET64
# define DWORD_HI(x) (x >> 32)
# define DWORD_LO(x) ((x) & 0xffffffff)
#else
# define DWORD_HI(x) (0)
# define DWORD_LO(x) (x)
#endif

size_t inline get_file_to_map(void* address)
{
	return ((unsigned long long)address - (unsigned long long)fmalloced_base) / MAPFILE_SIZE;
}


int fallocate(HANDLE hndl, long long int size_to_reserve)
{
    if (size_to_reserve <= 0)
        return 0;

    LARGE_INTEGER minus_one = {0}, zero = {0};
    minus_one.QuadPart = -1;

    // Get the current file position
    LARGE_INTEGER old_pos = {0};
    if (!SetFilePointerEx(hndl, zero, &old_pos, FILE_CURRENT))
        return -1;

    // Movie file position to the new end. These calls do NOT result in the actual allocation of
    // new blocks, but they must succeed.
    LARGE_INTEGER new_pos = {0};
    new_pos.QuadPart      = size_to_reserve;
    if (!SetFilePointerEx(hndl, new_pos, NULL, FILE_END))
        return -1;
    if (!SetEndOfFile(hndl))
        return -1;

    if (!SetFilePointerEx(hndl, minus_one, NULL, FILE_END))
        return -1;
    char  initializer_buf[1] = {1};
    DWORD written            = 0;
    if (!WriteFile(hndl, initializer_buf, 1, &written, NULL))
        return -1;

    return 0;
}

void nemory_mapping_init(const char* files_prefix, size_t size);
void nemory_mapping_deinit();

/* init routine */
void fmalloc_init(const char* filepath, size_t max_size)
{
	nemory_mapping_init(filepath, max_size);
	instance = o1heapInit(fmalloced_base, max_size);
	if (instance == NULL)
	{
		return;
	}
}

void *fmalloc(size_t size)
{
	return o1heapAllocate(instance, size);
}

void ffree(void *addr)
{
	o1heapFree(instance, addr);
}

XBOXFMALLOC_API void  fmalloc_close()
{
	instance = nullptr;
	nemory_mapping_deinit();
}

MapFileDescriptor open_map_file(const char* filepath, size_t max_size)
{
	struct _stat64 st;

	if (_stat64(filepath, &st) < 0 || st.st_size < max_size)
	{
		//try to create it
		int fd = _open(filepath, O_RDWR | O_CREAT, 0644);
		if (fd < 0)
		{
			return INVALID_MAPFILE;
		}

		if (fallocate((HANDLE)_get_osfhandle(fd), max_size) != 0)
		{
			return INVALID_MAPFILE;
		}
		_close(fd);


		if (_stat64(filepath, &st) < 0)
		{
			return INVALID_MAPFILE;
		}
	}

	int fd = _open(filepath, O_RDWR, 0644);
	if (fd < 0) {
		return INVALID_MAPFILE;
	}

	HANDLE section = CreateFileMapping(
		(HANDLE)_get_osfhandle(fd),
		nullptr,
		PAGE_READWRITE,
		DWORD_HI(max_size), DWORD_LO(max_size), nullptr
	);
	if (NULL == section)
	{
		return INVALID_MAPFILE;
	}
	return  { fd, section };
}

void close_map_file(MapFileDescriptor map_file)
{
	CloseHandle(map_file.mapping_handle);
	_close(map_file.file_descriptor);
}

//THE SHADOW!
static LONG CALLBACK
ShadowExceptionHandler(PEXCEPTION_POINTERS exception_pointers) {
	void* addr =
		(void*)(exception_pointers->ExceptionRecord->ExceptionInformation[1]);

	size_t file_index = get_file_to_map(addr);

	if (file_index >= descriptors.size())
		return EXCEPTION_CONTINUE_SEARCH;

	UnmapViewOfFile2(GetCurrentProcess(), view_handle, MEM_PRESERVE_PLACEHOLDER);

	view_handle = MapViewOfFile3(
		descriptors.at(file_index).mapping_handle,
		nullptr,
		(char*)fmalloced_base + file_index * MAPFILE_SIZE,
		0,
		MAPFILE_SIZE,
		MEM_REPLACE_PLACEHOLDER,
		PAGE_READWRITE,
		nullptr, 0);

	return EXCEPTION_CONTINUE_EXECUTION;
}

void nemory_mapping_init(const char* files_prefix, size_t size)
{
	size_t pages = (size / MAPFILE_SIZE);
	pages += (size % MAPFILE_SIZE > 0) ? 1 : 0;
	descriptors.resize(pages);
	for (size_t index = 0; index < pages; ++index)
	{
		std::string file_name = files_prefix + std::to_string(index);
		descriptors[index] = open_map_file(file_name.c_str(), MAPFILE_SIZE);
	}

	//allocate the whole address space
	fmalloced_base = VirtualAlloc2(
		nullptr,
		nullptr,
		pages * MAPFILE_SIZE,
		MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
		PAGE_NOACCESS,
		nullptr, 0
	);

	//split it in file pages
	for (size_t index = 0; index < pages - 1; ++index)
	{
		if (!VirtualFree(
			(char*)fmalloced_base + index * MAPFILE_SIZE,
			MAPFILE_SIZE,
			MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER
		))
		{
			int error = GetLastError();
			fmalloced_base = nullptr;
		};
	}

	//load first page
	view_handle = MapViewOfFile3(
		descriptors.at(0).mapping_handle,
		nullptr,
		fmalloced_base,
		0,
		MAPFILE_SIZE,
		MEM_REPLACE_PLACEHOLDER,
		PAGE_READWRITE,
		nullptr, 0
	);

	exception_handler = AddVectoredExceptionHandler(TRUE, &ShadowExceptionHandler);
}

void nemory_mapping_deinit()
{
	RemoveVectoredExceptionHandler(exception_handler);
	exception_handler = NULL;

	UnmapViewOfFile2(GetCurrentProcess(), view_handle, MEM_PRESERVE_PLACEHOLDER);
	view_handle = NULL;

	size_t pages = descriptors.size();
	VirtualFree(fmalloced_base, 0, MEM_RELEASE);
	fmalloced_base = nullptr;

	for (auto& descriptor : descriptors)
	{
		close_map_file(descriptor);
	}
}
