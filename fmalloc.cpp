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

#if ULONG_MAX / 2 < LONG_MAX
#error `unsigned long` too narrow.  Need new approach.
#endif

unsigned long distance(long x, long y) {
  return (x > y) ? (unsigned long)x - (unsigned long)y
                 : (unsigned long)y - (unsigned long)x;
}

#define MAPFILE_MAX_LOADED_BYTES 1073741824ull
#define MAPFILE_PAGE_SIZE 65536

struct MapFileDescriptor {
  int file_descriptor;
  HANDLE mapping_handle;
};

MapFileDescriptor INVALID_MAPFILE = {-1, NULL};

LPVOID fmalloced_base = nullptr;
MapFileDescriptor swap_file;
std::vector<HANDLE> views;
std::vector<long> views_last_swap;
HANDLE exception_handler = NULL;
size_t pages = 0;

long time = 0;

CRITICAL_SECTION memory_critical_section;

static O1HeapInstance *instance = NULL;

#define DWORD_HI(x) (x >> 32)
#define DWORD_LO(x) ((x)&0xffffffff)

size_t inline get_view_to_map(void *address) {
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

  // Movie file position to the new end. These calls do NOT result in the actual
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

MapFileDescriptor open_map_file(const char *filepath, size_t max_size) {
  struct _stat64 st;

  if (_stat64(filepath, &st) < 0 || st.st_size < max_size) {
    // try to create it
    int fd = _open(filepath, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
      return INVALID_MAPFILE;
    }

    if (fallocate((HANDLE)_get_osfhandle(fd), max_size) != 0) {
      return INVALID_MAPFILE;
    }
    _close(fd);

    if (_stat64(filepath, &st) < 0) {
      return INVALID_MAPFILE;
    }
  }

  int fd = _open(filepath, O_RDWR, 0644);
  if (fd < 0) {
    return INVALID_MAPFILE;
  }

  HANDLE section =
      CreateFileMapping((HANDLE)_get_osfhandle(fd), nullptr, PAGE_READWRITE,
                        DWORD_HI(max_size), DWORD_LO(max_size), nullptr);
  if (NULL == section) {
    return INVALID_MAPFILE;
  }
  return {fd, section};
}

void close_map_file(MapFileDescriptor map_file) {
  CloseHandle(map_file.mapping_handle);
  _close(map_file.file_descriptor);
}

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

// THE SHADOW!
// The handler is handled by process, so it's not thread safe
static LONG CALLBACK
ShadowExceptionHandler(PEXCEPTION_POINTERS exception_pointers) {
  void *addr =
      (void *)(exception_pointers->ExceptionRecord->ExceptionInformation[1]);

  size_t view_index = get_view_to_map(addr);

  if (view_index >= pages)
    return EXCEPTION_CONTINUE_SEARCH;

  //We got work to do. Lock
  EnterCriticalSection(&memory_critical_section);

  time += 1;

  size_t view_to_swap = get_view_to_unmap();

  HANDLE &swap_handle = views[view_to_swap];

  UnmapViewOfFile2(GetCurrentProcess(), swap_handle,
                   MEM_PRESERVE_PLACEHOLDER);

  swap_handle = MapFile(swap_file.mapping_handle, nullptr,
                        (char *)fmalloced_base + view_index * MAPFILE_PAGE_SIZE,
                        view_index * MAPFILE_PAGE_SIZE, MAPFILE_PAGE_SIZE,
                        MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE,
                          nullptr, 0);

  views_last_swap[view_to_swap] = time;

  LeaveCriticalSection(&memory_critical_section);

  return EXCEPTION_CONTINUE_EXECUTION;
}

void nemory_mapping_init(const char *files_prefix, size_t size) {
  swap_file = open_map_file(files_prefix, size);

  pages = (size / MAPFILE_PAGE_SIZE);

  // allocate the whole address space
  fmalloced_base =
      VAlloc(nullptr, nullptr, size,
             MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0);

  // split it in file pages
  for (size_t index = 0; index < pages - 1; ++index) {
    if (!VirtualFree((char *)fmalloced_base + index * MAPFILE_PAGE_SIZE,
                     MAPFILE_PAGE_SIZE,
                     MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
      int error = GetLastError();
      fmalloced_base = nullptr;
    };
  }

  size_t pages_to_load = MAPFILE_MAX_LOADED_BYTES / MAPFILE_PAGE_SIZE;
  views.resize(pages_to_load);
  views_last_swap.resize(pages_to_load, 0);

  for (size_t index = 0; index < pages_to_load; ++index) {
    views[index] = MapFile(swap_file.mapping_handle, nullptr,
                           (char*)fmalloced_base + index * MAPFILE_PAGE_SIZE,
                           index * MAPFILE_PAGE_SIZE, MAPFILE_PAGE_SIZE,
                           MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (views[index] == NULL)
    {
      int error = GetLastError();
      fmalloced_base = nullptr;
    }
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
