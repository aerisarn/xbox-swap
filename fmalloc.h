#ifndef _FMALLOC_H
#define _FMALLOC_H

#include <stdint.h>

#ifdef XBOXFMALLOC_EXPORTS
#define XBOXFMALLOC_API _declspec(dllexport)
#else
#define XBOXFMALLOC_API _declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	XBOXFMALLOC_API void  fmalloc_init(const char* filepath, size_t max_size);
	XBOXFMALLOC_API void* fmalloc(size_t size);
        XBOXFMALLOC_API void* frealloc(void *_Block, size_t _Size);
	XBOXFMALLOC_API void  ffree(void* addr);
	XBOXFMALLOC_API void  fmalloc_close();

#ifdef __cplusplus
}
#endif

#endif
