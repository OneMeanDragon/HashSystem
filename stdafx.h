// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

//Additional Defines
#define ROL(nr, shift)	((nr << shift) | (nr >> (32 - shift)))
#define F1(b, c, d) ((b & c) | (~b & d))
#define F2(d, c, b) (d ^ c ^ b)
#define F3(c, b, d)  ((c & b) | (d & c) | (d & b))
#define F4(w, x, y, z) (w ^ x ^ y ^ z)

#define RENDIAN_DWORD(value) (value = (((value) & 0xff000000) >> 24) | (((value) & 0x00ff0000) >>  8) | (((value) & 0x0000ff00) <<  8) | (((value) & 0x000000ff) << 24))

// Windows Header Files
#include <windows.h>

typedef UINT32	t_hash[5];


// reference additional headers your program requires here
#include "HashSystem.h"
