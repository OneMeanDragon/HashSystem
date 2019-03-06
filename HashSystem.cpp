// HashSystem.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"


namespace ns_BNCS {
	namespace HASH {
		void data_hash(t_hash *result, const void *src, const int len, bool broken_sha) {
			unsigned int a = 0x67452301u;
			unsigned int b = 0xefcdab89u;
			unsigned int c = 0x98badcfeu;
			unsigned int d = 0x10325476u;
			unsigned int e = 0xc3d2e1f0u;
			unsigned int g;
			int i;

			unsigned char bBuffer[320] = { 0 };
			memcpy(bBuffer, src, len);
			unsigned int *lpdwBuffer = (unsigned int *)bBuffer;

			for (i = 0; i < 80; ++i) {
				if (i < 64)
					if (broken_sha) {
						lpdwBuffer[i + 16] = ROL(1, F4(lpdwBuffer[i], lpdwBuffer[i + 8], lpdwBuffer[i + 2], lpdwBuffer[i + 13]) % 32);
					}
					else {
						lpdwBuffer[i + 16] = ROL(F4(lpdwBuffer[i], lpdwBuffer[i + 8], lpdwBuffer[i + 2], lpdwBuffer[i + 13]) % 32, 1);
					}
				if (i < 20)
					g = lpdwBuffer[i] + ROL(a, 5) + e + F1(b, c, d) + 0x5a827999lu;
				else if (i < 40)
					g = F2(d, c, b) + e + ROL(g, 5) + lpdwBuffer[i] + 0x6ed9eba1lu;
				else if (i < 60)
					g = lpdwBuffer[i] + ROL(g, 5) + e + F3(c, b, d) - 0x70e44324lu;
				else
					g = F2(d, c, b) + e + ROL(g, 5) + lpdwBuffer[i] - 0x359d3e2alu;
				e = d;
				d = c;
				c = ROL(b, 30);
				b = a;
				a = g;
			}

			(*result)[0] = 0x67452301u + g;
			(*result)[1] = 0xefcdab89u + b;
			(*result)[2] = 0x98badcfeu + c;
			(*result)[3] = 0x10325476u + d;
			(*result)[4] = 0xc3d2e1f0u + e;
		}
		bool matchhash(t_hash *a, t_hash *b) {
			if (((*a)[0] == (*b)[0]) && ((*a)[1] == (*b)[1]) && ((*a)[2] == (*b)[2]) && ((*a)[3] == (*b)[3]) && ((*a)[4] == (*b)[4])) {
				return true;
			}
			return false;
		}
	}
}
