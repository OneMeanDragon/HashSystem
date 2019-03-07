// HashSystem.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"


namespace ns_BNCS {
	namespace HASH {
		void initial_values(t_hash *result)
		{
			(*result)[0] = 0x67452301u;
			(*result)[1] = 0xefcdab89u;
			(*result)[2] = 0x98badcfeu;
			(*result)[3] = 0x10325476u;
			(*result)[4] = 0xc3d2e1f0u;
		}

		void set_buffer(const void *input, const int len, UINT32 *buffer, bool broken_sha)
		{
			UCHAR tmpBuffer[320];
			if (broken_sha) {
				ZeroMemory(tmpBuffer, 320);
				memcpy(tmpBuffer, input, len);
				memcpy(buffer, tmpBuffer, 320);
				return;
			}
			ZeroMemory(tmpBuffer, (16 * 4));
			memcpy(tmpBuffer, input, len);

			UINT32 i;
			UINT32 pos;

			for (pos = 0, i = 0; i < 16; i++)
			{
				buffer[i] = 0;

				{
					if (pos < len)
						buffer[i] |= ((UINT32)tmpBuffer[pos]) << 24;
					else if (pos == len)
						buffer[i] |= ((UINT32)0x80000000);
				}
				pos++;
				{
					if (pos < len)
						buffer[i] |= ((UINT32)tmpBuffer[pos]) << 16;
					else if (pos == len)
						buffer[i] |= ((UINT32)0x800000);
				}
				pos++;
				{
					if (pos < len)
						buffer[i] |= ((UINT32)tmpBuffer[pos]) << 8;
					else if (pos == len)
						buffer[i] |= ((UINT32)0x8000);
				}
				pos++;
				{
					if (pos < len)
						buffer[i] |= ((UINT32)tmpBuffer[pos]);
					else if (pos == len)
						buffer[i] |= ((UINT32)0x80);
				}
				pos++;
			}
		}

		void digest_hash(t_hash *result, UINT32 *buffer, bool broken_sha) {
			UINT32 a = (*result)[0];
			UINT32 b = (*result)[1];
			UINT32 c = (*result)[2];
			UINT32 d = (*result)[3];
			UINT32 e = (*result)[4];
			UINT32 g = 0;
			int i;

			for (i = 0; i < 80; ++i) {
				if (i < 64)
					if (broken_sha) {
						buffer[i + 16] = ROL(1, F4(buffer[i], buffer[i + 8], buffer[i + 2], buffer[i + 13]) % 32);
					}
					else {
						buffer[i + 16] = ROL(F4(buffer[i], buffer[i + 8], buffer[i + 2], buffer[i + 13]) % 32, 1);
					}
				if (i < 20)
					g = buffer[i] + ROL(a, 5) + e + F1(b, c, d) + 0x5a827999lu;
				else if (i < 40)
					g = F2(d, c, b) + e + ROL(g, 5) + buffer[i] + 0x6ed9eba1lu;
				else if (i < 60)
					g = buffer[i] + ROL(g, 5) + e + F3(c, b, d) - 0x70e44324lu;
				else
					g = F2(d, c, b) + e + ROL(g, 5) + buffer[i] - 0x359d3e2alu;
				e = d;
				d = c;
				c = ROL(b, 30);
				b = a;
				a = g;
			}

			(*result)[0] += g;
			(*result)[1] += b;
			(*result)[2] += c;
			(*result)[3] += d;
			(*result)[4] += e;
		}

		void data_hash(t_hash *result, const void *src, const int len, bool broken_sha)
		{
			initial_values(result);
			UINT32 SHABuffer[80];
			if (broken_sha) {
				set_buffer(src, len, SHABuffer, true);
				digest_hash(result, SHABuffer, true);
			}
			else {
				UINT32 original_length = len;
				UINT32 size = len;
				UINT32 inc;
				const UCHAR * data;
				data = (const UCHAR *)(src);

				while (size > 0) {
					if (size >= 64) {
						inc = 64;
					}
					else {
						inc = size;
					}

					if (size >= 64)
					{
						set_buffer(data, inc, SHABuffer, false);
						digest_hash(result, SHABuffer, false);
					}
					else if (size > 55) {

						set_buffer(data, inc, SHABuffer, false);
						digest_hash(result, SHABuffer, false);

						// now use blizz variant as we only wanna fill in zeros
						set_buffer(data, 0, SHABuffer, true);
						SHABuffer[15] |= (UINT32)(len * 8);
						digest_hash(result, SHABuffer, false);
					}
					else {
						set_buffer(data, inc, SHABuffer, false);
						SHABuffer[15] |= (UINT32)(len * 8);
						digest_hash(result, SHABuffer, false);
					}
					data += inc;
					size -= inc;
				}
			}
		}

		void little_endian_sha1(t_hash *hashout, const void *datain, UINT32 size)
		{
			data_hash(hashout, datain, size, false);
			for (int i = 0; i < 5; i++)
			{
				RENDIAN_DWORD((*hashout)[i]);
			}
		}

		bool matchhash(t_hash *a, t_hash *b) {
			if (((*a)[0] == (*b)[0]) && ((*a)[1] == (*b)[1]) && ((*a)[2] == (*b)[2]) && ((*a)[3] == (*b)[3]) && ((*a)[4] == (*b)[4])) {
				return true;
			}
			return false;
		}
	}
}
