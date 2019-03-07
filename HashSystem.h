#pragma once

namespace ns_BNCS {
	namespace HASH {
		void initial_values(t_hash *result);
		void set_buffer(const void *input, const int len, UINT32 *buffer, bool broken_sha);
		void digest_hash(t_hash *result, UINT32 *buffer, bool broken_sha);
		void data_hash(t_hash *result, const void *src, const int len, bool broken_sha);
		bool matchhash(t_hash *a, t_hash *b);
	}
}