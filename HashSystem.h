#pragma once

typedef UINT32	t_hash[5];

namespace ns_BNCS {
	namespace HASH {
		void data_hash(t_hash *result, const void *src, const int len, bool broken_sha);
		bool matchhash(t_hash *a, t_hash *b);
	}
}