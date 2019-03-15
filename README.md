# HashSystem

```
#ifdef _DEBUG
	#pragma comment(lib, "libs/debug/HashSystem.lib")
#else
	#pragma comment(lib, "libs/release/HashSystem.lib")
#endif

//Defines
typedef UINT32	t_hash[5];

#include "libs/HashSystem.h"
#include "libs/BigInt.h"
#include "libs/srp.h"
```

```
void TestValues(void *salt, void *verifier) {
	char Username[] = "SRP3TEST";
	char Password[] = "ASDFASDF";

	COMMON::LARGEMATH::BigInt s = COMMON::LARGEMATH::BigInt((unsigned char *)salt, BIGINT_SIZE, 4, false);
	//COMMON::LARGEMATH::BigInt v = COMMON::LARGEMATH::BigInt((BYTE *)verifier, BIGINT_SIZE, 4, false);
	unsigned char data[40];
	std::string outdata = "";
	//s.getData(data, 32);
	//StringToHex((unsigned char *)data, 32, outdata);
	//std::printf("S1: %s\n", outdata.c_str());
	//outdata = "";

	ns_BNCS::HASH::BnetSRP3 Client(Username, Password);

	Client.setSalt(s);

	COMMON::LARGEMATH::BigInt v2 = Client.getVerifier();
	COMMON::LARGEMATH::BigInt s2 = Client.getSalt();

	ns_BNCS::HASH::BnetSRP3 Server(Username, s);

	COMMON::LARGEMATH::BigInt A = Client.getClientSessionPublicKey();
	COMMON::LARGEMATH::BigInt B = Server.getServerSessionPublicKey(v2);

	COMMON::LARGEMATH::BigInt K1 = Client.getHashedClientSecret(B);
	COMMON::LARGEMATH::BigInt K2 = Server.getHashedServerSecret(A, v2);

	outdata = "";
	K1.getData(data, 40);
	StringToHex((unsigned char *)data, 40, outdata);
	std::printf("K1: %s\n", outdata.c_str());
	outdata = "";

	K2.getData(data, 40);
	StringToHex((unsigned char *)data, 40, outdata);
	std::printf("K2: %s\n", outdata.c_str());

	COMMON::LARGEMATH::BigInt M = Client.getClientPasswordProof(A, B, K1);

	COMMON::LARGEMATH::BigInt MV = Server.getClientPasswordProof(A, B, K2); //server verify m1
	COMMON::LARGEMATH::BigInt M2 = Server.getServerPasswordProof(A, M, K2);

	COMMON::LARGEMATH::BigInt M3 = Client.getServerPasswordProof(A, M, K1);

	assert(K1 == K2);
	assert(M == MV);
	assert(M2 == M3);
}
```
