/*
 * Class that implements the SRP-3 based authentication schema
 * used by Blizzards WarCraft 3. Implementations is based upon
 * public information available under
 * http://www.javaop.com/@ron/documents/SRP.html
 *
 * Copyright (C) 2008 - Olaf Freyer
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 */

#pragma once 

#ifndef __BNET_SRP3_INCLUDED__
#define __BNET_SRP3_INCLUDED__


namespace ns_BNCS
{
	namespace HASH {

		class BnetSRP3
		{
		public:
			BnetSRP3(const char* username, ::COMMON::LARGEMATH::BigInt& salt);
			BnetSRP3(const std::string& username, COMMON::LARGEMATH::BigInt& salt);
			BnetSRP3(const char* username, const char* password);
			BnetSRP3(const std::string& username, const std::string& password);
			~BnetSRP3();
			COMMON::LARGEMATH::BigInt getVerifier() const;
			COMMON::LARGEMATH::BigInt getSalt() const;
			void setSalt(COMMON::LARGEMATH::BigInt salt);
			COMMON::LARGEMATH::BigInt getClientSessionPublicKey() const;
			COMMON::LARGEMATH::BigInt getServerSessionPublicKey(COMMON::LARGEMATH::BigInt& v);
			COMMON::LARGEMATH::BigInt getHashedClientSecret(COMMON::LARGEMATH::BigInt& B) const;
			COMMON::LARGEMATH::BigInt getHashedServerSecret(COMMON::LARGEMATH::BigInt& A, COMMON::LARGEMATH::BigInt& v);
			COMMON::LARGEMATH::BigInt getClientPasswordProof(COMMON::LARGEMATH::BigInt& A, COMMON::LARGEMATH::BigInt& B, COMMON::LARGEMATH::BigInt& K) const;
			COMMON::LARGEMATH::BigInt getServerPasswordProof(COMMON::LARGEMATH::BigInt& A, COMMON::LARGEMATH::BigInt& M, COMMON::LARGEMATH::BigInt& K) const;

		private:
			int	init(const char* username, const char* password, COMMON::LARGEMATH::BigInt* salt);
			COMMON::LARGEMATH::BigInt	getClientPrivateKey() const;
			COMMON::LARGEMATH::BigInt	getScrambler(COMMON::LARGEMATH::BigInt& B) const;
			COMMON::LARGEMATH::BigInt	getClientSecret(COMMON::LARGEMATH::BigInt& B) const;
			COMMON::LARGEMATH::BigInt	getServerSecret(COMMON::LARGEMATH::BigInt& A, COMMON::LARGEMATH::BigInt& v);
			COMMON::LARGEMATH::BigInt  hashSecret(COMMON::LARGEMATH::BigInt& secret) const;
			static COMMON::LARGEMATH::BigInt	N;	// modulus
			static COMMON::LARGEMATH::BigInt	g;	// generator
			static COMMON::LARGEMATH::BigInt	I;	// H(g) xor H(N) where H() is standard SHA1
			COMMON::LARGEMATH::BigInt	a;	// client session private key
			COMMON::LARGEMATH::BigInt	b;	// server session private key
			COMMON::LARGEMATH::BigInt	s;	// salt
			COMMON::LARGEMATH::BigInt *B;	// server public key cache
			char*	username;
			size_t	username_length;
			char*	password;
			size_t	password_length;
			unsigned char raw_salt[32];
		};

	}
}

#endif /* __BNET_SRP3_INCLUDED__ */