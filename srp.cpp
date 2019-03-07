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

#include "stdafx.h"


namespace ns_BNCS
{
	namespace HASH {

		std::uint8_t bnetsrp3_g = 0x2F;

		const unsigned char bnetsrp3_N[] = {
			0xF8, 0xFF, 0x1A, 0x8B, 0x61, 0x99, 0x18, 0x03,
			0x21, 0x86, 0xB6, 0x8C, 0xA0, 0x92, 0xB5, 0x55,
			0x7E, 0x97, 0x6C, 0x78, 0xC7, 0x32, 0x12, 0xD9,
			0x12, 0x16, 0xF6, 0x65, 0x85, 0x23, 0xC7, 0x87
		};

		const unsigned char bnetsrp3_I[] = {
			0xF8, 0x01, 0x8C, 0xF0, 0xA4, 0x25, 0xBA, 0x8B,
			0xEB, 0x89, 0x58, 0xB1, 0xAB, 0x6B, 0xF9, 0x0A,
			0xED, 0x97, 0x0E, 0x6C
		};

		COMMON::LARGEMATH::BigInt BnetSRP3::N = COMMON::LARGEMATH::BigInt(bnetsrp3_N, 32);
		COMMON::LARGEMATH::BigInt BnetSRP3::g = COMMON::LARGEMATH::BigInt(bnetsrp3_g);
		COMMON::LARGEMATH::BigInt BnetSRP3::I = COMMON::LARGEMATH::BigInt(bnetsrp3_I, 32);

		int
			BnetSRP3::init(const char* username_, const char* password_, COMMON::LARGEMATH::BigInt* salt_)
		{
			unsigned int i;
			const char* source;
			char* symbol;

			if (!username_) {
				//eventlog(eventlog_level_error, __FUNCTION__, "got NULL username_");
				printf_s("%s\r\n", "SRP3: got NULL username_");
				return -1;
			}

			username_length = std::strlen(username_);
			username = (char*)xmalloc(username_length + 1);
			source = username_;
			symbol = username;
			for (i = 0; i < username_length; i++)
			{
				*(symbol++) = safe_toupper(*(source++));
			}

			if (!((password_ == NULL) ^ (salt_ == NULL))) {
				//eventlog(eventlog_level_error, __FUNCTION__, "need to init with EITHER password_ OR salt_");
				printf_s("%s\r\n", "SRP3: need to init with EITHER password_ OR salt_");
				return -1;
			}

			if (password_ != NULL) {
				password_length = std::strlen(password_);
				password = (char*)xmalloc(password_length + 1);
				source = password_;
				symbol = password;
				for (i = 0; i < password_length; i++)
				{
					*(symbol++) = safe_toupper(*(source++));
				}
				a = COMMON::LARGEMATH::BigInt::random(32) % N;
				s = COMMON::LARGEMATH::BigInt::random(32);
			}
			else {
				password = NULL;
				password_length = 0;
				b = COMMON::LARGEMATH::BigInt::random(32) % N;
				s = *salt_;
			}

			B = NULL;

			s.getData(raw_salt, 32);

			return 0;
		}


		BnetSRP3::BnetSRP3(const char* username_, COMMON::LARGEMATH::BigInt& salt)
		{
			init(username_, NULL, &salt);
		}

		BnetSRP3::BnetSRP3(const std::string& username_, COMMON::LARGEMATH::BigInt& salt)
		{
			init(username_.c_str(), NULL, &salt);
		}

		BnetSRP3::BnetSRP3(const char* username_, const char* password_)
		{
			init(username_, password_, NULL);
		}

		BnetSRP3::BnetSRP3(const std::string& username_, const std::string& password_)
		{
			init(username_.c_str(), password_.c_str(), NULL);
		}

		BnetSRP3::~BnetSRP3()
		{
			if (username)
				xfree(username);

			if (password)
				xfree(password);

			delete B;
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getClientPrivateKey() const
		{
			char* userpass;	// username,':',password
			t_hash userpass_hash;
			char private_value[32 + 20];	// s, H(userpass)
			t_hash private_value_hash;

			userpass = (char*)xmalloc(username_length + 1 + password_length + 1);
			std::memcpy(userpass, username, username_length);
			userpass[username_length] = ':';
			std::memcpy(userpass + username_length + 1, password, password_length);
			userpass[username_length + 1 + password_length] = '\0';
			HASH::little_endian_sha1(&userpass_hash, userpass, username_length + 1 + password_length);
			xfree(userpass);

			std::memcpy(&private_value[0], raw_salt, 32);
			std::memcpy(&private_value[32], userpass_hash, 20);
			HASH::little_endian_sha1(&private_value_hash, private_value, 52);

			return COMMON::LARGEMATH::BigInt((unsigned char const*)private_value_hash, 20, 1, false);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getScrambler(COMMON::LARGEMATH::BigInt& B) const
		{
			unsigned char raw_B[32];
			std::uint32_t scrambler;
			t_hash hash;

			B.getData(raw_B, 32, 4, false);
			HASH::data_hash(&hash, raw_B, 32, false);
			scrambler = *(std::uint32_t*)hash;

			return COMMON::LARGEMATH::BigInt(scrambler);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getClientSecret(COMMON::LARGEMATH::BigInt& B) const
		{
			COMMON::LARGEMATH::BigInt x = getClientPrivateKey();
			COMMON::LARGEMATH::BigInt u = getScrambler(B);
			return (N + B - g.powm(x, N)).powm((x*u) + a, N);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getServerSecret(COMMON::LARGEMATH::BigInt& A, COMMON::LARGEMATH::BigInt& v)
		{
			COMMON::LARGEMATH::BigInt B = getServerSessionPublicKey(v);
			COMMON::LARGEMATH::BigInt u = getScrambler(B);
			return ((A * v.powm(u, N)) % N).powm(b, N);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::hashSecret(COMMON::LARGEMATH::BigInt& secret) const
		{
			int i;
			unsigned char* raw_secret;
			unsigned char odd[16], even[16], hashedSecret[40];
			unsigned char* secretPointer;
			unsigned char* oddPointer;
			unsigned char* evenPointer;
			t_hash odd_hash, even_hash;

			raw_secret = secret.getData(32, 4, false);
			secretPointer = raw_secret;
			oddPointer = odd;
			evenPointer = even;

			for (i = 0; i < 16; i++)
			{
				*(oddPointer++) = *(secretPointer++);
				*(evenPointer++) = *(secretPointer++);
			}

			xfree(raw_secret);
			HASH::little_endian_sha1(&odd_hash, odd, 16);
			HASH::little_endian_sha1(&even_hash, even, 16);

			secretPointer = hashedSecret;
			oddPointer = (unsigned char*)odd_hash;
			evenPointer = (unsigned char*)even_hash;

			for (i = 0; i < 20; i++)
			{
				*(secretPointer++) = *(oddPointer++);
				*(secretPointer++) = *(evenPointer++);
			}

			return COMMON::LARGEMATH::BigInt(hashedSecret, 40, 1, false);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getVerifier() const
		{
			return g.powm(getClientPrivateKey(), N);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getSalt() const
		{
			return s;
		}

		void
			BnetSRP3::setSalt(COMMON::LARGEMATH::BigInt salt_)
		{
			s = salt_;
			s.getData(raw_salt, 32);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getClientSessionPublicKey() const
		{
			return g.powm(a, N);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getServerSessionPublicKey(COMMON::LARGEMATH::BigInt& v)
		{
			if (!B)
				B = new COMMON::LARGEMATH::BigInt((v + g.powm(b, N)) % N);

			return *B;
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getHashedClientSecret(COMMON::LARGEMATH::BigInt& B) const
		{
			COMMON::LARGEMATH::BigInt clientSecret = getClientSecret(B);
			return hashSecret(clientSecret);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getHashedServerSecret(COMMON::LARGEMATH::BigInt& A, COMMON::LARGEMATH::BigInt& v)
		{
			COMMON::LARGEMATH::BigInt serverSecret = getServerSecret(A, v);
			return hashSecret(serverSecret);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getClientPasswordProof(COMMON::LARGEMATH::BigInt& A, COMMON::LARGEMATH::BigInt& B, COMMON::LARGEMATH::BigInt& K) const
		{
			unsigned char proofData[176];
			t_hash usernameHash, proofHash;

			HASH::little_endian_sha1(&usernameHash, username, username_length);

			I.getData(&proofData[0], 20, 4, false);
			std::memcpy(&proofData[20], usernameHash, 20);
			s.getData(&proofData[40], 32);
			A.getData(&proofData[72], 32, 4, false);
			B.getData(&proofData[104], 32, 4, false);
			K.getData(&proofData[136], 40, 4, false);

			HASH::little_endian_sha1(&proofHash, proofData, 176);

			return COMMON::LARGEMATH::BigInt((unsigned char*)proofHash, 20, 1, false);
		}

		COMMON::LARGEMATH::BigInt
			BnetSRP3::getServerPasswordProof(COMMON::LARGEMATH::BigInt& A, COMMON::LARGEMATH::BigInt& M, COMMON::LARGEMATH::BigInt& K) const
		{
			unsigned char proofData[92];
			t_hash proofHash;

			A.getData(&proofData[0], 32, 4, false);
			M.getData(&proofData[32], 20, 4, false);
			K.getData(&proofData[52], 40, 4, false);

			HASH::little_endian_sha1(&proofHash, proofData, 92);

			return COMMON::LARGEMATH::BigInt((unsigned char*)proofHash, 20, 1, false);
		}

	}
}