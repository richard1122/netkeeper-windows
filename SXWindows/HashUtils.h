#pragma once
#include "SXException.h"
#include <vector>
#include <windows.h>
#include <Wincrypt.h>
using namespace std;

class HashUtil {
public:
	static vector<sxbyte> getMD5(const vector<sxbyte> data) {
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		DWORD dwStatus = 0;
		DWORD cbHash = 16;

		unsigned char digest[16];
		sxbyte *dataByte = new sxbyte[data.size()];
		for (int i = 0; i != data.size(); ++i)
			dataByte[i] = data[i];

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			throw SXException("win32 crypt context initialize failed.");
		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
			throw SXException("md5 context initialize failed.");
		if (!CryptHashData(hHash, dataByte, data.size(), 0))
			throw SXException("md5 calculation failed.");
		if (!CryptGetHashParam(hHash, HP_HASHVAL, digest, &cbHash, 0))
			throw SXException("CryptGetHashParam failed: " + GetLastError());

		vector<sxbyte> result;
		result.reserve(16);
		for (int i = 0; i != 16; ++i)
			result.push_back(digest[i]);
		return result;
	}
	static char* vecToChar(vector<sxbyte> vec) {
		char *c = new char[vec.size() + 1];
		for (int i = 0; i != vec.size(); ++i) c[i] = vec[i];
		c[vec.size()] = 0;
		return c;
 	}
	static sxbyte numToHex(char c) {
		char buffer[2];
		sprintf_s(buffer, "%x", c);
		return buffer[0];
	}
};