#pragma once
#include <string>
#include <algorithm>
#include "SXException.h"
#include <cstdint>
#include <vector>
#include <algorithm>
using namespace std;


class SXEncryption {
private:
	const string RADIUS = "singlenet01";
	string username;
	string passwd;
	string server;
public:
	SXEncryption(string username, string password, string server);
	vector<sxbyte> calculateRealUsername();
	void raiseVpn();
};