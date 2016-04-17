#include "SXEncryption.h"
#include <ctime>
#include <array>
#include "HashUtils.h"
#include "VpnUtils.h"
using namespace std;

SXEncryption::SXEncryption(string uname, string pwd, string srv) : username(uname), passwd(pwd), server(srv) {}

vector<uint8_t> SXEncryption::calculateRealUsername()
{
	time_t timestampNow = time(NULL);
	time_t timeByFive = timestampNow / 5;
	array<sxbyte, 4> timeByte;
	for (int i = 0; i != 4; ++i) timeByte[i] = (sxbyte) (timeByFive >> (8 * (3 - i)) & 0xff);

	string nameWithoutAT = username.substr(0, username.find('@'));

	vector<sxbyte> beforeMD5;
	copy(timeByte.begin(), timeByte.end(), back_inserter(beforeMD5));
	copy(nameWithoutAT.begin(), nameWithoutAT.end(), back_inserter(beforeMD5));
	copy(RADIUS.begin(), RADIUS.end(), back_inserter(beforeMD5));

	vector<sxbyte> afterMD5 = HashUtil::getMD5(beforeMD5);
	vector<sxbyte> md5H = {HashUtil::numToHex((sxbyte)( afterMD5[0] >> 4 & 0xF)), HashUtil::numToHex((sxbyte) (afterMD5[0] & 0xF))};

	vector<sxbyte> temp;
	for (int i = 0; i != 32; ++i) {
		temp.push_back(timeByte[(31 - i) / 8] & 1);
		timeByte[(31 - i) / 8] = timeByte[(31 - i) / 8] >> 1;
	}
	vector<sxbyte> timeHash(4, 0);
	for (int i = 0; i < 4; i++) {
		timeHash[i] = temp[i] * 128 + temp[4 + i] * 64 + temp[8 + i]
			* 32 + temp[12 + i] * 16 + temp[16 + i] * 8 + temp[20 + i]
			* 4 + temp[24 + i] * 2 + temp[28 + i];
	}
	temp[1] = (timeHash[0] & 3) << 4;
	temp[0] = (timeHash[0] >> 2) & 0x3F;
	temp[2] = (timeHash[1] & 0xF) << 2;
	temp[1] = (timeHash[1] >> 4 & 0xF) + temp[1];
	temp[3] = timeHash[2] & 0x3F;
	temp[2] = ((timeHash[2] >> 6) & 0x3) + temp[2];
	temp[5] = (timeHash[3] & 3) << 4;
	temp[4] = (timeHash[3] >> 2) & 0x3F;

	vector<sxbyte> PIN27(6, 0);
	for (int i = 0; i < 6; i++) {
		PIN27[i] = temp[i] + 0x020;
		if (PIN27[i] >= 0x40) {
			PIN27[i]++;
		}
	}

	vector<sxbyte> PIN;
	PIN.push_back('\r');
	PIN.push_back('\n');
	copy(PIN27.begin(), PIN27.end(), back_inserter(PIN));
	copy(md5H.begin(), md5H.end(), back_inserter(PIN));
	copy(username.begin(), username.end(), back_inserter(PIN));

	return PIN;
}

void SXEncryption::raiseVpn()
{
	VpnUtils::createVpn("zjuvpn", calculateRealUsername(), passwd, server);
}


