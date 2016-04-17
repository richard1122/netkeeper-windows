#pragma once
#include <Windows.h>
#include <Ras.h>
#pragma comment(lib, "rasapi32.lib")
#include "SXException.h"
#include "HashUtils.h"
#include <vector>
#include <algorithm>
using namespace std;

class VpnUtils {
public:
	static void createVpn(string name, vector<sxbyte> username, string passwd, string server) {
		DWORD size = 0;
		RasGetEntryProperties(NULL, "", NULL, &size, NULL, NULL);
		LPRASENTRY pras = (LPRASENTRY)malloc(size);
		memset(pras, 0, size);
		pras->dwSize = size;
		pras->dwType = RASET_Vpn;
		pras->dwRedialCount = 1;
		pras->dwRedialPause = 60;
		pras->dwfNetProtocols = RASNP_Ip;
		pras->dwEncryptionType = ET_Optional;
		strcpy_s(pras->szLocalPhoneNumber, server.c_str());
		strcpy_s(pras->szDeviceType, RASDT_Vpn);
		pras->dwfOptions = RASEO_RemoteDefaultGateway;

		pras->dwVpnStrategy = VS_L2tpOnly;
		pras->dwfOptions |= RASEO_RequireCHAP | RASEO_RequirePAP;
		pras->dwfOptions2 |= RASEO2_DisableIKENameEkuCheck;
		RasSetEntryProperties(NULL, name.c_str(), pras, pras->dwSize, NULL, 0);
		RASCREDENTIALS ras_cre = { 0 };
		ras_cre.dwSize = sizeof(ras_cre);
		ras_cre.dwMask = RASCM_UserName | RASCM_Password;

  		char *uname = HashUtil::vecToChar(username);

		strcpy_s(ras_cre.szUserName, uname);
		strcpy_s(ras_cre.szPassword, passwd.c_str());
		RasSetCredentials(NULL, name.c_str(), &ras_cre, FALSE);

		// Dial a RAS entry in synchronous mode
		HRASCONN hRasConn = NULL;
		RASDIALPARAMS rasDialParams;

		// Setup the RASDIALPARAMS structure for the entry we want
		// to dial
		memset(&rasDialParams, 0, sizeof(RASDIALPARAMS));

		rasDialParams.dwSize = sizeof(RASDIALPARAMS);
		strcpy_s(rasDialParams.szEntryName, name.c_str());
		strcpy_s(rasDialParams.szUserName, uname);
		strcpy_s(rasDialParams.szPassword, passwd.c_str());

		if (RasDial(NULL, NULL, &rasDialParams, 0, NULL, &hRasConn)
			!= 0) {
			throw SXException("could not diaup");
		}

		free(pras);
	}
};