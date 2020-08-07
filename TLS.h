#pragma once
#define SECURITY_WIN32


#include "Socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <wincrypt.h>
#include <WinTrust.h>
#include <security.h>
#include <sspi.h>
#include <schnlsp.h>
#include <schannel.h>
#include <utility>
#include <vector>

#pragma comment (lib,"Secur32.lib")
#pragma comment (lib,"Crypt32.Lib")


class TLS
{
private:
	int rc = 0;
	SECURITY_STATUS secStatus;

	char* url;
	string html;
	string get_req;
	Socket client{ url };

	CredHandle cred;
	CtxtHandle phContext;
	SecPkgContext_StreamSizes sizes;


	void connect_to_server();
	void get_schannel_creds();
	void handshake_loop();
	void encrypt_send();
	void recv_decrypt();

	int get_content_length(char *buff, int len);

public:
	TLS(char* url_);
	~TLS();
};

