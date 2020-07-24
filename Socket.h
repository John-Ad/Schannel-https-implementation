#pragma once
#pragma comment(lib,"Ws2_32.lib")

#include <WS2tcpip.h>
#include <Windows.h>
#include <iostream>
#include <string>

#define SCK_VERSION 0x0202

using namespace std;

class Socket
{
private:
	WSAData wdata;
	struct addrinfo hints, *result;		//creates a guiding structure for getaddrinfo
	int rc;
	string url;
	SOCKET client;
public:
	Socket(string url_);
	~Socket();

	void set_server_details();
	void create_socket();
	void connect_to_server();
	void send_token(char buff, int size);
	void receive_token(char* buff);
	SOCKET get_socket();
};
