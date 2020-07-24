#include "Socket.h"



Socket::Socket(string url_)
{
	url = url_;
	int error = WSAStartup(MAKEWORD(2, 2), &wdata);
	if (error != 0)
		cout << "WSAStartup failed with error code: " << error << endl << endl;
	else
		cout << "WSAStartup successful!" << endl << endl;
}


Socket::~Socket()
{
	shutdown(client, 0);
	closesocket(client);

	if (WSACleanup() == SOCKET_ERROR)
		cout << "WSACleanup failed!" << endl << endl;
	else
		cout << "WSACleanup successful!" << endl << endl;

	cin.get();
}

void Socket::set_server_details()
{
	memset(&hints, 0, sizeof(hints));	//hints should be zeroed out	

	hints.ai_flags = AI_CANONNAME;		//canonname states that the name is in the form of www.name.com
	hints.ai_family = AF_UNSPEC;		//states the type of address(ipv4 or ipv6). In this case both are accepted by AF_UNSPEC
	hints.ai_socktype = SOCK_STREAM;		//states the type of socket. In this case tcp
	hints.ai_protocol = IPPROTO_TCP;		//specifies the desired protocol. In this case tcp

	rc = getaddrinfo(url.c_str(), "443", &hints, &result);	//arg 3 is the data that guides getaddrinfo on what to do
															//arg 4 is where the results will be stored
	if (rc != 0)
	{
		cout << "unable to resolve name. Error: " << WSAGetLastError() << endl << endl;
		return;
	}
	else
	{
		cout << "name resolved successfully!   " << result->ai_canonname << endl << endl;
	}
}

void Socket::create_socket()
{
	client = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (client == INVALID_SOCKET)
		cout << "failed to create socket!" << endl << endl;
	else
		cout << "socket created successully!" << endl << endl;
}

void Socket::connect_to_server()
{
	rc = connect(client, result->ai_addr, result->ai_addrlen);
	if (rc == SOCKET_ERROR)
	{
		cout << "failed to connect!" << endl << endl;
		cout << "WSA error: " << WSAGetLastError() << endl << endl;
	}
	else
	{
		cout << "successfully connected!" << endl << endl;
	}
}

void Socket::send_token(char buff, int size)
{
	if (rc=send(client, &buff, size, 0) == SOCKET_ERROR)
	{
		cout << "Failed to send token! Error: " << WSAGetLastError() << endl << endl;
	}
	else
	{
		cout << "Token sent successfully!" << endl << "Bytes sent: " << rc << endl << endl;
	}
}

void Socket::receive_token(char* buf)
{
	string tkn{ "" };
	rc = 1;
	while (rc > 0)
	{
		rc = recv(client, buf, sizeof(buf), 0);
		if (rc != SOCKET_ERROR && rc != 0)
		{
			cout << "Token data received..." << endl << endl;
			tkn += buf;
		}
		else
			cout << "Error receiving data: " << WSAGetLastError() << endl << endl;
	}

	for (int i = 0; i < 12000; i++)
	{
		if (i < tkn.length())
		{
			buf[i] = tkn[i];
		}
		else
		{
			buf[i] = NULL;
		}
	}
	/*int buflen = 0;
	string tkn{ "" };
	while(buflen == 0||rc>0)
	{
		rc=recv(client, buf, 10, 0);
		if (rc != SOCKET_ERROR && rc != 0)
		{
			cout << "Token received successfully!" << endl << endl;
			tkn += buf;
			buflen += sizeof(buf);
		}
		if (rc == 0)
			cout << "Server dropped connection!" << endl;
	}
	for (int i = 0; i < 12000; i++)
	{
		if (i < tkn.length())
		{
			buf[i] = tkn[i];
		}
		else
		{
			buf[i] = NULL;
		}
	}
	cout << WSAGetLastError() << endl << tkn << endl;*/
	
}

SOCKET Socket::get_socket()
{
	return client;
}
