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
void Socket::send_data(char* buff, int size)
{
	rc = 0;
	int len = 0;

	do
	{
		size -= rc;
		rc = send(client, buff, size, 0);

		if (rc <= 0)
		{
			cout << "error sending data: " << WSAGetLastError() << endl << endl;
			return;
		}

		len += rc;
	} while ( rc < size);

	cout << "bytes sent: " << len << endl << endl;
}
int Socket::receive_data(char* buff, int length)
{
	int len = 0;
	int bytesToRecv = length;
	char buffer[10000];

	if (length == 0)
		len = recv(client, buff, 6000, 0);
	else
	{
		do
		{
			//cout << "buffer: " << endl << buff << endl << endl;

			for (int i = 0; i < 10000; i++)
			{
				if (buff[i] == NULL&&buff[i+1]==NULL)
				{
					rc = recv(client, &buff[i], bytesToRecv, 0);
					/*fill(buffer, buffer + 10000, 0);
					rc = recv(client, buffer, bytesToRecv, 0);
					copy(buffer, buffer + rc, buff + i);*/
					//delete above this line---------------
					
					//cout << "data: " << endl << buff << endl << "buffer: " << buffer << endl << endl;
					i = 10000;
				}
			}

			bytesToRecv -= rc;
			len += rc;

		} while (bytesToRecv > 0 && rc != 0);
	}
	
	if (len == SOCKET_ERROR || len == 0)
	{
		cout << "error receiving data: " << WSAGetLastError() << endl << endl;
		return 0;
	}
	else
	{
		cout << "bytes received: " << len << endl << endl;
		return len;
	}
}
SOCKET Socket::get_socket()
{
	return client;
}

