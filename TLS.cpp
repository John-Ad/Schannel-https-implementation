#include "TLS.h"

TLS::TLS()
{
	/*dllModule = LoadLibrary("Secur32.dll");
	if(dllModule!=NULL)
		cout << "library loaded successfully!" << endl << endl;*/

	connect_to_server();
	get_schannel_creds();
	handshake_loop();
}


TLS::~TLS()
{
}

//______INIT_functions___________________________________________
void TLS::connect_to_server()
{
	client.set_server_details();
	client.create_socket();
	client.connect_to_server();
}
void TLS::get_schannel_creds()
{
	pair<SECURITY_STATUS, string>error[6]{
		{SEC_E_INTERNAL_ERROR,"SEC_E_INTERNAL_ERROR" },
		{SEC_E_INSUFFICIENT_MEMORY, "SEC_E_INSUFFICIENT_MEMORY"},
		{SEC_E_NO_CREDENTIALS,"SEC_E_NO_CREDENTIALS" },
		{SEC_E_NOT_OWNER,"SEC_E_NOT_OWNER" },
		{SEC_E_SECPKG_NOT_FOUND,"SEC_E_SECPKG_NOT_FOUND"},
		{SEC_E_UNKNOWN_CREDENTIALS,"SEC_E_UNKNOWN_CREDENTIALS"}
	};
	SECURITY_STATUS secStatus;
	TimeStamp lifeTime;
	SCHANNEL_CRED credData;

	ZeroMemory(&credData, sizeof(credData));					//clear SCHANNEL_CRED memory or error: SEC_E_INSUFFICIENT_MEMORY occurs
	credData.dwVersion = SCHANNEL_CRED_VERSION;
	credData.grbitEnabledProtocols = SP_PROT_TLS1;

	secStatus = AcquireCredentialsHandle(		//gets the credentials necessary to make use of the ssp
			NULL,						//default principle
			(LPSTR)UNISP_NAME,			//name of schannel ssp
			SECPKG_CRED_OUTBOUND,		//states that the client will use the returned credential
			NULL,						//use current logon id instead of searching for previous one
			&credData,					//protocol specific data
			NULL,						//default
			NULL,						//default
			&cred,						//where the handle will be stored
			&lifeTime					//stores the time limit of the credential
	);

	if (secStatus != SEC_E_OK)
	{
		for (int i = 0; i < 6; i++)
		{
			if (secStatus == error[i].first)
			{
				cout << "Credentials could not be acquired. Error code: " << error[i].second << "   " << endl << endl;
				i = 6;
			}
		}
		
	}
	else
	{
		cout << "Credentials acquired successfully!" << endl << endl;
	}
}
void TLS::handshake_loop()
{
	pair<SECURITY_STATUS, string>success[6]{
		{SEC_I_COMPLETE_AND_CONTINUE,"SEC_I_COMPLETE_AND_CONTINUE"},
		{SEC_I_COMPLETE_NEEDED,"SEC_I_COMPLETE_NEEDED"},
		{SEC_I_CONTINUE_NEEDED,"SEC_I_CONTINUE_NEEDED"},
		{SEC_I_INCOMPLETE_CREDENTIALS,"SEC_I_INCOMPLETE_CREDENTIALS"},
		{SEC_E_INCOMPLETE_MESSAGE,"SEC_E_INCOMPLETE_MESSAGE"},
		{SEC_E_OK,"SEC_E_OK"}
	};
	pair<SECURITY_STATUS, string>error[10]{
		{SEC_E_INSUFFICIENT_MEMORY,"SEC_E_INSUFFICIENT_MEMORY"},
		{SEC_E_INTERNAL_ERROR,"SEC_E_INTERNAL_ERROR"},
		{SEC_E_INVALID_HANDLE,"SEC_E_INVALID_HANDLE"},
		{SEC_E_INVALID_TOKEN,"SEC_E_INVALID_TOKEN"},
		{SEC_E_LOGON_DENIED,"SEC_E_LOGON_DENIED"},
		{SEC_E_NO_AUTHENTICATING_AUTHORITY,"SEC_E_NO_AUTHENTICATING_AUTHORITY"},
		{SEC_E_NO_CREDENTIALS,"SEC_E_NO_CREDENTIALS"},
		{SEC_E_TARGET_UNKNOWN,"SEC_E_TARGET_UNKNOWN"},
		{SEC_E_UNSUPPORTED_FUNCTION,"SEC_E_UNSUPPORTED_FUNCTION"},
		{SEC_E_WRONG_PRINCIPAL,"SEC_E_WRONG_PRINCIPAL"}
	};

	SECURITY_STATUS secStatus;
	TimeStamp lifeTime;
	CtxtHandle phContext;
	SecBufferDesc outBuffDesc;
	SecBuffer outBuff[1];
	SecBufferDesc inBuffDesc;
	SecBuffer inBuff[2];
	ULONG ContextAttributes;
	DWORD flags;

	outBuffDesc.ulVersion = SECBUFFER_VERSION;
	outBuffDesc.cBuffers = 1;
	outBuffDesc.pBuffers = outBuff;

	outBuff[0].cbBuffer = 0;							//	size(cbBuff) is 0 and data(pvBuff) is null because ISC_ALLOC_MEM was
	outBuff[0].BufferType = SECBUFFER_TOKEN;			//	was specified and will automatically create memory and fill the buffer
	outBuff[0].pvBuffer = NULL;

	flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR;

	secStatus = InitializeSecurityContext(
		&cred,							//credentials acquired by acquireCredentialsHandle
		NULL,							//in the first call this is NULL, afterwards use hcText parameter variable
		(SEC_CHAR*)"www.google.com",							//targetname is left as the default
		flags,							//bit flags that state how the security context will function
		0,								//this argument is reserved and left as 0
		SECURITY_NATIVE_DREP,			//how the data is represented. In schannel this argument is not used and set to 0
		NULL,							//this is the buffer that will be received from the server. On the first call this is NULL
		0,								//reserved and set to 0
		&phContext,						//receives the context handle. With Schannel, after the first call, this must be NULL and 
										//	arg2 must take phContext
		&outBuffDesc,					//buffer where the token will be stored. This will be sent to the server later
		&ContextAttributes,				//this is where the set of bit flags will be received. These flags indicate the attributes of the context
		&lifeTime
	);

	for (int i = 0; i < 10; i++)
	{
		if (i < 6)
		{
			if (secStatus == success[i].first)
			{
				cout << "InitializeSecurityContext succeeded with code: " << success[i].second << endl << endl;
				i = 10;
			}
		}
		if (secStatus == error[i].first)
		{
			cout << "InitializeSecurityContext failed with error: " << error[i].second << endl << endl;
			i = 10;
		}
	}

	cout << "size of token: " << outBuff[0].cbBuffer << endl << endl;
	//end of creation of token

	char* token = static_cast<char*>(outBuff[0].pvBuffer);
	rc = send(client.get_socket(), token, outBuff[0].cbBuffer, 0);
	if (rc == SOCKET_ERROR)
		cout << "error sending token: " << WSAGetLastError() << endl << endl;
	else
		cout << "bytes sent: " << rc << endl << endl;

	FreeContextBuffer(outBuff[0].pvBuffer);

	char buff[2939];
	rc = recv(client.get_socket(), buff, 2939, 0);
	if (rc == SOCKET_ERROR)
		cout << "error receiving token: " << WSAGetLastError() << endl << endl;
	else
		cout << "bytes received: " << rc << endl << endl;

	
	//start of handshake loop
	inBuffDesc.cBuffers = 2;
	inBuffDesc.pBuffers = inBuff;
	inBuffDesc.ulVersion = SECBUFFER_VERSION;

	inBuff[0].cbBuffer = rc;
	inBuff[0].pvBuffer = buff;
	inBuff[0].BufferType = SECBUFFER_TOKEN;

	inBuff[1].cbBuffer = 0;
	inBuff[1].pvBuffer = NULL;
	inBuff[1].BufferType = SECBUFFER_EMPTY;

	outBuffDesc.cBuffers = 1;
	outBuffDesc.pBuffers = outBuff;
	outBuffDesc.ulVersion = SECBUFFER_VERSION;

	outBuff[0].cbBuffer = 0;
	outBuff[0].pvBuffer = NULL;
	outBuff[0].BufferType = SECBUFFER_VERSION;

	secStatus = InitializeSecurityContext(
		&cred,
		&phContext,
		(SEC_CHAR*)"www.google.com",
		flags,
		0,
		SECURITY_NATIVE_DREP,
		&inBuffDesc,
		0,
		NULL,
		&outBuffDesc,
		&ContextAttributes,
		&lifeTime
	);

	for (int i = 0; i < 10; i++)
	{
		if (i < 6)
		{
			if (secStatus == success[i].first)
			{
				cout << "InitializeSecurityContext succeeded with code: " << success[i].second << endl << endl;
				i = 10;
			}
		}
		if (secStatus == error[i].first)
		{
			cout << "InitializeSecurityContext failed with error: " << error[i].second << endl << endl;
			i = 10;
		}
	}
	if (inBuff[1].BufferType == SECBUFFER_EXTRA)
		cout << "extra data in inbuff" << endl << endl;

	cout << "second token size: " << outBuff[0].cbBuffer << endl << endl;

	token = static_cast<char*>(outBuff[0].pvBuffer);
	rc = send(client.get_socket(), token, outBuff[0].cbBuffer, 0);
	if (rc == SOCKET_ERROR)
		cout << "error sending token: " << WSAGetLastError() << endl << endl;
	else
		cout << "bytes sent: " << rc << endl << endl;

	rc = recv(client.get_socket(), buff, 2929, 0);
	if (rc == SOCKET_ERROR)
		cout << "error receiving token: " << WSAGetLastError() << endl << endl;
	else
		cout << "bytes received: " << rc << endl << endl;
	
//0000000000000000000000000000000000000000000000000000000000000000000000000
	FreeContextBuffer(outBuff[0].pvBuffer);
	inBuffDesc.cBuffers = 2;
	inBuffDesc.pBuffers = inBuff;
	inBuffDesc.ulVersion = SECBUFFER_VERSION;

	inBuff[0].cbBuffer = rc;
	inBuff[0].pvBuffer = buff;
	inBuff[0].BufferType = SECBUFFER_TOKEN;

	inBuff[1].cbBuffer = 0;
	inBuff[1].pvBuffer = NULL;
	inBuff[1].BufferType = SECBUFFER_EMPTY;

	outBuffDesc.cBuffers = 1;
	outBuffDesc.pBuffers = outBuff;
	outBuffDesc.ulVersion = SECBUFFER_VERSION;

	outBuff[0].cbBuffer = 0;
	outBuff[0].pvBuffer = NULL;
	outBuff[0].BufferType = SECBUFFER_VERSION;

	secStatus = InitializeSecurityContext(
		&cred,
		&phContext,
		NULL,
		flags,
		0,
		SECURITY_NATIVE_DREP,
		&inBuffDesc,
		0,
		NULL,
		&outBuffDesc,
		&ContextAttributes,
		&lifeTime
	);

	for (int i = 0; i < 10; i++)
	{
		if (i < 6)
		{
			if (secStatus == success[i].first)
			{
				cout << "InitializeSecurityContext succeeded with code: " << success[i].second << endl << endl;
				i = 10;
			}
		}
		if (secStatus == error[i].first)
		{
			cout << "InitializeSecurityContext failed with error: " << error[i].second << endl << endl;
			i = 10;
		}
	}
	cout << outBuff[0].cbBuffer << endl << endl;
	if (inBuff[1].BufferType == SECBUFFER_EXTRA)
		cout << "extra data in inbuff" << endl << endl;

	//11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
	/*token = static_cast<char*>(outBuff[0].pvBuffer);
	rc = send(client.get_socket(), token, outBuff[0].cbBuffer, 0);
	if (rc == SOCKET_ERROR)
		cout << "error sending token: " << WSAGetLastError() << endl << endl;
	else
		cout << "bytes sent: " << rc << endl << endl;

	rc = recv(client.get_socket(), buff, 2929, 0);
	if (rc == SOCKET_ERROR)
		cout << "error receiving token: " << WSAGetLastError() << endl << endl;
	else
		cout << "bytes received: " << rc << endl << endl;*/
}
//---------------------------------------------------------------------------------------------------------------








//			TODO:
//					- move the send and receive function to the socket class




