#include "TLS.h"

TLS::TLS(char* url_)
	:url{ url_ }
{
	get_req = "GET / HTTP/1.1\r\nHost: ";
	get_req += url;
	get_req += "\r\nConnection: close\r\n\r\n";
	connect_to_server();
	get_schannel_creds();
	handshake_loop();
	encrypt_send();
	recv_decrypt();
}
TLS::~TLS()
{
}

//___________________________________________________________________
void TLS::connect_to_server()
{
	client.set_server_details();
	client.create_socket();
	client.connect_to_server();
	cout << "/*********************************************************************************" << endl << endl;
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
	TimeStamp lifeTime;
	SCHANNEL_CRED credData;

	ZeroMemory(&credData, sizeof(credData));					//clear SCHANNEL_CRED memory or error: SEC_E_INSUFFICIENT_MEMORY occurs
	credData.dwVersion = SCHANNEL_CRED_VERSION;
	credData.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;

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
	cout << "/*********************************************************************************" << endl << endl;
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

	TimeStamp lifeTime;
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
		(SEC_CHAR*)url,							//targetname is the name of the server
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

	char* token;
	char buff[10000];

	while (secStatus == SEC_I_CONTINUE_NEEDED)
	{
		token = static_cast<char*>(outBuff[0].pvBuffer);
		client.send_data(token, outBuff[0].cbBuffer);
		FreeContextBuffer(outBuff[0].pvBuffer);
		rc = client.receive_data(buff,secStatus);

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
			(SEC_CHAR*)url,
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
		cout << "size of token: " << outBuff[0].cbBuffer << endl << endl;

		if (inBuff[1].BufferType == SECBUFFER_EXTRA)
			cout << "extra data in inbuff" << endl << endl;
	}

	if (secStatus == SEC_E_OK)
		cout << "Secure connection successfully established!" << endl << endl;

	cout << "/*********************************************************************************" << endl << endl;
}
void TLS::encrypt_send()
{
	BYTE *buff = NULL;		//BYTE can access raw memory
	int bufflen = 0;
	char* data;
	SECURITY_STATUS stat;
	SecBufferDesc msg;
	SecBuffer buffers[4];
	SecPkgContext_StreamSizes sizes;
	
	stat = QueryContextAttributes(&phContext, SECPKG_ATTR_STREAM_SIZES, &sizes);		//gets header,trailer etc sizes
	if (stat != SEC_E_OK)
		cout << "QueryContextAttributes failed with code: " << GetLastError() << endl << endl;
	else
		cout << "Sizes retrieved!" << endl << endl;

	bufflen = sizes.cbMaximumMessage + sizes.cbTrailer + sizes.cbHeader;
	buff = new BYTE[bufflen];													//creates memory space based on the sizes obtained above

	memcpy(buff + sizes.cbHeader, (BYTE*)get_req.c_str(), get_req.length());	//copies the get request just after the header in the buffer

	msg.cBuffers = 4;
	msg.pBuffers = buffers;
	msg.ulVersion = SECBUFFER_VERSION;

	buffers[0].cbBuffer = sizes.cbHeader;
	buffers[0].pvBuffer = buff;
	buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

	buffers[1].cbBuffer = get_req.length();
	buffers[1].pvBuffer = buff + sizes.cbHeader;
	buffers[1].BufferType = SECBUFFER_DATA;

	buffers[2].cbBuffer = sizes.cbTrailer;
	buffers[2].pvBuffer = buff + sizes.cbHeader + get_req.length();
	buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	buffers[3].cbBuffer = 0;
	buffers[3].pvBuffer = NULL;
	buffers[3].BufferType = SECBUFFER_EMPTY;

	stat = EncryptMessage(&phContext, 0, &msg, 0);
	if (stat != SEC_E_OK)
		cout << "Failed to encrypt message: " << GetLastError() << endl << endl;
	else
		cout << "Message successfully encrypted!" << endl << endl;

	bufflen = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
	client.send_data((char*)buff, bufflen);
	
	free(buff);

	cout << "/*********************************************************************************" << endl << endl;
}
void TLS::recv_decrypt()
{
	string html = "";
	string holder = "";
	char* buff = new char[20000];
	SECURITY_STATUS stat;
	SecBufferDesc msg;
	SecBuffer buffer[4];

	for (int i = 0; i < 3; i++)
	{
		rc = client.receive_data(buff, secStatus);

		msg.cBuffers = 4;
		msg.pBuffers = buffer;
		msg.ulVersion = SECBUFFER_VERSION;

		buffer[0].cbBuffer = rc;
		buffer[0].pvBuffer = buff;
		buffer[0].BufferType = SECBUFFER_DATA;

		buffer[1].BufferType = SECBUFFER_EMPTY;
		buffer[2].BufferType = SECBUFFER_EMPTY;
		buffer[3].BufferType = SECBUFFER_EMPTY;

		stat = DecryptMessage(&phContext, &msg, 0, NULL);
		if (stat != SEC_E_OK)
		{
			if (stat == SEC_E_INCOMPLETE_MESSAGE)
			{
				cout << "Failed to decrypt data: " << "SEC_E_INCOMPLETE_MESSAGE" << endl << endl;
			}
			else
				cout << "Failed to decrypt data: " << stat << endl << endl;

		}
		else
			cout << "Data successfully decrypted!" << endl << endl;

		cout << buff << endl;

	}

	cout << "/*********************************************************************************" << endl << endl;

	// TO DO: handle messages that are too large
	//		  implement loop to receive data
}

//			TO DO in future:
//							- add handling of extra data in inbuff




