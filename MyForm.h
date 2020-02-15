#pragma once
#include<WinSock2.h>
#include<mstcpip.h>
#include<stdio.h>
#include<ctime>
#pragma comment (lib,"Advapi32.lib")
#pragma comment (lib,"ws2_32")

namespace NetStreamCatch {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Threading;
	using namespace System::Drawing;

	BOOL falg = FALSE;

	typedef struct _IPHeader
	{
		unsigned char  iph_header_len : 4;
		unsigned char  iph_version : 4;
		unsigned char  iph_tos;
		unsigned short iph_total_length;
		unsigned short iph_id;
		unsigned char  iph_frag_offset : 5;
		unsigned char  iph_more_fragment : 1;
		unsigned char  iph_dont_fragment : 1;
		unsigned char  iph_reserved_zero : 1;
		unsigned char  iph_frag_offset1;
		unsigned char  iph_ttl;
		unsigned char  iph_protocol;
		unsigned short iph_checksum;
		ULONG        iph_source;
		ULONG        iph_destination;
	}IPHeader, *PIPHeader;

	typedef struct _TCPHeader{
		USHORT sourcePort;
		USHORT destinationPort;
		ULONG sequenceNumber;
		ULONG acknowledgeNumber;
		UCHAR dataoffest;
		UCHAR flags;
		USHORT windows;
		USHORT checksum;
		USHORT urgentPointer;
	}TCPHeader, *PTCPHeader;

	typedef struct _UDPHeader {
		USHORT sourcePort;
		USHORT destinationPort;
		USHORT len;
		USHORT checksum;
	}UDPHeader,*PUDPHeader;

	/// <summary>
	/// MyForm 的摘要
	/// </summary>
	public ref class MyForm : public System::Windows::Forms::Form
	{
	public:
		MyForm(void)
		{
			InitializeComponent();
			//
			//TODO:  在此加入建構函式程式碼
			//
		}

	protected:
		/// <summary>
		/// 清除任何使用中的資源。
		/// </summary>
		~MyForm()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Button^  button1;
	protected:
	private: System::Windows::Forms::TextBox^  textBox1;

	private:
		/// <summary>
		/// 設計工具所需的變數。
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// 此為設計工具支援所需的方法 - 請勿使用程式碼編輯器修改
		/// 這個方法的內容。
		/// </summary>
		void InitializeComponent(void)
		{
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->SuspendLayout();
			// 
			// button1
			// 
			this->button1->Font = (gcnew System::Drawing::Font(L"新細明體", 16.2F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(136)));
			this->button1->Location = System::Drawing::Point(12, 381);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(499, 64);
			this->button1->TabIndex = 0;
			this->button1->Text = L"擷取";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &MyForm::button1_Click);
			// 
			// textBox1
			// 
			this->textBox1->Location = System::Drawing::Point(12, 12);
			this->textBox1->Multiline = true;
			this->textBox1->Name = L"textBox1";
			this->textBox1->ScrollBars = System::Windows::Forms::ScrollBars::Both;
			this->textBox1->Size = System::Drawing::Size(499, 363);
			this->textBox1->TabIndex = 1;
			// 
			// MyForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(8, 15);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(523, 457);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->button1);
			this->Name = L"MyForm";
			this->Text = L"MyForm";
			this->ResumeLayout(false);
			this->PerformLayout();

		}

		

#pragma endregion
	

	void DecodeTCPPacket(char *pData,char *szSrcIP,char *szDestIP) {

		TCPHeader *pTCPHdr = (TCPHeader *)pData;

		String^ Src = gcnew String(szSrcIP);
		String^ Dis = gcnew String(szDestIP);
		
		textBox1->Text += Src + ":" + ntohs(pTCPHdr->sourcePort) + " -> " + Dis + ":" + ntohs(pTCPHdr->destinationPort)+"\r\n";

		switch (::ntohs(pTCPHdr->destinationPort))
		{
			case 21:
				textBox1->Text += "FTP===============================\r\n";
				pData = pData + sizeof(TCPHeader);
				if (strncmp(pData,"USER",4)==0) {
					String^ ppData = gcnew String(pData + 4);
					textBox1->Text += "User Name : " + ppData +"\r\n";
				}
				if (strncmp(pData, "PASS", 4) == 0) {
					String^ pppData = gcnew String(pData + 4);
					textBox1->Text += "User Pass : " + pppData + "\r\n";
				}
				textBox1->Text += "FTP===============================\r\n";
				break;
			case 80:{
				String ^ dData = gcnew String(pData + sizeof(TCPHeader));
				textBox1->Text += "HTTP===============================\r\n";
				textBox1->Text += dData + "\r\n";
				textBox1->Text += "HTTP===============================\r\n";
				break;}
			case 443:{
				String ^ ddData = gcnew String(pData + sizeof(TCPHeader));
				textBox1->Text += "HTTPS===============================\r\n";
				textBox1->Text += ddData + "\r\n";
				textBox1->Text += "HTTPS===============================\r\n";
				break;}
			case 8080:{
				String ^ ppppData = gcnew String(pData + sizeof(TCPHeader));
				textBox1->Text += "WEB===============================\r\n";
				textBox1->Text += ppppData +"\r\n";
				textBox1->Text += "WEB===============================\r\n";
				break;}
		}
	}
	void DecodeUDPPacket(char *pData, char *szSrcIP, char *szDestIP) {
		UDPHeader *pUDPHdr = (UDPHeader *)pData;

		String^ Src = gcnew String(szSrcIP);
		String^ Dis = gcnew String(szDestIP);
		
		textBox1->Text += Src +":"+ntohs(pUDPHdr->sourcePort) + " -> " + Dis + ":" + ntohs(pUDPHdr->destinationPort)+"\r\n";
		String ^ pppppppData = gcnew String(pData + sizeof(UDPHeader));
		textBox1->Text += "UDP===============================\r\n";
		textBox1->Text += pppppppData + "\r\n";
		textBox1->Text += "UDP===============================\r\n";
	}
	void DecodeIPPacket(char *pData) {
		IPHeader *pIPHdr = (IPHeader *)pData;
		in_addr source, dest;
		char szSourceIp[32], szDestIp[32];

		textBox1->Text += "------------------------------\r\n";

		source.S_un.S_addr = pIPHdr->iph_source;
		dest.S_un.S_addr = pIPHdr->iph_destination;
		strcpy(szSourceIp,inet_ntoa(source));
		strcpy(szDestIp,inet_ntoa(dest));

		int nHeaderLen = (pIPHdr->iph_header_len & 0xf) * sizeof(ULONG);
		switch (pIPHdr->iph_protocol)
		{
		case IPPROTO_TCP:
			DecodeTCPPacket(pData+nHeaderLen,szSourceIp,szDestIp);
			break;
		case IPPROTO_UDP:
			DecodeUDPPacket(pData + nHeaderLen, szSourceIp, szDestIp);
			break;
		case IPPROTO_ICMP:
			break;
		}
	}

	void testa() {
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
		SOCKET sRaw = socket(AF_INET, SOCK_RAW, IPPROTO_IP);


		char szHostName[56];
		SOCKADDR_IN addr_in;
		struct hostent *pHost;
		gethostname(szHostName, 56);

		if ((pHost = gethostbyname((char*)szHostName)) == NULL) {
			this->Close();
		}

		addr_in.sin_family = AF_INET;
		addr_in.sin_port = htons(0);
		memcpy(&addr_in.sin_addr.S_un.S_addr, pHost->h_addr_list[0], pHost->h_length);

		String ^ pppppData = gcnew String(::inet_ntoa(addr_in.sin_addr));

		textBox1->Text += "綁定介面" + pppppData + "\r\n";

		if (bind(sRaw, (PSOCKADDR)&addr_in, sizeof(addr_in)) == SOCKET_ERROR) {
			MessageBox::Show("SOCKET綁定失敗");
			this->Close();
		}
		DWORD dwValue = 1;
		if (ioctlsocket(sRaw, SIO_RCVALL, &dwValue) != 0) {
			MessageBox::Show("網卡混淆失敗");
			this->Close();
		}
		char buff[1024];
		int nRet;
		while (falg)
		{
			nRet = recv(sRaw, buff, 1024, 0);
			if (nRet>0) {
				DecodeIPPacket(buff);
			}
		}
		closesocket(sRaw);
		WSACleanup();
	}
	

	private: System::Void button1_Click(System::Object^  sender, System::EventArgs^  e) {

		::System::Threading::Thread^ thr1 = gcnew ::System::Threading::Thread(gcnew ::System::Threading::ThreadStart(this, &MyForm::testa));
		if(!falg)
		{	
			falg = TRUE;
			thr1->Start();
			button1->Text = "停止";
		}
		else
		{	
			falg = FALSE;
			thr1->Abort();		
			button1->Text = "擷取";
		}
		
	}
	};
}
