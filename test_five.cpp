/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
 /*
  * we do not want the warnings about the old deprecated and unsecure CRT functions
  * since these examples can be compiled under *nix as well
  */
#endif
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32
#include<iostream>
#include<sstream>
#include<string>
#include<map>
#include<fstream>
#define HAVE_REMOTE
#include <pcap.h>
#include "remote-ext.h"

#pragma comment(lib,"Wpcap.lib")
#pragma comment(lib,"Ws2_32.lib") 
#pragma warning(disable:4996)



using namespace std;

map<string, string[3]> ftp;
ofstream out("mark.txt");

  /* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_mac
{
	u_char byte5;
	u_char byte6;
	u_char byte7;
	u_char byte8;
	u_char byte9;
	u_char byte10;
	u_char byte11;
	u_char byte12;
}ip_mac;
typedef struct mac_header
{
	u_char dest_addr[6];	u_char src_addr[6];	u_char type[2];
} mac_header;

//IP头结构
/* IPv4 header */
//typedef struct ip_header
//{
//	ip_mac smac;
//	ip_mac dmac;
//	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
//	u_char	tos;			// Type of service 
//	u_short tlen;			// Total length 
//	u_short identification; // Identification
//	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
//	u_char	ttl;			// Time to live
//	u_char	proto;			// Protocol
//	u_short crc;			// Header checksum
//	ip_address	saddr;		// Source address
//	ip_address	daddr;		// Destination address
//	u_int	op_pad;			// Option + Padding
//}ip_header;
typedef struct ip_header
{
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)  	
	u_char  tos;            // 服务类型(Type of service)  	
	u_short tlen;           // 总长(Total length)  	
	u_short identification; // 标识(Identification)  	
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)  	
	u_char  ttl;            // 存活时间(Time to live)  	
	u_char  proto;          // 协议(Protocol)  	
	u_short crc;            // 首部校验和(Header checksum)  	
	u_char  saddr[4];      // 源地址(Source address)  	
	u_char  daddr[4];      // 目的地址(Destination address)  	
	u_int   op_pad;         // 选项与填充(Option + Padding)  
}ip_header;
/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

typedef struct tcp_header
{
	u_short sport;            //源端口号  	
	u_short dport;             //目的端口号  	
	u_int th_seq;                //序列号  	
	u_int th_ack;               //确认号  	
	u_int th1 : 4;              //tcp头部长度  	
	u_int th_res : 4;             //6位中的4位首部长度  	
	u_int th_res2 : 2;            //6位中的2位首部长度  	
	u_char th_flags;            //6位标志位  	
	u_short th_win;             //16位窗口大小  	
	u_short th_sum;             //16位tcp检验和  	
	u_short th_urp;             //16位紧急指针  
}tcp_header;

/* prototype of the packet handler */
//原型的数据包处理程序
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
string get_request_m_ip_message(const u_char* pkt_data)
{
	mac_header *mh;
	ip_header *ih;
	string m_ip_message;
	string str;//empty string	
	ostringstream sout;
	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));
	for (int i = 0; i < 5; i++)
		sout << hex << (int)(mh->src_addr[i]) << "-";
	sout << (int)(mh->src_addr[5]) << ",";
	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->saddr[i]) << ".";
	sout << (int)(ih->saddr[3]) << ",";
	for (int i = 0; i < 5; i++)
		sout << hex << (int)(mh->dest_addr[i]) << "-";
	sout << (int)(mh->dest_addr[5]) << ",";
	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->daddr[i]) << ".";
	sout << (int)(ih->daddr[3]);
	m_ip_message = sout.str();
	return m_ip_message;
}

string get_response_m_ip_message(const u_char* pkt_data)
{
	mac_header *mh;
	ip_header *ih;
	string m_ip_message;
	string str;//empty string	
	ostringstream sout;
	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));
	for (int i = 0; i < 5; i++)
		sout << hex << (int)(mh->dest_addr[i]) << "-";
	sout << (int)(mh->dest_addr[5]) << ",";
	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->daddr[i]) << ".";
	sout << (int)(ih->daddr[3]) << ",";
	for (int i = 0; i < 5; i++)
		sout << hex << (int)(mh->src_addr[i]) << "-";
	sout << (int)(mh->src_addr[5]) << ",";
	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->saddr[i]) << ".";
	sout << (int)(ih->saddr[3]);
	m_ip_message = sout.str();
	return m_ip_message;
}

void print(const struct pcap_pkthdr *header, string m_ip_message)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* 将时间戳转化为可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* 打印时间戳*/
	cout << timestr << ",";	cout << m_ip_message << ",";
	for (int i = 0; i < 2; i++)
		cout << ftp[m_ip_message][i] << ",";
	cout << ftp[m_ip_message][2] << endl;
	out << timestr << ",";
	out << m_ip_message << ",";
	for (int i = 0; i < 2; i++)
		out << ftp[m_ip_message][i] << ",";
	out << ftp[m_ip_message][2] << endl;
	ftp.erase(m_ip_message);
}

int main()
{

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp";
	struct bpf_program fcode;

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	//跳转到所选的适配器
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	

	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	tcp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec; 	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	

	/*
	 * unused parameter
	 */
	
	/*int y, m, d;
	time_t T;
	struct tm *timeinfo;
	time(&T);
	timeinfo = localtime(&T);
	y = timeinfo->tm_year + 1900;
	m = timeinfo->tm_mon + 1;
	d = timeinfo->tm_mday;*/
	//printf("%d年%d月%d日：", y, m, d);

	/* convert the timestamp to readable format */
	/*local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);*/

	/* print timestamp and length of the packet */
	//printf("%s.%.6d 大小:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	//ih = (ip_header *)(pkt_data +
	//	14); //length of ethernet header

	/* retireve the position of the udp header */
	//ip_len = (ih->ver_ihl & 0xf) * 4;
	//uh = (tcp_header *)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	//sport = ntohs(uh->sport);
	//dport = ntohs(uh->dport);

	int head = 54;//14位以太网头，20位ip头，20位tcp头  				  
				  //选择出comman为USER和PASS的包，当然这里就简单的以首字母来代表了，反正其他的  				  
				  //command 没有以U和P开头的  	
	string com;
	for (int i = 0; i < 4; i++)
		com += (char)pkt_data[head + i];
	if (com == "USER")
	{
		string m_ip_message = get_request_m_ip_message(pkt_data);
		string user;
		ostringstream sout;
		for (int i = head + 5; pkt_data[i] != 13; i++)
		{
			sout << pkt_data[i];
		}
		user = sout.str();
		ftp[m_ip_message][0] = user;
	}

	if (com == "PASS")
	{
		string m_ip_message = get_request_m_ip_message(pkt_data);
		string pass;
		ostringstream sout;
		for (int i = head + 5; pkt_data[i] != 13; i++)
		{
			sout << pkt_data[i];
		}

		pass = sout.str();
		ftp[m_ip_message][1] = pass;
	}
	if (com == "230 ")
	{
		string m_ip_message = get_response_m_ip_message(pkt_data);
		ftp[m_ip_message][2] = "SUCCEED";
		print(header, m_ip_message);
	}
	if (com == "530 ")
	{
		string m_ip_message = get_response_m_ip_message(pkt_data);
		ftp[m_ip_message][2] = "FAILD";
		print(header, m_ip_message);
	}

	/* print ip addresses and udp ports */
	//printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
	//	ih->saddr.byte1,
	//	ih->saddr.byte2,
	//	ih->saddr.byte3,
	//	ih->saddr.byte4,
	//	sport,
	//	ih->daddr.byte1,
	//	ih->daddr.byte2,
	//	ih->daddr.byte3,
	//	ih->daddr.byte4,
	//	dport);
	//printf("该数据从-%.2x.%.2x.%.2x.%.2x.%.2x.%.2x- 发送到 -%.2x.%.2x.%.2x.%.2x.%.2x.%.2x-\n",
	//	ih->smac.byte5,
	//	ih->smac.byte6,
	//	ih->smac.byte7,
	//	ih->smac.byte8,
	//	ih->smac.byte9,

	//	ih->smac.byte10,

	//	ih->smac.byte11,
	//	ih->smac.byte12,
	//	/*sport,*/
	//	ih->dmac.byte5,

	//	ih->dmac.byte6,
	//	ih->dmac.byte7,
	//	ih->dmac.byte8,
	//	ih->dmac.byte9,
	//	ih->dmac.byte10,
	//	ih->dmac.byte11,
	//	ih->dmac.byte12);

	//
	//fprintf(fp, "%d年%d月%d日", y, m, d);
	//printf(" %s.%.6d  ", timestr, header->ts.tv_usec);
	//fprintf(fp," %d.%d.%d.%d.%d  %.2x.%.2x.%.2x.%.2x.%.2x.%.2x ",
	//	ih->saddr.byte1,
	//	ih->saddr.byte2,
	//	ih->saddr.byte3,
	//	ih->saddr.byte4,
	//	sport,
	//	ih->smac.byte5,

	//	ih->smac.byte6,
	//	ih->smac.byte7,
	//	ih->smac.byte8,
	//	ih->smac.byte9,
	//	ih->smac.byte10,
	//	ih->smac.byte11,
	//	ih->smac.byte12);
	//fprintf(fp, " %d.%d.%d.%d.%d  %.2x.%.2x.%.2x.%.2x.%.2x.%.2x ",
	//	ih->daddr.byte1,
	//	ih->daddr.byte2,
	//	ih->daddr.byte3,
	//	ih->daddr.byte4,
	//	dport,
	//	ih->dmac.byte5,

	//	ih->dmac.byte6,
	//	ih->dmac.byte7,
	//	ih->dmac.byte8,
	//	ih->dmac.byte9,
	//	ih->dmac.byte10,
	//	ih->dmac.byte11,
	//	ih->dmac.byte12);
	//fprintf(fp, " %d", header->len);
	//fprintf(fp, "\n");
	//fclose(fp);
}
