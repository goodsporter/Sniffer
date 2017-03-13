#pragma once

/*
		本部分作为模型和基本助手类
		应注意：
		+XHandler类类型的方法使用前，必须调用其Handler方法
		+MAC和IP地址是点分十进制的字符串
		+return 0作为拓展预留
*/

#ifndef PROTOCOLS
#define PROTOCOLS

#include "Common.h"

namespace Protocols
{
#pragma region Ethernet

		struct MacAddress//6*4
		{
			u_char byte[6];
		};

		struct EthernetRawHeader//(6+6+2)*4
		{
			MacAddress des;
			MacAddress src;
			u_short type;
		};

		class EthernetHandler
		{
		public:
			inline static int Handler(const u_char* rawHeader)
			{
				header = (EthernetRawHeader*)(rawHeader +0);
			}
			static EthernetRawHeader* header;
			inline static bool HasHeader()
			{
				return (header != NULL) ? true : false;
			}

			inline static int getSrcMacString(char* macBuffer)
			{
				u_char* bytePointer = header->src.byte;
				sprintf(macBuffer, "%02x.%02x.%02x.%02x.%02x.%02x",
					*bytePointer,
					*(bytePointer + 1),
					*(bytePointer + 2),
					*(bytePointer + 3),
					*(bytePointer + 4),
					*(bytePointer + 5));
				return 0;
			}
			inline static int getDesMacString(char* macBuffer)
			{
				u_char* bytePointer = header->des.byte;
				sprintf(macBuffer, "%02x.%02x.%02x.%02x.%02x.%02x",
					*bytePointer,
					*(bytePointer + 1),
					*(bytePointer + 2),
					*(bytePointer + 3),
					*(bytePointer + 4),
					*(bytePointer + 5));
				return 0;
			}

			inline static int getType(u_short& type)
			{
				type = ntohs(header->type);
				return 0;
			}
		};
		EthernetRawHeader* EthernetHandler::header = NULL;

#pragma endregion

#pragma region IP

		struct IpAddress//4*8
		{
			u_char byte[4];
		};

		struct IpRawHeader//(1+1+2+2+2+1+1+2+4+4)*8
		{
			byte ver_headlen;
			byte tos;
			u_short len;
			u_short id;
			u_short flag3_offset13;
			byte ttl;
			byte protocol;
			u_short checksum;
			IpAddress src;
			IpAddress des;
		};

		class IpHandler
		{
		public:
			inline static int Handler(const u_char* rawHeader)
			{
				header = (IpRawHeader*)(rawHeader + 14);
				return 0;
			}
			static IpRawHeader* header;
			inline static bool HasHeader()
			{
				return (header != NULL) ? true : false;
			}

			inline static int getVersion(byte& ipVersion)
			{
				ipVersion = (header->ver_headlen >> 4) & 0x0f;
				return 0;
			}

			inline static int getHeaderLength(u_short& ipLength)
			{
				ipLength = (header->ver_headlen & 0x0f) * 4;
				return 0;
			}

			inline static int getTos(byte& tos)
			{
				tos = header->tos;
				return 0;
			}

			inline static int getLength(u_short& len)
			{
				len = ntohs(header->len);
				return 0;
			}

			inline static int getId(u_short& id)
			{
				id = ntohs(header->id);
				return id;
			}

			inline static int getFlag(byte& flag)
			{
				flag = header->flag3_offset13 >> 13;
				return 0;
			}

			inline static int getOffset(u_short& offset)
			{
				offset = header->flag3_offset13 & 0x1fff;
				return 0;
			}

			inline static int getTtl(byte& ttl)
			{
				ttl = header->ttl;
				return 0;
			}

			inline static int getProtocol(byte& protocol)
			{
				protocol = header->protocol;
				return 0;
			}

			inline static int getCheckSum(u_short& checksum)
			{
				checksum = ntohs(header->checksum);
				return 0;
			}

			inline static int getIpSrcString(char* ipBuffer)
			{
				const u_char* bytePointer = header->src.byte;
				sprintf(ipBuffer, "%d.%d.%d.%d",
					*bytePointer,
					*(bytePointer + 1),
					*(bytePointer + 2),
					*(bytePointer + 3)
					);
				return 0;
			}
			inline static int getIpDesString(char* ipBuffer)
			{
				const u_char* bytePointer = header->des.byte;
				sprintf(ipBuffer, "%d.%d.%d.%d",
					*bytePointer,
					*(bytePointer + 1),
					*(bytePointer + 2),
					*(bytePointer + 3)
					);
				return 0;
			}
		};
		IpRawHeader* IpHandler::header = NULL;

#pragma endregion

#pragma region Tcp

		struct TcpRawHeader//(2+2+4+4+1+1+2+2+2)*8
		{
			u_short src;
			u_short des;
			u_long seq;
			u_long ack;
			byte len_sp4;
			byte sp2_urg_ack_psh_rst_syn_fin;
			u_short window;
			u_short checksum;
			u_short emp;
		};

		class TcpHandler
		{
		public :
			inline static int Handler(const u_char* rawHeader)
			{
				u_short ipheadlen = 0;
				IpHandler::Handler(rawHeader);
				IpHandler::getHeaderLength(ipheadlen);
				header = (TcpRawHeader*)(rawHeader + 14 + ipheadlen);
				return 0;
			}
			static TcpRawHeader* header;
			inline static bool HasHeader()
			{
				return (header != NULL) ? true : false;
			}

			inline static int getSrc(u_short& src)
			{
				src = ntohs(header->src);
				return 0;
			}

			inline static int getDes(u_short& des)
			{
				des = ntohs(header->des);
				return 0;
			}

			inline static int getSeq(u_long& seq)
			{
				seq = ntohl(header->seq);
				return 0;
			}

			inline static int getAck(u_long& ack)
			{
				ack = ntohl(header->ack);
				return 0;
			}

			inline static int getHeaderLength(u_short& ipLength)
			{
				ipLength = (header->len_sp4 >> 4) * 4;
				return 0;
			}

			inline static int getAck(bool& ipAck)
			{
				ipAck = (header->sp2_urg_ack_psh_rst_syn_fin >> 4) & 1;
				return 0;
			}

			inline static int getUrg(bool& ipUrg)
			{
				ipUrg = (header->sp2_urg_ack_psh_rst_syn_fin >> 5) & 1;
				return 0;
			}

			inline static int getPsh(bool& ipPsh)
			{
				ipPsh = (header->sp2_urg_ack_psh_rst_syn_fin >> 3) & 1;
				return 0;
			}

			inline static int getRsr(bool& ipRsr)
			{
				ipRsr = (header->sp2_urg_ack_psh_rst_syn_fin >> 2) & 1;
				return 0;
			}

			inline static int getSyn(bool& ipSyn)
			{
				ipSyn = (header->sp2_urg_ack_psh_rst_syn_fin >> 1) & 1;
				return 0;
			}

			inline static int getFin(bool& ipFin)
			{
				ipFin = header->sp2_urg_ack_psh_rst_syn_fin & 1;
				return 0;
			}

			inline static int getWindow(u_short& window)
			{
				window = ntohs(header->window);
				return 0;
			}

			inline static int getChecksum(u_short& checksum)
			{
				checksum = ntohs(header->checksum);
				return 0;
			}

			inline static int getEmp(u_short& emp)
			{
				emp = ntohs(header->emp);
				return 0;
			}
		};
		TcpRawHeader* TcpHandler::header = NULL;

#pragma endregion

#pragma region Udp

		struct UdpRawHeader//(2+2+2+2)*8
		{
			u_short src;
			u_short des;
			u_short len;
			u_short checksum;
		};

		class UdpHandler
		{
		public:
			inline static int Handler(const u_char* rawHeader)
			{
				u_short ipheadlen = 0;
				IpHandler::Handler(rawHeader);
				IpHandler::getHeaderLength(ipheadlen);
				header = (UdpRawHeader*)(rawHeader + 14 + ipheadlen);
				return 0;
			}
			static UdpRawHeader* header;
			inline static bool HasHeader()
			{
				return (header != NULL) ? true : false;
			}

			inline static int getSrc(u_short& src)
			{
				src = ntohs(header->src);
				return 0;
			}

			inline static int getDes(u_short& des)
			{
				des = ntohs(header->des);
				return 0;
			}

			inline static int getLen(u_short& len)
			{
				len = ntohs(header->len);
				return 0;
			}

			inline static int getChecksum(u_short& checksum)
			{
				checksum = ntohs(header->checksum);
				return 0;
			}
		};
		UdpRawHeader* UdpHandler::header = NULL;
#pragma endregion
}


#endif // Protocols