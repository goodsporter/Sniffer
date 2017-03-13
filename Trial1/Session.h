#pragma once

/*
		本部分作为会话部分
		应注意：
		+不要手动设定fp
		+不要手动设定pcapHeader
		+不要手动设定pktData
		+不要手动设定fcode
		+如需调整包过滤规则，在Init之前调整filterString
*/

#ifndef SESSIOIN
#define SESSIOIN

#include "Common.h"
#include "Log.h"

using namespace std;
using namespace Log;

namespace Session
{
	pcap_t* fp = NULL;
	struct pcap_pkthdr* pcapHeader = NULL;
	const u_char* pktData = NULL;

	struct bpf_program fcode;
	const string filterString = "ip and tcp";

	int Init(pcap_t** fp, bpf_program& fcode, const string filterString)
	{
		pcap_if_t* allDevs, *aDev = NULL;

		char errBuf[PCAP_ERRBUF_SIZE]{ '0' };

		char logBuf[500]{ 0 };

		int devCount = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevs, errBuf);

		{
			ofstream log("Log.txt", ios::app);
			if (!log)
			{
				ofstream log("Log.txt", ios::out);
			}
		}

		{
			ofstream devices("Devices.txt", ios::out);
			u_int i = 0;
			for (aDev = allDevs; aDev; aDev = aDev->next)
			{
				devices << "Device " << ++i << ": " << endl;
				devices << "\t" << aDev->description << endl;
				devices << "\t" << aDev->name << endl;
			}
			devices.close();
		}

		string deviceName = "";
		{
			ifstream Config("Config.txt", ios::app);
			if (!Config)
			{
				sprintf(logBuf, "\tError : Didn't set device name. Please SET it.\n");
				LogWriteOnce(logBuf);

				pcap_freealldevs(allDevs);

				exit(-1);
			}
			else
			{
				ifstream config("Config.txt", ios::in);
				getline(config, deviceName);
				config.close();

				sprintf(logBuf, "\tConfig Loaded.\n");
				LogWriteOnce(logBuf);
			}
		}

		{
			for (aDev = allDevs; aDev; aDev = aDev->next)
			{
				if (strcmp(aDev->name, deviceName.c_str()) == 0)
				{
					break;
				}
			}
			if (aDev == NULL)
			{
				sprintf(logBuf, "\tError : This Device is NOT exist.\n");
				LogWriteOnce(logBuf);

				pcap_freealldevs(allDevs);
				exit(-1);
			}
		}

		if ((*fp = pcap_open_live(aDev->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, errBuf)) == NULL)
		{
			sprintf(logBuf, "\tError : Session Start Failure.\n");
			LogWriteOnce(logBuf);

			pcap_close(*fp);
			pcap_freealldevs(allDevs);
			exit(-1);
		}

		{
			if (pcap_datalink(*fp) != DLT_EN10MB)
			{
				sprintf(logBuf, "\tThis program works only on Ethernet networks.\n");
				LogWriteOnce(logBuf);

				pcap_close(*fp);
				pcap_freealldevs(allDevs);
				exit(-1);
			}
		}

		bpf_u_int32 netmask = 0;

		if (aDev->addresses != NULL)
			netmask = ((struct sockaddr_in *)(aDev->addresses->netmask))->sin_addr.S_un.S_addr;
		else
			netmask = 0xffffff;


		if (pcap_compile(*fp, &fcode, filterString.c_str(), 1, netmask) < 0)
		{
			sprintf(logBuf, "\tError : Filter Compile Error.\n");
			LogWriteOnce(logBuf);

			pcap_close(*fp);
			pcap_freealldevs(allDevs);
			exit(-1);
		}

		if (pcap_setfilter(*fp, &fcode)<0)
		{
			sprintf(logBuf, "\tError : Filter Set Error.\n");
			LogWriteOnce(logBuf);

			pcap_close(*fp);
			pcap_freealldevs(allDevs);
			exit(-1);
		}

		pcap_freealldevs(allDevs);

		return 0;
	}

	int Capture(pcap_t* fp, struct pcap_pkthdr** pcapHeader, const u_char** pktData)
	{
		int res= pcap_next_ex(fp, pcapHeader, pktData);
		return res;
	}

	int UnInit(pcap_t* fp, bpf_program& fcode)
	{
		pcap_freecode(&fcode);
		pcap_close(fp);

		return 0;
	}

#endif // !SESSIOIN
}