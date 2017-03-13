#pragma once

/*
		本部分作为内存缓存
		应注意：
		+不要手动设定currentPktDataCachePosition
		+不要手动设定lpPktDataCacheName
		+将pPktDataCache作为内存指针，一旦Init，不要改变其值
		+将hPktDataCache作为内存句柄，一旦Init，不要改变其值
		+如需更大缓存，在Init之前调整cacheSize
		+不要手动调整pcv，它是地址映射目录
*/

#ifndef CACHE
#define CACHE
#include "Common.h"
#include "Log.h"

using namespace Log;

namespace Cache
{
	int currentPktDataCachePosition = 0;
	int cacheSize = 10 * 1024;

	LPVOID pPktDataCache = NULL;
	HANDLE hPktDataCache = NULL;
	const LPCWSTR lpPktDataCacheName = L"PacketDataCache";

	struct PointerMap
	{
		pcap_pkthdr* pPcapHeader;
		u_char* pPktData;
		u_int pPktDataLen;
	};
	vector<PointerMap> pcv;

	int Init(LPVOID* pBuffer, HANDLE* hMap, int bufferSize, const LPCWSTR pktDataMemoryName)
	{
		char logBuf[500]{ 0 };

		if ((*hMap = ::CreateFileMapping(
			INVALID_HANDLE_VALUE, 
			NULL, 
			PAGE_READWRITE, 
			0, 
			bufferSize, 
			pktDataMemoryName))==NULL)
		{
			sprintf(logBuf, "\tError : Cache Init Error.\n");
			LogWriteOnce(logBuf);
		}

		if ((*pBuffer = ::MapViewOfFile(
			*hMap, 
			FILE_MAP_ALL_ACCESS, 
			0, 
			0, 
			0))==NULL)
		{
			sprintf(logBuf, "\tError : Cache Init Error.\n");
			LogWriteOnce(logBuf);
		}

		return 0;
	}

	int _SetMemory(LPVOID des, const LPVOID src, int currentPosition, int length)
	{
		char logBuf[500]{0};

		if ((memcpy(
			(LPVOID)((byte* )des + currentPosition), 
			src, 
			length)) == NULL)
		{
			sprintf(logBuf, "\tError : Memory Copy Error.\n");
			LogWriteOnce(logBuf);
		}

		return 0;
	}

	int SetMemory(LPVOID pPktDataCache, pcap_pkthdr* pcapHeader, const u_char* pktData, int& currentPktDataCachetPosition)
	{
		PointerMap mm;

		mm.pPcapHeader = (pcap_pkthdr*)((byte*)pPktDataCache + currentPktDataCachetPosition);
		_SetMemory(
			pPktDataCache, 
			pcapHeader, 
			currentPktDataCachetPosition, 
			sizeof(*pcapHeader));
		currentPktDataCachetPosition += sizeof(*pcapHeader);

		mm.pPktData = (u_char*)((byte*)pPktDataCache + currentPktDataCachetPosition);
		_SetMemory(
			pPktDataCache, 
			(LPVOID)pktData, 
			currentPktDataCachetPosition, 
			pcapHeader->len);
		currentPktDataCachetPosition += pcapHeader->len;

		pcv.push_back(mm);

		return 0;
	}

	int UninitMemory(LPVOID pBuffer, HANDLE hMap)
	{
		char logBuf[500]{ 0 };

		if (::UnmapViewOfFile(pBuffer)==false)
		{
			sprintf(logBuf, "\tError : Cache UnInit Error.\n");
			LogWriteOnce(logBuf);
		}

		if (::CloseHandle(hMap)==false)
		{
			sprintf(logBuf, "\tError : Cache UnInit Error.\n");
			LogWriteOnce(logBuf);
		}

		pcv.clear();

		return 0;
	}
}

#endif // !CACHE
