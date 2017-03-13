/*
		本部分作为示例
		应注意：
		+首次执行会生成Device.txt，并退出
		+根据Device.txt，配置Config.txt
		+错误信息输出至Log.txt

		当前演示的功能是
		1.超时不捕捉
		2.缓存满后不捕捉
		3.显示捕捉到的TCP端口号对
*/

#include "Common.h"
#include "Session.h"
#include "Cache.h"
#include "Protocols.h"

using namespace std;
using namespace Session;
using namespace Cache;
using namespace Protocols;

int main(int argc, char** argv)
{
	Init(&fp, fcode, filterString);

	{
		Init(&pPktDataCache, &hPktDataCache, cacheSize, lpPktDataCacheName);

		int i = 0;
		while (currentPktDataCachePosition + sizeof(pktData) <= cacheSize)
		{
			if (Capture(fp, &pcapHeader, &pktData) >= 0)
			{
				if (pcapHeader->len==0)
				{
					continue;
				}

				SetMemory(pPktDataCache, pcapHeader, pktData, currentPktDataCachePosition);

				//分析部分
				TcpHandler::Handler(Cache::pcv[i++].pPktData);
				u_short buffer2[2];
				TcpHandler::getSrc(buffer2[0]);
				TcpHandler::getDes(buffer2[1]);
				cout << buffer2[0] << endl;
				cout << buffer2[1] << endl;
				cout << endl;
			}
		}

		UninitMemory(pPktDataCache, hPktDataCache);
	}

	UnInit(fp, fcode);

	return 0;
}