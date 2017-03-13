#pragma once

/*
		本部分作为日志
		应注意：
		+固定向Log.txt写出
		+LogWriteOnce不适宜频繁调用
*/

#ifndef LOG
#define LOG

#include"Common.h"

using namespace std;

namespace Log
{
	int LogWriteOnce(char* buffer)
	{
		ofstream log("Log.txt", ios::app);
		time_t rawTime;
		time(&rawTime);
		log << ctime(&rawTime);
		log << buffer;
		memset(buffer, '\0', sizeof(buffer));
		log.close();

		return 0;
	}
}

#endif // !LOG
