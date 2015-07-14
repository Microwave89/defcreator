#include "global.h"

WCHAR szTestBuf[MAXSHORT + 1];


//NTSTATUS myfgetws(__inout PWCHAR pInputBuffer, __in ULONG maxWCharCount, PULONGLONG pInputBufferSize){
//	ULONGLONG inputBufferSize = 0;
//
//	if ((NULL == pInputBuffer) || (0 == maxWCharCount)){
//		printf("string length error");
//		return 0;
//	}
//	
//	fflush(stdin);
//	fgetws(pInputBuffer, maxWCharCount, stdin);
//	fflush(stdin);
//
//	if (FAILED(StringCbLengthW(pInputBuffer, (maxWCharCount)*sizeof(WCHAR), &inputBufferSize))){
//		printf("string length error");
//		return 0;
//	}
//
//	if (0x0A == pInputBuffer[inputBufferSize / sizeof(WCHAR) - 1]){
//		pInputBuffer[inputBufferSize / sizeof(WCHAR) - 1] = 0x0;
//		inputBufferSize -= sizeof(WCHAR);
//	}
//	return (ULONG)inputBufferSize;
//}

NTSTATUS myfgetws(__inout PWCHAR pInputBuffer, __in ULONG maxWCharCount, PULONGLONG pInputBufferSize){
	ULONGLONG inputBufferSize = 0;

	if ((NULL == pInputBuffer) || (0 == maxWCharCount)){
		printf("string length error");
		return 0;
	}
	
	fflush(stdin);
	fgetws(pInputBuffer, maxWCharCount, stdin);
	fflush(stdin);

	if (FAILED(StringCbLengthW(pInputBuffer, (maxWCharCount)*sizeof(WCHAR), &inputBufferSize))){
		printf("string length error");
		return 0;
	}

	if (0x0A == pInputBuffer[inputBufferSize / sizeof(WCHAR) - 1]){
		pInputBuffer[inputBufferSize / sizeof(WCHAR) - 1] = 0x0;
		inputBufferSize -= sizeof(WCHAR);
	}
	return (ULONG)inputBufferSize;
}

void mymain(void){
	//struct sockaddr socketAddr;
	//SOCKET newSocket = INVALID_SOCKET;	
	//DebugPrint2A("hallo %d, %.4f", 21134, cos(bind(newSocket, &socketAddr, 45)));
	//printf("hallo welt");
	fflush(stdin);
	fgetws(szTestBuf, 20, stdin);
	szTestBuf[56] = 0x0;
	fflush(stdin);
	printf_s("hallo welt %d%ws", 789, szTestBuf);
	fgetws(szTestBuf, 20, stdin);
	//DbgBreakPoint();
}