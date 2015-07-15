#include "global.h"
#include <conio.h>

static WCHAR sg_szDefFile[MAXSHORT + 1];

void mydie(NTSTATUS status){
	printf_s("\nNTSTATUS error: 0x%lX", status);
	fflush(stdin);
	_getch();
	NtTerminateProcess(INVALID_HANDLE_VALUE, status);
}

NTSTATUS myfgetws(__inout PWCHAR pInputBuffer, __in ULONGLONG inputBufferSize, __out PULONGLONG pStrSize){
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG maxWcharCount = (ULONG)inputBufferSize / sizeof(WCHAR);

	if (!pInputBuffer || !inputBufferSize || !pStrSize)
		return STATUS_INVALID_PARAMETER;

	*pStrSize = 0;
	
	fflush(stdin);
	fgetws(pInputBuffer, maxWcharCount, stdin);
	fflush(stdin);

	status = RtlStringCbLengthW(pInputBuffer, maxWcharCount * sizeof(WCHAR), pStrSize);
	if (status)
		return status;

	///Eliminate 0x0A char if there is one in buffer
	if (0x0A == pInputBuffer[*pStrSize / sizeof(WCHAR) - 1]){
		pInputBuffer[*pStrSize / sizeof(WCHAR) - 1] = 0x0;
		return STATUS_SUCCESS;
	}

	*pStrSize += sizeof(UNICODE_NULL);
	return STATUS_SUCCESS;
}

NTSTATUS getAndLoadDllByInput(PVOID* ppDllBase){
	WCHAR szDllName[MAX_PATH];		///It's impossible, that the DLL's image name length exceeds 260 chars,
									///since the maximum length of a file path part is limited to ~255 by Windows.
	ULONGLONG dllStrSize;
	UNICODE_STRING uDllName;

	ULONG loadFlags = 0x0;
	NTSTATUS status = STATUS_HANDLE_NO_LONGER_VALID;

	status = myfgetws(szDllName, sizeof(szDllName), &dllStrSize);
	if (status)
		mydie(status);

	///Although we don't want any DllMain() to be called, we intend to use standard PE math
	///when walking the EAT at a later time. So we still need to load the DLL as an image file.	
	loadFlags = LOAD_LIBRARY_AS_IMAGE_RESOURCE;
	loadFlags |= LOAD_LIBRARY_SEARCH_SYSTEM32;
	loadFlags |= LOAD_LIBRARY_SEARCH_APPLICATION_DIR;

	RtlInitUnicodeString(&uDllName, szDllName);
	status = LdrLoadDll(NULL, &loadFlags, &uDllName, ppDllBase);
	if (status)
		mydie(status);

	return STATUS_SUCCESS;
}

NTSTATUS obtainImageFileEatEntries(PVOID pImageFileBase, PVOID pListBuffer, ULONGLONG listBufferSize, PULONGLONG neededBufferSize){
	PIMAGE_NT_HEADERS64 pPeHdr = NULL;
	pPeHdr = (PIMAGE_NT_HEADERS64)((PUCHAR)pImageFileBase + ((PIMAGE_DOS_HEADER)pImageFileBase)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER64 pOptionalHdr = &pPeHdr->OptionalHeader;
	///TODO: Check if image has export directory!!!!!!!!!!!!! 
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionalHdr->DataDirectory;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pImageFileBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	printf_s("\nImage exports %d named functions.", pExportDirectory->NumberOfNames);
	return STATUS_SUCCESS;
}

NTSTATUS dumpEatEntriesToFile(PVOID pEatList, ULONGLONG listBufferSize){
	OBJECT_ATTRIBUTES defFileAttr;
	UNICODE_STRING uDefFileName;
	IO_STATUS_BLOCK ioSb;

	NTSTATUS status = STATUS_DATA_NOT_ACCEPTED;
	HANDLE hDefFile = NULL;
	HANDLE hParentDir = NULL;
	hParentDir = NtCurrentPeb()->ProcessParameters->CurrentDirectory.Handle;
	RtlInitUnicodeString(&uDefFileName, L"exports.def");
	InitializeObjectAttributes(&defFileAttr, &uDefFileName, OBJ_CASE_INSENSITIVE, hParentDir, NULL);
	status = NtCreateFile(&hDefFile, FILE_ALL_ACCESS | SYNCHRONIZE, &defFileAttr, &ioSb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (status)
		return status;

	NtClose(hDefFile);
	return STATUS_SUCCESS;
}

void mymain(void){
	PVOID pDllBase = NULL;
	NTSTATUS status = STATUS_HANDLE_NO_LONGER_VALID;

	printf_s("Welcome to .def File Creator V0.1!\n\n");
	printf_s("Enter the full DLL or exe name as in the following example:\n");
	printf_s("\"ntdll.dll\" (without quotes).\n\n");
	printf_s("DLL must reside in \\System32 or in current directory.\n\n");
	printf_s("DLL name: ");

	status = getAndLoadDllByInput(&pDllBase);
	if (status)
		mydie(status);

	printf_s("DLL loaded successfully. Address: %p\n", pDllBase);
	obtainImageFileEatEntries(pDllBase, NULL, 0, NULL);

	dumpEatEntriesToFile(NULL, 0);
	fflush(stdin);
	_getch();
}