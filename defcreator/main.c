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

NTSTATUS validatePePointer(PVOID pImageBase, PVOID pArbitraryPtr, ULONGLONG accessLength, BOOLEAN isNewImage){
	UNREFERENCED_PARAMETER(accessLength);
	MEMORY_BASIC_VLM_INFORMATION vlmImageInfo;
	ULONGLONG returnLen = 0;
	NTSTATUS status = 0;

	static ULONGLONG peSize = 0;
	if (!peSize || isNewImage){
		status = NtQueryVirtualMemory(INVALID_HANDLE_VALUE, pImageBase, MemoryBasicVlmInformation, &vlmImageInfo, sizeof(MEMORY_BASIC_VLM_INFORMATION), &returnLen);
		if (status)
			return status;

		peSize = vlmImageInfo.SizeOfImage;
	}

	///The viability of this pointer validation is based on three assumptions:
	///0. The amount of data read is at maximum 8 bytes!!!!
	///1. Each mapped section of the image is at least readable (R) without guard (+G).
	///2. There don't exist any free pages between two sections of the same image.
	if ((pImageBase < ALIGN_DOWN_POINTER(pArbitraryPtr, PVOID)) && (((PUCHAR)ALIGN_UP_POINTER(pArbitraryPtr, PVOID) + accessLength) < ((PUCHAR)pImageBase + peSize)))
		return STATUS_SUCCESS;

	return STATUS_INVALID_ADDRESS;
}

NTSTATUS obtainImageFileEatEntries(PVOID pImageFileBase, PUCHAR pListBuffer, ULONGLONG listBufferSize, PULONGLONG pNeededBufferSize){
	IMAGE_DATA_DIRECTORY dataDirectory;

	ULONG nameRvaCheck = 0;
	ULONGLONG nameLength = 0;
	ULONGLONG maxReadSize = 0;
	NTSTATUS status = STATUS_UNABLE_TO_UNLOAD_MEDIA;
	ULONGLONG exportSize = 0;
	PIMAGE_NT_HEADERS64 pImagePeHdr = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PULONG pNameRvaArray = NULL;
	PUCHAR pCurrName = NULL;
	PUCHAR pNextName = NULL;
	PUCHAR pListPointer = NULL;

	if (!pImageFileBase || !pNeededBufferSize || !pListBuffer && listBufferSize)
		return STATUS_INVALID_PARAMETER;

	pImagePeHdr = (PIMAGE_NT_HEADERS64)((PUCHAR)pImageFileBase + ((PIMAGE_DOS_HEADER)pImageFileBase)->e_lfanew);
	pDataDirectory = pImagePeHdr->OptionalHeader.DataDirectory;
	maxReadSize = sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_DIRECTORY_ENTRY_EXPORT + 1);
	status = validatePePointer(pImageFileBase, pDataDirectory, maxReadSize, TRUE);
	if (status)
		return status;

	exportSize = pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	printf_s("\nexportSize: %lu, Export Directory RVA: %lu", exportSize, pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (listBufferSize < PAGE_ROUND_UP(exportSize)){
		*pNeededBufferSize = PAGE_ROUND_UP(exportSize);
		return STATUS_BUFFER_TOO_SMALL;
	}
	
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pImageFileBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	maxReadSize = sizeof(IMAGE_EXPORT_DIRECTORY);
	status = validatePePointer(pImageFileBase, pExportDirectory, maxReadSize, FALSE);
	if (status)
		return status;

	pNameRvaArray = (PULONG)((PUCHAR)pImageFileBase + pExportDirectory->AddressOfNames);
	maxReadSize = 7;
	status = validatePePointer(pImageFileBase, pNameRvaArray, maxReadSize, FALSE);
	if (status)
		return status;

	pListPointer = pListBuffer;
	for (ULONG i = 0; i < pExportDirectory->NumberOfNames; i++){
		pCurrName = (PUCHAR)pImageFileBase + pNameRvaArray[i];
		///At the end of RVA array there isn't a next name entry anymore.
		///There must be a terminating zero though, which we're going to exploit
		///in order to still have a valid name length.
		if (pExportDirectory->NumberOfNames - 1 == i){
			int j = 0;
			while (pCurrName[j])
				j++;

			nameLength = j;
		}
		else{
			pNextName = (PUCHAR)pImageFileBase + pNameRvaArray[i + 1];
			nameLength = (ULONGLONG)(pNextName - pCurrName) - 1;
		}
		RtlCopyMemory(pListPointer, pCurrName, nameLength);
		*(PWCHAR)&pListPointer[nameLength] = (WCHAR)0x0A0D;
		pListPointer += nameLength + sizeof(WCHAR);
	}

	///Hit two birds with one stone by replacing last 0D 0A sequence with a terminating WCHAR 0.
	*((PWCHAR)pListPointer - 1) = (WCHAR)0x0;

	*pNeededBufferSize = (ULONGLONG)(pListPointer - pListBuffer);
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
	PVOID pListBuf = NULL;
	ULONGLONG requiredBufSize = 0;
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
	status = obtainImageFileEatEntries(pDllBase, NULL, 0, &requiredBufSize);
	if (status != STATUS_BUFFER_TOO_SMALL)
		mydie(status);

	status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &pListBuf, 0, &requiredBufSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (status)
		mydie(status);
	
	status = obtainImageFileEatEntries(pDllBase, pListBuf, requiredBufSize, &requiredBufSize);
	if (status)
		mydie(status);

	printf_s("\n%s\n\nlist size: 0x%llX", pListBuf, requiredBufSize);


	dumpEatEntriesToFile(NULL, 0);
	fflush(stdin);
	_getch();
}