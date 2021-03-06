#include "global.h"
#include <conio.h>

static WCHAR sg_szDefFile[MAXSHORT + 1];


void mydie(NTSTATUS status, NTSTATUS fatalStatus){
	printf_s("\nAn error occurred. NTSTATUS: %lX", status);
	if (fatalStatus){
		printf_s("\nWhile handling this error, a fatal error occurred.");
		printf_s("\nProgram termination due to NTSTATUS 0x%lX.", fatalStatus);
		fflush(stdin);
		_getch();
		NtTerminateProcess(INVALID_HANDLE_VALUE, status);
	}
	fflush(stdin);
	_getch();
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

int mycompare(const void* pElem1, const void* pElem2){
	if (*(PULONG)pElem1 < *(PULONG)pElem2)
		return -1;
	else if (*(PULONG)pElem1 > *(PULONG)pElem2)
		return 1;
	else
		return 0;
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
		return status;

	///Although we don't want any DllMain() to be called, we intend to use standard PE math
	///when walking the EAT at a later time. So we still need to load the DLL as an image file.	
	loadFlags = LOAD_LIBRARY_AS_IMAGE_RESOURCE;
	loadFlags |= LOAD_LIBRARY_SEARCH_SYSTEM32;
	loadFlags |= LOAD_LIBRARY_SEARCH_APPLICATION_DIR;

	RtlInitUnicodeString(&uDllName, szDllName);
	status = LdrLoadDll(NULL, &loadFlags, &uDllName, ppDllBase);

	return status;
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
	///1. Each mapped section of the image is at least readable (R) without guard (+G).
	///2. There don't exist any free pages between two sections of the same image.
	if ((pImageBase < ALIGN_DOWN_POINTER(pArbitraryPtr, PVOID)) && (((PUCHAR)ALIGN_UP_POINTER(pArbitraryPtr, PVOID) + accessLength) < ((PUCHAR)pImageBase + peSize)))
		return STATUS_SUCCESS;

	return STATUS_INVALID_ADDRESS;
}

NTSTATUS obtainImageFileEatEntries(PVOID pImageFileBase, PUCHAR pListBuffer, PULONGLONG pNeededBufferSize, PUCHAR pModuleName, ULONGLONG moduleNameSize){
	UCHAR szError[] = "Error";
	ULONGLONG nameLength = 0;
	ULONGLONG maxReadSize = 0;
	ULONGLONG minExportSize = 0;
	NTSTATUS status = STATUS_UNABLE_TO_UNLOAD_MEDIA;
	ULONGLONG exportSize = 0;
	PIMAGE_NT_HEADERS64 pImagePeHdr = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PULONG piListBuffer = NULL;
	PULONG pNameRvaArray = NULL;
	PUCHAR pCurrName = NULL;
	PUCHAR pListPointer = NULL;

	if (!pImageFileBase || !pNeededBufferSize || !pModuleName)
		return STATUS_INVALID_PARAMETER;

	if (!pListBuffer && *pNeededBufferSize)
		return STATUS_INVALID_PARAMETER;

	pImagePeHdr = (PIMAGE_NT_HEADERS64)((PUCHAR)pImageFileBase + ((PIMAGE_DOS_HEADER)pImageFileBase)->e_lfanew);
	pDataDirectory = pImagePeHdr->OptionalHeader.DataDirectory;
	///Is it safe to read the data directory array until the desired entry?
	maxReadSize = sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_DIRECTORY_ENTRY_EXPORT + 1);
	status = validatePePointer(pImageFileBase, pDataDirectory, maxReadSize, TRUE);
	if (status)
		return status;

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pImageFileBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	///Is it safe to read all members of the export directory structure?
	maxReadSize = sizeof(IMAGE_EXPORT_DIRECTORY);
	status = validatePePointer(pImageFileBase, pExportDirectory, maxReadSize, FALSE);
	if (status)
		return status;

	///Is the claimed export size viable?
	exportSize = pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	status = validatePePointer(pImageFileBase, pExportDirectory, exportSize, FALSE);
	if (status)
		return status;

	///By doing some math one can prove that the maximum needed buffer size is guaranteed
	///to not exceed the export directory size: Due to PE specifications the export size is going to be
	///more than at least: all_namelengths + NumberOfNames * (sizeof(ANSI_NULL) + sizeof(ULONG)). 
	///This simplifies to: all_namelengths + 5 * NumberOfNames.
	///Since we will be adding one more char for each name entry, our actual needed buffer size becomes at maximum:
	///all_namelengths + NumberOfNames * 2 * sizeof(char), which simplifies to all_namelengths + 2 * NumberOfNames.
	///As we can see, there exists still a huge safety margin, even though we completely neglected
	///the sizes of both the function RVA and the ordinal tables. It is therefore fully sufficient if we
	///set the needed buffer size to the export size.
	if (*pNeededBufferSize < PAGE_ROUND_UP(exportSize)){
		*pNeededBufferSize = PAGE_ROUND_UP(exportSize);
		return STATUS_BUFFER_TOO_SMALL;
	}

	///Is it safe to scan down the name RVA array?
	pNameRvaArray = (PULONG)((PUCHAR)pImageFileBase + pExportDirectory->AddressOfNames);
	maxReadSize = pExportDirectory->NumberOfNames * sizeof(ULONG);
	status = validatePePointer(pImageFileBase, pNameRvaArray, maxReadSize, FALSE);
	if (status)
		return status;

	///Since NumberOfNames can be any value, we need to roughly estimate the exportSize
	///according to the combined sizes of the three export describing arrays.
	///If this yields to greater export size than the claimed export size, the image must be rejected.
	minExportSize = sizeof(ULONG) * pExportDirectory->NumberOfFunctions + pExportDirectory->NumberOfNames * sizeof(ULONG) + sizeof(USHORT) + sizeof(ANSI_NULL);
	if (exportSize <= minExportSize)
		return STATUS_INVALID_IMAGE_FORMAT;

	///It is NOT guaranteed, that an entry in the name RVA array at position 'n' has a value
	///which also orders as the n-th element in the entire name RVA range.
	///It is therefore not permissible to calculate the name length by simply doing
	///pNameRvaArray[n+1] - pNameRvaArray[n]. If we still want to make this assumption
	///the RVAs values must be sorted until they are in an ascending order.
	///By utilizing the last unused bytes of the caller-allocated buffer we avoid having
	///to allocate a buffer on our own. Doing the math above (see exportsize calculation)
	///one can prove that the safety margin is sufficient if we use the buffer in that way.
	piListBuffer = (PULONG)(pListBuffer + *pNeededBufferSize - pExportDirectory->NumberOfNames * sizeof(ULONG));
	RtlCopyMemory(piListBuffer, pNameRvaArray, pExportDirectory->NumberOfNames * sizeof(ULONG));
	qsort(piListBuffer, (ULONGLONG)pExportDirectory->NumberOfNames, sizeof(ULONG), mycompare);

	///Is it safe to read the module name?
	maxReadSize = pNameRvaArray[0] - pExportDirectory->Name;
	status = validatePePointer(pImageFileBase, (PVOID)((PUCHAR)pImageFileBase + pExportDirectory->Name), maxReadSize, FALSE);
	if (status)
		return status;

	if (moduleNameSize < maxReadSize)
		return STATUS_STACK_OVERFLOW;
	
	RtlCopyMemory(pModuleName, (PUCHAR)pImageFileBase + pExportDirectory->Name, maxReadSize);
	pModuleName[maxReadSize - 1] = 0x0;
	pListPointer = pListBuffer;
	printf_s("\nmodule name: %s", pModuleName);

	pNameRvaArray = piListBuffer;
	for (ULONG i = 0; i < pExportDirectory->NumberOfNames; i++){
		///Will none of the obtained name RVAs evaluate to an invalid name pointer?
		if (!(exportSize + pDataDirectory->VirtualAddress > pNameRvaArray[i]))
			return STATUS_INVALID_IMAGE_FORMAT;
		
		pCurrName = (PUCHAR)pImageFileBase + pNameRvaArray[i];
		///At the end of RVA array there is no longer a next name entry.
		///There must by PE design a terminating zero though, which we're going to exploit
		///in order to still have a valid name length.
		if (pExportDirectory->NumberOfNames - 1 == i){
			int j = 0;
			while (pCurrName[j])
				j++;

			nameLength = j;
		}
		else{
			nameLength = (ULONGLONG)(pNameRvaArray[i + 1] - pNameRvaArray[i]/*pNextName - pCurrName*/) - 1;
		}
		///If for some reason the allocated buffer is about to be overran
		///we print an error signature into the buffer and abort the scan.
		///In regard of our thousands of sanity checks this surely denotes a major PE damage.
		///Additionally, we break a little earlier to not have the failure overwrite the sorted RVAs.
		if ((PUCHAR)piListBuffer <= pListPointer + nameLength + sizeof(WCHAR)){
			pCurrName = szError;
			nameLength = sizeof(szError) - 1;
			pListPointer = (PUCHAR)piListBuffer - (nameLength + sizeof(WCHAR));
			///Indirect break, bail out.
			i = pExportDirectory->NumberOfNames;
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

NTSTATUS dumpEatEntriesToDefFile(PVOID pEatEntryList, ULONGLONG listBufferSize, PUCHAR pModuleName){
	OBJECT_ATTRIBUTES defFileAttr;
	UNICODE_STRING uDefFileName;
	IO_STATUS_BLOCK ioSb;

	NTSTATUS status, fatalStatus = STATUS_CLUSTER_NETINTERFACE_EXISTS;
	
	PCHAR pDefPreamble = NULL;
	///Keep it simple. We can't allocate less than 4 kB using NtXxx funcs anyway,
	///so just allocate 4 kB although we never will need that much.
	ULONGLONG defPreambleSize = PAGE_SIZE;
	HANDLE hDefFile = NULL;
	HANDLE hParentDir = NULL;
	///Quite some ugly hacking...
	char szDefPreamblePart[] = { 0x0D, 0x0A, 0x0D, 0x0A, 'E', 'X', 'P', 'O', 'R', 'T', 'S', 0x0D, 0x0A, 0x0 };

	status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &pDefPreamble, 0, &defPreambleSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (status)
		return status;

	status = RtlStringCbPrintfA(pDefPreamble, defPreambleSize, "LIBRARY %s%s", pModuleName, szDefPreamblePart);
	if (status){
		fatalStatus = NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pDefPreamble, &defPreambleSize, MEM_RELEASE);
		if (fatalStatus)
			mydie(status, fatalStatus);

		return status;
	}

	status = RtlStringCbLengthA(pDefPreamble, defPreambleSize, &defPreambleSize);
	if (status){
		fatalStatus = NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pDefPreamble, &defPreambleSize, MEM_RELEASE);
		if (fatalStatus)
			mydie(status, fatalStatus);

		return status;
	}

	hParentDir = NtCurrentPeb()->ProcessParameters->CurrentDirectory.Handle;
	RtlInitUnicodeString(&uDefFileName, L"exports.def");
	InitializeObjectAttributes(&defFileAttr, &uDefFileName, OBJ_CASE_INSENSITIVE, hParentDir, NULL);
	status = NtCreateFile(&hDefFile, FILE_ALL_ACCESS | SYNCHRONIZE, &defFileAttr, &ioSb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (status){
		fatalStatus = NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pDefPreamble, &defPreambleSize, MEM_RELEASE);
		if (fatalStatus)
			mydie(status, fatalStatus);

		return status;
	}

	status = NtWriteFile(hDefFile, NULL, NULL, NULL, &ioSb, pDefPreamble, (ULONG)defPreambleSize, NULL, NULL);
	if (!status)
		status = NtWriteFile(hDefFile, NULL, NULL, NULL, &ioSb, pEatEntryList, (ULONG)listBufferSize, NULL, NULL);

	fatalStatus = NtClose(hDefFile);
	if (fatalStatus)
		mydie(status, fatalStatus);

	fatalStatus = NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pDefPreamble, &defPreambleSize, MEM_RELEASE);
	if (fatalStatus)
		mydie(status, fatalStatus);

	return status;
}

void mymain(void){
	///A valid module name cannot exceed the Windows path part constraints.
	UCHAR szInternalDllName[MAX_PATH];
	PVOID pDllBase = NULL;
	PVOID pListBuf = NULL;
	ULONGLONG requiredBufSize = 0;
	ULONGLONG bufSize = 0;
	ULONGLONG entryStringLength = 0;
	NTSTATUS status, fatalStatus = STATUS_HANDLE_NO_LONGER_VALID;

	for (;;){
		pDllBase = NULL;
		pListBuf = NULL;
		requiredBufSize = 0;
		bufSize = 0;
		entryStringLength = 0;

		system("CLS");
		printf_s("Welcome to .def File Creator V0.1!\n\n");
		printf_s("Enter the full DLL or exe name as in the following example:\n");
		printf_s("\"ntdll.dll\" (without quotes).\n\n");
		printf_s("DLL must reside in \\System32 or in current directory.\n\n");
		printf_s("DLL name: ");

		status = getAndLoadDllByInput(&pDllBase);
		if (status){
			mydie(status, STATUS_SUCCESS);
			continue;
		}
		
		printf_s("DLL loaded successfully. Address: %p\n", pDllBase);
		status = obtainImageFileEatEntries(pDllBase, NULL, &requiredBufSize, szInternalDllName, sizeof(szInternalDllName));
		if (status != STATUS_BUFFER_TOO_SMALL){
			mydie(status, STATUS_SUCCESS);
			continue;
		}
		
		status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &pListBuf, 0, &requiredBufSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (status){
			mydie(status, STATUS_SUCCESS);
			continue;
		}

		bufSize = requiredBufSize;
		status = obtainImageFileEatEntries(pDllBase, pListBuf, &requiredBufSize, szInternalDllName, sizeof(szInternalDllName));
		if (status){
			mydie(status, STATUS_SUCCESS);
			continue;
		}

		printf_s("\n%s\n\nlist size: 0x%llX", pListBuf, requiredBufSize);

		///We don't want to write zeros into the file. The standard EOF is sufficient.
		entryStringLength = requiredBufSize - sizeof(WCHAR);
		status = dumpEatEntriesToDefFile(pListBuf, entryStringLength, szInternalDllName);

		fatalStatus = NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pListBuf, &bufSize, MEM_RELEASE);
		if (status || fatalStatus){
			mydie(status, fatalStatus);
			continue;
		}

		printf_s("\nThe image has been successfully scanned and its exports were");
		printf_s("\ndumped into \"exports.def\" successfully.");
		printf_s("\n\nYou can press any key to dump another module or close the window to exit.");
		fflush(stdin);
		_getch();
	}
}