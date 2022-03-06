#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include "openssl/md5.h"
#include <queue>
#include <vector>

#define MAX_UNIC_PATH 32767

CONDITION_VARIABLE BufferNotEmpty;
CONDITION_VARIABLE BufferNotFull;
CRITICAL_SECTION   BufferLock;

BOOL StopRequested;
int NUMBER_OF_CORES;

int sum[16];
std::queue<wchar_t*> Q;

DWORD WINAPI ProducerProc(LPVOID lpParam) {
	std::vector<wchar_t*>& filesList = *(std::vector<wchar_t*>*)lpParam;
	size_t len = filesList.size();
	int count = 0;
	while (true) {
		EnterCriticalSection(&BufferLock);
		while (Q.size() == NUMBER_OF_CORES && StopRequested == FALSE) {
			SleepConditionVariableCS(&BufferNotFull, &BufferLock, INFINITE);
		}
		if (StopRequested == TRUE) {
			LeaveCriticalSection(&BufferLock);
			break;
		}
		Q.push(filesList[count]);
		wprintf(L"Producer Thread: `%s`, queue size = %llu\n\n", Q.back(), Q.size());
		count++;
		if (count == len) {
			StopRequested = TRUE;
		}
		LeaveCriticalSection(&BufferLock);
		WakeConditionVariable(&BufferNotEmpty);
	}
	printf("Producer exiting\n");
	return 0;
}

DWORD fileMD5(wchar_t* filePath, unsigned char mdOut[]) {
	HANDLE hFileIn;
	char ReadBuffer[MD5_DIGEST_LENGTH + 1] = { 0 };
	DWORD dwBytesRead = 0;

	hFileIn = CreateFile(filePath,
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_READONLY | FILE_FLAG_SEQUENTIAL_SCAN, // readonly, from start to finish
		NULL);                 // no attr. template

	if (GetLastError() == 2) {
		wprintf(L"\"%ls\" file not found.\n", filePath);
		return 2;
	}
	if (hFileIn == INVALID_HANDLE_VALUE) {
		wprintf(L"Terminal failure: unable to open file \"%ls\" for read.\n", filePath);
		return -3;
	}

	MD5_CTX c;
	MD5_Init(&c);
	bool r = ReadFile(hFileIn, ReadBuffer, MD5_DIGEST_LENGTH, &dwBytesRead, NULL);
	while (dwBytesRead != 0) {
		if (r == FALSE) {
			DWORD err = GetLastError();
			printf("Terminal failure: Unable to read from file.\n GetLastError=%08x\n", err);
			CloseHandle(hFileIn);
			return err;
		}
		size_t len = strlen(ReadBuffer);
		MD5_Update(&c, ReadBuffer, len);
		r = ReadFile(hFileIn, ReadBuffer, MD5_DIGEST_LENGTH, &dwBytesRead, NULL);
	}
	MD5_Final(mdOut, &c);
	return 0;
}

DWORD WINAPI ThreadProc(LPVOID lpParam) {
	while (true) {
		EnterCriticalSection(&BufferLock);
		while (Q.size() == 0 && StopRequested == FALSE) {
			SleepConditionVariableCS(&BufferNotEmpty, &BufferLock, INFINITE);
		}
		if (StopRequested == TRUE && Q.size() == 0) {
			LeaveCriticalSection(&BufferLock);
			break;
		}
		if (Q.size() != 0) {
			wchar_t* x = Q.front();
			unsigned char md[MD5_DIGEST_LENGTH];
			fileMD5(x, md);
			wprintf(L"ConsumerThread #%d :'%s', %llu queue size\n", *(int*)lpParam, x, Q.size());
			printf("%02x", md[0]);
			for (int i = 1; i < MD5_DIGEST_LENGTH; i++)
				printf("-%02x", md[i]);
			printf("\n\n");
			Q.pop();
		}
		LeaveCriticalSection(&BufferLock);
		WakeConditionVariable(&BufferNotFull);
	}
	printf("Consumer exiting\n");
	return 0;
}

DWORD createPath(const wchar_t* src, const wchar_t* suffix, wchar_t*& res) {
	size_t len = 0;
	size_t sl = 0;
	StringCchLength(src, MAX_UNIC_PATH, &len);
	StringCchLength(suffix, MAX_UNIC_PATH, &sl);
	if (len + sl > MAX_UNIC_PATH) {
		wprintf(L"\nPath \"%ls\" is too long.\n", src);
		return -1;
	}
	wchar_t* Dir = (wchar_t*)calloc(len + sl + 1, sizeof(wchar_t));
	if (Dir == NULL) {
		wprintf(L"No free memory\n");
		return -2;
	}
	StringCchCopy(Dir, len + sl + 1, src);
	StringCchCat(Dir, len + sl + 1, suffix);
	res = Dir;
	return 0;
}

DWORD ListDirectory(wchar_t argSrc[], std::vector<wchar_t*> &outputList) {
	DWORD dwError;
	WIN32_FIND_DATA FindFileData;
	LARGE_INTEGER filesize;
	wchar_t* srcDir = 0;
	dwError = createPath(argSrc, L"\\*", srcDir);
	if (dwError == -1) {
		wprintf(L"\nPath \"%ls\" is too long.\n", argSrc);
		return dwError;
	}
	if (dwError == -2) {
		wprintf(L"No free memory\n");
		return dwError;
	}

	HANDLE hFind = FindFirstFile(srcDir, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		dwError = GetLastError();
		printf("FindFirstFile failed (%d)\n", dwError);
		free(srcDir);
		return dwError;
	}
	size_t srcLen = 0;
	StringCchLength(srcDir, MAX_UNIC_PATH, &srcLen);
	srcDir[srcLen - 1] = 0;

	do {
		wchar_t* fileSrcPath = 0;
		DWORD dwError1 = createPath(srcDir, FindFileData.cFileName, fileSrcPath);
		// path not created, no memory allocated for those wstrings
		if (dwError1 != 0) {
			wprintf(L"  %ls\t\tFAIL: error code %d\n", FindFileData.cFileName, dwError1);
			continue;
		}
		// FindFileData is not a directory
		if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			outputList.push_back(fileSrcPath);
		}
		//FindFileData is a directory and not '.' or '..'
		else if (!(wcscmp(FindFileData.cFileName, L".") == 0 || wcscmp(FindFileData.cFileName, L"..") == 0)) {
			ListDirectory(fileSrcPath, outputList);
			free(fileSrcPath);
		}
	} while (FindNextFile(hFind, &FindFileData) != 0);

	free(srcDir);
	FindClose(hFind);
	return 0;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc < 2) {
		wprintf(L"Incorrect number of arguments.\nUsage:\n\t%ls {inFolderPath}\n", argv[0]);
		return -1;
	}
	std::vector<wchar_t*> filesList;
	DWORD err = ListDirectory(argv[1], filesList);
	if (err) {
		exit(err);
	}
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	NUMBER_OF_CORES = sysInfo.dwNumberOfProcessors;

	HANDLE hProducerThread;
	HANDLE* hThread = (HANDLE*)calloc(NUMBER_OF_CORES, sizeof(HANDLE));
	DWORD idThread;
	if (hThread == NULL) {
		return -1;
	}

	InitializeConditionVariable(&BufferNotEmpty);
	InitializeConditionVariable(&BufferNotFull);
	InitializeCriticalSection(&BufferLock);

	hProducerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProducerProc, &filesList, 0, &idThread);
	if (hProducerThread == NULL) {
		return -3;
	}
	
	for (int i = 0; i < NUMBER_OF_CORES; ++i) {
		int* index = (int*)malloc(sizeof(int));
		*index = i;
		hThread[i] = CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)ThreadProc,
			index, // args
			0,
			&idThread
		);
		if (hThread[i] == NULL) {
			return -3;
		}
	}

	WaitForSingleObject(hProducerThread, INFINITE);
	WaitForMultipleObjects(NUMBER_OF_CORES, hThread, TRUE, INFINITE);

	CloseHandle(hProducerThread);
	for (int i = 0; i < NUMBER_OF_CORES; ++i) {
		CloseHandle(hThread[i]);
	}
	free(hThread);
	for (wchar_t* filePath : filesList) {
		free(filePath);
	}
	return 0;
}