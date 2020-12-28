#pragma once
#include <Windows.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <DbgHelp.h>

#include <inttypes.h>
#include <Zydis/Zydis.h>
#pragma comment(lib,"Zydis.lib")
#define QWORD unsigned __int64

// debugger status
enum class DebuggeeStatus
{
	NONE,
	SUSPENDED,
	INTERRUPTED
};

struct LineInfo 
{
	std::string filePath;
	DWORD lineNumber;
};

// flag
struct Flag
{
	DWORD continueStatus;
	DWORD resetUserBreakPointAddress;
	bool isBeingStepOver;
	bool isBeingStepOut;
	bool isBeingSingleInstruction;
	LineInfo glf;
} ;

extern struct Flag FLAG;

// breakpoint
struct BreakPoint
{
	QWORD address;
	BYTE content;
};

extern bool bExcept;
extern BreakPoint bpStepOver;
extern DebuggeeStatus debuggeeStatus;
extern DWORD continueStatus;
extern HANDLE debuggeehProcess;
extern HANDLE debuggeehThread;
extern DWORD debuggeeprocessID;
extern DWORD debuggeethreadID;

extern QWORD procBase;
extern std::string filename;
extern DWORD dwAttached;

enum class BpType
{
	INIT,
	STEP_OVER,
	STEP_OUT,
	USER,
	CODE
};

bool AttachProcess(DWORD pid);
void Detach();
void InitProcess(const char* szFile);
CONTEXT GetContext();
void SetContext(CONTEXT* c);
void setCPUTrapFlag();
void Run();
void StepIn();
void resetBreakPointHandler();
void SingleStep();
QWORD GetRegisterValue(ZydisRegister registerValue);
bool SetRegisterValue(ZydisRegister registerV, QWORD registerValue);

bool OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO* pInfo);
BpType getBreakPointType(DWORD addr);
bool OnBreakPoint(const EXCEPTION_DEBUG_INFO* pInfo);

void ReadTo(QWORD addr, LPBYTE dest, DWORD nSize);

template <class T>
T Read(QWORD addr)
{
	T out;
	size_t nRead;
	ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, &out, sizeof(T), &nRead);
	return out;
}

template <class T>
void Write(QWORD addr, T t);

template <class T>
T Read(LPBYTE adr)
{
	T t = T();
	ReadProcessMemory(debuggeehProcess, (LPBYTE)adr, &t, sizeof(T), NULL);
	return t;
}

