#include "Dbg.h"

bool bExcept = false;
bool DispatchDebugEvent(const DEBUG_EVENT& debugEvent);
CONTEXT GetContext();

ZydisDecoder decoder;

bool DEBUG = !true;

BreakPoint bpStepOver;
DebuggeeStatus debuggeeStatus;
DWORD continueStatus;
HANDLE debuggeehProcess;
HANDLE debuggeehThread;
DWORD debuggeeprocessID;
DWORD debuggeethreadID;

QWORD procBase;
std::string filename;
DWORD dwAttached = 0;

struct Flag FLAG;

template <class T>
void Write(QWORD addr, T t)
{
	size_t nRead;
	WriteProcessMemory(debuggeehProcess, (LPVOID)addr, &t, sizeof(T), &nRead);
}

bool AttachProcess(DWORD pid)
{

	auto r = DebugActiveProcess(pid);
	if (r)
	{
		debuggeeStatus = DebuggeeStatus::SUSPENDED;

		debuggeeprocessID = pid;
		debuggeehThread = 0;

		debuggeeStatus = DebuggeeStatus::SUSPENDED;
		printf("T[%i] P[%04X] Process attached and suspended. [%p]\n", debuggeethreadID, debuggeeprocessID, procBase);
		dwAttached = pid;
	}
	return r;
}

void Detach()
{
	if (dwAttached) {
		DebugActiveProcessStop(dwAttached);
		dwAttached = 0;
	}
}

void InitProcess(const char* szFile)
{
	STARTUPINFOA startupinfo = { 0 };
	startupinfo.cb = sizeof(startupinfo);
	PROCESS_INFORMATION processinfo = { 0 };

	if (CreateProcessA(szFile, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &startupinfo, &processinfo) == FALSE)
	{
		std::cout << "CreateProcess failed: " << GetLastError() << std::endl;
		return;
	}

	debuggeehProcess = processinfo.hProcess;
	debuggeehThread = processinfo.hThread;
	debuggeeprocessID = processinfo.dwProcessId;
	debuggeethreadID = processinfo.dwThreadId;

	filename = szFile;
	auto c = GetContext();
	procBase = Read<QWORD>(c.Rdx + 0x10);

	debuggeeStatus = DebuggeeStatus::SUSPENDED;
	printf("T[%i] P[%04X] Process launched and suspended. [%p]\n", debuggeethreadID, debuggeeprocessID, procBase);
}

CONTEXT GetContext()
{
	CONTEXT c;
	c.ContextFlags = CONTEXT_ALL;

	if (GetThreadContext(debuggeehThread, &c))
	{
		//return false;
	}
	return c;
}

void SetContext(CONTEXT* c)
{
	SetThreadContext(debuggeehThread, c);
}

void setCPUTrapFlag()
{
	CONTEXT c = GetContext();
	c.EFlags |= 0x100;
	SetContext(&c);
}

void Run()
{
	if (debuggeeStatus == DebuggeeStatus::NONE)
		return;
	
	if (debuggeeStatus == DebuggeeStatus::SUSPENDED)
		ResumeThread(debuggeehThread);
	else
		ContinueDebugEvent(debuggeeprocessID, debuggeethreadID, FLAG.continueStatus);

	DEBUG_EVENT debugEvent;
	while (WaitForDebugEvent(&debugEvent, INFINITE) == TRUE)
	{
		debuggeeprocessID = debugEvent.dwProcessId;
		debuggeethreadID = debugEvent.dwThreadId;
		if (DispatchDebugEvent(debugEvent) == TRUE)
		{
			ContinueDebugEvent(debuggeeprocessID, debuggeethreadID, FLAG.continueStatus);
		}
		else
		{
			break;
		}
	}
}

void StepIn() 
{
	setCPUTrapFlag();
	FLAG.isBeingSingleInstruction = true;
	Run();
}

void resetBreakPointHandler()
{
	FLAG.continueStatus = DBG_CONTINUE;
	FLAG.isBeingSingleInstruction = false;
	FLAG.isBeingStepOut = false;
	FLAG.isBeingStepOver = false;
	FLAG.resetUserBreakPointAddress = 0;
	FLAG.glf.lineNumber = 0;
	FLAG.glf.filePath = std::string();

	//moduleMap.clear();
}

bool OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO* pInfo)
{
	debuggeehProcess = pInfo->hProcess;
	debuggeehThread = pInfo->hThread;
	printf("%p / %p\n", debuggeehProcess, debuggeehThread);
	procBase = (QWORD)pInfo->lpBaseOfImage;
	std::cout << "Debuggee created." << std::endl;

	resetBreakPointHandler();

	if (pInfo->lpImageName) {
		filename = std::string((char*)pInfo->lpImageName);
	}

	if (SymInitialize(debuggeehProcess, NULL, FALSE) == TRUE)
	{
		QWORD moduleAddress = SymLoadModule64(
			debuggeehProcess,
			pInfo->hFile,
			NULL,
			NULL,
			(QWORD)pInfo->lpBaseOfImage,
			0
		);
		if (moduleAddress == 0)
		{
			std::cout << "SymLoadModule64 failed: " << GetLastError() << std::endl;
		}
		else {
			// set entry stop 
			//setDebuggeeEntryPoint();
		}
	}
	else
	{
		std::cout << "SymInitialize failed: " << GetLastError() << std::endl;
	}
	return true;
}

BpType getBreakPointType(DWORD addr) 
{
	static bool isInitBpSet = false;
	if (isInitBpSet == false)
	{
		isInitBpSet = true;
		return BpType::INIT;
	}
	return BpType::CODE;
}

bool OnBreakPoint(const EXCEPTION_DEBUG_INFO* pInfo)
{
	auto bpType = getBreakPointType((DWORD)(pInfo->ExceptionRecord.ExceptionAddress));
	printf("bp type: %i\n", bpType);
	switch (bpType)
	{
	case BpType::INIT:
		FLAG.continueStatus = DBG_CONTINUE;
		//auto c = GetContext();
		//c.Rip = procBase + 0xE74D84;
		//SetContext(&c);
		return dwAttached ? false : true;

		/*case BpType::CODE:
			return onNormalBreakPoint(pInfo);

		case BpType::STEP_OVER:
			deleteStepOverBreakPoint();
			backwardDebuggeeEIP();
			return onSingleStepCommonProcedures();

		case BpType::USER:
			return onUserBreakPoint(pInfo);

		case BpType::STEP_OUT:
			return onStepOutBreakPoint(pInfo);*/
	}

	return true;
}
bool getCurrentLineInfo(LineInfo& lf)
{
	CONTEXT context = GetContext();

	DWORD displacement;
	IMAGEHLP_LINE64 lineInfo = { 0 };
	lineInfo.SizeOfStruct = sizeof(lineInfo);

	if (SymGetLineFromAddr64(
		debuggeehProcess,
		context.Rip,
		&displacement,
		&lineInfo) == TRUE) {

		lf.filePath = std::string(lineInfo.FileName);
		lf.lineNumber = lineInfo.LineNumber;

		return true;
	}
	else {
		lf.filePath = std::string();
		lf.lineNumber = 0;

		return false;
	}
}
bool isLineChanged()
{
	LineInfo lf;
	if (false == getCurrentLineInfo(lf))
	{
		return false;
	}

	if (lf.lineNumber == FLAG.glf.lineNumber &&
		lf.filePath == FLAG.glf.filePath)
	{
		return false;
	}

	return true;
}
int isCallInstruction(QWORD addr)
{
	BYTE instruction[10];

	size_t nRead;
	ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, instruction, 10, &nRead);

	switch (instruction[0]) {

	case 0xE8:
		return 5;

	case 0x9A:
		return 7;

	case 0xFF:
		switch (instruction[1]) {

		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x16:
		case 0x17:
		case 0xD0:
		case 0xD1:
		case 0xD2:
		case 0xD3:
		case 0xD4:
		case 0xD5:
		case 0xD6:
		case 0xD7:
			return 2;

		case 0x14:
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
			return 3;

		case 0x15:
		case 0x90:
		case 0x91:
		case 0x92:
		case 0x93:
		case 0x95:
		case 0x96:
		case 0x97:
			return 6;

		case 0x94:
			return 7;
		}

	default:
		return 0;
	}
}

void ReadTo(QWORD addr, LPBYTE dest, DWORD nSize)
{
	size_t nRead;
	ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, dest, nSize, &nRead);
}

BYTE setBreakPointAt(QWORD addr)
{
	BYTE byte = Read<BYTE>(addr);
	//readDebuggeeMemory(addr, 1, &byte);

	Write<BYTE>(addr, 0xCC);//BYTE intInst = 0xCC;
	//writeDebuggeeMemory(addr, 1, &intInst);
	return byte;
}

void setStepOverBreakPointAt(QWORD addr)
{
	bpStepOver.address = addr;
	bpStepOver.content = setBreakPointAt(addr);
}

bool OnSingleStepCommonProcedures()
{
	if (isLineChanged() == false)
	{
		if (true == FLAG.isBeingStepOver)
		{
			CONTEXT c = GetContext();
			int pass = isCallInstruction(c.Rip);

			if (pass != 0)
			{
				setStepOverBreakPointAt(c.Rip + pass);
				FLAG.isBeingSingleInstruction = false;
			}
			else {
				setCPUTrapFlag();
				FLAG.isBeingSingleInstruction = true;
			}
		}
		else {
			setCPUTrapFlag();
			FLAG.isBeingSingleInstruction = true;
		}

		FLAG.continueStatus = DBG_CONTINUE;
		return true;
	}

	if (FLAG.isBeingStepOver == true)
	{
		FLAG.isBeingStepOver = false;
	}

	debuggeeStatus = DebuggeeStatus::INTERRUPTED;

	return false;
}

bool OnSingleStepTrap(const EXCEPTION_DEBUG_INFO* pInfo)
{
	if (true == FLAG.isBeingSingleInstruction)
	{
		return  OnSingleStepCommonProcedures();
	}

	FLAG.continueStatus = DBG_CONTINUE;
	return true;
}
bool bGotSingleStep = false;
bool OnException(const EXCEPTION_DEBUG_INFO* pInfo)
{
	if (DEBUG == true)
	{
		std::cout << "An exception has occured " << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
			<< pInfo->ExceptionRecord.ExceptionAddress << " - Exception code: " << pInfo->ExceptionRecord.ExceptionCode << std::dec << std::endl;
	}

	switch (pInfo->ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
		return OnBreakPoint(pInfo);
	case EXCEPTION_SINGLE_STEP:
		bGotSingleStep = true;
		debuggeeStatus = DebuggeeStatus::INTERRUPTED;
		return false;// OnSingleStepTrap(pInfo);
		break;
	case 0xC0000005:
		debuggeeStatus = DebuggeeStatus::INTERRUPTED;
		bExcept = true;
		//printf("//%p - access violation!!!\n", pInfo->ExceptionRecord.ExceptionAddress);
		return false;//
		break;
	}

	if (pInfo->dwFirstChance == TRUE)
	{
		if (DEBUG == true)
		{
			std::cout << "First chance." << std::endl;
		}
	}
	else
	{
		if (DEBUG == true)
		{
			std::cout << "Second chance." << std::endl;
		}
	}

	debuggeeStatus = DebuggeeStatus::INTERRUPTED;
	return false;
}
bool DispatchDebugEvent(const DEBUG_EVENT& debugEvent) {

	switch (debugEvent.dwDebugEventCode)
	{
	case CREATE_PROCESS_DEBUG_EVENT:
		OnProcessCreated(&debugEvent.u.CreateProcessInfo);
		setCPUTrapFlag();
		FLAG.isBeingSingleInstruction = true;
		return true;
	case CREATE_THREAD_DEBUG_EVENT:
		//printf("Thread created!\n");
		return true;
		break;
	case LOAD_DLL_DEBUG_EVENT:
		//wprintf(L"dll loaded.. %p\n", debugEvent.u.LoadDll.lpBaseOfDll);
		return true;// onDllLoaded(&debugEvent.u.LoadDll);
		break;
	case UNLOAD_DLL_DEBUG_EVENT:
		//wprintf(L"dll unloaded.. %p\n", debugEvent.u.LoadDll.lpBaseOfDll);
		return true;// onDllLoaded(&debugEvent.u.LoadDll);
		break;
	case EXIT_THREAD_DEBUG_EVENT:
		//printf("Thread Exit!\n");
		return true;// onThreadExited(&debugEvent.u.ExitThread);
		break;
	case EXCEPTION_DEBUG_EVENT:
		//printf("[%i] debug event\n", debugEvent.dwThreadId);
		return OnException(&debugEvent.u.Exception);
		break;
	default:

		printf("UNK event: %i\n", debugEvent.dwDebugEventCode);
		break;
	}
	return false;
}

void SingleStep()
{

	setCPUTrapFlag();
	FLAG.isBeingSingleInstruction = true;
	Run();
}

QWORD GetRegisterValue(ZydisRegister registerValue)
{
	CONTEXT c = GetContext();

	if (ZydisRegisterGetWidth64(registerValue) == 32)
	{
		ZydisI16 regID = ZydisRegisterGetId(registerValue);
		registerValue = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, regID);
	}

	switch (registerValue)
	{
	case ZYDIS_REGISTER_RIP:
		return c.Rip;
		break;
	case ZYDIS_REGISTER_RAX:
		return c.Rax;
		break;
	case ZYDIS_REGISTER_RCX:
		return c.Rcx;
		break;
	case ZYDIS_REGISTER_RDX:
		return c.Rdx;
		break;
	case ZYDIS_REGISTER_RBX:
		return c.Rbx;
		break;
	case ZYDIS_REGISTER_RSP:
		return c.Rsp;
		break;
	case ZYDIS_REGISTER_RBP:
		return c.Rbp;
		break;
	case ZYDIS_REGISTER_RSI:
		return c.Rsi;
		break;
	case ZYDIS_REGISTER_RDI:
		return c.Rdi;
		break;
	case ZYDIS_REGISTER_R8:
		return c.R8;
		break;
	case ZYDIS_REGISTER_R9:
		return c.R9;
		break;
	case ZYDIS_REGISTER_R10:
		return c.R10;
		break;
	case ZYDIS_REGISTER_R11:
		return c.R11;
		break;
	case ZYDIS_REGISTER_R12:
		return c.R12;
		break;
	case ZYDIS_REGISTER_R13:
		return c.R13;
		break;
	case ZYDIS_REGISTER_R14:
		return c.R14;
		break;
	case ZYDIS_REGISTER_R15:
		return c.R15;
		break;
	default:
		return 0;
		break;
	}
}
bool SetRegisterValue(ZydisRegister registerV, QWORD registerValue)
{
	CONTEXT c = GetContext();

	if (ZydisRegisterGetWidth64(registerV) == 32)
	{
		ZydisI16 regID = ZydisRegisterGetId(registerV);
		registerV = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, regID);
	}

	switch (registerV)
	{
	case ZYDIS_REGISTER_RIP:
		c.Rip = registerValue;
		break;
	case ZYDIS_REGISTER_RAX:
		c.Rax = registerValue;
		break;
	case ZYDIS_REGISTER_RCX:
		c.Rcx = registerValue;
		break;
	case ZYDIS_REGISTER_RDX:
		c.Rdx = registerValue;
		break;
	case ZYDIS_REGISTER_RBX:
		c.Rbx = registerValue;
		break;
	case ZYDIS_REGISTER_RSP:
		c.Rsp = registerValue;
		break;
	case ZYDIS_REGISTER_RBP:
		c.Rbp = registerValue;
		break;
	case ZYDIS_REGISTER_RSI:
		c.Rsi = registerValue;
		break;
	case ZYDIS_REGISTER_RDI:
		c.Rdi = registerValue;
		break;
	case ZYDIS_REGISTER_R8:
		c.R8 = registerValue;
		break;
	case ZYDIS_REGISTER_R9:
		c.R9 = registerValue;
		break;
	case ZYDIS_REGISTER_R10:
		c.R10 = registerValue;
		break;
	case ZYDIS_REGISTER_R11:
		c.R11 = registerValue;
		break;
	case ZYDIS_REGISTER_R12:
		c.R12 = registerValue;
		break;
	case ZYDIS_REGISTER_R13:
		c.R13 = registerValue;
		break;
	case ZYDIS_REGISTER_R14:
		c.R14 = registerValue;
		break;
	case ZYDIS_REGISTER_R15:
		c.R15 = registerValue;
		break;
	default:
		return false;
		break;
	}

	SetContext(&c);
	return true;
}
void ShowCtx(CONTEXT c) {
	printf("RAX: %p\n", c.Rax);
	printf("RBX: %p\n", c.Rbx);
	printf("RCX: %p\n", c.Rcx);
	printf("RDX: %p\n", c.Rdx);
	printf("RBP: %p\n", c.Rbp);
	printf("RSP: %p\n", c.Rsp);
	printf("RSI: %p\n", c.Rsi);
	printf("RDI: %p\n", c.Rdi);
}
