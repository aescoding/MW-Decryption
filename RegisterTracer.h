#pragma once

#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <map>

#include <Zydis/Zydis.h>
#pragma comment(lib,"Zydis.lib")
#define QWORD unsigned __int64

using namespace std;
class RegisterTracer
{
public:
	int LineNumber = 0;
	string DisplayValue = "";
	string DebugComment = "";
	QWORD Offset = false;
	bool LastEncryptedPointer = false;
	vector<ZydisRegister> userRegisters;
	bool sameline = false;

	bool printMe = false;

	ZydisRegister firstReg;

	std::string GetZydisRegisterString(ZydisRegister reg, int lineNumber, ZydisDecodedInstruction instruction);
};

