#pragma once
#include <Windows.h>
#include <string>

#include <Zydis/Zydis.h>
#pragma comment(lib,"Zydis.lib")

using namespace std;

class RegisterTracker
{

public:
	std::string currentFormula = "";
	std::string mainFormula;
	std::string GetFormula(ZydisDecodedInstruction Instruction, bool encryptedPointer, ZydisRegister me);
	bool firstValue;
	ZydisRegister myRegister = NULL;
	void Clear();
	void WriteFormula(std::string value, ZydisMnemonic Mnemonic);

	int MyIndex = 0;
	bool beenUsed = false;

};

