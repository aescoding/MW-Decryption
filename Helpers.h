#pragma once
#include <Windows.h>
#include "Dbg.h"
#include <vector>
#include <string>
#include <sstream>
#include <Zydis/Zydis.h>
#pragma comment(lib,"Zydis.lib")

class Helpers
{
public:
	static DWORD DoScan(std::string pattern, DWORD offset = 0, DWORD base_offset = 0, DWORD pre_base_offset = 0, DWORD rIndex = 0);
	static void PrintPEB(QWORD currentRIP, ZydisRegister& pebRegister);
	static void PrintSwitch(QWORD currentRIP);
	static QWORD FindInstruction(ZydisMnemonic instructionMnemonic, QWORD currentRIP);
	static QWORD SkipOverInstruction(ZydisMnemonic instructionMnemonic, QWORD currentRIP);
	static ZydisDecodedInstruction Decode(QWORD rip);
	static void SetRIP(QWORD offset);
	static PIMAGE_SECTION_HEADER getCodeSection(LPVOID lpHeader);
	static std::vector<QWORD> AOBScan(std::string str_pattern, bool bSingle);
};

