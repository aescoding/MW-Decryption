#include "Helpers.h"

using namespace std;

#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD))
#define PEFHDROFFSET(a) (PIMAGE_FILE_HEADER)((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE))
#define SECHDROFFSET(ptr) (PIMAGE_SECTION_HEADER)((LPVOID)((BYTE *)(ptr)+((PIMAGE_DOS_HEADER)(ptr))->e_lfanew+SIZE_OF_NT_SIGNATURE+sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_OPTIONAL_HEADER)))

PIMAGE_SECTION_HEADER Helpers::getCodeSection(LPVOID lpHeader) 
{
	PIMAGE_FILE_HEADER pfh = PEFHDROFFSET(lpHeader);
	if (pfh->NumberOfSections < 1)
	{
		return NULL;
	}
	PIMAGE_SECTION_HEADER psh = SECHDROFFSET(lpHeader);
	return psh;
}

size_t replace_all(std::string& str, const std::string& from, const std::string& to) {
	size_t count = 0;

	size_t pos = 0;
	while ((pos = str.find(from, pos)) != std::string::npos) {
		str.replace(pos, from.length(), to);
		pos += to.length();
		++count;
	}

	return count;
}

bool is_hex_char(const char& c) {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
}
std::vector<int> pattern(std::string patternstring) {
	std::vector<int> result;
	const uint8_t hashmap[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
	};
	replace_all(patternstring, "??", " ? ");
	replace_all(patternstring, "?", " ?? ");
	replace_all(patternstring, " ", "");
	//boost::trim(patternstring);
	//assert(patternstring.size() % 2 == 0);
	for (std::size_t i = 0; i < patternstring.size() - 1; i += 2) {
		if (patternstring[i] == '?' && patternstring[i + 1] == '?') {
			result.push_back(0xFFFF);
			continue;
		}
		//assert(is_hex_char(patternstring[i]) && is_hex_char(patternstring[i + 1]));
		result.push_back((uint8_t)(hashmap[patternstring[i]] << 4) | hashmap[patternstring[i + 1]]);
	}
	return result;
}

std::vector<std::size_t> find_pattern(const uint8_t* data, std::size_t data_size, const std::vector<int>& pattern, bool bSingle = false) {
	// simple pattern searching, nothing fancy. boyer moore horsepool or similar can be applied here to improve performance
	std::vector<std::size_t> result;
	for (std::size_t i = 0; i < data_size - pattern.size() + 1; i++) {
		std::size_t j;
		for (j = 0; j < pattern.size(); j++) {
			if (pattern[j] == 0xFFFF) {
				continue;
			}
			if (pattern[j] != data[i + j]) {
				break;
			}
		}
		if (j == pattern.size()) {
			result.push_back(i);
			if (bSingle) break;
		}
	}
	return result;
}


std::vector<QWORD> Helpers::AOBScan(std::string str_pattern, bool bSingle = false) 
{
	std::vector<QWORD> ret;
	HANDLE hProc = debuggeehProcess;

	ULONG_PTR dwStart = procBase;

	LPVOID lpHeader = malloc(0x1000);
	ReadProcessMemory(hProc, (LPCVOID)dwStart, lpHeader, 0x1000, NULL);

	DWORD delta = 0x1000;
	LPCVOID lpStart = 0; //0
	DWORD nSize = 0;// 0x548a000;

	PIMAGE_SECTION_HEADER SHcode = getCodeSection(lpHeader);
	if (SHcode) 
	{
		nSize = SHcode->Misc.VirtualSize;
		delta = SHcode->VirtualAddress;
		lpStart = ((LPBYTE)dwStart + delta);
	}
	if (nSize) {

		LPVOID lpCodeSection = malloc(nSize);
		ReadProcessMemory(hProc, lpStart, lpCodeSection, nSize, NULL);

		//sprintf_s(szPrint, 124, "Size: %i / Start:%p / Base: %p", nSize, dwStart,lpStart);
		//MessageBoxA(0, szPrint, szPrint, 0);
		//
		auto res = find_pattern((const uint8_t*)lpCodeSection, nSize, pattern(str_pattern.c_str()), bSingle);
		ret = res;
		for (UINT i = 0; i < ret.size(); i++) {
			ret[i] += delta;
		}

		free(lpCodeSection);
	}
	else {
		printf("bad .code section.\n");
	}
	free(lpHeader);


	return ret;
}
DWORD Helpers::DoScan(std::string pattern, DWORD offset , DWORD base_offset , DWORD pre_base_offset , DWORD rIndex )
{
	auto r = AOBScan(pattern);
	if (!r.size())
		return 0;

	DWORD ret = r[rIndex] + pre_base_offset;
	if (offset == 0) {
		return ret + base_offset;
	}
	DWORD dRead = Read<DWORD>((LPBYTE)procBase + ret + offset);
	ret = ret + dRead + base_offset;
	return ret;
}



void Helpers::SetRIP(QWORD offset)
{
	CONTEXT c = GetContext();
	c.Rip = procBase + offset;
	SetContext(&c);

}

ZydisDecodedInstruction Helpers::Decode(QWORD rip)
{

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);


	ZydisDecodedInstruction instruction;
	BYTE bRead[20];
	ReadTo(rip, bRead, 20);

	if (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, bRead, 20,
		rip, &instruction))) {
	}
	return instruction;
}

QWORD Helpers::SkipOverInstruction(ZydisMnemonic instructionMnemonic, QWORD currentRIP)
{
	bool foundInstruction = false;
	ZydisDecodedInstruction instruction;

	while (!foundInstruction)
	{
		instruction = Decode(currentRIP);
		if (instruction.mnemonic == instructionMnemonic)
		{
			foundInstruction = true;
			currentRIP += instruction.length;
			continue;

		}
		currentRIP += instruction.length;
	}

	SetRIP(currentRIP - procBase);
	return currentRIP;
}
QWORD Helpers::FindInstruction(ZydisMnemonic instructionMnemonic, QWORD currentRIP)
{
	bool foundInstruction = false;
	ZydisDecodedInstruction instruction;

	while (!foundInstruction)
	{
		instruction = Decode(currentRIP);
		if (instruction.mnemonic == instructionMnemonic)
		{
			foundInstruction = true;
			continue;

		}
		currentRIP += instruction.length;
	}

	SetRIP(currentRIP - procBase);
	return currentRIP;
}

void Helpers::PrintSwitch(QWORD currentRIP)
{
	ZydisDecodedInstruction instruction;
	bool pebFound = false;
	std::string  pebstring = "";
	int i = 0;
	printf("\033[0;33m");
	printf("Settings::ClientBaseCase = ");
	while (i < 15)
	{
		instruction = Decode(currentRIP);
		currentRIP += instruction.length;
		ZydisRegister r1 = instruction.operands[0].reg.value;
		ZydisRegister r2 = instruction.operands[1].reg.value;

		switch (instruction.mnemonic)
		{
		case ZYDIS_MNEMONIC_MOV:
			if (instruction.operandCount >= 2 && instruction.operands[1].mem.segment == ZYDIS_REGISTER_GS)
			{
				pebstring = "Peb";
				pebFound = true;
			}
			break;
		case ZYDIS_MNEMONIC_NOT:
			if (pebFound)
				pebstring = "~Peb";
			break;
		case ZYDIS_MNEMONIC_ROR:
			if(pebFound)
				printf("_rotr64(%s %s%x %s" , pebstring.c_str() , ", 0x" , instruction.operands[1].imm.value.u, ")");
			break;
		case ZYDIS_MNEMONIC_ROL:
			if(pebFound)
				printf("_rotl64(%s %s%x %s" , pebstring.c_str() , ", 0x", instruction.operands[1].imm.value.u , ")");
			break;
		case ZYDIS_MNEMONIC_AND:
			if(pebFound)
				if (instruction.operands[1].imm.value.s != 0 && instruction.operands[0].reg.value != 0)
					printf(" & 0x%x%s" , instruction.operands[1].imm.value.s , ";\n");

			break;
		}
		i++;
	}
	printf("\033[0m");
}

void Helpers::PrintPEB(QWORD currentRIP, ZydisRegister& pebRegister)
{
	ZydisDecodedInstruction instruction;
	bool checkNotPeb = false;

	int i = 0;

	std::stringstream pebSS;
	pebSS.str("");

	while (pebSS.str().empty() && i < 15)
	{
		instruction = Decode(currentRIP);
		currentRIP += instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.operands[1].mem.segment == ZYDIS_REGISTER_GS)
		{
			pebRegister = instruction.operands[0].reg.value;
			printf("\033[0;32mQWORD %s %s", ZydisRegisterGetString(instruction.operands[0].reg.value), " = Peb;\n");
			continue;
		}
		i++;
	}

	if (!pebSS.str().empty())
	{
		instruction = Decode(currentRIP);

		if (instruction.mnemonic == ZYDIS_MNEMONIC_NOT)
			printf("\033[0;32m %s %s %s %s", ZydisRegisterGetString(instruction.operands[0].reg.value), " = ~", ZydisRegisterGetString(instruction.operands[0].reg.value), ";");
	}
}