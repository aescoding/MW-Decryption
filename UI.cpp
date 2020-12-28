#include <filesystem>
#include <Windows.h>
#include <CommCtrl.h>
#include <map>
#include <string> 
#include <iostream>
#include <sstream>  
#include "RegisterTracker.h"
#include "RegisterTracer.h"
#include "Helpers.h"
#include "Dbg.h"

#pragma comment(lib,"Dbghelp.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <vector>
#include <ShObjIdl_core.h>
#define QWORD unsigned __int64

int CurrentIndex = 0;
bool bShowComments = true;
std::vector<std::string> vLastFiles;
std::vector<std::string> base_scripts;

int CurrentInstructionLength = 0;

RegisterTracer regTracer[450];
vector<ZydisRegister> registersInList;


string commands[200];
int line = 0;
int EncryptedPtrIndex = 0;
vector<ZydisRegister> allowedregisters;
ZydisRegister trackingRegister = NULL;
bool DebugMode = false;
bool NewRegisterDecryption(ZydisRegister EncryptedPointer = ZYDIS_REGISTER_RBX, ZydisMnemonic EndMnemonic = ZYDIS_MNEMONIC_MOVZX, bool PrintAll = false)
{
	CONTEXT c = GetContext();
	static ZydisDecodedInstruction instruction;
	std::stringstream ss;
	ZydisDecoder decoder;
	ZydisFormatter formatter;
	ZydisU64 currentInstruction = c.Rip;

	bool skip = false;
	bool mov = false;
	std::string guiText = "";

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	BYTE bRead[20];
	ReadTo(c.Rip, bRead, 20);

	QWORD CurrentOffset = c.Rip - procBase;

	if (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, bRead, 20, c.Rip, &instruction)))
	{
		if (DebugMode)
		{
			// Print current instruction pointer.
			printf("%016" PRIX64 "  ", c.Rip);

			// Format & print the binary instruction structure to human readable format
			char buffer[256];
			ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer));
			puts(buffer);
		}

		CurrentInstructionLength = instruction.length;

		//End Decryption
		if (instruction.mnemonic == EndMnemonic || line == 200)
		{
			//Find last Tracking Register
			for (int i = 0; i < line; i++)
			{
				if (regTracer[i].LineNumber != 0)
				{

					if (regTracer[i].userRegisters.size() > 0)
						registersInList.push_back(regTracer[i].userRegisters[0]);

					if (regTracer[i].userRegisters[0] == EncryptedPointer)
					{
						if (EncryptedPtrIndex != 0)
						{
							//Remove old one
							regTracer[EncryptedPtrIndex].LastEncryptedPointer = false;
							//New encrypted Pointer
							regTracer[i].LastEncryptedPointer = true;
							EncryptedPtrIndex = i;
							regTracer[i].printMe = true;
							trackingRegister = EncryptedPointer;
						}
						else
						{
							regTracer[i].LastEncryptedPointer = true;
							EncryptedPtrIndex = i;
							regTracer[i].printMe = true;
						}
					}
				}
			}

			if (EncryptedPtrIndex != 0)
			{
				for (int i = EncryptedPtrIndex; i >= 0; i--)
				{
					if (regTracer[i].userRegisters.size() > 0)
					{
						string test = ZydisRegisterGetString(regTracer[i].userRegisters[0]);
						string test2 = ZydisRegisterGetString(trackingRegister);
					}

					//Assign new tracking register
					if (regTracer[i].userRegisters.size() >= 2 && EncryptedPointer == regTracer[i].userRegisters[0])
					{
						for (int j = 0; j < regTracer[i].userRegisters.size(); j++)
						{
							if (std::find(allowedregisters.begin(), allowedregisters.end(), regTracer[i].userRegisters[j]) != allowedregisters.end())
							{
							}
							else
								allowedregisters.push_back(regTracer[i].userRegisters[j]);
						}
					}
					else if (regTracer[i].userRegisters.size() >= 2 && std::find(allowedregisters.begin(), allowedregisters.end(), regTracer[i].userRegisters[0]) != allowedregisters.end())
					{
						for (int j = 0; j < regTracer[i].userRegisters.size(); j++)
						{
							if (std::find(allowedregisters.begin(), allowedregisters.end(), regTracer[i].userRegisters[j]) != allowedregisters.end())
							{
							}
							else
								allowedregisters.push_back(regTracer[i].userRegisters[j]);
						}
					}

					//Decide whether to print me
					if (regTracer[i].userRegisters.size() > 0 && std::find(allowedregisters.begin(), allowedregisters.end(), regTracer[i].userRegisters[0]) != allowedregisters.end())
					{
						//Dont print values these values until next used as we are checking if this register is equal to the encrypted register
						if (regTracer[i].userRegisters.size() == 2 && regTracer[i].DisplayValue.find(" = ") != std::string::npos && regTracer[i].userRegisters[1] == EncryptedPointer)
							allowedregisters.erase(std::remove(allowedregisters.begin(), allowedregisters.end(), regTracer[i].userRegisters[0]), allowedregisters.end());

						//If the first register = a value then dont print any more until used
						if (regTracer[i].userRegisters.size() > 0 && regTracer[i].DisplayValue.find(" = ") != std::string::npos && !regTracer[i].sameline)
							allowedregisters.erase(std::remove(allowedregisters.begin(), allowedregisters.end(), regTracer[i].userRegisters[0]), allowedregisters.end());

						regTracer[i].printMe = true;
					}
				}
			}

			//cout << "return EncryptedPointer" << CurrentIndex -1 << ";" << endl;
			for (int i = 0; i <= EncryptedPtrIndex; i++)
			{
				if (!DebugMode)
				{
					if (regTracer[i].printMe && PrintAll == false)
						cout << regTracer[i].DisplayValue << "\n";
					else if (PrintAll == true)
						cout << regTracer[i].DisplayValue << "\n";
				}
				else
				{
					if (regTracer[i].printMe && PrintAll == false)
					{
						cout << regTracer[i].DisplayValue << "            ";
						printf("\033[0;32m");
						cout << "//" << regTracer[i].DebugComment << "\n";
						printf("\033[0m");
					}
					else if (PrintAll == true)
					{
						cout << regTracer[i].DisplayValue << "            ";
						printf("\033[0;32m");
						cout << "//" << regTracer[i].DebugComment << "\n";
						printf("\033[0m");
					}
				}
			}
			printf("\033[0;32mreturn %s%s", ZydisRegisterGetString(EncryptedPointer), ";\n");
			printf("\033[0m");
			return true;
		}

		ZydisRegister r1 = instruction.operands[0].reg.value;
		ZydisRegister r2 = instruction.operands[1].reg.value;
		ZydisRegister r3 = instruction.operands[2].reg.value;
		ZydisRegister r4 = instruction.operands[3].reg.value;

		std::string RegisterString1 = ZydisRegisterGetString(r1);
		std::string RegisterString2 = ZydisRegisterGetString(r2);
		std::string RegisterString3 = ZydisRegisterGetString(r3);
		std::string RegisterString4 = ZydisRegisterGetString(r4);
		string opCode = "";

		string retval = "";
		std::transform(RegisterString1.begin(), RegisterString1.end(), RegisterString1.begin(), ::toupper);
		std::transform(RegisterString2.begin(), RegisterString2.end(), RegisterString2.begin(), ::toupper);

		std::string mnemonicString = ZydisMnemonicGetString(instruction.mnemonic);

		switch (instruction.mnemonic)
		{
		case ZYDIS_MNEMONIC_LEA:
		case ZYDIS_MNEMONIC_MOV:

			//RAX,0x4b2bd3eca30d631
			if (instruction.operandCount >= 2 && instruction.operands[1].imm.value.s != 0)
			{
				if (instruction.operands[1].imm.isSigned)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << "0x" << hex << uppercase << instruction.operands[1].imm.value.s;
				else
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << "0x" << hex << uppercase << instruction.operands[1].imm.value.u;
			}
			//Peb
			else if (instruction.operandCount >= 2 && instruction.operands[1].mem.segment == ZYDIS_REGISTER_GS)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << "peb";
			}
			// LEA   RAX,[RAX + RCX*0x2]
			else if (instruction.operandCount >= 2 && instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.index != 0 && instruction.operands[1].mem.scale != 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << regTracer[line].GetZydisRegisterString(instruction.operands[1].mem.base, line, instruction) << " + " << regTracer[line].GetZydisRegisterString(instruction.operands[1].mem.index, line, instruction) << " * " << (int)instruction.operands[1].mem.scale;
			}
			//R9,qword ptr [DAT_04f67224]
			else if (instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.hasDisplacement)
			{
				if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << "Read<QWORD>(baseModuleAddr + 0x" << hex << uppercase << (c.Rip + instruction.operands[1].mem.disp.value + instruction.length) - procBase << ")";
				else
				{
					if ((c.Rip + instruction.operands[1].mem.disp.value + instruction.length) - procBase != 0)
						ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << "(baseModuleAddr + 0x" << hex << uppercase << (c.Rip + instruction.operands[1].mem.disp.value + instruction.length) - procBase << ")";
					else
						ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << "baseModuleAddr";
				}
			}

			else if (instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.base != ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.hasDisplacement)
			{
				if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = Read<QWORD>(" << regTracer[line].GetZydisRegisterString(instruction.operands[1].mem.base, line, instruction) << " + 0x" << hex << instruction.operands[1].mem.disp.value << ")";
				else
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << regTracer[line].GetZydisRegisterString(instruction.operands[1].mem.base, line, instruction) << " + 0x" << hex << instruction.operands[1].mem.disp.value;
			}
			else if (instruction.operandCount == 2 && instruction.operands[1].reg.value != 0 && instruction.operands[0].reg.value != 0 && instruction.operands[1].mem.disp.value == 0 && instruction.operands[1].imm.value.s == 0 && instruction.operands[0].imm.value.s == 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << regTracer[line].GetZydisRegisterString(r2, line, instruction);//<< CurrentIndex;
			}
			//Register to Register
			else
				ss << "?? MOV";

			break;

		case ZYDIS_MNEMONIC_SHR:

			ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " >>= 0x" << hex << uppercase << instruction.operands[1].imm.value.s;
			break;
		case ZYDIS_MNEMONIC_MOVZX:
		case ZYDIS_MNEMONIC_MOVSX:
			// MOVSX    R15D,word ptr [RCX + R11*0x1 + 0x4dfb360]
			if (instruction.operandCount == 2 && instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.index != 0 && instruction.operands[1].mem.disp.value != 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = Read<uint16_t>(" << uppercase << regTracer[line].GetZydisRegisterString(instruction.operands[1].mem.base, line, instruction) << " + " << regTracer[line].GetZydisRegisterString(instruction.operands[1].mem.index, line, instruction) << " * "
					<< (int)instruction.operands[1].mem.scale << " + 0x" << hex << instruction.operands[1].mem.disp.value << ")";
			}
			else
				ss << "???MOZZD";

			break;
		case ZYDIS_MNEMONIC_ROL:
		case ZYDIS_MNEMONIC_SHL:
			ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " <<= 0x" << hex << uppercase << instruction.operands[1].imm.value.s;

			break;
		case ZYDIS_MNEMONIC_SUB:
			//Reg to Reg
			if (instruction.operandCount == 3 && instruction.operands[1].reg.value != 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " -= " << regTracer[line].GetZydisRegisterString(r2, line, instruction);
			}
			else if (instruction.operandCount >= 2 && instruction.operands[1].imm.value.s != 0)
			{
				if (instruction.operands[1].imm.isSigned)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " -= 0x" << hex << uppercase << instruction.operands[1].imm.value.s;
				else
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " -= 0x" << hex << uppercase << instruction.operands[1].imm.value.u;
			}
			else
				ss << "-????";

			break;
		case ZYDIS_MNEMONIC_ADD:
			//Reg to Reg
			if (instruction.operandCount == 3 && instruction.operands[1].reg.value != 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " += " << uppercase << regTracer[line].GetZydisRegisterString(r2, line, instruction);
			}
			//ADD   RCX, 0x236d1de3
			else if (instruction.operandCount >= 2 && instruction.operands[1].imm.value.s != 0)
			{
				if (instruction.operands[1].imm.isSigned)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " += 0x" << hex << uppercase << instruction.operands[1].imm.value.s;
				else
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " += 0x" << hex << uppercase << instruction.operands[1].imm.value.u;
			}
			else
				ss << "+???";

			break;
		case ZYDIS_MNEMONIC_AND:

			//Reg to Value
			if (instruction.operands[1].imm.value.s != 0 && instruction.operands[0].reg.value != 0)
			{
				if (instruction.operands[1].imm.isSigned)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " " << " &= 0x" << hex << instruction.operands[1].imm.value.s, line;
				else
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " " << " &= 0x" << hex << instruction.operands[1].imm.value.u, line;

			}
			//Reg to Reg
			else if (instruction.operands[0].reg.value != 0 && instruction.operands[1].reg.value != 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " &= " << regTracer[line].GetZydisRegisterString(instruction.operands[1].reg.value, line, instruction);
			}
			else
			{
				ss << "?? &";
			}

			break;

		case ZYDIS_MNEMONIC_XOR:
			if (instruction.operands[1].mem.disp.value != 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " ^= " << "Read<QWORD>(baseModuleAddr + 0x" << hex << uppercase << (c.Rip + instruction.operands[1].mem.disp.value + instruction.length) - procBase << ")";
			}
			else
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " ^= " << regTracer[line].GetZydisRegisterString(r2, line, instruction);
			}

			break;
		case ZYDIS_MNEMONIC_BSWAP:
			ss << "_byteswap_uint64(" << regTracer[line].GetZydisRegisterString(r1, line, instruction) << ")";
			break;
		case ZYDIS_MNEMONIC_NOT:
			ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " =( ~" << regTracer[line].GetZydisRegisterString(r1, line, instruction) << ")";
			break;
		case ZYDIS_MNEMONIC_MUL:
			if (instruction.operandCount == 4)
			{
				ss << regTracer[line].GetZydisRegisterString(r2, line, instruction) << uppercase << " = _umul128(" << regTracer[line].GetZydisRegisterString(r2, line, instruction) << ", " << regTracer[line].GetZydisRegisterString(r1, line, instruction) << ", (QWORD*)&" << regTracer[line].GetZydisRegisterString(r3, line, instruction) << ")";
			}
			else
				ss << "MUL??";
			break;
		case ZYDIS_MNEMONIC_IMUL:
			//Reg to Reg
			if ((instruction.operandCount == 2 || instruction.operandCount == 3) && instruction.operands[1].reg.value != 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " *= " << regTracer[line].GetZydisRegisterString(instruction.operands[1].reg.value, line, instruction);
			}
			//Value
			else if (instruction.operandCount == 2 && instruction.operands[1].imm.value.s != 0)
			{
				if (instruction.operands[1].imm.isSigned)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " *= 0x" << hex << uppercase << instruction.operands[1].imm.value.s;
				else
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " *= 0x" << hex << uppercase << instruction.operands[1].imm.value.u;
			}
			//IMUL  RAX,qword ptr [RCX + 0xb]
			else if (instruction.operands[1].mem.base != 0  && instruction.operands[1].mem.disp.hasDisplacement)
			{
				if (instruction.operands[1].mem.base != ZYDIS_REGISTER_RSP && instruction.operands[1].mem.base != ZYDIS_REGISTER_RBP)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " *= " << "Read<QWORD>(" << regTracer[line].GetZydisRegisterString(instruction.operands[1].mem.base, line, instruction) << " + 0x" << hex << instruction.operands[1].mem.disp.value << ")";
				else if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RSP)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " *= 0x" << hex << uppercase << Read<QWORD>(c.Rsp + instruction.operands[1].mem.disp.value);
				else if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RBP)
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " *= 0x" << hex << uppercase << Read<QWORD>(c.Rbp + instruction.operands[1].mem.disp.value);
				else
					ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " *= 0x" << hex << uppercase << Read<QWORD>(c.Rip + instruction.operands[1].mem.disp.value);
			}
			//IMUL  RAX,RAX,0x25a3
			else if (instruction.operandCount == 4 && instruction.operands[0].reg.value != 0 && instruction.operands[1].reg.value != 0 && instruction.operands[2].imm.value.s != 0)
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " = " << regTracer[line].GetZydisRegisterString(r2, line, instruction) << " * 0x" << hex << uppercase << instruction.operands[2].imm.value.s;
			}
			else
			{
				ss << regTracer[line].GetZydisRegisterString(r1, line, instruction) << " " << "?????";
			}
			break;
		case ZYDIS_MNEMONIC_ROR:
			ss << "_rotr64(" << regTracer[line].GetZydisRegisterString(instruction.operands[0].reg.value, line, instruction) << ", 0x" << hex << uppercase << instruction.operands[1].imm.value.u << ")";
			break;

		case ZYDIS_MNEMONIC_CALL:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JMP:
		case ZYDIS_MNEMONIC_NOP:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_CMP:
		case ZYDIS_MNEMONIC_TEST:
		case ZYDIS_MNEMONIC_JZ:
			skip = true;
			break;
		default:
			ss << "?? " << mnemonicString << CurrentOffset;
		}

		//ss << "                                      //0x" << hex << CurrentOffset;

		if (!skip)
		{
			if (DebugMode)
			{
				// Format & print the binary instruction structure to human readable format
				char buffer[256];
				ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer));
				regTracer[line].DebugComment = buffer;
			}

			ss << ";";
			regTracer[line].Offset = CurrentOffset;
			regTracer[line].DisplayValue = ss.str();
			commands[line].append(ss.str());
			line++;
		}
	}
	return false;
}

void StepOver() 
{
	CONTEXT c = GetContext();
	SingleStep();
	
	if (bExcept) 
	{
		c.Rip++;

		SetContext(&c);
		bExcept = false;
		
	}
	c = GetContext();


	char msg[124];
	sprintf_s(msg, 124, "RVA: %p", c.Rip);
	
	string RIPstring = ZydisRegisterGetString(ZYDIS_REGISTER_RIP);
	transform(RIPstring.begin(), RIPstring.end(), RIPstring.begin(), ::toupper);
	RIPstring += " = " + to_string(GetRegisterValue(ZYDIS_REGISTER_RIP));
	

	for (DWORD i = ZYDIS_REGISTER_RAX; i <= ZYDIS_REGISTER_R15; i++)
	{
		string RegsiterValue = ZydisRegisterGetString(i);
		transform(RegsiterValue.begin(), RegsiterValue.end(), RegsiterValue.begin(), ::toupper);
		RegsiterValue += " = " + to_string(GetRegisterValue(i));
		
	}

}

//OLD and Don't think they work anymore
void OffsetsDump()
{
	ZydisDecodedInstruction instruction;
	QWORD ClientInfoScan = Helpers::DoScan("48 8B CE E8 ?? ?? ?? ?? 44 89 B3 ?? ?? ?? ??");
	printf("#define clientinfo_t_entitynum 0x%08X\n", Read<DWORD>(procBase + ClientInfoScan + 11));
	printf("#define decrypt_client_PosInfo 0x%08X\n", Read<DWORD>(procBase + ClientInfoScan + 18));
	printf("#define clientinfo_t_isvalid 0x%08X\n", Read<DWORD>(procBase + ClientInfoScan + 24));
	printf("#define clientinfo_t_isdead 0x%08X\n", Read<DWORD>(procBase + ClientInfoScan + 68));

	printf("#define BONE_BASE_POS 0x%08X\n", Read<DWORD>(procBase + Helpers::DoScan(("74 0e ?? ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 74 05 B8")) + 17));

	//LEA   RSI,[DAT_1404b488]
	QWORD NameArray = procBase + Helpers::DoScan("48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 48 63 f9");;
	NameArray = Helpers::FindInstruction(ZYDIS_MNEMONIC_LEA, NameArray);
	instruction = Helpers::Decode(NameArray);
	printf("#define NAME_ARRAY_OFFSET 0x%08X\n", NameArray + instruction.operands[1].mem.disp.value - procBase + instruction.length);

	QWORD RefDef = procBase + Helpers::DoScan("33 15 fe 5e ae 12 f3 0f 10 73 18 8d 4a 02 0f af ca");
	RefDef = Helpers::SkipOverInstruction(ZYDIS_MNEMONIC_XOR, RefDef);
	RefDef = Helpers::FindInstruction(ZYDIS_MNEMONIC_XOR, RefDef);
	instruction = Helpers::Decode(RefDef);
	printf("#define DEFREF_PTR 0x%08X\n", RefDef + instruction.operands[1].mem.disp.value - procBase + instruction.length);

	printf("#define decrypt_client_NORECOIL_OFFSET\n", Helpers::DoScan("0F 85 ?? ?? ?? ?? 4C 8D 96 ?? ?? ?? ??"));
	printf("#decrypt_NAME_LIST_OFFSET\n", Helpers::DoScan("48 8b 84 24 ?? ?? ?? ?? ?? ?? 00 48 83 c0 40 48 b9 15 7c 4a 7f b9 79 37 9e 48 8b 00 48 03 c1 48 89 84 ?? ?? ?? ?? ?? ?? 00 00"));

	QWORD gamemode = procBase + Helpers::DoScan("75 05 48 8b c1 eb 2d");
	gamemode = Helpers::SkipOverInstruction(ZYDIS_MNEMONIC_CMP, gamemode);
	gamemode = Helpers::FindInstruction(ZYDIS_MNEMONIC_CMP, gamemode);
	instruction = Helpers::Decode(gamemode);
	printf("#define gamemode 0x%08X\n", gamemode + instruction.operands[0].mem.disp.value - procBase + instruction.length);

	QWORD gameraObj = procBase + Helpers::DoScan("48 63 41 30 48 8b d9") + 19;
	instruction = Helpers::Decode(gameraObj);
	printf("#define decrypt_CAMER_OBJ 0x%08X\n", gameraObj + instruction.operands[1].mem.disp.value - procBase + instruction.length);

	QWORD gameraObjPos= procBase + Helpers::DoScan("48 8b cf 41 c1 e8 11 41 80 e0 01 0f 29 74 24 70") + 21;
	instruction = Helpers::Decode(gameraObjPos);
	printf("#define decrypt_CAMER_POS 0x%08X\n", instruction.operands[1].mem.disp.value);
}

void ClearRegisterDecryption()
{
	EncryptedPtrIndex = 0;
	allowedregisters.clear();

	for (int i = 0; i < sizeof(regTracer) / sizeof(regTracer[0]); i++)
	{
		regTracer[i].printMe = false;
		regTracer[i].DisplayValue = "";
		regTracer[i].Offset = 0;
		regTracer[i].LastEncryptedPointer = false;
		regTracer[i].LineNumber = 0;
		regTracer[i].userRegisters.clear();

	}

	line = 0;
	std::fill_n(commands, 200, "");
	CurrentIndex = 0;
}

void GetBoneIndexPtr()
{
	printf("\033[1;31m");
	cout << "---------------- Bone Index Pointer -------------------\n\n";
	printf("\033[0m");
	bool retval = false;
	CONTEXT c = GetContext();
	ZydisRegister peb = NULL;
	
	QWORD ClientInfoScan = procBase + Helpers::DoScan("84 ?? 0F 84 ?? ?? ?? ?? 48 ?? ?? C8 13 00 00 ??");
	ClientInfoScan = Helpers::FindInstruction(ZYDIS_MNEMONIC_JZ, ClientInfoScan);
	c = GetContext();

	//Start decryption
	while (!retval)
	{
		SetContext(&c);

		SingleStep();

		if (bExcept)
		{
			c.Rip += CurrentInstructionLength;
			SetContext(&c);
			bExcept = false;
		}
		c = GetContext();
		retval = NewRegisterDecryption(ZYDIS_REGISTER_R15, ZYDIS_MNEMONIC_TEST, true);
	}

}

void GetBone()
{
	printf("\033[1;31m");
	cout << "---------------- Bone Dump -------------------\n\n";
	printf("\033[0m");
	bool retval = false;

	CONTEXT c = GetContext();

	ZydisRegister peb = NULL;
	QWORD ADDScan = 0;
	QWORD CMPScan = 0;

	//Find Starting Point of Decryption
	QWORD BoneScan = procBase + Helpers::DoScan("0F BF B4 ? ? ? ? ? 89 ? 24 ? 85 ?");
	
	Helpers::PrintSwitch(BoneScan);
	Helpers::PrintPEB(BoneScan, peb);
	BoneScan = Helpers::SkipOverInstruction(ZYDIS_MNEMONIC_JZ, BoneScan);
	BoneScan = Helpers::SkipOverInstruction(ZYDIS_MNEMONIC_JZ, BoneScan);
	BoneScan = Helpers::FindInstruction(ZYDIS_MNEMONIC_AND, BoneScan);

	c = GetContext();

	//For Each Case
	for (int i = 0; i < 16; i++)
	{
		//Set RIP
		c.Rip = BoneScan;
		SetContext(&c);

		//Print Case
		printf("\033[0;34m");
		cout << "\ncase " << i << ":" << endl;
		cout << "{ " << endl;
		printf("\033[0m");

		//c.Rax = i;
		//c.R11 = procBase;
		SetContext(&c);

		//Set Base for the add JMP //c.Rdi = procBase; // Base Program
		if (!ADDScan)
			ADDScan = Helpers::FindInstruction(ZYDIS_MNEMONIC_ADD, BoneScan);
		ZydisDecodedInstruction instruction = Helpers::Decode(ADDScan);
		if (instruction.mnemonic == ZYDIS_MNEMONIC_ADD)
			SetRegisterValue(instruction.operands[1].reg.value, procBase);

		// Set CMP = i // c.Rax = i;
		if(!CMPScan)
			CMPScan = Helpers::FindInstruction(ZYDIS_MNEMONIC_CMP, BoneScan);
		instruction = Helpers::Decode(CMPScan);
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP)
			SetRegisterValue(instruction.operands[0].reg.value, i);

		while (!retval)
		{

			SingleStep();

			if (bExcept)
			{
				c.Rip += CurrentInstructionLength;
				SetContext(&c);
				bExcept = false;
			}

			c = GetContext();
			retval = NewRegisterDecryption(ZYDIS_REGISTER_R8, ZYDIS_MNEMONIC_MOVSXD);
			//retval = NewRegisterDecryption(ZYDIS_REGISTER_R8, ZYDIS_MNEMONIC_MOVSX);

		}
		printf("\033[1;31mbreak;\n");
		printf("\033[0;34m");
		printf("} \n");
		printf("\033[0m");

		ClearRegisterDecryption();
		retval = false;
	}

}

void GetClientInfoBase()
{
	printf("\033[1;31m");
	cout << "---------------- Client Info Base Dump -------------------\n\n";
	printf("\033[0m");
	bool retval = false;
	CONTEXT c = GetContext();

	ZydisRegister peb = NULL;
	QWORD ADDScan = 0;
	QWORD CMPScan = 0;

	//Find Starting Point of Decryption
	//QWORD ClientInfoBaseScan = procBase + Helpers::DoScan("48 8B 05 88 04 6B 0D");
	QWORD ClientInfoBaseScan = procBase + Helpers::DoScan("48 8B 83 ?? ?? ?? ?? C6 44 24 ?? ?? 0F B6");

	Helpers::PrintSwitch(ClientInfoBaseScan);
	Helpers::PrintPEB(ClientInfoBaseScan, peb);
	ClientInfoBaseScan = Helpers::SkipOverInstruction(ZYDIS_MNEMONIC_JZ, ClientInfoBaseScan);
	ClientInfoBaseScan = Helpers::FindInstruction(ZYDIS_MNEMONIC_AND, ClientInfoBaseScan);

	c = GetContext();

	//For Each Case
	for (int i = 0; i < 16; i++)
	{
		//Set the instruction pointer
		c.Rip = ClientInfoBaseScan;
		SetContext(&c);

		printf("\033[0;34m");
		cout << "\ncase " << i << ":" << endl;
		cout << "{ " << endl;
		printf("\033[0m");

		//Set Base for the add JMP //c.Rdi = procBase; // Base Program
		if (!ADDScan)
			ADDScan = Helpers::FindInstruction(ZYDIS_MNEMONIC_ADD, ClientInfoBaseScan);
		ZydisDecodedInstruction instruction = Helpers::Decode(ADDScan);
		if (instruction.mnemonic == ZYDIS_MNEMONIC_ADD)
			SetRegisterValue(instruction.operands[1].reg.value, procBase);

		//Set CMP = i // c.Rax = i;
		if (!CMPScan)
			CMPScan = Helpers::FindInstruction(ZYDIS_MNEMONIC_CMP, ClientInfoBaseScan);
		instruction = Helpers::Decode(CMPScan);
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP)
			SetRegisterValue(instruction.operands[0].reg.value, i);

		c = GetContext();

		while (!retval)
		{
			SingleStep();

			if (bExcept)
			{
				c.Rip += CurrentInstructionLength;
				SetContext(&c);
				bExcept = false;
			}

			c = GetContext();
			//retval = NewRegisterDecryption(ZYDIS_REGISTER_RAX, ZYDIS_MNEMONIC_MOV);
			retval = NewRegisterDecryption(ZYDIS_REGISTER_RAX, ZYDIS_MNEMONIC_MOVSXD);
			//retval = NewDecryption(ZYDIS_REGISTER_RAX, ZYDIS_MNEMONIC_MOVZX);
		}
		printf("\033[1;31mbreak;\n");
		printf("\033[0;34m");
		printf("} \n");
		printf("\033[0m");
		ClearRegisterDecryption();
		retval = false;
	}

}

void GetClientInfo()
{
	printf("\033[1;31m");
	printf("---------------- Client Info Dump -------------------\n\n");
	printf("\033[0m");

	bool retval = false;
	CONTEXT c = GetContext();
	ZydisRegister peb = NULL;
	
	QWORD ClientInfoScan = procBase + Helpers::DoScan("48 8b 04 c1 48 8b 1c 03 48 8b cb 48 8b 03 ff 90 98 00 00 00");
	Helpers::PrintPEB(ClientInfoScan, peb);
	printf("\033[0m");
	ClientInfoScan = Helpers::SkipOverInstruction(ZYDIS_MNEMONIC_JZ, ClientInfoScan);
	ClientInfoScan = Helpers::SkipOverInstruction(ZYDIS_MNEMONIC_JZ, ClientInfoScan);
	c = GetContext();

	//Start decryption
	while (!retval)
	{

		SetContext(&c);

		SingleStep();

		if (bExcept)
		{
			c.Rip += CurrentInstructionLength;
			SetContext(&c);
			bExcept = false;
		}
		c = GetContext();
		retval = NewRegisterDecryption(ZYDIS_REGISTER_RBX, ZYDIS_MNEMONIC_CALL,true);
		//retval = NewDecryption(ZYDIS_REGISTER_RBX, ZYDIS_MNEMONIC_CALL);
	}

}

std::string wstrtostr(const std::wstring& wstr)
{
	std::string strTo;
	char* szTo = new char[wstr.length() + 1];
	szTo[wstr.size()] = '\0';
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
	strTo = szTo;
	delete[] szTo;
	return strTo;

}

std::string openFile()
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED |
		COINIT_DISABLE_OLE1DDE);
	std::string t;
	if (SUCCEEDED(hr))
	{
		IFileOpenDialog* pFileOpen;

		// Create the FileOpenDialog object.
		hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL,
			IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));

		if (SUCCEEDED(hr))
		{
			// Show the Open dialog box.
			hr = pFileOpen->Show(NULL);

			// Get the file name from the dialog box.
			if (SUCCEEDED(hr))
			{
				IShellItem* pItem;
				hr = pFileOpen->GetResult(&pItem);
				if (SUCCEEDED(hr))
				{
					LPWSTR pszFilePath;
					hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
					// Display the file name to the user.
					if (SUCCEEDED(hr))
					{
						t = wstrtostr(pszFilePath);
						CoTaskMemFree(pszFilePath);
					}
					pItem->Release();
				}
			}
			pFileOpen->Release();
		}
		CoUninitialize();
	}
	return t;
}

void LoadFileDump()
{
	static int iInit = 0;
	STARTUPINFOA startupinfo = { 0 };
	startupinfo.cb = sizeof(startupinfo);
	PROCESS_INFORMATION processinfo = { 0 };
	unsigned int creationflags = DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_NEW_CONSOLE;
	std::string openFileLocation = openFile();
	if (CreateProcessA(

		openFileLocation.c_str()
		, NULL,
		NULL,
		NULL,
		FALSE,
		creationflags,
		NULL,
		NULL,
		&startupinfo,
		&processinfo) == FALSE)
	{
		std::cout << "CreateProcess failed: " << GetLastError() << std::endl;
		return;
	}

	debuggeehProcess = processinfo.hProcess;
	debuggeehThread = processinfo.hThread;
	debuggeeprocessID = processinfo.dwProcessId;
	debuggeethreadID = processinfo.dwThreadId;

	auto c = GetContext();
	procBase = Read <QWORD>(c.Rdx + 0x10);

	debuggeeStatus = DebuggeeStatus::SUSPENDED;
	printf("T[%i] P[%04X] Process launched and suspended. [%p]\n", debuggeethreadID, debuggeeprocessID, procBase);

}

void LoadFile(std::string file)
{
	printf("Loading %s\n", file.c_str());
	InitProcess(file.c_str());
	Sleep(5000);
	AttachProcess(debuggeeprocessID);
	SingleStep();
	bExcept = false;

	auto c = GetContext();
	char msg[124];
	sprintf_s(msg, 124, "RVA: %p", c.Rip);

}

int main() 
{
	int answer = 0;
	string DumpLocation;

	printf("\033[0;32m");
	printf("\nWhat would you like to do?");
	printf("\033[0m");
	printf("\n[1]Open Last file?");
	printf("\n[2]New File");
	printf("\n[3]Launch and Attach to MW");
	printf("\n[4]Launch and Attach to CW\n");
	cin >> answer;

	switch (answer)
	{
		case 1:
			//LoadPreviousFile();
			//show disasm
			//ShowDisasm();
			break;
		case 2:
			LoadFileDump();
			break;
		case 3:
			LoadFile("C:\\Program Files (x86)\\Call of Duty Modern Warfare\\ModernWarfare.exe");
			break;
		case 4:
			LoadFile("C:\\Program Files (x86)\\Call of Duty Black Ops Cold War\\BlackOpsColdWar.exe");
			break;
	}

	if (answer >= 5)
	{
		printf("Invalid Input!!");
		main();
	}

	printf("\033[0;32m");
	printf("\nWhat would you like to do?");
	printf("\033[0m");
	printf("\n[1]Offsets");
	printf("\n[2]Client Info");
	printf("\n[3]Client Info Base");
	printf("\n[4]Get Bone");
	printf("\n[5]Get Bone Index Pointer\n");
	cin >> answer;

	switch (answer)
	{
	case 1:
		OffsetsDump();
		break;
	case 2:
		GetClientInfo();
		break;
	case 3:
		GetClientInfoBase();
		break;
	case 4:
		GetBone();
		break;
	case 5:
		GetBoneIndexPtr();
		break;
	}
	auto c = GetContext();

	char msg[124];

	return 0;

}
