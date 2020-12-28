#include "RegisterTracer.h"

std::string RegisterTracer::GetZydisRegisterString(ZydisRegister reg, int lineNumber, ZydisDecodedInstruction instruction)
{

	if (reg == ZYDIS_REGISTER_RBP || reg == ZYDIS_REGISTER_RSP)
	{

	}

	//If Same Line and first register uses itself again
	if (LineNumber == lineNumber && reg == firstReg)
	{
		sameline = true;
	}
	//Same Line but not first register, do nothing
	else if (LineNumber == lineNumber)
	{

	}
	//New Line
	else
	{
		firstReg = reg;
		sameline = false;
		LineNumber = lineNumber;
	}

	if (ZydisRegisterGetWidth64(reg) == 32)
	{
		ZydisI16 regID = ZydisRegisterGetId(reg);
		reg = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, regID);
	}

	//If Already contains, don't add again, unless same line
	if (std::find(userRegisters.begin(), userRegisters.end(), reg) != userRegisters.end() && !sameline)
	{

	}
	else
		userRegisters.push_back(reg);
	
    return ZydisRegisterGetString(reg);
}
