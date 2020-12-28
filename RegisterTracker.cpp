#include "RegisterTracker.h"

void RegisterTracker::WriteFormula(std::string value, ZydisMnemonic Mnemonic)
{
	if (Mnemonic == ZYDIS_MNEMONIC_MOV || Mnemonic == ZYDIS_MNEMONIC_LEA)
	{
		Clear();
	}

	//append the current formula
	if (Mnemonic == ZYDIS_MNEMONIC_BSWAP)
		currentFormula = "(" + value + currentFormula + ")";
	else
	{
		if (!firstValue)
		{
			currentFormula += value;
			firstValue = true;
		}
		else
		{
			currentFormula += value;
			firstValue = false;

			currentFormula = "(" + currentFormula + ")";
		}
	}
}

std::string RegisterTracker::GetFormula(ZydisDecodedInstruction Instruction, bool encryptedPointer, ZydisRegister me)
{
	string opCode = "";
	string retVal = "";
	size_t position = 0;
	int sizeOfOpCode = 0;

	//My register is?
	if (myRegister == NULL)
		myRegister = me;

	switch (Instruction.mnemonic)
	{
		case ZYDIS_MNEMONIC_XOR:
			if (encryptedPointer)
			{
				opCode = " ^= ";
				position = currentFormula.find_first_of('^');
				sizeOfOpCode = 1;
			}
			break;
		case ZYDIS_MNEMONIC_SUB:
			if (encryptedPointer)
			{
				opCode = " -= ";
				position = currentFormula.find_first_of('-');
				sizeOfOpCode = 1;
			}
			break;
		case ZYDIS_MNEMONIC_ADD:
			if (encryptedPointer)
			{
				opCode = " += ";
				position = currentFormula.find_first_of('+');
				sizeOfOpCode = 1;
			}
			break;
		case ZYDIS_MNEMONIC_IMUL:
			if (encryptedPointer)
			{
				opCode = " *= ";
				position = currentFormula.find_first_of('*');
				sizeOfOpCode = 1;
			}
			break;
		case ZYDIS_MNEMONIC_MOV:
		case ZYDIS_MNEMONIC_LEA:
			if (encryptedPointer)
			{
				opCode = " = ";
			}
			break;
		case ZYDIS_MNEMONIC_SHR:
			if (encryptedPointer)
			{
				opCode = " >> ";
				position = currentFormula.find_first_of(opCode);
				sizeOfOpCode = 2;
				opCode = " = (EncryptedPointer ";
			}
			break;
		case ZYDIS_MNEMONIC_ROL:
			if (encryptedPointer)
			{
				opCode = " << ";
				position = currentFormula.find_first_of(opCode);
				sizeOfOpCode = 2;
				opCode = " = (EncryptedPointer ";
			}
			break;
		case ZYDIS_MNEMONIC_ROR:
			if (encryptedPointer)
			{
				opCode = " = ";
			}
			break;
		case ZYDIS_MNEMONIC_NOT:
			if (encryptedPointer)
			{
				opCode = " ~ ";
			}
			break;
		default:
			opCode = " ?? ";
			break;
	}
	

	//Removing duplicate opCode
	if (encryptedPointer && position > 0 && position < 50)
	{
		currentFormula.erase(position, sizeOfOpCode);
	}

	if (currentFormula.length() > 0)
	{
		if (encryptedPointer)
		{
			//retVal = "EncryptedPointer" + to_string(CurrentIndex + 1) + opCode + currentFormula;
			retVal = "EncryptedPointer" + opCode + currentFormula;
			//MyIndex = CurrentIndex;
			//CurrentIndex++;
			beenUsed = true;
		}
		else
		{
			retVal = opCode + currentFormula;
			//MyIndex = CurrentIndex;
			beenUsed = true;
		}
	}
	//Get the previous formula
	else if (beenUsed)
	{
		//retVal.append("EncryptedPointer").append(to_string(MyIndex));
		retVal.append("EncryptedPointer");
	}
	// No previous formula or current formula, use register name as we dont know what this is
	else
	{
		retVal.append(ZydisRegisterGetString(myRegister));
	}

	Clear();
	return retVal;
}

void RegisterTracker::Clear()
{
	//Reset Current value
	currentFormula = "";
	firstValue = false;
	bool beenUsed = false;
}
