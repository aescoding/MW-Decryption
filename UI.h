#pragma once
#include <vector>
#include <unordered_map>

//dbg API
class CRegisterTrace;

enum MATH_OP {
	NOP,
	SET,
	MEM,
	MEM_REG,
	ADD,
	SUB,
	IMUL,
	XOR,
	NOT,
	AND,
	SHR,
	SHL,
	ROL,
	ROR,
	BSWAP,
	ALIAS,
	FORMULA,
	REGISTER,
};
struct ASM_OP {
	MATH_OP op = { NOP };
	CRegisterTrace* r0 = NULL;
	CRegisterTrace* r1 = NULL;
	CRegisterTrace* formula = NULL;
	std::string alias;
	DWORD64 iValue = 0;
	bool mem_base = 0;
};


class CRegisterTrace {
public:
	std::vector<CRegisterTrace> vTrace;
	CRegisterTrace() {
		vTrace.clear();
	}
	ZydisRegister r = 0;
	DWORD regSize;
	DWORD64 rva;
	ASM_OP op;
	bool formulaPrinted = false;
	DWORD opCount();
	DWORD count();
	CRegisterTrace* get_prev();
	std::string get_operation(DWORD parentRegSize = 8);
	DWORD get_formulas(std::vector< CRegisterTrace*>* vFormulas);
	std::string get_formula(std::vector< CRegisterTrace*>* vFormulas);
};

//UI
class CScriptGUI {
public:
	std::string newScript;
	HWND hWnd;
	HWND hLogEdit;
	HWND hScriptEdit;
	HWND hScriptBox;
	DWORD iCurScript = 0;
	void Init();
	void SetScript(std::string script) {
		SetWindowText(hScriptEdit, script.c_str());
	};
};
extern CScriptGUI* scriptGui;