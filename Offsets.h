//#pragma once
//#include <Windows.h>
//#include <iostream>
//#include <cstdio>
//#include <Zydis/Zydis.h>
//#include "Pe.h"
//#include <unordered_map>
//#include <set>
//#pragma comment(lib,"Zydis.lib")
//
//template <class T>
//static T adv_search(const char* pattern, int patternOffset, int insOffset, int insLength, bool addRip = true, int start_search = 0)
//{
//	int offset = search(pattern, start_search);
//	if (offset)
//	{
//		offset += patternOffset;
//
//		auto val = *reinterpret_cast<T*>(base + offset + insOffset) + insLength;
//		if (addRip)
//		{
//			val += offset;
//		}
//		return val;
//	}
//	return 0;
//}
//
//class local_var
//{
//public:
//	int id;
//	std::string eval;
//	std::set<int> deps;
//	bool declared;
//
//	local_var()
//	{
//	}
//
//	local_var(int id, std::string eval)
//	{
//		this->id = id;
//		this->eval = eval;
//		this->declared = false;
//	}
//
//	local_var(int id, std::string eval, bool declared, int num_refs, const local_var*...)
//	{
//		this->id = id;
//		this->eval = eval;
//		this->declared = declared;
//
//		va_list ap;
//		va_start(ap, num_refs);
//		for (int i = 0; i < num_refs; i++)
//		{
//			auto ref = va_arg(ap, local_var*);
//			this->deps.emplace(ref->id);
//			for (int dep : ref->deps)
//			{
//				this->deps.emplace(dep);
//			}
//			//this->deps.insert(this->deps.end(), ref->deps.begin(), ref->deps.end());
//		}
//		va_end(ap);
//	}
//
//	local_var(int id, std::string eval, bool declared, std::vector<local_var*>& deps)
//	{
//		this->id = id;
//		this->eval = eval;
//		this->declared = declared;
//
//		for (auto ref : deps) {
//			this->deps.emplace(ref->id);
//			for (int dep : ref->deps)
//			{
//				this->deps.emplace(dep);
//			}
//
//			//this->deps.push_back(ref->id);
//			//this->deps.insert(this->deps.end(), ref->deps.begin(), ref->deps.end());
//		}
//	}
//};
//
//struct xor_shift_ctx
//{
//	ZydisRegister ptrReg;
//	ZydisRegister pebReg;
//	ZydisRegister bswapReg;
//
//	int var_idx;
//	bool debug;
//	bool skip_call;
//
//	uint64_t start_rsp;
//	std::unordered_map<ZydisRegister, local_var> register_var;
//	std::unordered_map<int, local_var> stack_var;
//	std::unordered_map<int, local_var> local_vars;
//
//
//	void reset() {
//		var_idx = 0;
//		start_rsp = 0;
//		register_var.clear();
//		stack_var.clear();
//		local_vars.clear();
//	}
//};
//
//static bool is_hex(char c)
//{
//	const auto u = uint8_t(c);
//	return (u >= uint8_t('0') && u <= uint8_t('9'))
//		|| (u >= uint8_t('A') && u <= uint8_t('F'))
//		|| (u >= uint8_t('a') && u <= uint8_t('f'));
//}
//
//static uint8_t unhex_byte(char a, char b) { return (unhex_char(a) << 4) + unhex_char(b); }
//
//bool convert_pattern(const char* pattern, char wildcard, char** pattern_out, int* size_out)
//{
//	std::string new_pattern;
//
//	int pattern_len = strlen(pattern);
//	for (int i = 0; i < pattern_len;)
//	{
//		auto c = pattern[i];
//
//		if (c == '?')
//		{
//			new_pattern += wildcard;
//			i++;
//		}
//		else if (c != ' ' && i + 1 < pattern_len)
//		{
//			auto c2 = pattern[i + 1];
//
//			if (!is_hex(c) || !is_hex(c2))
//			{
//				return false;
//			}
//
//			new_pattern += static_cast<char>(unhex_byte(c, c2));
//			i += 2;
//		}
//		else
//		{
//			i++;
//		}
//	}
//
//	char* new_pattern_bytes = new char[new_pattern.length()];
//	memcpy(new_pattern_bytes, new_pattern.c_str(), new_pattern.length());
//	*pattern_out = new_pattern_bytes;
//	*size_out = new_pattern.length();
//	return true;
//}
//
//int search_back(const char* pattern, int offset = 0)
//{
//	if (offset < 0) {
//		_errorl("Invalid offset: %i", offset);
//		return 0;
//	}
//
//	char* cpattern;
//	int pattern_len;
//
//	if (!convert_pattern(pattern, 0xCC, &cpattern, &pattern_len))
//	{
//		_errorl("Failed to convert pattern: '%s'", pattern);
//		return 0;
//	}
//
//	auto pos = ((uint64_t)RtlpFindPatternExBack(((PBYTE)base) + offset, ((PBYTE)base), (PBYTE)cpattern, pattern_len, 0xCC));
//	if (!pos)
//	{
//		return 0;
//	}
//
//	return (int)(pos - ((uint64_t)base));
//}
//
//static void dump_client_info()
//{
//	ZydisDecoder decoder;
//	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
//
//	ZydisDecodedInstruction instruction;
//	ZydisDecodedInstruction lastInstruction{};
//	ZydisDecodedInstruction lastInstruction2{};
//	int offset = search("2C 02 A8 FD 75 04");//search("E8 ? ? ? ? 48 63 F8 83 FF FF 0F 84 ? ? ? ?");//search("0F 29 74 24 20 0F 28 F3 81 FB FF 07 00 00");
//	if (!offset)
//	{
//		_line;
//		_errorl("Client info pattern not found!");
//		return;
//	}
//
//	while (offset > 0) {
//		auto v = *reinterpret_cast<uint32_t*>(base + offset);
//		//48 83 EC 20
//		//48 89 5C 24
//		if (v == 0x20EC8348) {//0xCCCCCCCC) {
//			break;
//		}
//		offset--;
//	}
//	offset += 4;
//
//	int lastOffset = 0;
//	int lastOffset2 = 0;
//
//	int cmpOffset = 0;
//	int pEncryptedPtr = 0;
//	int pReversedAddr = 0;
//	int size = 0;
//	int baseOffset = 0;
//	ZydisRegister baseReg = ZYDIS_REGISTER_NONE;
//
//	int baseCmpOffset = 0;
//	int basePReversedAddr = 0;
//	ZydisRegister baseBaseReg = ZYDIS_REGISTER_NONE;
//
//	xor_shift_ctx reg_ctx{};
//
//	while ((!cmpOffset || !pEncryptedPtr || !pReversedAddr || !reg_ctx.pebReg || !baseReg)
//		&& ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + offset), 0x100, &instruction)))
//	{
//		if (instruction.mnemonic == ZYDIS_MNEMONIC_JZ && lastInstruction.mnemonic == ZYDIS_MNEMONIC_TEST)
//		{
//			if (!cmpOffset)
//			{
//				cmpOffset = offset + instruction.length;
//			}
//		}
//		else if (instruction.mnemonic == ZYDIS_MNEMONIC_NOT) {
//			if (!reg_ctx.pebReg) {
//				reg_ctx.pebReg = instruction.operands[0].reg.value;
//			}
//		}
//		else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA)
//		{
//			auto* op1 = &instruction.operands[0];
//			auto* op2 = &instruction.operands[1];
//
//			if (op1->type == ZYDIS_OPERAND_TYPE_REGISTER &&
//				op2->type == ZYDIS_OPERAND_TYPE_MEMORY && op2->mem.base == ZYDIS_REGISTER_RIP
//				&& op2->mem.disp.has_displacement)
//			{
//				auto pos = op2->mem.disp.value + offset + instruction.length;
//				if (pos == 0)
//				{
//					baseReg = op1->reg.value;
//					set_regx(&reg_ctx, op1->reg.value, local_var(-1, "baseModuleAddr"));
//				}
//			}
//
//		}
//
//		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV || instruction.mnemonic == ZYDIS_MNEMONIC_LEA)
//		{
//			auto* op2 = &instruction.operands[1];
//			if (!pEncryptedPtr) {
//				if (op2->type == ZYDIS_OPERAND_TYPE_MEMORY && op2->mem.disp.has_displacement)
//				{
//					if ((uint64_t)op2->mem.disp.value > 0x1000) {
//						if (op2->mem.base == ZYDIS_REGISTER_RIP) {
//							pEncryptedPtr = op2->mem.disp.value + offset + instruction.length;
//						}
//						else {
//							pEncryptedPtr = op2->mem.disp.value;
//						}
//
//						reg_ctx.ptrReg = instruction.operands[0].reg.value;
//					}
//				}
//			}
//		}
//
//		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV || instruction.mnemonic == ZYDIS_MNEMONIC_XOR)
//		{
//			auto* op2 = &instruction.operands[1];
//			if (op2->type == ZYDIS_OPERAND_TYPE_MEMORY && op2->mem.type == ZYDIS_MEMOP_TYPE_MEM && op2->mem.base == ZYDIS_REGISTER_RIP && op2->mem.disp.has_displacement)
//			{
//				if (cmpOffset && !pReversedAddr) {
//					pReversedAddr = op2->mem.disp.value + offset + instruction.length;
//
//					reg_ctx.bswapReg = instruction.operands[0].reg.value;
//				}
//			}
//		}
//
//		lastInstruction2 = lastInstruction;
//		lastOffset2 = lastOffset;
//		lastInstruction = instruction;
//		lastOffset = offset;
//
//		offset += instruction.length;
//	}
//
//	xor_shift_ctx base_ctx{};
//
//	offset = search("44 0F B6 88 ? ? ? ? 45 84 C9 0F 84 ? ? ? ?");
//	if (offset != 0) {
//		offset = search("48 8B 03 48 8B CB FF 50 50 84 C0", offset);
//		if (offset != 0)
//		{
//			offset = search("E8 ? ? ? ? E9 ? ? ? ?", offset);
//		}
//	}
//
//	if (offset) {
//		offset += 10;
//
//		if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + offset), 0x100, &instruction)))
//		{
//			base_ctx.ptrReg = instruction.operands[0].reg.value;
//			baseOffset = instruction.operands[1].mem.disp.value;
//
//
//			while ((!baseCmpOffset || !basePReversedAddr || !baseBaseReg || !base_ctx.pebReg) && ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + offset), 0x100, &instruction))) {
//				if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP)
//				{
//					if (!baseCmpOffset)
//					{
//						baseCmpOffset = offset;
//					}
//				}
//				else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
//				{
//					auto* op2 = &instruction.operands[1];
//					if (op2->type == ZYDIS_OPERAND_TYPE_MEMORY && op2->mem.type == ZYDIS_MEMOP_TYPE_MEM && op2->mem.base == ZYDIS_REGISTER_RIP && op2->mem.disp.has_displacement)
//					{
//						if (!basePReversedAddr) {
//							basePReversedAddr = op2->mem.disp.value + offset + instruction.length;
//
//							base_ctx.bswapReg = instruction.operands[0].reg.value;
//						}
//					}
//				}
//				else if (instruction.mnemonic == ZYDIS_MNEMONIC_NOT) {
//					auto* op1 = &instruction.operands[0];
//					if (!base_ctx.pebReg) {
//						base_ctx.pebReg = op1->reg.value;
//					}
//				}
//				else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA)
//				{
//					auto* op1 = &instruction.operands[0];
//					auto* op2 = &instruction.operands[1];
//
//					if (op1->type == ZYDIS_OPERAND_TYPE_REGISTER &&
//						op2->type == ZYDIS_OPERAND_TYPE_MEMORY && op2->mem.base == ZYDIS_REGISTER_RIP
//						&& op2->mem.disp.has_displacement)
//					{
//						auto pos = op2->mem.disp.value + offset + instruction.length;
//						if (pos == 0)
//						{
//							set_regx(&base_ctx, op1->reg.value, local_var(-1, "baseModuleAddr"));
//							baseBaseReg = op1->reg.value;
//						}
//					}
//
//				}
//
//				lastInstruction = instruction;
//				lastOffset = offset;
//
//				offset += instruction.length;
//			}
//		}
//	}
//
//	//int noRecoil = adv_search<int>("0F 28 C2 0F 28 CA F3 0F 59 45 00 F3 AA F3 0F 11 45 00", 46, 0, 0, false);
//
//	uint32_t localOffset = 0;
//
//	offset = search("F3 0F 10 0D ? ? ? ? ?  8B ? 24 ? 41 8B ? 0C ? 3B ? 74 ?");//search("41 8B 54 24 0C 41 8B 4D 0C 3B CA 74 ?");
//	if (!offset) {
//		offset = search("F3 0F 10 0D ? ? ? ? ? 8B ? 24 ? 41 8B ? 0C 3B ? 74 ?");
//	}
//	if (offset)
//	{
//		localOffset = *reinterpret_cast<uint32_t*>(base + offset - 4);
//		if (localOffset > 0x100000)
//		{
//			localOffset = *reinterpret_cast<uint8_t*>(base + offset - 1);
//		}
//	}
//
//	//offset = search("E8 ? ? ? ? 48 8B D7 8B CE 0F B6 D8 E8 ? ? ? ? 84 DB 75 16 84 C0 75 12 B0 01 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 20 5F");
//	//49 8D B9 D0 C1 01 00
//	//offset = search("48 8D ? ? ? ? ?", offset - 20); //48 8D
//	//int timeOffset = *reinterpret_cast<uint32_t*>(base + offset + 3);
//	//if (*reinterpret_cast<uint8_t*>(base + offset + 2) ==  0x7A) {
//	//	timeOffset = *reinterpret_cast<uint8_t*>(base + offset + 3);
//	//}
//	//offset = search("41 89 41 44 E8 ? ? ? ? 4C 8B C0");
//
//	offset = search("E8 ? ? ? ? 48 8B D7 8B CE 0F B6 D8 E8 ? ? ? ? 84 DB 75 16 84 C0 75 12 B0 01 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 20 5F");
//	if (offset)
//	{
//		offset = search_back("? 8D ? ? ? ? ?", offset);
//	}
//	int timeOffset = 0;
//	if (offset)
//	{
//		//offset += 12;
//		if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + offset), 0x100, &instruction)))
//		{
//			if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA)
//			{
//				timeOffset = instruction.operands[1].mem.disp.value;
//			}
//		}
//	}
//
//	//offset = search("F3 0F 5C C8 4D 8B CF 4D 8D 46 24 49 8B CF E8 ? ? ? ? E9 ? ? ? ?");
//	offset = search("F3 0F 5F 05 ? ? ? ? C1 E9 03 F3 0F 5D C7 F3 0F 59 05 ? ? ? ? F6 C1 01");
//	int gunAnglesOffset = 0;
//	if (offset) {
//		int cmpCount = 0;
//
//		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + offset), 0x100, &instruction)))
//		{
//			if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP)
//			{
//				cmpCount++;
//			}
//			else if (cmpCount > 0 && instruction.mnemonic == ZYDIS_MNEMONIC_MOVSS)
//			{
//				gunAnglesOffset = instruction.operands[1].mem.disp.value;
//				break;
//			}
//
//			offset += instruction.length;
//		}
//	}
//
//	offset = search("8B C1 D1 E8 A8 01 0F 85 ? ? ? ? C1 E9 08 F6 C1 01");
//	if (offset)
//	{
//		offset = search_back("48 69 C8 ? ? ? ?", offset);
//	}
//	int clientValidOffset = 0;
//	int clientEntityIdOffset = 0;
//	int clientTeamIdOffset = 0;
//	if (offset)
//	{
//		int cmpCount = 0;
//
//		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + offset), 0x100, &instruction)))
//		{
//
//			if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP)
//			{
//				cmpCount++;
//
//				switch (cmpCount)
//				{
//				case 1:
//					clientValidOffset = instruction.operands[0].mem.disp.value;
//					break;
//				case 2:
//					clientTeamIdOffset = instruction.operands[1].mem.disp.value;
//					break;
//				case 3:
//					clientEntityIdOffset = instruction.operands[0].mem.disp.value;
//					break;
//				}
//			}
//
//			if (cmpCount == 3)
//			{
//				break;
//			}
//
//			offset += instruction.length;
//		}
//	}
//
//	//					   
//	offset = search("0F BF ? ? ? ? ? 3B 05 ? ? ? ? 89");
//	if (offset)
//	{
//		offset += 7;
//	}
//	else
//	{
//		offset = search("41 0F ? ? ? 3B 05 ? ? ? ? 89");
//		if (offset)
//		{
//			offset += 5;
//		}
//	}
//	int localIndexOffset = 0;
//	if (offset) {
//		//offset += 7;
//
//		int movCount = 0;
//
//		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + offset), 0x100, &instruction)))
//		{
//			if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
//			{
//				movCount++;
//
//				if (movCount == 2)
//				{
//					localIndexOffset = instruction.operands[1].mem.disp.value;
//					break;
//				}
//			}
//
//			offset += instruction.length;
//		}
//	}
//
//
//	auto dynAnglesOffset = adv_search<uint32_t>("0F 94 C0 F3 0F 2A C8 F3 0F 59 C1", 11, 4, 0, false);
//	if (dynAnglesOffset > 0x1000000) {
//		dynAnglesOffset = adv_search<uint32_t>("0F 94 C0 F3 0F 2A C8 F3 0F 59 C1", 16, 4, 0, false);
//	}
//
//	int originOffset = adv_search<uint32_t>("F3 0F 10 ?  ? ? ? ? F3 0F 11 45 ? F3 0F 10  ? ? ? ? ? F3 0F 11 4D ? F3 0F 10 ?  ? ? ? ? EB 22", 0, 4, 0, false);
//	if (!originOffset) {
//		originOffset = adv_search<uint32_t>("F3 41 0F 10 ? ? ? ? ? F3 0F 11 45 ? F3 41 0F 10 ? ? ? ? ? F3 0F 11 4D ? F3 41 0F 10 ? ? ? ? ? EB ?", 0, 5, 0, false);
//	}
//
//	int staticAnglesOffset = adv_search<uint32_t>("F3 41 0F 10 86 ? ? ? ? F3 0F 11 44 24 ? F3 41 0F 10 8E ? ? ? ? F3 0F 11 4C 24 ? F3 41 0F 10 86 ? ? ? ? F3 0F 11 44 24 ? EB 17", 0, 5, 0, false);
//	if (staticAnglesOffset == 0) {
//		staticAnglesOffset = adv_search<uint32_t>("F3    0F 10 83 ? ? ? ? F3 0F 11 44 24 ? F3    0F 10 8B ? ? ? ? F3 0F 11 4C 24 ? F3    0F 10 83 ? ? ? ? F3 0F 11 44 24 ? EB 17", 0, 4, 0, false);
//	}
//
//	int disp = 0;
//	ZydisRegister indexReg = instruction.operands[0].reg.value;
//
//	int base_disp = 0;
//
//	//_line;
//	//printf("CLIENT_INFO_BASE:\n");
//	//printf("encryptedReg: %s\n", reg_str(base_ctx.ptrReg, nullptr).c_str());
//	//printf("bswapReg: %s\n", reg_str(base_ctx.bswapReg, nullptr).c_str());
//	//printf("pebReg: %s\n", reg_str(base_ctx.pebReg, nullptr).c_str());
//
//	int clientbase_dec_end = 0;
//
//	for (int i = 0; i < 16; i++) {
//		int rip = emulate_decryption(baseCmpOffset, baseBaseReg, indexReg, i, &base_ctx);
//		if (!clientbase_dec_end)
//		{
//			clientbase_dec_end = rip;
//		}
//
//		char file_name[256];
//		sprintf_s(file_name, "C:\\Users\\elsia\\Desktop\\Decyption\\client_base_%i.cpp", i);
//		char prototype[256];
//		sprintf_s(prototype, "uint64_t client_base_dec_%i(uint64_t baseModuleAddr, uint64_t not_peb, uint64_t encrypted_address)", i);
//		dump_dec(&base_ctx, file_name, prototype);
//	}
//
//	if (clientbase_dec_end) {
//		offset = clientbase_dec_end;
//		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + offset), 0x100, &instruction)))
//		{
//			if (instruction.mnemonic == ZYDIS_MNEMONIC_IMUL)
//			{
//				size = instruction.operands[2].imm.value.u;
//
//				break;
//			}
//
//			offset += instruction.length;
//		}
//	}
//
//
//	printf("namespace clientinfo {\n\n");
//	printf("\tconstexpr uint32_t encrypted_ptr = 0x%X;\n", pEncryptedPtr);
//	//printf("\tconstexpr uint32_t reversed_address = 0x%X;\n", pReversedAddr);
//	//printf("\tconstexpr uint32_t displacement = 0x%X;\n", disp);
//	printf("\tconstexpr uint32_t size = 0x%X;\n", size);
//	printf("\tconstexpr uint32_t local_base_offset = 0x%X;\n", localOffset);
//	printf("\tconstexpr uint32_t timer_offset = 0x%X;\n", timeOffset);
//	printf("\tconstexpr uint32_t static_angles_offset = 0x%X;\n", staticAnglesOffset);
//	printf("\tconstexpr uint32_t dynamic_angles_offset = 0x%X;\n", dynAnglesOffset);
//	printf("\tconstexpr uint32_t local_origin_offset = 0x%X;\n", originOffset);
//	printf("\tconstexpr uint32_t base_offset = 0x%X;\n", baseOffset);
//	printf("\tconstexpr uint32_t gun_angles_offset = 0x%X;\n", gunAnglesOffset);
//	printf("\tconstexpr uint32_t valid_off = 0x%X;\n", clientValidOffset);
//	printf("\tconstexpr uint32_t entity_index = 0x%X;\n", clientEntityIdOffset);
//	printf("\tconstexpr uint32_t team_id = 0x%X;\n", clientTeamIdOffset);
//	printf("\tconstexpr uint32_t local_index_offset = 0x%X;\n", localIndexOffset);
//
//	//printf("\tconstexpr uint32_t base_reversed_addr = 0x%X;\n", basePReversedAddr);
//	//printf("\tconstexpr uint32_t base_displacement = 0x%X;\n", base_disp);
//
//
//	printf("}\n");
//}