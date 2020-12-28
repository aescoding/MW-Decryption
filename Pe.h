#pragma once
#pragma once

#include <windows.h>

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#ifndef RvaToVa
#define RvaToVa(Cast,Base,Rel) ((Cast)((DWORD_PTR)(Base) + (DWORD_PTR)(Rel)))
#endif

PIMAGE_NT_HEADERS
RtlImageNtHeader(
	PVOID Base
);

PVOID
LdrFindProcAdressA(
	PVOID Base,
	const char* Name
);

PIMAGE_SECTION_HEADER
RtlpFindSection(
	PVOID Base,
	const char* SectionName
);

BOOLEAN
RtlSectionRange(
	PVOID Base,
	const char* SectionName,
	PVOID* Min,
	PVOID* Max
);

PVOID
RtlpFindPatternEx(
	PBYTE Start,
	PBYTE End,
	PBYTE Pattern,
	size_t PatternLen,
	BYTE WildCard
);

PVOID RtlpFindPatternExBack(PBYTE Start, PBYTE End, PBYTE Pattern, SIZE_T PatternLen,
	BYTE WildCard);

#ifndef FindPattern
#define FindPattern(Start,End,Pattern,WildCard) RtlpFindPatternEx(Start,End,Pattern,_countof(Pattern),WildCard)
#endif
