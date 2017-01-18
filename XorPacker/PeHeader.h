#pragma once
typedef  unsigned char BYTE;
typedef  unsigned short WORD;
typedef  unsigned long DWORD;

typedef struct _IMAGE_DOS_HEADER {
	WORD  e_magic;      /* 00: MZ Header signature */
	WORD  e_cblp;       /* 02: Bytes on last page of file */
	WORD  e_cp;         /* 04: Pages in file */
	WORD  e_crlc;       /* 06: Relocations */
	WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
	WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
	WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
	WORD  e_ss;         /* 0e: Initial (relative) SS value */
	WORD  e_sp;         /* 10: Initial SP value */
	WORD  e_csum;       /* 12: Checksum */
	WORD  e_ip;         /* 14: Initial IP value */
	WORD  e_cs;         /* 16: Initial (relative) CS value */
	WORD  e_lfarlc;     /* 18: File address of relocation table */
	WORD  e_ovno;       /* 1a: Overlay number */
	WORD  e_res[4];     /* 1c: Reserved words */
	WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
	WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
	WORD  e_res2[10];   /* 28: Reserved words */
	DWORD e_lfanew;     /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;
	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
typedef struct _IMAGE_NT_HEADERS {
	DWORD Signatures;                  // PE Signature : 50450000 ("PE"00)
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
typedef struct PEStructure {
IMAGE_DOS_HEADER  ImageDosHeader;
WORD  DoSstubCode[50];
IMAGE_NT_HEADERS32 NTHeader;
} PE_STRUCTURE;