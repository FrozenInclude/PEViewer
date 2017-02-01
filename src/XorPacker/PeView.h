#include<stdio.h>
#include "PeHeader.h"
#include <stddef.h>

#define maxsize 5000
#define Signature 0x5a4d
#define NTSignature 0x4550
WORD pebuffer[maxsize];
void inipe(char * filepath);
void SetDosHeader();
void ShowDosHeader();
void SetNtHeader();
void ShowNtHeader();
WORD LittleEndiantoBig(WORD num);
 PE_STRUCTURE  pe;
 static int count = 0;

WORD LittleEndiantoBig(WORD num) {
	WORD num1 = num >> 8;
	WORD num2 = num << 8;
	return num1 + num2;
}
void inipe(char * filepath) {
	FILE* file;
	int ch;

	if ((file = fopen(filepath, "rb")) == NULL) {
		printf("File read error!\n");
		exit(0);
		return;
	}
	else {
		printf("%s read Success.\n\n",filepath);
	    fread(pebuffer, sizeof(WORD), maxsize, file);
		int i = 0;
	}
	fclose(file);
	if (pebuffer[0] != Signature) {
		printf("This is not pe excutable file.\nprogram exit!\n\n");
		exit(0);
	    return;
	};
}
void SetDosHeader() {
	pe.ImageDosHeader.e_magic = pebuffer[0];
	pe.ImageDosHeader.e_cblp = pebuffer[1];
	pe.ImageDosHeader.e_cp = pebuffer[2];
	pe.ImageDosHeader.e_crlc = pebuffer[3];
	pe.ImageDosHeader.e_cparhdr = pebuffer[4];
	pe.ImageDosHeader.e_minalloc = pebuffer[5];
	pe.ImageDosHeader.e_maxalloc = pebuffer[6];
	pe.ImageDosHeader.e_ss = pebuffer[7];
	pe.ImageDosHeader.e_sp = pebuffer[8];
	pe.ImageDosHeader.e_csum = pebuffer[9];
	pe.ImageDosHeader.e_ip = pebuffer[10];
	pe.ImageDosHeader.e_cs = pebuffer[11];
	pe.ImageDosHeader.e_lfarlc = pebuffer[12];
	pe.ImageDosHeader.e_ovno = pebuffer[13];
	for (int i = 14; i <= 17; i++) {
		pe.ImageDosHeader.e_res[i - 14] = pebuffer[i];
	}
	pe.ImageDosHeader.e_oemid = pebuffer[18];
	pe.ImageDosHeader.e_oeminfo = pebuffer[19];
	for (int i = 20; i <= 30; i++) {
		pe.ImageDosHeader.e_res2[i - 20] = pebuffer[i];
	}
	pe.ImageDosHeader.e_lfanew = (pebuffer[31] << 4) + pebuffer[30];
	for (int i = 32; pebuffer[i] != NTSignature; i++) {
		if (pebuffer[i] == NTSignature)break;
		count++;
	}
	for (int i = 0; i <= count; i++) {
		pe.DoSstubCode[i] = pebuffer[i+32];
	}
}
void SetNtHeader() {
	char chracteristcsList[15]="";
	int pushcount = 0;
	const NTheaderIndex = count + 32;
	pe.NTHeader.Signatures = pebuffer[NTheaderIndex];
	pe.NTHeader.FileHeader.Machine = pebuffer[NTheaderIndex+1];
	pe.NTHeader.FileHeader.NumberOfSections = pebuffer[NTheaderIndex + 2];
	pe.NTHeader.FileHeader.TimeDateStamp = (pebuffer[NTheaderIndex+4] << 4) + pebuffer[NTheaderIndex+3];
	pe.NTHeader.FileHeader.PointerToSymbolTable = (pebuffer[NTheaderIndex + 6] << 4) + pebuffer[NTheaderIndex + 5];
	pe.NTHeader.FileHeader.NumberOfSymbols= (pebuffer[NTheaderIndex + 8] << 4) + pebuffer[NTheaderIndex + 7];
	pe.NTHeader.FileHeader.Characteristics = pebuffer[NTheaderIndex + 9];
	if ((pe.NTHeader.FileHeader.Characteristics & 0x1) == IMAGE_FILE_RELOCS_STRIPPED)chracteristcsList[pushcount++]=" IMAGE_FILE_RELOCS_STRIPPED";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x2) == IMAGE_FILE_EXECUTABLE_IMAGE)chracteristcsList[pushcount++] = "IMAGE_FILE_EXECUTABLE_IMAGE";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x4) == IMAGE_FILE_LINE_NUMS_STRIPPED)chracteristcsList[pushcount++] = "IMAGE_FILE_LINE_NUMS_STRIPPED";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x8) == IMAGE_FILE_LOCAL_SYMS_STRIPPED)chracteristcsList[pushcount++] = "IMAGE_FILE_LOCAL_SYMS_STRIPPED";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x10) == IMAGE_FILE_AGGRESIVE_WS_TRIM)chracteristcsList[pushcount++] = "IMAGE_FILE_AGGRESIVE_WS_TRIM";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x20) == IMAGE_FILE_LARGE_ADDRESS_AWARE)chracteristcsList[pushcount++] = " IMAGE_FILE_LARGE_ADDRESS_AWARE";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x80) == IMAGE_FILE_BYTES_REVERSED_LO)chracteristcsList[pushcount++] = "IMAGE_FILE_BYTES_REVERSED_LO";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x100) == IMAGE_FILE_32BIT_MACHINE)chracteristcsList[pushcount++] = "IMAGE_FILE_32BIT_MACHINE";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x200) == IMAGE_FILE_DEBUG_STRIPPED)chracteristcsList[pushcount++] = "IMAGE_FILE_DEBUG_STRIPPED";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x400) == IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)chracteristcsList[pushcount++] = "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x800) == IMAGE_FILE_NET_RUN_FROM_SWAP)chracteristcsList[pushcount++] = "IMAGE_FILE_NET_RUN_FROM_SWAP";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x1000) == IMAGE_FILE_SYSTEM)chracteristcsList[pushcount++] = "IMAGE_FILE_SYSTEM";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x2000) == IMAGE_FILE_DLL)chracteristcsList[pushcount++] = "IMAGE_FILE_DLL";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x4000) == IMAGE_FILE_UP_SYSTEM_ONLY)chracteristcsList[pushcount++] = "IMAGE_FILE_UP_SYSTEM_ONLY";
	if ((pe.NTHeader.FileHeader.Characteristics & 0x8000) == IMAGE_FILE_BYTES_REVERSED_HI)chracteristcsList[pushcount++] = "IMAGE_FILE_BYTES_REVERSED_HI";
}
void ShowNtHeader() {
	printf("\n\n============ImageNtHeader============\n\n");
	printf("%08X - Signature:0x%04X\n", pe.ImageDosHeader.e_lfanew, pe.NTHeader.Signatures);
	printf("\n\n============File Header============\n\n");
	printf("%08X - Machine:0x%04X\n", offsetof(IMAGE_FILE_HEADER,Machine) + (pe.ImageDosHeader.e_lfanew + sizeof(WORD), pe.NTHeader.FileHeader.Machine));
}
void ShowDosStopCode() {
	printf("\n\n============Dos stub Code============\n\n");
	for (int i = 0; i <= count-1; i++) {
		static int line = 0;
		if (i == 0)printf("%08X - ", offsetof(PE_STRUCTURE, DoSstubCode));
	    printf("%02X %02X ",LittleEndiantoBig(pe.DoSstubCode[i])>>8,pe.DoSstubCode[i] >> 8);
		line++;
		if (line % 8 == 0&&line!=count) {
			static int z = 0;
			z++;
			printf("\n");
			printf("%08X - ", offsetof(PE_STRUCTURE, DoSstubCode)+(0x10*z));
		}
	}
	printf("\n\n           -ASCII-\n\n");
	for (int i = 0; i <= count-1; i++) {
		static int line = 0;
		 printf("%c ", LittleEndiantoBig(pe.DoSstubCode[i]) >> 8);
		 printf("%c ", pe.DoSstubCode[i]>>8);
		line++;
		if (line % 8 == 0 && line != count) {
			printf("\n");
		}
	}
}
void ShowDosHeader() {
	printf("============ImageDosHeader============\n\n");
	printf("%08X - Signature:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_magic), pe.ImageDosHeader.e_magic);
	printf("%08X - Bytes on Last Page of File:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_cblp), pe.ImageDosHeader.e_cblp);
	printf("%08X - Pages in File:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_cp), pe.ImageDosHeader.e_cp);
	printf("%08X - Relocations:0x%04X%\n", offsetof(IMAGE_DOS_HEADER, e_crlc), pe.ImageDosHeader.e_crlc);
	printf("%08X - Size of Header in Paragraphs:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_cparhdr), pe.ImageDosHeader.e_cparhdr);
	printf("%08X - Minimum Extra Patagraphs:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_minalloc), pe.ImageDosHeader.e_minalloc);
	printf("%08X - Maximum Extra Patagraphs:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_maxalloc), pe.ImageDosHeader.e_maxalloc);
	printf("%08X - Intial (relative) SS:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_ss), pe.ImageDosHeader.e_ss);
	printf("%08X - Intial SP:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_sp), pe.ImageDosHeader.e_sp);
	printf("%08X - Checksum:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_csum), pe.ImageDosHeader.e_csum);
	printf("%08X - Initial IP:0x%04X%\n", offsetof(IMAGE_DOS_HEADER, e_ip), pe.ImageDosHeader.e_ip);
	printf("%08X - Initial (relative) CS:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_ip), pe.ImageDosHeader.e_cs);
	printf("%08X - File adress of Relocation Table:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_lfarlc), pe.ImageDosHeader.e_lfarlc);
	printf("%08X - Overlay Number:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_ovno), pe.ImageDosHeader.e_ovno);
	for (int i = 0; i <= (int)(sizeof(pe.ImageDosHeader.e_res) / sizeof(pe.ImageDosHeader.e_res[0]))-1; i++) {
		printf("%08X - Reserved:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_res[i]), pe.ImageDosHeader.e_res[i]);
	}
	printf("%08X - OEM Identifier:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_oemid), pe.ImageDosHeader.e_oemid);
	printf("%08X - OEM Information:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_oeminfo), pe.ImageDosHeader.e_oeminfo);
	for (int i = 0; i <= (int)(sizeof(pe.ImageDosHeader.e_res2) / sizeof(pe.ImageDosHeader.e_res2[0]))-1; i++) {
		printf("%08X - Reserved:0x%04X\n", offsetof(IMAGE_DOS_HEADER, e_res2[i]), pe.ImageDosHeader.e_res2[i]);
	}
	printf("%08X - Offset to New EXE Header:0x%08X\n", offsetof(IMAGE_DOS_HEADER, e_lfanew), pe.ImageDosHeader.e_lfanew);
}