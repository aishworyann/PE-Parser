#include<iostream>
#include<windows.h>
#include<winnt.h>
#include<fstream>

using namespace std;

//--------------------------------------------Function to access DOS Header----------------------------------------------------------
void PrintDosHeader(const IMAGE_DOS_HEADER& dosHeader) {
	cout << "------------------------------------------DOS HEADER------------------------------------------"<< endl;
	cout << "=============================================================================================" << endl;
	cout << "MZ Header Signature: 0x" << hex<< dosHeader.e_magic<< " ";
	if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE)cout << "MZ" ;
	else if (dosHeader.e_magic == IMAGE_OS2_SIGNATURE)cout << "NE" ;
	else if (dosHeader.e_magic == IMAGE_OS2_SIGNATURE_LE)cout << "LE" ;
	else if (dosHeader.e_magic == IMAGE_VXD_SIGNATURE)cout << "LE" ;
	cout << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_magic) << endl;
	cout << "Bytes on last page of file: 0x" << dosHeader.e_cblp << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_cblp) << endl;
	cout << "Pages in file: 0x" << dosHeader.e_cp << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_cp) << endl;
	cout << "Relocations:0x " << dosHeader.e_crlc << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_crlc) << endl;
	cout << "Size of header in paragraphs: 0x" << dosHeader.e_cparhdr << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_cparhdr) << endl;
	cout << "Minimum extra paragraphs needed: 0x" << dosHeader.e_minalloc << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_minalloc) << endl;
	cout << "Maximum extra paragraphs needed: 0x" << dosHeader.e_maxalloc << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_maxalloc) << endl;
	cout << "Initial (relative) SS value: 0x" << dosHeader.e_ss << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_ss) << endl;
	cout << "Initial SP value: 0x" << dosHeader.e_sp << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_sp) << endl;
	cout << "Checksum: " << dosHeader.e_csum << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_csum) << endl;
	cout << "Initial IP value: " << dosHeader.e_ip << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_ip) << endl;
	cout << "Initial (relative) CS value : " << dosHeader.e_cs << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_cs) << endl;
	cout << "File address of relocation table: " << dosHeader.e_lfarlc << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_lfarlc) << endl;
	cout << "Overlay number: " << dosHeader.e_ovno << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_ovno) << endl;
	cout << "Reserved Numbers: " << endl;
	for (int i = 0; i < 4; i++) {
		cout << dosHeader.e_res[i] << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_res[i]) << endl;
	}
	cout << "OEM identifier: " << dosHeader.e_oemid << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_oemid) << endl;
	cout << "OEM Information: " << dosHeader.e_oeminfo << " Offset: " << offsetof(IMAGE_DOS_HEADER, e_oeminfo) << endl;
	cout << "Offset to new .exe header: " << dosHeader.e_lfanew <<" Offset: "<<hex<<offsetof(IMAGE_DOS_HEADER, e_lfanew)<< endl;
}

//-----------------------------------------Function to print File Header-----------------------------------------------------------
void PrintFileHeader(const IMAGE_FILE_HEADER& fileHeader, streampos &fileHeaderOffset ) {
	cout << "------------------------------------------File Header------------------------------------------" << endl;
	cout << "Machine: " << hex<< fileHeader.Machine  << " Offset: " <<hex<< (static_cast<size_t>(fileHeaderOffset) + offsetof(IMAGE_FILE_HEADER, Machine)) << endl;
    cout << "Number of Sections: " << hex<<fileHeader.NumberOfSections<<dec<< " Offset: " << hex << (static_cast<size_t>(fileHeaderOffset) + offsetof(IMAGE_FILE_HEADER, NumberOfSections)) << endl;
    cout << "TimeDateStamp: " << fileHeader.TimeDateStamp << " Offset: " << (static_cast<size_t>(fileHeaderOffset) + offsetof(IMAGE_FILE_HEADER , TimeDateStamp)) << endl;
    cout << "Pointer to Symbol Table: " << fileHeader.PointerToSymbolTable << " Offset: " << (static_cast<size_t>(fileHeaderOffset) + offsetof(IMAGE_FILE_HEADER , PointerToSymbolTable)) << endl;
    cout << "Number of Symbols: " << fileHeader.NumberOfSymbols << " Offset: " << (static_cast<size_t>(fileHeaderOffset) + offsetof(IMAGE_FILE_HEADER , NumberOfSymbols)) << endl;
    cout << "Size of Optional Header: " <<hex<< fileHeader.SizeOfOptionalHeader << " Offset: " << (static_cast<size_t>(fileHeaderOffset) + offsetof(IMAGE_FILE_HEADER , SizeOfOptionalHeader)) << endl;
    cout << "Characteristics: " << fileHeader.Characteristics <<  " Offset: " << (static_cast<size_t>(fileHeaderOffset) + offsetof(IMAGE_FILE_HEADER, Characteristics)) << endl;
	cout << endl;

}

//---------------------------------------- Function to fetch Optional Header-----------------------------------------------------
void PrintOptionalHeader(const IMAGE_OPTIONAL_HEADER& optionalHeader) {
	cout << "------------------------------------------Optional Header:----------------------------------- " << endl;
	cout << "=============================================================================================" << endl;
	if(optionalHeader.Magic)
    cout << "Magic: " << hex << optionalHeader.Magic << dec << endl;
    cout << "Major Linker Version: " << (int)optionalHeader.MajorLinkerVersion << endl;
    cout << "Minor Linker Version: " << (int)optionalHeader.MinorLinkerVersion << endl;
    cout << "Size of Code: " << optionalHeader.SizeOfCode << endl;
    cout << "Size of Initialized Data: " << optionalHeader.SizeOfInitializedData << endl;
    cout << "Size of Uninitialized Data: " << optionalHeader.SizeOfUninitializedData << endl;
    cout << "Address of Entry Point: " << hex << optionalHeader.AddressOfEntryPoint << dec << endl;
    cout << "Base of Code: " << hex << optionalHeader.BaseOfCode << dec << endl;
    cout << "Image Base: " << hex << optionalHeader.ImageBase << endl;
    cout << "Section Alignment: " << optionalHeader.SectionAlignment << endl;
    cout << "File Alignment: " << optionalHeader.FileAlignment << endl;
    cout << "Major Operating System Version: " << optionalHeader.MajorOperatingSystemVersion << endl;
    cout << "Minor Operating System Version: " << optionalHeader.MinorOperatingSystemVersion << endl;
    cout << "Major Image Version: " << optionalHeader.MajorImageVersion << endl;
    cout << "Minor Image Version: " << optionalHeader.MinorImageVersion << endl;
    cout << "Major Subsystem Version: " << optionalHeader.MajorSubsystemVersion << endl;
    cout << "Minor Subsystem Version: " << optionalHeader.MinorSubsystemVersion << endl;
    cout << "Win32 Version Value: " << optionalHeader.Win32VersionValue << endl;
    cout << "Size of Image: " << optionalHeader.SizeOfImage << endl;
    cout << "Size of Headers: " << optionalHeader.SizeOfHeaders << endl;
    cout << "Checksum: " << optionalHeader.CheckSum << endl;
    cout << "Subsystem: " << hex << optionalHeader.Subsystem << dec << endl;
    cout << "Dll Characteristics: " << hex << optionalHeader.DllCharacteristics << dec << endl;
    cout << "Size of Stack Reserve: " << optionalHeader.SizeOfStackReserve << endl;
    cout << "Size of Stack Commit: " << optionalHeader.SizeOfStackCommit << endl;
    cout << "Size of Heap Reserve: " << optionalHeader.SizeOfHeapReserve << endl;
    cout << "Size of Heap Commit: " << optionalHeader.SizeOfHeapCommit << endl;
    cout << "Loader Flags: " << optionalHeader.LoaderFlags << endl;
    cout << "Number of Rva and Sizes: " << optionalHeader.NumberOfRvaAndSizes << endl;
	cout << endl; 
    // Print the Data Directories
	cout << "------------------------------------------Data Dirctories:------------------------------------------ " << endl;
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        cout << "Data Directory [" << i << "]:" << endl;
        cout << "  Virtual Address: " << optionalHeader.DataDirectory[i].VirtualAddress << endl;
        cout << "  Size: " << optionalHeader.DataDirectory[i].Size << endl;
    }
	cout << endl;
}

//--------------------------------------Function to Print sections ----------------------------------------------------------
void PrintSections(const IMAGE_SECTION_HEADER* secHeader, int NoOfSections) {
	cout << "------------------------------------------ Section Header:------------------------------------------" << endl;
	cout << "=============================================================================================" << endl;

	for (int i = 0; i < NoOfSections; ++i) {
		char sectionName[9] = { 0 };
		strncpy_s(sectionName, reinterpret_cast<const char*>(secHeader[i].Name), 8);
		cout << "Section Name: " << sectionName << endl;
		cout << "Physical Address: " << (secHeader[i].Misc.PhysicalAddress) << endl;
		cout << "Virtual Size: " << (secHeader[i].Misc.VirtualSize) << endl;
		cout << "Virtual Address: " << hex << (secHeader[i].VirtualAddress) << dec << endl;
		cout << "Size of Raw Data: " << (secHeader[i].SizeOfRawData) << endl;
		cout << "Pointer to Raw Data: " << hex << secHeader[i].PointerToRawData << dec << endl;
		cout << "Pointer To Relocations: " << hex << secHeader[i].PointerToRelocations << dec << endl;
		cout << "Pointer To Line numbers: " << hex << secHeader[i].PointerToLinenumbers << dec << endl;
		cout << "No. of Reloactions: " << hex << secHeader[i].NumberOfRelocations << dec << endl;
		cout << "No. of Line numbers: " << hex << secHeader[i].NumberOfLinenumbers << dec << endl;
		cout << "Characteristics: " << hex << secHeader[i].Characteristics << dec << endl;
		cout << endl;
	}
}

//Main Function to Parse PE Header
void ParsePeHeader(const char* filePath) {
	ifstream peFile(filePath, ios::binary);
	if (!peFile) {
		cerr << "Unable to open file: " << filePath << endl;
		return;
	}

	//-----------------------------------------------DOS HEADER-------------------------------------------------------
	// Read the DOS Header
	IMAGE_DOS_HEADER dosHeader;
	peFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
	PrintDosHeader(dosHeader);

	//-----------------------------------------------NT HEADER-------------------------------------------------------
	peFile.seekg(dosHeader.e_lfanew, ios::beg);
	streampos ntHeaderOffset = peFile.tellg();

	//reading NT Header
	IMAGE_NT_HEADERS ntHeader;
	peFile.read(reinterpret_cast<char*>(&ntHeader), sizeof(ntHeader));
    cout << "------------------------------------------NT HEADER:------------------------------------------" << endl;
	cout << "=============================================================================================" << endl;
    cout << "Signature:" <<ntHeader.Signature<<" Offset: "<< (static_cast<size_t>(	ntHeaderOffset)+offsetof(IMAGE_NT_HEADERS, Signature)) << endl;


	//--------------------File HEADER-----------------------------------------------------------------------------------
	peFile.seekg(dosHeader.e_lfanew + sizeof(ntHeader.Signature),ios::beg);
	streampos fileHeaderOffset = peFile.tellg();

	IMAGE_FILE_HEADER fileHeader;
    peFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
	PrintFileHeader(fileHeader,fileHeaderOffset);
	
	//--------------------OPTIONAL HEADER-----------------------------------------------------------------------------------
	peFile.seekg(dosHeader.e_lfanew + sizeof(ntHeader.Signature)+sizeof(fileHeader),ios::beg);

	IMAGE_OPTIONAL_HEADER optionalHeader;
	peFile.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));
	PrintOptionalHeader(optionalHeader);

	//-----------------------------------------------SECTION HEADER-------------------------------------------------------

	peFile.seekg(dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), ios::beg); //Moving to setion header

	IMAGE_SECTION_HEADER* secHeader = new IMAGE_SECTION_HEADER[ntHeader.FileHeader.NumberOfSections];
	peFile.read(reinterpret_cast<char*>(secHeader), ntHeader.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	PrintSections(secHeader, ntHeader.FileHeader.NumberOfSections);


}

int main(int argc, char* argv[]) {
	const char* filePath = "C:\\Windows\\System32\\kernel32.dll";
	ParsePeHeader(filePath);
}