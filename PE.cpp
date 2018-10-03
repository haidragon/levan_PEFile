#include<stdio.h>
#include<windows.h>
#include<time.h>
#include<tchar.h>
 
void Help()
{
        printf("\nUsage \ntest <path to exe file> [ -h <section> ]\n");
}
void HexDump(char * p ,int size,int secAddress)
{
        int i=1,temp=0;
        wchar_t buf[18];          //Buffer      to store the character dump displayed at the right side
        printf("\n\n%x: |",secAddress);
 
        buf[temp]        = ' ' ;  //initial space
        buf[temp+16] = ' ' ;  //final space    
        buf[temp+17] =  0  ;  //End of buf
        temp++;                           //temp = 1;
        for( ; i <= size ; i++, p++,temp++)
        {
                buf[temp] = !iswcntrl((*p)&0xff)? (*p)&0xff :'.';
                printf("%-3.2x",(*p)&0xff );
 
                if(i%16 == 0){    //print the chracter dump to the right       
                        _putws(buf);
                        if(i+1<=size)printf("%x: ",secAddress+=16);
                        temp=0;
                }
                if(i%4==0)printf("|");
        }
        if(i%16!=0){
                buf[temp]=0;
                for(;i%16!=0;i++)
                        printf("%-3.2c",' ');
                _putws(buf);
        }
}
 
main(int argc , char ** argv){
       
        int i=0;
        HANDLE hMapObject,hFile;                        //File Mapping Object
        LPVOID lpBase;                                          //Pointer to the base memory of mapped file
        PIMAGE_DOS_HEADER dosHeader;            //Pointer to DOS Header
        PIMAGE_NT_HEADERS ntHeader;                     //Pointer to NT Header
        IMAGE_FILE_HEADER header;                       //Pointer to image file header of NT Header
        IMAGE_OPTIONAL_HEADER opHeader;         //Optional Header of PE files present in NT Header structure
        PIMAGE_SECTION_HEADER pSecHeader;       //Section Header or Section Table Header
        if(argc>1){
               
                //Open the Exe File
                hFile = CreateFile(argv[1],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
                if(hFile == INVALID_HANDLE_VALUE){printf("\nERROR : Could not open the file specified\n"); goto info;};
               
                //Mapping Given EXE file to Memory
                hMapObject = CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
                lpBase = MapViewOfFile(hMapObject,FILE_MAP_READ,0,0,0);
               
                //Get the DOS Header Base
                dosHeader = (PIMAGE_DOS_HEADER)lpBase;// 0x04000000
               
                //Check for Valid DOS file
                if(dosHeader->e_magic == IMAGE_DOS_SIGNATURE){
                        //Dump the Dos Header info
                        printf("\nValid Dos Exe File\n------------------\n");
                        printf("\nDumping DOS Header Info....\n---------------------------");
                        printf("\n%-36s%s ","Magic number : ",dosHeader->e_magic==0x5a4d?"MZ(Mark Zbikowski)":"-");
                        printf("\n%-36s%#x","Bytes on last page of file :",dosHeader->e_cblp);
                        printf("\n%-36s%#x","Pages in file : ",dosHeader->e_cp);
                        printf("\n%-36s%#x","Relocation : ",dosHeader->e_crlc);
                        printf("\n%-36s%#x","Size of header in paragraphs : ",dosHeader->e_cparhdr);
                        printf("\n%-36s%#x","Minimum extra paragraphs needed : ",dosHeader->e_minalloc);
                        printf("\n%-36s%#x","Maximum extra paragraphs needed : ",dosHeader->e_maxalloc);
                        printf("\n%-36s%#x","Initial (relative) SS value : ",dosHeader->e_ss);
                        printf("\n%-36s%#x","Initial SP value : ",dosHeader->e_sp);
                        printf("\n%-36s%#x","Checksum : ",dosHeader->e_csum);
                        printf("\n%-36s%#x","Initial IP value : ",dosHeader->e_ip);
                        printf("\n%-36s%#x","Initial (relative) CS value : ",dosHeader->e_cs);
                        printf("\n%-36s%#x","File address of relocation table : ",dosHeader->e_lfarlc);
                        printf("\n%-36s%#x","Overlay number : ",dosHeader->e_ovno);
                        printf("\n%-36s%#x","OEM identifier : ",dosHeader->e_oemid);
                        printf("\n%-36s%#x","OEM information(e_oemid specific) :",dosHeader->e_oeminfo);
                        printf("\n%-36s%#x","RVA address of PE header : ",dosHeader->e_lfanew);
                        printf("\n===============================================================================\n");
                }
                else {
                        printf("\nGiven File is not a valid DOS file\n");
                        goto end;
                }
               
                //Offset of NT Header is found at 0x3c location in DOS header specified by e_lfanew
                //Get the Base of NT Header(PE Header)  = dosHeader + RVA address of PE header
                ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader) + (dosHeader->e_lfanew));
                //Identify for valid PE file  
                if(ntHeader->Signature == IMAGE_NT_SIGNATURE){
                        printf("\nValid PE file \n-------------\n");
 
                        //Dump NT Header Info....
                        printf("\nDumping COFF/PE Header Info....\n--------------------------------");
                        printf("\n%-36s%s","Signature :","PE");
                       
                       
                        //Get the IMAGE FILE HEADER Structure
                        header = ntHeader->FileHeader;
                       
                        //Determine Machine Architechture
                        printf("\n%-36s","Machine Architechture :");
                        switch(header.Machine){ //Only few are determined (for remaining refer to the above specification)
                        case 0x0:        printf("All "); break;
                        case 0x14d:  printf("Intel i860"); break;
                        case 0x14c:  printf("Intel i386,i486,i586"); break;
                        case 0x200:  printf("Intel Itanium processor"); break;
                        case 0x8664: printf("AMD x64"); break;
                        case 0x162:  printf("MIPS R3000"); break;
                        case 0x166:  printf("MIPS R4000"); break;
                        case 0x183:  printf("DEC Alpha AXP"); break;
                        default:         printf("Not Found"); break;
                        }
                        //Determine the characteristics of the given file
                        printf("\n%-36s","Characteristics : ");
                        if((header.Characteristics&0x0002) == 0x0002) printf("Executable Image ,");
                        if((header.Characteristics&0x0020) == 0x0020) printf("Application can address > 2GB ,");
                        if((header.Characteristics&0x1000) == 0x1000) printf("System file (Kernel Mode Driver(I think)) ,");
                        if((header.Characteristics&0x2000) == 0x2000) printf("Dll file ,");
                        if((header.Characteristics&0x4000) == 0x4000) printf("Application runs only in Uniprocessor ,");
                       
                       
                        printf("\n%-36s%s","Time Stamp :",ctime(&(header.TimeDateStamp)));                      //Determine Time Stamp
                        printf("%-36s%d","No.sections(size) :",header.NumberOfSections);                        //Determine number of sections
                        printf("\n%-36s%d","No.entries in symbol table :",header.NumberOfSymbols);
                        printf("\n%-36s%d","Size of optional header :",header.SizeOfOptionalHeader);
                       
                        printf("\n\nDumping PE Optional Header Info....\n-----------------------------------");
                        //Info about Optional Header
                        opHeader = ntHeader->OptionalHeader;
                        //printf("\n\nInfo of optional Header\n-----------------------");
                        printf("\n%-36s%#x","Address of Entry Point : ",opHeader.AddressOfEntryPoint);
                        printf("\n%-36s%#x","Base Address of the Image : ",opHeader.ImageBase);
                        printf("\n%-36s%s","SubSystem type : ",
                                opHeader.Subsystem==1?"Device Driver(Native windows Process)":
                        opHeader.Subsystem==2?"Windows GUI":
                        opHeader.Subsystem==3?"Windows CLI":
                        opHeader.Subsystem==9?"Windows CE GUI":
                        "Unknown"
                                );
                        printf("\n%-36s%s","Given file is a : ",opHeader.Magic==0x20b?"PE32+(64)":"PE32");
                        printf("\n%-36s%d","Size of code segment(.text) : ",opHeader.SizeOfCode);
                        printf("\n%-36s%#x","Base address of code segment(RVA) :",opHeader.BaseOfCode);
                        printf("\n%-36s%d","Size of Initialized data : ",opHeader.SizeOfInitializedData);
                        printf("\n%-36s%#x","Base address of data segment(RVA) :",opHeader.BaseOfData);
                        printf("\n%-36s%#x","Section Alignment :",opHeader.SectionAlignment);
                        printf("\n%-36s%d","Major Linker Version : ",opHeader.MajorLinkerVersion);
                        printf("\n%-36s%d","Minor Linker Version : ",opHeader.MinorLinkerVersion);                             
                       
                       
                       
                        printf("\n\nDumping Sections Header Info....\n--------------------------------");
                       
                        //Retrive a pointer to First Section Header(or Section Table Entry)
                       
                       
                        for(pSecHeader = IMAGE_FIRST_SECTION(ntHeader),i=0;i<ntHeader->FileHeader.NumberOfSections;i++,pSecHeader++){  
                                printf("\n\nSection Info (%d of %d)",i+1,ntHeader->FileHeader.NumberOfSections);
                                printf("\n---------------------");
                                printf("\n%-36s%s","Section Header name : ", pSecHeader->Name);
                                printf("\n%-36s%#x","ActualSize of code or data : ", pSecHeader->Misc.VirtualSize);
                                printf("\n%-36s%#x","Virtual Address(RVA) :", pSecHeader->VirtualAddress);
                                printf("\n%-36s%#x","Size of raw data (rounded to FA) : ", pSecHeader->SizeOfRawData);
                                printf("\n%-36s%#x","Pointer to Raw Data : ", pSecHeader->PointerToRawData);
                                printf("\n%-36s%#x","Pointer to Relocations : ", pSecHeader->PointerToRelocations);
                                printf("\n%-36s%#x","Pointer to Line numbers : ", pSecHeader->PointerToLinenumbers);
                                printf("\n%-36s%#x","Number of relocations : ", pSecHeader->NumberOfRelocations);
                                printf("\n%-36s%#x","Number of line numbers : ", pSecHeader->NumberOfLinenumbers);
                                printf("\n%-36s%s","Characteristics : ","Contains ");
                                if((pSecHeader->Characteristics&0x20)==0x20)printf("executable code, ");
                                if((pSecHeader->Characteristics&0x40)==0x40)printf("initialized data, ");
                                if((pSecHeader->Characteristics&0x80)==0x80)printf("uninitialized data, ");
                                if((pSecHeader->Characteristics&0x80)==0x80)printf("uninitialized data, ");
                                if((pSecHeader->Characteristics&0x200)==0x200)printf("comments and linker commands, ");
                                if((pSecHeader->Characteristics&0x10000000)==0x10000000)printf("shareable data(via DLLs), ");
                                if((pSecHeader->Characteristics&0x40000000)==0x40000000)printf("Readable, ");
                                if((pSecHeader->Characteristics&0x80000000)==0x80000000)printf("Writable, ");
                               
                               
                                // If -h or /h option is given then provide HexDump
                                if(argc==4&& (!strcmpi(argv[2],"-h")||!strcmpi(argv[2],"/h"))){
                                        if(!strcmpi(argv[3],pSecHeader->Name))
                                                if(pSecHeader->SizeOfRawData!=0)
                                                HexDump((char *)((DWORD)dosHeader + pSecHeader->PointerToRawData) , pSecHeader->SizeOfRawData , opHeader.ImageBase + pSecHeader->VirtualAddress);
                                }
                               
                        }
                       
                       
                        printf("\n===============================================================================\n");
                }
                else goto end;
               
end:
                //UnMaping
                UnmapViewOfFile(lpBase);
                CloseHandle(hMapObject);
        }
        else Help();
info:
       
        printf("\
                        \
                        \
                                                        This Program is written by\
                                                        K.Vineel Kumar Reddy.\
                                                                        III/IV IT\
                                                        Gayathri Vidya Parishad college of Eng.\
                        \
                        \
                        ");
}