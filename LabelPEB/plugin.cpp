#include "plugin.h"
#include "undocumented.h"

/**
This function is from x64dbg repository
\brief Compares two strings without case-sensitivity.
\param a The first string.
\param b The second string.
\return true if the strings are equal (case-insensitive).
*/
inline bool scmp(const char* a, const char* b)
{
    if(!a || !b)
        return false;
    return !_stricmp(a, b);
}

//called from CBADDRINFO
template<size_t Size>
static bool getLabelPEB(duint addr, char (&label)[Size])
{
    duint peb = (duint)GetPEBLocation(DbgGetProcessHandle());
    duint size = DbgMemGetPageSize(peb);
    if(addr >= peb && addr < peb + size)
    {
        addr -= peb;
#define CASE(member) if(addr == offsetof(PEB, member)) { strcpy_s(label, "PEB." #member); } else
#include "pebcases.h"
#undef CASE
        return false;
        return true;
    }
    else
        return false;
}

//called from CBVALFROMSTRING
static bool valpebfromstring(const char* name, duint* value, int* value_size, bool* isvar)
{
#define CASE(member) if(_stricmp(name, "PEB." #member) == 0) { *value = offsetof(PEB, member); } else
#include "pebcases.h"
#undef CASE
    return false;
    *value += (duint)GetPEBLocation(DbgGetProcessHandle());
    if(value_size)
        *value_size = sizeof(duint);
    if(isvar)
        *isvar = true;
    return true;
}

//called from CBVALFROMSTRING
static bool valpefromstring(const char* name, duint* value, int* value_size, bool* isvar)
{
    //The following piece of code is from x64dbg
    const char* apiname = strchr(name, ':'); //the ':' character cannot be in a path: https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx#naming_conventions
    if(!apiname) //not found
    {
        apiname = strstr(name, "..") ? strchr(name, '.') : strrchr(name, '.'); //kernel32.GetProcAddress support
        if(!apiname) //not found
            apiname = strchr(name, '?'); //the '?' character cannot be in a path either
    }
    if(!apiname)
        return false;
    if(apiname)
    {
        duint modbase;
        if(name == apiname) //:[expression] <= currently selected module
        {
            SELECTIONDATA seldata;
            memset(&seldata, 0, sizeof(seldata));
            GuiSelectionGet(GUI_DISASSEMBLY, &seldata);
            modbase = DbgFunctions()->ModBaseFromAddr(seldata.start);
        }
        else
        {
            char modname[MAX_MODULE_SIZE] = "";
            strncpy_s(modname, name, _TRUNCATE);
            modname[apiname - name] = 0;
            modbase = DbgModBaseFromName(modname);
        }
        if(modbase == 0)
            return false;
        apiname++;
        if(!strlen(apiname))
            return false;
        //end code from x64dbg repository
        duint peheader = 0;
        if(!DbgMemRead(modbase + 0x3C, &peheader, 4)) //failed getting pe header offset.
            return false;
        peheader += modbase;
        if(!DbgMemIsValidReadPtr(peheader)) //bad offset to pe header
            return false;
#define CASE(x, y) if(scmp(apiname,"PE." x)) { *value = peheader + (y); } else
        CASE("header", 0)
        CASE("fileheader", 4)
        CASE("imagefileheader", 4)
        CASE("PointerToSymbolTable", 4 + offsetof(IMAGE_FILE_HEADER, PointerToSymbolTable))
        CASE("SizeOfOptionalHeader", 4 + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader))
        CASE("Characteristics", 4 + offsetof(IMAGE_FILE_HEADER, Characteristics))
        CASE("optionalheader", 4 + sizeof(IMAGE_FILE_HEADER))
        CASE("imageoptionalheader", 4 + sizeof(IMAGE_FILE_HEADER))
        CASE("AddressOfEntryPoint", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, AddressOfEntryPoint))
        CASE("BaseOfCode", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, BaseOfCode))
        CASE("ImageBase", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, ImageBase))
        CASE("FileAlignment", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, FileAlignment))
        CASE("SizeOfImage", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfImage))
        CASE("SizeOfHeaders", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfHeaders))
        CASE("Subsystem", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, Subsystem))
        CASE("DllCharacteristics", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DllCharacteristics))
        CASE("LoaderFlags", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, LoaderFlags))
        CASE("NumberOfRvaAndSizes", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, NumberOfRvaAndSizes))
        CASE("DataDirectory", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory))
        CASE("imagedirectoryentryexport", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory))
        CASE("directoryentryexport", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory))
        CASE("imagedirectoryentryimport", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY))
        CASE("directoryentryimport", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY))
        CASE("imagedirectoryentryresource", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 2)
        CASE("directoryentryresource", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 2)
        CASE("imagedirectoryentryexception", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 3)
        CASE("directoryentryexception", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 3)
        CASE("imagedirectoryentrybasereloc", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 5)
        CASE("directoryentrybasereloc", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 5)
        CASE("imagedirectoryentrydebug", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 6)
        CASE("directoryentrydebug", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 6)
        CASE("imagedirectoryentrytls", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 9)
        CASE("directoryentrytls", 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY) * 9)
        CASE("imagesectiontable", 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER))
        CASE("section", 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER))
        if(scmp(apiname, "PE.IAT"))
        {
            duint rva = 0;
            if(!DbgMemRead(peheader + 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + sizeof(IMAGE_DATA_DIRECTORY), &rva, 4))
                return false;
            if(rva == 0) // too crazy to use "MZ..." as OriginalFirstTrunk
                return false;
            rva += modbase;
            if(!DbgMemIsValidReadPtr(rva)) //bad RVA to IAT
                return false;
            *value = rva;
        }
        else if(scmp(apiname, "PE.EAT"))
        {
            duint rva = 0;
            if(!DbgMemRead(peheader + 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory), &rva, 4))
                return false;
            if(rva == 0) // although it's OK to use "MZ..." as Characteristics, it's highly unusual...
                return false;
            rva += modbase;
            if(!DbgMemIsValidReadPtr(rva)) //bad RVA to EAT
                return false;
            *value = rva;
        }
        else
        return false;
#undef CASE

        if(value_size)
            *value_size = sizeof(duint);
        if(isvar)
            *isvar = true;
        return true;
    }
    return false;
}

//called from CBVALTOSTRING
static bool valpebtostring(const char* name, duint value)
{
    duint addr = 0;
    duint size = 0;
#define member_size(type, member) sizeof(((type*)0)->member)
#define CASE(member) if((size = member_size(PEB, member)) <= sizeof(duint) && _stricmp(name, "PEB." #member) == 0) { addr = offsetof(PEB, member); } else
#include "pebcases.h"
#undef CASE
#undef member_size
    return false;
    addr += (duint)GetPEBLocation(DbgGetProcessHandle());
    return DbgMemWrite(addr, &value, size);
}

PLUG_EXPORT void CBADDRINFO(CBTYPE cbType, PLUG_CB_ADDRINFO* info)
{
    if(!info->retval && (info->addrinfo->flags & flaglabel))
        info->retval = getLabelPEB(info->addr, info->addrinfo->label);
}

PLUG_EXPORT void CBVALFROMSTRING(CBTYPE cbType, PLUG_CB_VALFROMSTRING* info)
{
    if(!info->retval)
        info->retval = valpebfromstring(info->string, &info->value, info->value_size, info->isvar);
    if(!info->retval)
        info->retval = valpefromstring(info->string, &info->value, info->value_size, info->isvar);
}

PLUG_EXPORT void CBVALTOSTRING(CBTYPE cbType, PLUG_CB_VALTOSTRING* info)
{
    if(!info->retval)
        info->retval = valpebtostring(info->string, info->value);
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    return true; //Return false to cancel loading the plugin.
}

bool pluginStop()
{
    return true;
}

void pluginSetup()
{
}
