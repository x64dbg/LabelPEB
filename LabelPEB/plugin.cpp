#include "plugin.h"
#include "undocumented.h"

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
