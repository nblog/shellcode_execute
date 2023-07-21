
#include <iostream>
#include <functional>
#include <unordered_map>
#include <initializer_list>

#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")

#include <Windows.h>

#include <fontsub.h>
#pragma comment(lib, "FontSub.lib")

#include <t2embapi.h>
#pragma comment(lib, "T2embed.lib")
#include <Vfw.h>
#pragma comment(lib, "Vfw32.lib")
#include <CommCtrl.h>
#pragma comment(lib, "Comctl32.lib")
#include <SetupAPI.h>
#pragma comment(lib, "SetupAPI.lib")
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")
#include <powrprof.h>
#pragma comment(lib, "PowrProf.lib")

#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "Imm32.lib")




typedef std::function<void(void*)> creeper;


static const std::initializer_list<creeper> templates = {
    [](void* code) {
        std::cout << "EnumFontFamiliesExA";
        EnumFontFamiliesExA(0, 0, FONTENUMPROCA(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumFontFamiliesExW";
        EnumFontFamiliesExW(0, 0, FONTENUMPROCW(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumFontFamiliesA";
        EnumFontFamiliesA(0, 0, FONTENUMPROCA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumFontFamiliesW";
        EnumFontFamiliesW(0, 0, FONTENUMPROCW(code), 0);
    },
    [](void* code) {
        std::cout << "EnumFontsA";
        EnumFontsA(0, 0, FONTENUMPROCA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumFontsW";
        EnumFontsW(0, 0, FONTENUMPROCW(code), 0);
    },
    [](void* code) {
        std::cout << "EnumObjects";
        EnumObjects(0, 0, GOBJENUMPROC(code), 0);
    },
    [](void* code) {
        std::cout << "LineDDA";
        LineDDA(0, 0, 0, 0, LINEDDAPROC(code), 0);
    },
    [](void* code) {
        std::cout << "EnumMetaFile";
        EnumMetaFile(0, 0, MFENUMPROC(code), 0);
    },
    [](void* code) {
        std::cout << "EnumEnhMetaFile";
        EnumEnhMetaFile(0, 0, ENHMFENUMPROC(code), 0, 0);
    },
    [](void* code) {
        std::cout << "CreateFontPackage";
        CreateFontPackage(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, CFP_ALLOCPROC(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "MergeFontPackage";
        MergeFontPackage(0, 0, 0, 0, 0, 0, 0, 0, CFP_ALLOCPROC(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "TTEmbedFont";
        TTEmbedFont(0, 0, 0, 0, 0, WRITEEMBEDPROC(code), 0, 0, 0, 0, 0);
    },
    [](void* code) {
        std::cout << "TTEmbedFontFromFileA";
        TTEmbedFontFromFileA(0, 0, 0, 0, 0, 0, 0, WRITEEMBEDPROC(code), 0, 0, 0, 0, 0);
    },
    [](void* code) {
        std::cout << "TTLoadEmbeddedFont";
        TTLoadEmbeddedFont(0, 0, 0, 0, 0, READEMBEDPROC(code), 0, 0, 0, 0);
    },
    [](void* code) {
        std::cout << "TTGetEmbeddedFontInfo";
        TTGetEmbeddedFontInfo(0, 0, 0, 0, READEMBEDPROC(code), 0, 0);
    },
    [](void* code) {
        std::cout << "TTEmbedFontEx";
        TTEmbedFontEx(0, 0, 0, 0, 0, WRITEEMBEDPROC(code), 0, 0, 0, 0, 0);
    },
    //[](void* code) {
    //    std::cout << "GrayStringA";
    //    GrayStringA(0, 0, GRAYSTRINGPROC(code), 0, 0, 0, 0, 0, 0);
    //},
    //[](void* code) {
    //    std::cout << "GrayStringW";
    //    GrayStringW(0, 0, GRAYSTRINGPROC(code), 0, 0, 0, 0, 0, 0);
    //},
    [](void* code) {
        std::cout << "DrawStateA";
        DrawStateA(0, 0, DRAWSTATEPROC(code), 0, 0, 0, 0, 0, 0, 0);
    },
    [](void* code) {
        std::cout << "DrawStateW";
        DrawStateW(0, 0, DRAWSTATEPROC(code), 0, 0, 0, 0, 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumDisplayMonitors";
        EnumDisplayMonitors(0, 0, MONITORENUMPROC(code), 0);
    },
    [](void* code) {
        std::cout << "mciSetYieldProc";
        mciSetYieldProc(0, YIELDPROC(code), 0);
    },
    [](void* code) {
        std::cout << "mmDrvInstall";
        mmDrvInstall(0, 0, DRIVERMSGPROC(code), 0);
    },
    [](void* code) {
        std::cout << "mmioInstallIOProcA";
        mmioInstallIOProcA(0, LPMMIOPROC(code), 0);
    },
    [](void* code) {
        std::cout << "mmioInstallIOProcW";
        mmioInstallIOProcW(0, LPMMIOPROC(code), 0);
    },
    [](void* code) {
        std::cout << "ICOpenFunction";
        ICOpenFunction(0, 0, 0, FARPROC(code));
    },
    [](void* code) {
        std::cout << "SetWindowSubclass";
        SetWindowSubclass(0, SUBCLASSPROC(code), 0, 0);
    },
    [](void* code) {
        std::cout << "GetWindowSubclass";
        GetWindowSubclass(0, SUBCLASSPROC(code), 0, 0);
    },
    [](void* code) {
        std::cout << "RemoveWindowSubclass";
        RemoveWindowSubclass(0, SUBCLASSPROC(code), 0);
    },
    [](void* code) {
        std::cout << "SetupDiRegisterDeviceInfo";
        SetupDiRegisterDeviceInfo(0, 0, 0, PSP_DETSIG_CMPPROC(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumCalendarInfoA";
        EnumCalendarInfoA(CALINFO_ENUMPROCA(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumCalendarInfoW";
        EnumCalendarInfoW(CALINFO_ENUMPROCW(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumCalendarInfoExA";
        EnumCalendarInfoExA(CALINFO_ENUMPROCEXA(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumCalendarInfoExW";
        EnumCalendarInfoExW(CALINFO_ENUMPROCEXW(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumTimeFormatsA";
        EnumTimeFormatsA(TIMEFMT_ENUMPROCA(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumTimeFormatsW";
        EnumTimeFormatsW(TIMEFMT_ENUMPROCW(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumDateFormatsA";
        EnumDateFormatsA(DATEFMT_ENUMPROCA(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumDateFormatsW";
        EnumDateFormatsW(DATEFMT_ENUMPROCW(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumDateFormatsExA";
        EnumDateFormatsExA(DATEFMT_ENUMPROCEXA(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumDateFormatsExW";
        EnumDateFormatsExW(DATEFMT_ENUMPROCEXW(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumSystemGeoID";
        EnumSystemGeoID(0, 0, GEO_ENUMPROC(code));
    },
    [](void* code) {
        std::cout << "EnumSystemGeoNames";
        EnumSystemGeoNames(0, GEO_ENUMNAMEPROC(code), 0);
    },
    [](void* code) {
        std::cout << "EnumSystemLocalesA";
        EnumSystemLocalesA(LOCALE_ENUMPROCA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumSystemLocalesW";
        EnumSystemLocalesW(LOCALE_ENUMPROCW(code), 0);
    },
    [](void* code) {
        std::cout << "EnumSystemLanguageGroupsA";
        EnumSystemLanguageGroupsA(LANGUAGEGROUP_ENUMPROCA(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumSystemLanguageGroupsW";
        EnumSystemLanguageGroupsW(LANGUAGEGROUP_ENUMPROCW(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumLanguageGroupLocalesA";
        EnumLanguageGroupLocalesA(LANGGROUPLOCALE_ENUMPROCA(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumLanguageGroupLocalesW";
        EnumLanguageGroupLocalesW(LANGGROUPLOCALE_ENUMPROCW(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumUILanguagesA";
        EnumUILanguagesA(UILANGUAGE_ENUMPROCA(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumUILanguagesW";
        EnumUILanguagesW(UILANGUAGE_ENUMPROCW(code), 0, 0);
    },
    [](void* code) {
        std::cout << "EnumSystemCodePagesA";
        EnumSystemCodePagesA(CODEPAGE_ENUMPROCA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumSystemCodePagesW";
        EnumSystemCodePagesW(CODEPAGE_ENUMPROCW(code), 0);
    },
    [](void* code) {
        std::cout << "EnumCalendarInfoExEx";
        EnumCalendarInfoExEx(CALINFO_ENUMPROCEXEX(code), 0, 0, 0, 0, 0);
    },
    //[](void* code) {
    //    std::cout << "EnumDateFormatsExEx";
    //    EnumDateFormatsExEx(DATEFMT_ENUMPROCEXEX(code), 0, 0, 0);
    //},
    //[](void* code) {
    //    std::cout << "EnumTimeFormatsEx";
    //    EnumTimeFormatsEx(TIMEFMT_ENUMPROCEX(code), 0, 0, 0);
    //},
    [](void* code) {
        std::cout << "EnumSystemLocalesEx";
        EnumSystemLocalesEx(LOCALE_ENUMPROCEX(code), 0, 0, 0);
    },
    //[](void* code) {
    //    std::cout << "WSASetBlockingHook";
    //    WSASetBlockingHook(FARPROC(code));
    //},
    [](void* code) {
        std::cout << "WSAAccept";
        WSAAccept(0, 0, 0, LPCONDITIONPROC(code), 0);
    },
    [](void* code) {
        std::cout << "SetAbortProc";
        SetAbortProc(0, ABORTPROC(code));
    },
    //[](void* code) {
    //    std::cout << "StackWalk64";
    //    StackWalk64(0, 0, 0, 0, 0, PREAD_PROCESS_MEMORY_ROUTINE64(code), 0, 0, 0);
    //},
    //[](void* code) {
    //    std::cout << "StackWalkEx";
    //    StackWalkEx(0, 0, 0, 0, 0, PREAD_PROCESS_MEMORY_ROUTINE64(code), 0, 0, 0, 0);
    //},
    //[](void* code) {
    //    std::cout << "StackWalk2";
    //    StackWalk2(0, 0, 0, 0, 0, PREAD_PROCESS_MEMORY_ROUTINE64(code), 0, 0, 0, 0, 0);
    //},
    //[](void* code) {
    //    std::cout << "StackWalk";
    //    StackWalk(0, 0, 0, 0, 0, PREAD_PROCESS_MEMORY_ROUTINE(code), 0, 0, 0);
    //},
    [](void* code) {
        std::cout << "SymFunctionTableAccess64AccessRoutines";
        SymFunctionTableAccess64AccessRoutines(0, 0, PREAD_PROCESS_MEMORY_ROUTINE64(code), 0);
    },
    [](void* code) {
        std::cout << "SymEnumProcesses";
        SymEnumProcesses(PSYM_ENUMPROCESSES_CALLBACK(code), 0);
    },
    [](void* code) {
        std::cout << "EnumResourceLanguagesExA";
        EnumResourceLanguagesExA(0, 0, 0, ENUMRESLANGPROCA(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumResourceLanguagesExW";
        EnumResourceLanguagesExW(0, 0, 0, ENUMRESLANGPROCW(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumResourceNamesExA";
        EnumResourceNamesExA(0, 0, ENUMRESNAMEPROCA(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumResourceNamesExW";
        EnumResourceNamesExW(0, 0, ENUMRESNAMEPROCW(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumResourceTypesExA";
        EnumResourceTypesExA(0, ENUMRESTYPEPROCA(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumResourceTypesExW";
        EnumResourceTypesExW(0, ENUMRESTYPEPROCW(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumResourceNamesW";
        EnumResourceNamesW(0, 0, ENUMRESNAMEPROCW(code), 0);
    },
    [](void* code) {
        std::cout << "EnumResourceNamesA";
        EnumResourceNamesA(0, 0, ENUMRESNAMEPROCA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumResourceTypesA";
        EnumResourceTypesA(0, ENUMRESTYPEPROCA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumResourceTypesW";
        EnumResourceTypesW(0, ENUMRESTYPEPROCW(code), 0);
    },
    [](void* code) {
        std::cout << "EnumResourceLanguagesA";
        EnumResourceLanguagesA(0, 0, 0, ENUMRESLANGPROCA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumResourceLanguagesW";
        EnumResourceLanguagesW(0, 0, 0, ENUMRESLANGPROCW(code), 0);
    },
    //[](void* code) {
    //    std::cout << "IsBadCodePtr";
    //    IsBadCodePtr(FARPROC(code));
    //},
    //[](void* code) {
    //    std::cout << "EnumPwrSchemes";
    //    EnumPwrSchemes(PWRSCHEMESENUMPROC(code), 0);
    //},
    //[](void* code) {
    //    std::cout << "WinWatchNotify";
    //    WinWatchNotify(0, WINWATCHNOTIFYPROC(code), 0);
    //},
    [](void* code) {
        std::cout << "SetWinEventHook";
        SetWinEventHook(0, 0, 0, WINEVENTPROC(code), 0, 0, 0);
    },
    [](void* code) {
        std::cout << "EnumICMProfilesA";
        EnumICMProfilesA(0, ICMENUMPROCA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumICMProfilesW";
        EnumICMProfilesW(0, ICMENUMPROCW(code), 0);
    },
    [](void* code) {
        std::cout << "ImmEnumRegisterWordA";
        ImmEnumRegisterWordA(0, REGISTERWORDENUMPROCA(code), 0, 0, 0, 0);
    },
    [](void* code) {
        std::cout << "ImmEnumRegisterWordW";
        ImmEnumRegisterWordW(0, REGISTERWORDENUMPROCW(code), 0, 0, 0, 0);
    },
    //[](void* code) {
    //    std::cout << "ImmEnumInputContext";
    //    ImmEnumInputContext(0, IMCENUMPROC(code), 0);
    //},
    [](void* code) {
        std::cout << "SendMessageCallbackA";
        SendMessageCallbackA(0, 0, 0, 0, SENDASYNCPROC(code), 0);
    },
    [](void* code) {
        std::cout << "SendMessageCallbackW";
        SendMessageCallbackW(0, 0, 0, 0, SENDASYNCPROC(code), 0);
    },
    [](void* code) {
        std::cout << "CallWindowProcA";
        CallWindowProcA(WNDPROC(code), 0, 0, 0, 0);
    },
    [](void* code) {
        std::cout << "CallWindowProcW";
        CallWindowProcW(WNDPROC(code), 0, 0, 0, 0);
    },
    [](void* code) {
        std::cout << "CreateDialogParamA";
        CreateDialogParamA(0, 0, 0, DLGPROC(code), 0);
    },
    [](void* code) {
        std::cout << "CreateDialogParamW";
        CreateDialogParamW(0, 0, 0, DLGPROC(code), 0);
    },
    //[](void* code) {
    //    std::cout << "CreateDialogIndirectParamA";
    //    CreateDialogIndirectParamA(0, 0, 0, DLGPROC(code), 0);
    //},
    //[](void* code) {
    //    std::cout << "CreateDialogIndirectParamW";
    //    CreateDialogIndirectParamW(0, 0, 0, DLGPROC(code), 0);
    //},
    //[](void* code) {
    //    std::cout << "DialogBoxParamA";
    //    DialogBoxParamA(0, 0, 0, DLGPROC(code), 0);
    //},
    //[](void* code) {
    //    std::cout << "DialogBoxParamW";
    //    DialogBoxParamW(0, 0, 0, DLGPROC(code), 0);
    //},
    //[](void* code) {
    //    std::cout << "DialogBoxIndirectParamA";
    //    DialogBoxIndirectParamA(0, 0, 0, DLGPROC(code), 0);
    //},
    //[](void* code) {
    //    std::cout << "DialogBoxIndirectParamW";
    //    DialogBoxIndirectParamW(0, 0, 0, DLGPROC(code), 0);
    //},
    [](void* code) {
        std::cout << "SetTimer";
        SetTimer(0, 0, 0, TIMERPROC(code));
    },
    [](void* code) {
        std::cout << "SetCoalescableTimer";
        SetCoalescableTimer(0, 0, 0, TIMERPROC(code), 0);
    },
    [](void* code) {
        std::cout << "EnumPropsExA";
        EnumPropsExA(0, PROPENUMPROCEXA(code), 0);
    },
    [](void* code) {
        std::cout << "EnumPropsExW";
        EnumPropsExW(0, PROPENUMPROCEXW(code), 0);
    },
    [](void* code) {
        std::cout << "EnumPropsA";
        EnumPropsA(0, PROPENUMPROCA(code));
    },
    [](void* code) {
        std::cout << "EnumPropsW";
        EnumPropsW(0, PROPENUMPROCW(code));
    },
    [](void* code) {
        std::cout << "EnumChildWindows";
        EnumChildWindows(0, WNDENUMPROC(code), 0);
    },
    [](void* code) {
        std::cout << "EnumWindows";
        EnumWindows(WNDENUMPROC(code), 0);
    },
    [](void* code) {
        std::cout << "EnumThreadWindows";
        EnumThreadWindows(0, WNDENUMPROC(code), 0);
    },
    [](void* code) {
        std::cout << "SetWindowsHookA";
        SetWindowsHookA(0, HOOKPROC(code));
    },
    [](void* code) {
        std::cout << "SetWindowsHookW";
        SetWindowsHookW(0, HOOKPROC(code));
    },
    [](void* code) {
        std::cout << "UnhookWindowsHook";
        UnhookWindowsHook(0, HOOKPROC(code));
    },
    [](void* code) {
        std::cout << "SetWindowsHookExA";
        SetWindowsHookExA(0, HOOKPROC(code), 0, 0);
    },
    [](void* code) {
        std::cout << "SetWindowsHookExW";
        SetWindowsHookExW(0, HOOKPROC(code), 0, 0);
    },
    //[](void* code) {
    //    std::cout << "EnumDesktopsA";
    //    EnumDesktopsA(0, DESKTOPENUMPROCA(code), 0);
    //},
    //[](void* code) {
    //    std::cout << "EnumDesktopsW";
    //    EnumDesktopsW(0, DESKTOPENUMPROCW(code), 0);
    //},
    [](void* code) {
        std::cout << "EnumDesktopWindows";
        EnumDesktopWindows(0, WNDENUMPROC(code), 0);
    },
    //[](void* code) {
    //    std::cout << "EnumWindowStationsA";
    //    EnumWindowStationsA(WINSTAENUMPROCA(code), 0);
    //},
    //[](void* code) {
    //    std::cout << "EnumWindowStationsW";
    //    EnumWindowStationsW(WINSTAENUMPROCW(code), 0);
    //},
};


struct MyAlloc {
    ~MyAlloc() {
        if (fnCall) {
            VirtualFree(fnCall, 0, MEM_RELEASE); fnCall = 0;
        }
    }
    MyAlloc(const void* code, const size_t length) {
        fnCall = VirtualAlloc(
            NULL,
            4096 > length ? 4096 : length,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (fnCall) memcpy(fnCall, code, length);
    }
    void* fnCall = 0;
};


bool runcode(creeper call) {

    /* AddAtomA("DUMMY??"); */
    static const unsigned char shellcode[] = {
        0xE8, 0x00, 0x00, 0x00, 0x00, 0x59, 0x48, 0x81, 0xC1, 0x9E, 0x01, 0x00, 0x00, 0xE8, 0x11, 0x00,
        0x00, 0x00, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xE8, 0x25, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x0F, 0xE8, 0x25, 0x00,
        0x00, 0x00, 0x8B, 0x0C, 0x24, 0x8D, 0x49, 0x01, 0x89, 0x01, 0xEB, 0x10, 0xE8, 0x21, 0x00, 0x00,
        0x00, 0x48, 0x8B, 0x0C, 0x24, 0x48, 0x8D, 0x49, 0x01, 0x48, 0x89, 0x01, 0xC3, 0x31, 0xC0, 0x48,
        0x0F, 0x88, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x51, 0xE8, 0xD2, 0x00, 0x00, 0x00, 0x59, 0x51, 0xFF,
        0xD0, 0xC3, 0x51, 0x48, 0x83, 0xEC, 0x30, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x30,
        0x59, 0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x48, 0x83, 0xEC, 0x28,
        0x48, 0x83, 0xE4, 0xF0, 0x48, 0x31, 0xC9, 0x65, 0x48, 0x8B, 0x41, 0x60, 0x48, 0x8B, 0x40, 0x18,
        0x48, 0x8B, 0x70, 0x20, 0x48, 0xAD, 0x48, 0x96, 0x48, 0xAD, 0x48, 0x8B, 0x58, 0x20, 0x4D, 0x31,
        0xC0, 0x44, 0x8B, 0x43, 0x3C, 0x4C, 0x89, 0xC2, 0x48, 0x01, 0xDA, 0x48, 0x31, 0xC9, 0xB1, 0x88,
        0x48, 0x01, 0xD1, 0x44, 0x8B, 0x01, 0x49, 0x01, 0xD8, 0x48, 0x31, 0xF6, 0x41, 0x8B, 0x70, 0x20,
        0x48, 0x01, 0xDE, 0x48, 0x31, 0xC9, 0x49, 0xB9, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41,
        0x48, 0xFF, 0xC1, 0x48, 0x31, 0xC0, 0x8B, 0x04, 0x8E, 0x48, 0x01, 0xD8, 0x4C, 0x39, 0x08, 0x75,
        0xEF, 0x48, 0x31, 0xF6, 0x41, 0x8B, 0x70, 0x24, 0x48, 0x01, 0xDE, 0x66, 0x8B, 0x0C, 0x4E, 0x48,
        0x31, 0xF6, 0x41, 0x8B, 0x70, 0x1C, 0x48, 0x01, 0xDE, 0x48, 0x31, 0xD2, 0x8B, 0x14, 0x8E, 0x48,
        0x01, 0xDA, 0x48, 0x89, 0xD7, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xB9, 0x41, 0x64, 0x64,
        0x41, 0x74, 0x6F, 0x6D, 0x41, 0x51, 0x48, 0x89, 0xE2, 0x48, 0x89, 0xD9, 0x48, 0x83, 0xEC, 0x30,
        0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x48, 0x83, 0xC4, 0x10, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x31,
        0xC9, 0x64, 0x8B, 0x41, 0x30, 0x8B, 0x40, 0x0C, 0x8B, 0x70, 0x14, 0xAD, 0x96, 0xAD, 0x8B, 0x58,
        0x10, 0x8B, 0x53, 0x3C, 0x01, 0xDA, 0x8B, 0x52, 0x78, 0x01, 0xDA, 0x8B, 0x72, 0x20, 0x01, 0xDE,
        0x31, 0xC9, 0x41, 0xAD, 0x01, 0xD8, 0x81, 0x38, 0x47, 0x65, 0x74, 0x50, 0x75, 0xF4, 0x81, 0x78,
        0x04, 0x72, 0x6F, 0x63, 0x41, 0x75, 0xEB, 0x81, 0x78, 0x08, 0x64, 0x64, 0x72, 0x65, 0x75, 0xE2,
        0x8B, 0x72, 0x24, 0x01, 0xDE, 0x66, 0x8B, 0x0C, 0x4E, 0x49, 0x8B, 0x72, 0x1C, 0x01, 0xDE, 0x8B,
        0x14, 0x8E, 0x01, 0xDA, 0x31, 0xC9, 0x53, 0x52, 0x51, 0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x74,
        0x6F, 0x6D, 0x41, 0x68, 0x41, 0x64, 0x64, 0x41, 0x54, 0x53, 0xFF, 0xD2, 0x83, 0xC4, 0x0C, 0x83,
        0xC4, 0x0C, 0xC3, 0x44, 0x55, 0x4D, 0x4D, 0x59, 0x3F, 0x3F, 0x00
    };

    auto m = MyAlloc(shellcode, sizeof(shellcode));

    call(m.fnCall);

    auto has = FindAtomA("DUMMY??");

    return bool(has && 0 == DeleteAtom(has));
}

LONG
WINAPI
VectoredHandlerCallback(
    PEXCEPTION_POINTERS pExceptionInfo
)
{
    UNREFERENCED_PARAMETER(pExceptionInfo);

    return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
    AddVectoredExceptionHandler(TRUE, VectoredHandlerCallback);

    for (const auto& f : templates) {
        std::cout << "\t\t\t\t\t\tresult: " << (runcode(f) ? "true" : "false") << std::endl;
    }

	return 0;
}