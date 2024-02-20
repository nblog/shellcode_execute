# shellcode execute
POCs for Shellcode Injection via Callbacks, Only Windows.

### win32metadata
In order to quickly and accurately parse out the publicly available portion of the win32api, as well as to meet the functionality of the `Callback` program, the `win32metadata` project is used for this purpose.

See: [win32metadata-generate](./win32metadata/generate.py)


### For testing examples
here [AddAtomA](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-addatoma) is used, as a load for [shellcode](https://github.com/nblog/auto-inject), combine the generated template, with a test example, to perform call testing.
```
/* AddAtomA("DUMMY??"); */
static const unsigned char shellcode[] = {
    ...
};

auto m = MyAlloc(shellcode, sizeof(shellcode));

call(m.fnCall);

auto has = FindAtomA("DUMMY??");

return bool(has && 0 == DeleteAtom(has));
```


### Test results
See: [output](./out.log)


### Design flaw
For some functions that require valid parameters to be calibrated, not all of them can be satisfied and are not discussed at this time.

For example, [EnumFontsA](https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-enumfontsa), when HDC is invalid, then `Callback` will not be triggered.


### Credits:
[microsoft/win32metadata](https://github.com/microsoft/win32metadata)

[ynkdir/win32metadata-json](https://github.com/ynkdir/py-win32more/raw/main/win32generator/resources/metadata/Windows.Win32.json.xz)

