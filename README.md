# defcreator
Pre-test of creating .def files by parsing the EAT of an x64 DLL

Usage:
- Copy defcreator in the same directory the 3rd party 64 bit DLL resides in.
- Type the DLL name and press enter.

If everything went fine, an "exports.def" now has been created in the same directory.
If you don't have write permissions to the directory you might start defcreator as an admin.

Otherways, open http://www.joyasystems.com/list-of-ntstatus-codes to lookup the error code.

The usage is not restricted to DLLs, you can also dump export of driver .sys (e.g. clfs.sys)
or of executable files (they export rarely symbols, except ntoskrnl.exe).

Tested on Windows 7 SP1 x64