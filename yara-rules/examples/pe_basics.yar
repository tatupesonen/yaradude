import "pe"
import "math"

// Private helper: never reported on its own, only through other rules.
private rule IsPE
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

/* Example rule: a small PE file that also carries the classic DOS stub
   message, written with a hex string using a jump, an alternative and a
   wildcard. */
rule Small_PE_With_DOS_Stub : pe example
{
    meta:
        description = "Small PE file with the standard DOS stub message"
        author = "yaradude examples"
        max_size = 2097152
    strings:
        $stub = "This program cannot be run in DOS mode"
        $stub_hex = { 54 68 69 73 [2-4] 70 72 6F ( 67 | 47 ) 72 61 ?? }  // "This ... progra"
    condition:
        IsPE and filesize < 2MB and any of them
}

rule PE_DLL_With_Exports : pe
{
    meta:
        description = "PE DLL that exports at least one function"
        author = "yaradude examples"
    condition:
        IsPE and pe.is_dll() and pe.number_of_exports > 0
}

rule High_Entropy_Tail : example
{
    meta:
        description = "Last kilobyte of the file has high entropy"
        author = "yaradude examples"
    condition:
        filesize > 4096 and math.entropy(filesize - 1024, 1024) > 7.5
}
