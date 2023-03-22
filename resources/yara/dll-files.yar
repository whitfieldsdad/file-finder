import "pe"

rule is_dll
{
    condition:
        pe.characteristics & pe.DLL
}
