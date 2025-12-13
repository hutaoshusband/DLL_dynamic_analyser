/*
    File: yara/rules/compilers_languages.yar
    Description: YARA rules for detecting specific compilers, languages, and installers.
    Author: Multiple Authors (compiled by HUTAOSHUSBAND)
*/

import "pe"
import "elf"

/* Compilers & Languages */

rule Golang {
    meta:
        description = "Detects Go-compiled binaries"
        author = "HUTAOSHUSBAND"
    strings:
        $go_symbol = "go.buildid" ascii
        $go_runtime = "runtime.main" ascii
    condition:
        any of them
}

rule Rust {
    meta:
        description = "Detects Rust-compiled binaries"
        author = "HUTAOSHUSBAND"
    strings:
        $rust_panic = "rust_panic" ascii
    condition:
        any of ($rust*) or 
        (uint16(0) == 0x5A4D and pe.number_of_sections > 0 and 
            (
                for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == ".rustc"
                )
            )
        )
}

rule PyInstaller {
    meta:
        description = "Detects PyInstaller packed binaries"
        author = "HUTAOSHUSBAND"
    strings:
        $s1 = "MEIPASS" ascii
        $s2 = "pyi-runtime-tmpdir" ascii
        $s3 = "Error detected starting Python VM." ascii
    condition:
        any of ($s*) or 
        (uint16(0) == 0x5A4D and pe.number_of_sections > 0 and 
            (
                for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == "pydata"
                )
            )
        ) or
        (elf.number_of_sections > 0 and
            (
                for any i in (0..elf.number_of_sections - 1) : (
                    elf.sections[i].name == "pydata"
                )
            )
        )
}

rule AutoIt {
    meta:
        description = "Detects AutoIt compiled scripts"
        author = "Jean-Philippe Teissier / @Jipe_"
    strings:
        $a = "This is a compiled AutoIt script. AV researchers please email avsupport@autoitscript.com for support." ascii wide
        $b = "AU3!EA06" ascii
    condition:
        any of them
}

rule Borland_Delphi {
    meta:
        description = "Detects Borland Delphi compiled binaries"
        author = "malware-lu"
    strings:
        $s1 = "Borland Delphi" ascii
        $s2 = "TApplication" ascii
    condition:
        any of them
}

rule Visual_Basic {
    meta:
        description = "Detects Visual Basic compiled binaries"
        author = "HUTAOSHUSBAND"
    strings:
        $s1 = "MSVBVM60.DLL" ascii
        $s2 = "MSVBVM50.DLL" ascii
        $s3 = "__vbaExceptHandler" ascii
    condition:
        any of them
}

/* Installers */

rule Inno_Setup {
    meta:
        description = "Detects Inno Setup installers"
        author = "malware-lu"
    strings:
        $s1 = "Inno Setup" ascii wide
        $s2 = "Inno Setup Setup Data" ascii
    condition:
        any of them
}

rule NSIS {
    meta:
        description = "Detects Nullsoft Scriptable Install System (NSIS)"
        author = "malware-lu"
    strings:
        $s1 = "Nullsoft Inst" ascii
        $s2 = "NSIS Error" ascii
    condition:
        any of them
}

rule InstallShield {
    meta:
        description = "Detects InstallShield installers"
        author = "malware-lu"
    strings:
        $s1 = "InstallShield" ascii wide
        $s2 = "ISSetup.dll" ascii
    condition:
        any of them
}
