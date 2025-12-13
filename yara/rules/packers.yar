/*
    File: yara/rules/packers.yar
    Description: YARA rules for detecting High and Medium priority packers and protectors.
    Author: Multiple Authors (compiled by HUTAOSHUSBAND)
*/

import "pe"

/* High Priority Targets */

rule VMProtect {
    meta:
        description = "Detects VMProtect packed files"
        author = "HUTAOSHUSBAND"
    strings:
        $s1 = "VMProtect begin" ascii
        $s2 = "VMProtect end" ascii
    condition:
        any of ($s*) or 
        (pe.number_of_sections > 0 and 
            (
                for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == ".vmp0" or 
                    pe.sections[i].name == ".vmp1"
                )
            )
        )
}

rule Themida_WinLicense {
    meta:
        description = "Detects Themida / WinLicense packed files"
        author = "HUTAOSHUSBAND"
    strings:
        $s1 = "Themida" ascii wide
        $s2 = "WinLicense" ascii wide
        $s3 = "Oreans Technologies" ascii wide
    condition:
        any of ($s*) or
        (pe.number_of_sections > 0 and
            (
                for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == ".themida"
                )
            )
        )
}

rule Enigma_Protector {
    meta:
        description = "Detects Enigma Protector"
        author = "malware-lu (modified by HUTAOSHUSBAND)"
    strings:
        $a1 = "Enigma protector" ascii wide nocase
        $a2 = { 60 E8 00 00 00 00 5D 83 ED 06 81 }
    condition:
        any of them
}

rule StarForce {
    meta:
        description = "Detects StarForce Protection"
        author = "malware-lu"
    strings:
        $a0 = { 57 68 ?? 0D 01 00 68 00 [2] 00 E8 50 ?? FF FF 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 }
    condition:
        $a0 at pe.entry_point
}

rule Obsidium {
    meta:
        description = "Detects Obsidium Protector"
        author = "Kevin Falcoz"
    strings:
        $str1 = {EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04}
    condition:
        $str1 at pe.entry_point
}

rule VBox {
    meta:
        description = "Detects VBox Protector"
        author = "malware-lu"
    strings:
        $a0 = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
    condition:
        $a0
}

/* Medium Priority Targets */

rule ASProtect {
    meta:
        description = "Detects ASProtect"
        author = "malware-lu"
    strings:
        $a0 = { 68 01 [3] E8 01 [3] C3 C3 }
    condition:
        $a0 at pe.entry_point
}

rule ASPack {
    meta:
        description = "Detects ASPack"
        author = "Kevin Falcoz"
    strings:
        $str1 = {60 E8 00 00 00 00 5D 81 ED 5D 3B 40 00 64 A1 30 00 00 00 0F B6 40 02 0A C0 74 04 33 C0 87 00 B9 [2] 00 00 8D BD B7 3B 40 00 8B F7 AC}
    condition:
        $str1 at pe.entry_point
}

rule Armadillo {
    meta:
        description = "Detects Armadillo"
        author = "malware-lu"
    strings:
        $a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
    condition:
        $a0 at pe.entry_point
}

rule EXECryptor {
    meta:
        description = "Detects EXECryptor"
        author = "Kevin Falcoz"
    strings:
        $str1 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 64 8F 05 00 00 00 00}
    condition:
        $str1 at pe.entry_point
}

rule FSG {
    meta:
        description = "Detects FSG Packer"
        author = "malware-lu"
    strings:
        $a0 = { EB 02 CD 20 EB 01 91 8D 35 80 [2] 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }
    condition:
        $a0 at pe.entry_point
}

rule MEW {
    meta:
        description = "Detects MEW Packer"
        author = "Kevin Falcoz"
    strings:
        $signature1 = {50 72 6F 63 41 64 64 72 65 73 73 00 E9 [6-7] 00 00 00 00 00 00 00 00 00 [7] 00}
    condition:
        $signature1
}

rule MoleBox {
    meta:
        description = "Detects MoleBox"
        author = "malware-lu"
    strings:
        $a0 = { E8 [4] 60 E8 4F }
    condition:
        $a0
}

rule PC_Guard {
    meta:
        description = "Detects PC Guard"
        author = "malware-lu"
    strings:
        $a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 [3] 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }
    condition:
        $a0 at pe.entry_point
}

rule PELock {
    meta:
        description = "Detects PELock"
        author = "malware-lu"
    strings:
        $a0 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }
    condition:
        $a0 at pe.entry_point
}

rule Petite {
    meta:
        description = "Detects Petite"
        author = "malware-lu"
    strings:
        $a0 = { B8 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 66 9C 60 50 }
    condition:
        $a0 at pe.entry_point
}

rule PECompact {
    meta:
        description = "Detects PECompact"
        author = "Kevin Falcoz"
    strings:
        $str1 = {B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43}
    condition:
        $str1 at pe.entry_point
}

rule UPX {
    meta:
        description = "Detects UPX Packer (Generic)"
        author = "Kevin Falcoz"
    strings:
        $str1 = {60 BE 00 [2] 00 8D BE 00 [2] FF [1-12] EB 1? 90 90 90 90 90 [1-3] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01}
    condition:
        $str1 at pe.entry_point
}

rule MPRESS {
    meta:
        description = "Detects MPRESS Packer"
        author = "Kevin Falcoz"
    strings:
        $signature1 = {60 E8 00 00 00 00 58 05 [2] 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6}
    condition:
        $signature1 at pe.entry_point
}
