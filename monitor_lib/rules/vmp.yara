/*
    YARA Rules for VMProtect and Themida Detection
    Complete collection for malware analysis and reverse engineering
*/

// ============================================================================
// VMProtect 1.x Detection
// ============================================================================

rule VMProtect_1x_Signature
{
    meta:
        description = "Detects VMProtect 1.x protected executables"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // VMProtect 1.x characteristic patterns
        $vmp1_pattern1 = { 55 8B EC 83 C4 ?? 53 56 57 8B 75 ?? 8B 7D ?? 8B 4D ?? 8B 55 ?? 8B 45 ?? }
        $vmp1_pattern2 = { 9C 60 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 05 ?? ?? ?? ?? 50 }
        $vmp1_pattern3 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 8B 44 24 ?? 8B 00 }

        // Section names
        $vmp_section1 = ".vmp0" ascii
        $vmp_section2 = ".vmp1" ascii

        // Characteristic strings
        $vmp_string1 = "VMProtect" ascii wide

    condition:
        uint16(0) == 0x5A4D and // MZ header
        (
            any of ($vmp1_pattern*) or
            any of ($vmp_section*) or
            $vmp_string1
        )
}

// ============================================================================
// VMProtect 2.x Detection
// ============================================================================

rule VMProtect_2x_Signature
{
    meta:
        description = "Detects VMProtect 2.x protected executables"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // VMProtect 2.x patterns
        $vmp2_pattern1 = { 8B 45 ?? 8B 00 50 8B 45 ?? 8B 00 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? }
        $vmp2_pattern2 = { 9C 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 8B 7E ?? }
        $vmp2_pattern3 = { 55 8B EC 83 EC ?? 53 56 57 E8 ?? ?? ?? ?? 8B 75 ?? 8B 7D ?? }
        $vmp2_pattern4 = { 68 ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 }

        // VMProtect 2.x virtualization opcodes
        $vmp2_vm1 = { 0F B6 ?? 8A ?? 32 ?? 88 ?? 40 3B ?? 72 ?? }
        $vmp2_vm2 = { 8B ?? 83 ?? ?? 8B ?? 33 ?? 89 ?? }

        // Section names
        $vmp2_section1 = ".vmp0" ascii
        $vmp2_section2 = ".vmp1" ascii
        $vmp2_section3 = ".vmp2" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($vmp2_pattern*) or
            all of ($vmp2_vm*) or
            2 of ($vmp2_section*)
        )
}

// ============================================================================
// VMProtect 3.x Detection
// ============================================================================

rule VMProtect_3x_Signature
{
    meta:
        description = "Detects VMProtect 3.x protected executables"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // VMProtect 3.x specific patterns
        $vmp3_pattern1 = { 48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 57 41 56 41 57 48 83 EC ?? }
        $vmp3_pattern2 = { E8 00 00 00 00 58 48 83 C0 ?? 48 89 44 24 ?? }
        $vmp3_pattern3 = { 48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 44 24 ?? FF 10 }
        $vmp3_pattern4 = { 40 53 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 48 8B C8 }

        // VMProtect 3.x VM handler patterns
        $vmp3_vm1 = { 48 8B ?? 48 83 ?? ?? 0F B6 ?? 48 8B ?? 0F B6 ?? }
        $vmp3_vm2 = { 48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 }

        // Section names (VMProtect 3.x uses numbered sections)
        $vmp3_section1 = ".00" ascii
        $vmp3_section2 = ".01" ascii
        $vmp3_section3 = ".02" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($vmp3_pattern*) or
            any of ($vmp3_vm*) or
            2 of ($vmp3_section*)
        )
}

// ============================================================================
// VMProtect 3.5+ Detection (Latest versions)
// ============================================================================

rule VMProtect_35_Plus
{
    meta:
        description = "Detects VMProtect 3.5+ protected executables"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // VMProtect 3.5+ patterns with improved obfuscation
        $vmp35_pattern1 = { 48 89 4C 24 ?? 48 83 EC ?? 48 8B 44 24 ?? 48 8B 00 FF D0 }
        $vmp35_pattern2 = { E8 00 00 00 00 48 8B 04 24 48 83 C4 08 48 83 C0 ?? }
        $vmp35_pattern3 = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF D0 }

        // Advanced VM patterns
        $vmp35_vm1 = { 4C 8B ?? 49 83 ?? ?? 41 0F B6 ?? 4C 8B ?? }
        $vmp35_vm2 = { 48 8B 44 24 ?? 48 83 C0 ?? 48 89 44 24 ?? }

        // Import table encryption marker
        $vmp35_import = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? }

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($vmp35_pattern*) or
            any of ($vmp35_vm*) or
            $vmp35_import
        )
}

// ============================================================================
// Themida 1.x Detection
// ============================================================================

rule Themida_1x_Signature
{
    meta:
        description = "Detects Themida 1.x protected executables"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // Themida 1.x entry point patterns
        $themida1_ep1 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 }
        $themida1_ep2 = { 8B C0 60 0B C0 74 68 E8 00 00 00 00 }
        $themida1_ep3 = { B8 ?? ?? ?? ?? 60 0B C0 74 ?? E8 00 00 00 00 58 05 ?? 00 00 00 }

        // Characteristic strings
        $themida_string1 = "Themida" ascii wide
        $themida_string2 = "Oreans" ascii wide
        $themida_string3 = "SecureEngine" ascii wide

        // Section names
        $themida_section1 = ".themida" ascii
        $themida_section2 = ".oreans" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($themida1_ep*) or
            any of ($themida_string*) or
            any of ($themida_section*)
        )
}

// ============================================================================
// Themida 2.x Detection
// ============================================================================

rule Themida_2x_Signature
{
    meta:
        description = "Detects Themida 2.x protected executables"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // Themida 2.x patterns
        $themida2_pattern1 = { EB 00 EB ?? B8 ?? ?? ?? ?? EB ?? EB ?? 60 EB ?? EB ?? 0B C0 }
        $themida2_pattern2 = { 8B C0 EB 01 ?? 60 EB 01 ?? 0B C0 EB 01 ?? 74 }
        $themida2_pattern3 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 }
        $themida2_pattern4 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 68 }

        // Virtual machine patterns
        $themida2_vm1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? EB }
        $themida2_vm2 = { 50 53 51 52 56 57 55 E8 ?? ?? ?? ?? 8B D4 }

        // Macro detection
        $themida2_macro1 = "PROTECTED_WITH_THEMIDA" ascii wide
        $themida2_macro2 = "SecureEngineSDK" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($themida2_pattern*) or
            any of ($themida2_vm*) or
            any of ($themida2_macro*)
        )
}

// ============================================================================
// Themida 3.x Detection
// ============================================================================

rule Themida_3x_Signature
{
    meta:
        description = "Detects Themida 3.x protected executables (64-bit)"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // Themida 3.x 64-bit patterns
        $themida3_pattern1 = { 48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 48 89 78 ?? 41 56 }
        $themida3_pattern2 = { E8 00 00 00 00 48 8B 0C 24 48 83 C4 08 }
        $themida3_pattern3 = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 50 C3 }
        $themida3_pattern4 = { 40 53 48 83 EC ?? 48 8B D9 FF 15 ?? ?? ?? ?? }

        // Themida 3.x VM handlers
        $themida3_vm1 = { 4C 8B DC 49 89 5B ?? 49 89 6B ?? 49 89 73 ?? 57 48 83 EC }
        $themida3_vm2 = { 48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ?? }

        // Anti-debugging patterns
        $themida3_antidb1 = { 65 48 8B 04 25 60 00 00 00 48 8B 40 18 }
        $themida3_antidb2 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? FF 15 }

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and // PE signature
        uint16(uint32(0x3C)+0x18) == 0x020B and // PE32+ (64-bit)
        (
            2 of ($themida3_pattern*) or
            any of ($themida3_vm*) or
            any of ($themida3_antidb*)
        )
}

// ============================================================================
// WinLicense Detection (Themida variant)
// ============================================================================

rule WinLicense_Signature
{
    meta:
        description = "Detects WinLicense protected executables"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // WinLicense specific strings
        $winlic_string1 = "WinLicense" ascii wide
        $winlic_string2 = "SmartTrialController" ascii wide
        $winlic_string3 = "TrialExtensionDLL" ascii wide

        // WinLicense patterns
        $winlic_pattern1 = { B8 ?? ?? ?? ?? 60 0B C0 74 ?? E8 00 00 00 00 58 05 ?? 00 00 00 }
        $winlic_pattern2 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? EB ?? 8D 85 }

        // Registry keys
        $winlic_reg1 = "Software\\Oreans\\WinLicense" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($winlic_string*) or
            any of ($winlic_pattern*) or
            $winlic_reg1
        )
}

// ============================================================================
// Generic Oreans Technologies Products
// ============================================================================

rule Oreans_Generic
{
    meta:
        description = "Generic detection for Oreans products (Themida/WinLicense/Code Virtualizer)"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // Common Oreans strings
        $oreans1 = "Oreans Technologies" ascii wide
        $oreans2 = "www.oreans.com" ascii wide
        $oreans3 = "SecureEngine" ascii wide

        // Common patterns
        $oreans_pattern1 = { B8 ?? ?? ?? ?? 60 0B C0 }
        $oreans_pattern2 = { E8 00 00 00 00 5? 81 }

        // Encrypted import table marker
        $oreans_import = { 00 00 00 00 00 00 00 00 FF 15 }

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($oreans*) or
            all of ($oreans_pattern*)
        )
}

// ============================================================================
// Code Virtualizer Detection
// ============================================================================

rule CodeVirtualizer_Signature
{
    meta:
        description = "Detects Code Virtualizer by Oreans"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // Code Virtualizer patterns
        $cv_pattern1 = { 55 8B EC 83 C4 ?? 53 56 57 EB ?? E8 ?? ?? ?? ?? }
        $cv_pattern2 = { E8 00 00 00 00 58 83 C0 ?? 50 C3 }

        // VM opcode patterns
        $cv_vm1 = { 8A ?? FE ?? 88 ?? 8A ?? FE ?? 88 ?? }
        $cv_vm2 = { 8B ?? 03 ?? C1 ?? ?? 33 ?? 89 ?? }

        // Characteristic string
        $cv_string = "Code Virtualizer" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($cv_pattern*) or
            all of ($cv_vm*) or
            $cv_string
        )
}

// ============================================================================
// VMProtect Hybrid Detection (All versions)
// ============================================================================

rule VMProtect_Hybrid_Detection
{
    meta:
        description = "Hybrid detection for any VMProtect version"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // Common section patterns
        $vmp_sec1 = ".vmp" ascii
        $vmp_sec2 = ".00" ascii
        $vmp_sec3 = ".01" ascii

        // Common VM patterns
        $vmp_vm1 = { 0F B6 ?? 8A ?? 32 ?? 88 ?? }
        $vmp_vm2 = { 8B ?? 83 ?? ?? 8B ?? 33 ?? }
        $vmp_vm3 = { 48 8B ?? 48 83 ?? ?? 0F B6 }

        // Pushad/Popad patterns
        $vmp_push = { 60 E8 00 00 00 00 }
        $vmp_pop = { 61 E9 ?? ?? ?? ?? }

        // Import table encryption
        $vmp_iat1 = { 68 ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 CB }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            any of ($vmp_sec*) or
            2 of ($vmp_vm*) or
            ($vmp_push and $vmp_pop) or
            $vmp_iat1
        ) and
        // High entropy in code sections (typical for packers)
        math.entropy(0, filesize) > 7.0
}

// ============================================================================
// Themida Hybrid Detection (All versions)
// ============================================================================

rule Themida_Hybrid_Detection
{
    meta:
        description = "Hybrid detection for any Themida version"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        // Common strings
        $themida1 = "Themida" ascii wide nocase
        $themida2 = "Oreans" ascii wide nocase
        $themida3 = "SecureEngine" ascii wide nocase

        // Common patterns across versions
        $themida_ep1 = { B8 ?? ?? ?? ?? 60 0B C0 74 }
        $themida_ep2 = { EB 00 EB ?? B8 ?? ?? ?? ?? }

        // VM patterns
        $themida_vm1 = { 60 E8 00 00 00 00 5? 81 }
        $themida_vm2 = { 50 53 51 52 56 57 55 E8 }

        // Anti-debug patterns
        $themida_adb1 = { 65 ?? 8B ?? 25 }
        $themida_adb2 = { 64 A1 30 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            any of ($themida*) or
            any of ($themida_ep*) or
            2 of ($themida_vm*) or
            all of ($themida_adb*)
        ) and
        math.entropy(0, filesize) > 6.5
}

// ============================================================================
// Advanced Detection: Packed DLL with Suspicious Characteristics
// ============================================================================

rule Suspicious_Packed_DLL
{
    meta:
        description = "Detects DLLs with packer characteristics (VMP/Themida/Generic)"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    condition:
        uint16(0) == 0x5A4D and // MZ header
        uint32(uint32(0x3C)) == 0x00004550 and // PE signature
        // Check if it's a DLL
        (uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000 and
        (
            // High entropy
            math.entropy(0, filesize) > 7.0 or
            // Abnormal number of sections
            uint16(uint32(0x3C)+0x06) > 8 or
            // Suspicious section names
            for any i in (0..pe.number_of_sections-1): (
                pe.sections[i].name contains ".vmp" or
                pe.sections[i].name contains ".themida" or
                pe.sections[i].name matches /^\.\d\d$/ or
                pe.sections[i].name == ".00"
            ) or
            // No visible imports
            pe.number_of_imports == 0 or
            // Executable stack
            for any i in (0..pe.number_of_sections-1): (
                (pe.sections[i].characteristics & 0x20000000) and // EXECUTE
                (pe.sections[i].characteristics & 0x40000000) // WRITE
            )
        )
}

// ============================================================================
// VMProtect Import Protection Detection
// ============================================================================

rule VMProtect_Import_Protection
{
    meta:
        description = "Detects VMProtect import protection mechanism"
        author = "Multiple Sources"
        date = "2024"
        version = "1.0"

    strings:
        $import_stub1 = { 68 ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 CB }
        $import_stub2 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        $import_stub3 = { FF 15 ?? ?? ?? ?? 8B ?? 89 ?? }

    condition:
        uint16(0) == 0x5A4D and
        2 of them and
        (pe.number_of_imports == 0 or pe.number_of_imports < 5)
}