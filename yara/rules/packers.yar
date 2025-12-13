
rule Themida_WinLicense {
    meta:
        description = "Themida/WinLicense Protector"
        author = "HUTAOSHUSBAND"
    strings:
        $sect1 = ".themida" wide ascii
        $sect2 = ".winlice" wide ascii
        $str1 = "Themida" wide ascii
        $str2 = "WinLicense" wide ascii
    condition:
        any of them
}

rule VMProtect {
    meta:
        description = "VMProtect"
        author = "HUTAOSHUSBAND"
    strings:
        $sect1 = ".vmp0" wide ascii
        $sect2 = ".vmp1" wide ascii
        $sect3 = ".vmp2" wide ascii
        $sect_vmp = ".vmp" wide ascii
    condition:
        any of them
}

rule Enigma_Protector {
    meta:
        description = "Enigma Protector"
        author = "HUTAOSHUSBAND"
    strings:
        $sect1 = ".enigma1" wide ascii
        $sect2 = ".enigma2" wide ascii
        $sect_enigma = ".enigma" wide ascii
    condition:
        any of them
}

rule UPX {
    meta:
        description = "UPX Packer"
        author = "HUTAOSHUSBAND"
    strings:
        $sect1 = "UPX0" wide ascii
        $sect2 = "UPX1" wide ascii
        $sig = "UPX!" wide ascii
    condition:
        all of ($sect*) or $sig
}

rule MPress {
    meta:
        description = "MPRESS Packer"
        author = "HUTAOSHUSBAND"
    strings:
        $sect1 = ".MPRESS1" wide ascii
        $sect2 = ".MPRESS2" wide ascii
    condition:
        any of them
}
