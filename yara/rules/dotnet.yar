/*
    File: yara/rules/dotnet.yar
    Description: YARA rules for detecting .NET obfuscators and protectors.
    Author: Multiple Authors (compiled by HUTAOSHUSBAND)
*/

import "pe"

rule ConfuserEx {
    meta:
        description = "Detects ConfuserEx obfuscated binaries"
        author = "HUTAOSHUSBAND"
    strings:
        $s1 = "ConfuserEx v" ascii
        $s2 = "Confuser.Core" ascii
        $a1 = "ConfusedByAttribute" ascii
    condition:
        any of them
}

rule Dotfuscator {
    meta:
        description = "Detects Dotfuscator obfuscated binaries"
        author = "Jean-Philippe Teissier / @Jipe_"
    strings:
        $a = "Obfuscated with Dotfuscator" ascii
        $b = "DotfuscatorAttribute" ascii
    condition:
        any of them
}

rule Eazfuscator {
    meta:
        description = "Detects Eazfuscator.NET obfuscated binaries"
        author = "HUTAOSHUSBAND"
    strings:
        $s1 = "Eazfuscator.NET" ascii
        $a1 = "Zupholos" ascii
    condition:
        any of them
}

rule SmartAssembly {
    meta:
        description = "Detects SmartAssembly obfuscated binaries"
        author = "HUTAOSHUSBAND"
    strings:
        $s1 = "SmartAssembly" ascii
        $s2 = "Powered by SmartAssembly" ascii
        $a1 = "SmartAssembly.Attributes" ascii
    condition:
        any of them
}

rule KoiVM {
    meta:
        description = "Detects KoiVM virtualization"
        author = "ditekShen"
    strings:
        $s1 = "KoiVM" ascii wide
    condition:
        any of them
}

rule NET_Reactor {
    meta:
        description = "Detects .NET Reactor obfuscated binaries"
        author = "eSentire TI"
    strings:
        $s1 = {37 39 31 37 32 42 31 33 2d 45 44 42 41 2d 34 30 39 36 2d 42 37 32 35 2d 38 45 39 32 42 37 33 30 42 32 42 41}
        $s2 = "Eziriz" ascii
        $s3 = "Created with .NET Reactor" ascii
    condition:
        any of them
}

rule Babel_NET {
    meta:
        description = "Detects Babel .NET obfuscated binaries"
        author = "HUTAOSHUSBAND"
    strings:
        $s1 = "Babel Obfuscator" ascii
        $s2 = "Babel.Licensing" ascii
    condition:
        any of them
}
