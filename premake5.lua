workspace "readpe"
    configurations { "Debug", "Release" }

project "pe"
    language "C"
    location "lib/libpe"
    includedirs { "lib/libpe/include" }
    targetdir "build/%{cfg.buildcfg}"
    files { "lib/libpe/**.h", "lib/libpe/**.c" }
    defines {
        "_GNU_SOURCE",
    }
    links { "crypto" }

    filter { "system:linux" }
        links { "m" }

    filter "Debug"
        kind "StaticLib"

    filter "Release"
        kind "SharedLib"

project "udis86"
    kind "StaticLib"
    location "lib/libudis86/libudis86"
    targetdir "build/%{cfg.buildcfg}"
    files { "lib/libudis86/libudis86/*.h", "lib/libudis86/libudis86/*.c" }
    defines { "HAVE_STRING_H=1" }

-- TODO: ZIP Packing
project "readpe"
    kind "ConsoleApp"
    language "C"
    location "src"
    includedirs { "include", "lib/libpe/include", "lib" }
    targetdir "build/%{cfg.buildcfg}"

    files { "src/*.h", "src/*.c", "src/compat/*.c" }
    -- removefiles { "src/ofs2rva.c", "src/pedis.c", "src/pehash.c", "src/pepack.c", "src/peres.c", "src/pescan.c", "src/pesec.c", "src/readpe.c", "src/rva2ofs.c" }

    defines {
        "_GNU_SOURCE",
        "SHAREDIR=\"\"",
        "PLUGINSDIR=\"pev/plugins\""
    }

    links { "pe", "udis86", "crypto" }

    warnings "Extra"
    flags { "LinkTimeOptimization" }

    filter { "system:linux" }
        links { "m" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        enablewarnings {
            "pedantic",
            "shadow",
            "undef",
            "double-promotion",
            "format=2",
            "format-security",
            "conversion"
        }
        symbols "On"

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
