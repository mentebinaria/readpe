workspace "readpe"
    configurations { "Static", "Debug", "Release" }

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

	filter "Static"
		kind "StaticLib"
		staticruntime "On"
		flags { "OmitDefaultLibrary" }
		syslibdirs { "/home/gogo/src/git.musl-libc.org/musl/lib" }
		links { "c:static", "m:static", "crypto:static" }

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
	cdialect "gnu11"
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


    warnings "Extra"

    filter { "system:linux" }
        links { "m" }

	filter "configurations:Static"
		staticruntime "On"
		flags { "OmitDefaultLibrary" }
		syslibdirs { "/home/gogo/src/git.musl-libc.org/musl/lib" }
		links { "pe", "udis86", "c:static", "m:static", "crypto:static", "rt:static", "util:static", "dl:static", "resolv:static", "pthread:static" }
		defines {
			"CFLAGS=\"-no-pie -static -static-libgcc\"",
			"LDFLAGS=\"-Wl,-Bstatic -static-libgcc\""
		}
		-- -no-pie -static 

    filter "configurations:Debug"
    	links { "pe", "udis86", "crypto" }
    	flags { "LinkTimeOptimization" }
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
    	links { "pe", "udis86", "crypto" }
    	flags { "LinkTimeOptimization" }
        defines { "NDEBUG" }
        optimize "Full"

-- Function to create single C file plugin
function create_simple_plugin(name)
	project("plugin_" .. name) 
	kind "SharedLib"
    language "C"
    location "lib/libpe"
    includedirs { "include" }
    targetdir "build/%{cfg.buildcfg}/plugins"
	files { "src/plugins/" .. name .. ".c" }

	filter "Static"
		kind "StaticLib"
	
	filter "Debug"
		kind "SharedLib"
	
	filter "Release"
		kind "SharedLib"
end

create_simple_plugin "csv"
create_simple_plugin "html"
create_simple_plugin "json"
create_simple_plugin "text"
create_simple_plugin "xml"

