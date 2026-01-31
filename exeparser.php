#!/bin/php
<?php
/* =========================
 * PE32+ (x64) IMPORT PARSER
 * ========================= */

if ($argc < 2) {
    echo "Usage: php exeparser.php <file.exe>\n";
    exit(1);
}

$buf = file_get_contents($argv[1]);
if ($buf === false) {
    echo "Cannot read file\n";
    exit(1);
}

$size = strlen($buf);

/* -------------------------
 * DOS HEADER
 * ------------------------- */
if (substr($buf, 0, 2) !== "MZ") {
    die("Not a PE (no MZ)\n");
}

$e_lfanew = unpack("V", substr($buf, 0x3C, 4))[1];
if ($e_lfanew <= 0 || $e_lfanew + 4 > $size) {
    die("Invalid e_lfanew\n");
}

/* -------------------------
 * NT HEADER
 * ------------------------- */
if (substr($buf, $e_lfanew, 4) !== "PE\0\0") {
    die("Invalid NT header\n");
}

echo "Valid PE: NT header found at 0x" . dechex($e_lfanew) . "\n";

/* -------------------------
 * FILE HEADER
 * ------------------------- */
$fileHdr = unpack(
    "vMachine/" .
        "vNumberOfSections/" .
        "VTimeDateStamp/" .
        "VPointerToSymbolTable/" .
        "VNumberOfSymbols/" .
        "vSizeOfOptionalHeader/" .
        "vCharacteristics",
    substr($buf, $e_lfanew + 4, 20)
);

/* -------------------------
 * OPTIONAL HEADER (PE32+)
 * ------------------------- */
$opt_off = $e_lfanew + 0x18;
$magic = unpack("v", substr($buf, $opt_off, 2))[1];
if ($magic !== 0x20b) {
    die("Not PE32+ (x64)\n");
}

$optional = unpack(
    "vMagic/" .
        "CMajorLinkerVersion/" .
        "CMinorLinkerVersion/" .
        "VSizeOfCode/" .
        "VSizeOfInitializedData/" .
        "VSizeOfUninitializedData/" .
        "VAddressOfEntryPoint/" .
        "VBaseOfCode/" .
        "QImageBase/" .
        "VSectionAlignment/" .
        "VFileAlignment/" .
        "vMajorOSVersion/" .
        "vMinorOSVersion/" .
        "vMajorImageVersion/" .
        "vMinorImageVersion/" .
        "vMajorSubsystemVersion/" .
        "vMinorSubsystemVersion/" .
        "VWin32VersionValue/" .
        "VSizeOfImage/" .
        "VSizeOfHeaders/" .
        "VCheckSum/" .
        "vSubsystem/" .
        "vDllCharacteristics/" .
        "QSizeOfStackReserve/" .
        "QSizeOfStackCommit/" .
        "QSizeOfHeapReserve/" .
        "QSizeOfHeapCommit/" .
        "VLoaderFlags/" .
        "VNumberOfRvaAndSizes",
    substr($buf, $opt_off, 0x70)
);

printf("ImageBase:        0x%X\n", $optional['ImageBase']);
printf("EntryPoint RVA:   0x%X\n", $optional['AddressOfEntryPoint']);
printf("SectionAlign:     0x%X\n", $optional['SectionAlignment']);
printf("FileAlign:        0x%X\n", $optional['FileAlignment']);
printf("SizeOfImage:      0x%X\n", $optional['SizeOfImage']);
printf("Subsystem:        0x%X\n", $optional['Subsystem']);

/* -------------------------
 * DATA DIRECTORIES
 * ------------------------- */
$dirs = [];
$dir_off = $opt_off + 0x70;

for ($i = 0; $i < 16; $i++) {
    $dirs[$i] = unpack(
        "VRVA/VSize",
        substr($buf, $dir_off + $i * 8, 8)
    );
}

/* -------------------------
 * SECTION TABLE
 * ------------------------- */
$sec_off = $e_lfanew + 0x18 + $fileHdr['SizeOfOptionalHeader'];
$sections = [];

for ($i = 0; $i < $fileHdr['NumberOfSections']; $i++) {
    $s = unpack(
        "a8Name/" .
            "VVirtualSize/" .
            "VVirtualAddress/" .
            "VSizeOfRawData/" .
            "VPointerToRawData/" .
            "VPointerToRelocations/" .
            "VPointerToLinenumbers/" .
            "vNumberOfRelocations/" .
            "vNumberOfLinenumbers/" .
            "VCharacteristics",
        substr($buf, $sec_off + $i * 40, 40)
    );
    $sections[] = $s;
}

/* -------------------------
 * RVA -> FILE OFFSET
 * ------------------------- */
function rva_to_offset($rva, $sections)
{
    foreach ($sections as $s) {
        $va   = $s['VirtualAddress'];
        $size = max($s['VirtualSize'], $s['SizeOfRawData']);
        if ($rva >= $va && $rva < $va + $size) {
            return $s['PointerToRawData'] + ($rva - $va);
        }
    }
    return null;
}

/* -------------------------
 * IMPORT TABLE
 * ------------------------- */
for ($o = 0; $o < 1; $o++) {
    $import = $dirs[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
    if ($import['RVA'] == 0) {
        echo "No imports\n";
        break;
    }

    $imp_off = rva_to_offset($import['RVA'], $sections);
    echo "\n=== IMPORT TABLE ===\n";

    while (true) {
        $desc = unpack(
            "VOriginalFirstThunk/" .
                "VTimeDateStamp/" .
                "VForwarderChain/" .
                "VName/" .
                "VFirstThunk",
            substr($buf, $imp_off, 20)
        );

        if (
            $desc['OriginalFirstThunk'] == 0 &&
            $desc['Name'] == 0 &&
            $desc['FirstThunk'] == 0
        )
            break;

        /* DLL name */
        $name_off = rva_to_offset($desc['Name'], $sections);
        $dll = "";
        for ($i = $name_off; $buf[$i] !== "\0"; $i++)
            $dll .= $buf[$i];

        echo "\n[$dll]\n";

        /* thunk table */
        $thunk_rva = $desc['OriginalFirstThunk'] ?: $desc['FirstThunk'];
        $thunk_off = rva_to_offset($thunk_rva, $sections);

        while (true) {
            $q = unpack("Q", substr($buf, $thunk_off, 8))[1];
            if ($q == 0) break;

            if ($q & 0x8000000000000000) {
                $ord = $q & 0xFFFF;
                echo "  Ordinal: $ord\n";
            } else {
                $hna_off = rva_to_offset($q, $sections);
                $hint = unpack("v", substr($buf, $hna_off, 2))[1];

                $fn = "";
                for ($i = $hna_off + 2; $buf[$i] !== "\0"; $i++)
                    $fn .= $buf[$i];

                echo "  $fn (hint $hint)\n";
            }

            $thunk_off += 8;
        }

        $imp_off += 20;
    }
}
/* -------------------------
 * EXPORT TABLE
 * ------------------------- */
for ($o = 0; $o < 1; $o++) {
    $export = $dirs[0]; // IMAGE_DIRECTORY_ENTRY_EXPORT

    if ($export['RVA'] == 0) {
        echo "\nNo exports\n";
        break;
    }

    $exp_off = rva_to_offset($export['RVA'], $sections);

    $exp = unpack(
        "VCharacteristics/" .
            "VTimeDateStamp/" .
            "vMajorVersion/" .
            "vMinorVersion/" .
            "VName/" .
            "VBase/" .
            "VNumberOfFunctions/" .
            "VNumberOfNames/" .
            "VAddressOfFunctions/" .     // RVA array
            "VAddressOfNames/" .         // RVA array
            "VAddressOfNameOrdinals",    // RVA array
        substr($buf, $exp_off, 40)
    );

    /* DLL name */
    $name_off = rva_to_offset($exp['Name'], $sections);
    $dllname = "";
    for ($i = $name_off; $buf[$i] !== "\0"; $i++)
        $dllname .= $buf[$i];

    echo "\n=== EXPORT TABLE ===\n";
    echo "DLL Name: $dllname\n";
    echo "Functions: {$exp['NumberOfFunctions']}\n";
    echo "Named exports: {$exp['NumberOfNames']}\n\n";

    /* Tables */
    $func_table = rva_to_offset($exp['AddressOfFunctions'], $sections);
    $name_table = rva_to_offset($exp['AddressOfNames'], $sections);
    $ord_table  = rva_to_offset($exp['AddressOfNameOrdinals'], $sections);

    /* Iterate named exports */
    for ($i = 0; $i < $exp['NumberOfNames']; $i++) {

        $name_rva = unpack("V", substr($buf, $name_table + $i * 4, 4))[1];
        $name_off = rva_to_offset($name_rva, $sections);

        $fname = "";
        for ($j = $name_off; $buf[$j] !== "\0"; $j++)
            $fname .= $buf[$j];

        $ord_index = unpack("v", substr($buf, $ord_table + $i * 2, 2))[1];
        $ordinal = $exp['Base'] + $ord_index;

        $func_rva = unpack("V", substr($buf, $func_table + $ord_index * 4, 4))[1];

        printf(
            "%4d  RVA 0x%08X  %s\n",
            $ordinal,
            $func_rva,
            $fname
        );
    }
}
