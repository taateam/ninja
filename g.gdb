add-symbol-file msvcrt.dll 0x141818000
add-symbol-file winapp.exe 0x140001000
add-symbol-file ntdll.dll 0x140024000
add-symbol-file ninja.dll 0x1403e0000
add-symbol-file KERNEL32.dll 0x141026000
add-symbol-file kernelbase.dll 0x1411e7000
break *5368714256
break *0x1403e39f2
/*
0x140000000
0x140023000
0x1403df000
0x141025000
0x1411e6000
0x141817000

add-symbol-file msvcrt.dll 0x141817000
add-symbol-file winapp.exe 0x140000000
add-symbol-file ntdll.dll 0x140023000
add-symbol-file ninja.dll 0x1403df000
add-symbol-file KERNEL32.dll 0x141025000
add-symbol-file kernelbase.dll 0x1411e6000

add-symbol-file msvcrt.dll 0x141818000
add-symbol-file winapp.exe 0x140001000
add-symbol-file ntdll.dll 0x140024000
add-symbol-file ninja.dll 0x1403e0000
add-symbol-file KERNEL32.dll 0x141026000
add-symbol-file kernelbase.dll 0x1411e7000

-exec add-symbol-file msvcrt.dll 0x141818000
-exec add-symbol-file winapp.exe 0x140001000
-exec add-symbol-file ntdll.dll 0x140024000
-exec add-symbol-file ninja.dll 0x1403e0000
-exec add-symbol-file KERNEL32.dll 0x141026000
-exec add-symbol-file kernelbase.dll 0x1411e7000
*/