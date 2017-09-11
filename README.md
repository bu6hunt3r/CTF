# CTF

## r2 exploitation cheatsheet

### Gathering info

| cmd 			| aim 					|
------------------------|--------------------------------------:|
|ii [q]			|Imports				|
|?v sym.imp.fuc_name	|Get address of fubc_name@PLT		|
|?v reloc.func_name	|Get address of fubc_name@GOT		|
|ie [q]			|Get address of entry point		|
|iS			|Show sections with perms		|
|i~canary		|Check canaries				|
|i~nx			|Check NX bit				|
|i~pic			|Check if Position Independent Code     |


### Memory
| cmd 				| aim 					|
--------------------------------|--------------------------------------:|
|dm				|Show memory maps			|
|dmm				|List modules				|
|dmi [addr|libname] [symname]	|List symbols of target lib		|


### Searching
| cmd 				| aim 					|
--------------------------------|--------------------------------------:|
|e search.*			|Config search commands (i.e dmg.maps 	|
|/?				|Search strig in memory			|
|/R [?]				|Search for ROP gadgets			|
|/R/ [?]			|Search for ROP gadgets with regexp	|A



### Debugging
| cmd 				| aim 					|
--------------------------------|--------------------------------------:|
|dc 				|Continue execution			|
|dcu addr			|Continue execution until address	|
|dcr				|Continue execution until ret		|
|dbt				|Display backtrace			|
|doo [args			|Reopen in debugger mode		|
|ds				|Step one instruction			|
|dso				|Step over				|


### Visual Modes
| cmd 				| aim 								|
--------------------------------|--------------------------------------------------------------:|
|pdf @ addr			|Print assembly of function at given offset			|
|V				|Visual mode, use p/P to toggle between different modes 	|
|VV				|Visual Graph mode, navigating through ASCII graph		|
|V!				|Visual panels mode. Very useful for exploitation		|

