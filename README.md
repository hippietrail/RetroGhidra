# RetroGhidra

<img src="https://github.com/user-attachments/assets/4b48b672-e1a0-43c1-b6f1-b45808ab8224" width="256">

[Ghidra](https://github.com/NationalSecurityAgency/ghidra) Loaders, FileSystems, and Processors for various retrocomputing platforms.

# Done
## Loaders
- Apple II NAPS (NuLib2 Attribute Preservation String) loader
- Apple Lisa object file loader
- Atari 2600 .a26/.bin cartridge file loader - only 2K and 4K are possible
- Atari 8-bit .XEX file loader
- Atari ST executable file loader
- Classic 680x0 Mac application loader
- Commodore 64 .CRT cartridge loader - loads straightforward cartridges
- Commodore VIC-20 .PRG cartridge loader - not other types of .PRG
- Exidy Sorcerer .SNP snapshot loader
- RISC OS AIF (Arm Image Format) loader
- Sharp X68000 .X executable file loader
- Sinclair QL executable file loader
- Sinclair ZX Spectrum .SNA snapshot loader - 48K snapshots
- Tandy TRS-80 Model I/III /CMD command file loader
- Tandy TRS-80 Color Computer .CCC cartridge loader - 2K, 4K, and 8K
- TI 99/4A .bin file loader
- TI-99/4A FIAD (V9T9) file loader
- TI-99/4A .rpk cartridge loader
- TI-99/4A TIFILES (XMODEM) file loader

## FileSystems
- Apple II Binary II file system

# In progress
## Loaders
- Amstrad CPC .SNA snapshot format loader - some 64K snapshots might be usable
- Commodore 64 X00 format (P00, R00, S00, U00, etc)
- Commodore Amiga: "Hunk" executable and object file loader - identifies but does not load yet
- CP/M .CMD command file loader
- Sharp X68000 .Z executable format - identifies but does not load yet
- Sinclair QL Zip file system that handles the QDOS headers in zip extra fields
- Sinclair ZX Spectrum PZX tape image loader - identifies but does not load yet
- Sinclair ZX Spectrum TAP tape image loader - identifies but does not load yet
- Sinclair ZX Spectrum TZX tape image loader - identifies but does not load yet
- TI-99/4A .ctg cartridge format - identifies but does not load yet
- TK2000/Microprofessor II: .ct2 tape format - identifies but does not load yet

## Processors
- TI-99/4A GPL bytecode disassembler

## Ghidra features
- [Submitted a PR](https://github.com/NationalSecurityAgency/ghidra/pull/7062) allowing FileSystems to pass filetype info to the filesystem browser, which works on filename extensions by default.

# Planned
## Loaders
- Sharp X68000: .R executable format
- Sinclair QL: SROFF object file format
- Sinclair ZX Spectrum: .SNA snapshot format - 128K variant
- Sinclair ZX Spectrum: More snapshot and emulator formats

## FileSystems
- Apple II .do and .po disk image formats
- Commodore 64 disk image format
- Sinclair Spectrum: .DSK +3DOS disk image format
- Sinclair Spectrum: .SCL disk format
- Sinclair Spectrum: .TRD Beta Disk TR-DOS disk iamge format
- Tandy Coco disk formats
- Tandy TRS-80 Model I/III: .DMK disk image format
- Tandy TRS-80 Model I/III: .JV1 disk image format
- Tandy TRS-80 Model I/III: .JV3 disk image format
- TI-99/4A: .ark Archiver format

# To investigate
- Acorn: UEF (Unified Emulator Format) for BBC Micro and Electron
- Apple IIgs
- Apple Newton
- Atari 8-bit cartridge, disk, and tape formats
- Atari ST DRI object and/or library file format
- Atari ST GST object and/or library file format
- BeOS (Ghidra natively supports PEF)
- Commodore PET
- CP/M .REL file loader
- CP/M .SPR file loader
- CP/M Plus and MP/M .PRL relocatable binary file loader
- Dragon 32/64
- Jupiter Ace
- Neo Geo
- NeXT
- Oric
- Palm Pilot
- Philips CD-i
- MSX
- OS-9/68000
- Panasonic 3DO
- RISC OS AOF (ARM Object Format) and ALF (Acorn Library Format)
- SAM Coupé
- Sinclair ZX81
- Tandy Coco: .cas tape images
- Thomson MO, TO
- TI-89, TI-92
- Timex Sinclair
- Xerox Alto, Star
