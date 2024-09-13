Ghidra Loaders and FileSystems for various retrocomputing platforms.

# Done
- Apple II Binary II archive loader - only first binary is loaded
- Apple II NAPS (NuLib2 Attribute Preservation String) loader
- Atari 2600 .a26/.bin cartridge file loader - only 2K and 4K are possible
- Atari 8-bit .XEX file loader
- Atari ST executable format loader
- Classic 680x0 Mac application loader
- Commodore 64 .CRT cartridge loader - loads straightforward cartridges
- Commodore VIC-20 .PRG cartridge loader - not other types of .PRG
- Exidy Sorcerer .SNP snapshot loader
- RISC OS AIF (Arm Image Format) loader
- Sharp X68000 .X executable format loader
- Sinclair QL executable format loader
- Sinclair ZX Spectrum .SNA snapshot loader - 48K snapshots
- Tandy TRS-80 Model I/III /CMD command file loader
- Tandy TRS-80 Color Computer .CCC cartridge loader - 2K, 4K, and 8K

# In progress
- Amstrad CPC .SNA snapshot format - some 64K snapshots might be usable
- Commodore Amiga: "Hunk" executable and object file loader - identifies but does not load yet
- CP/M .CMD command file loader
- Sharp X68000 .Z executable format - identifies but does not load yet
- Sinclair QL Zip file system that handles the QDOS headers in zip extra fields
- TI 99/4A .bin file formats
- TI-99/4A FIAD (V9T9) file format
- TI-99/4A .rpk cartridge format
- TI-99/4A TIFILES (XMODEM) file loader

# Planned
## Loaders
- Sharp X68000: .R executable format
- Sinclair QL: SROFF object file format
- Sinclair ZX Spectrum: .SNA snapshot format - 128K variant
- Sinclair ZX Spectrum: More snapshot and emulator formats

## FileSystems
- Apple II Binary II archives
- Apple II .do and .po disk image formats
- Commodore 64 disk image format
- Sinclair Spectrum: .DSK +3DOS disk image format
- Sinclair Spectrum: .SCL disk format
- Sinclair Spectrum: .TRD Beta Disk TR-DOS disk iamge format
- Tandy Coco disk formats
- Tandy TRS-80 Model I/III: .DMK disk image format
- Tandy TRS-80 Model I/III: .JV1 disk image format
- Tandy TRS-80 Model I/III: .JV3 disk image format

# To investigate
- Acorn: UEF (Unified Emulator Format) for BBC Micro and Electron
- Apple IIgs
- Apple Lisa
- Atari 8-bit cartridge, disk, and tape formats
- BeOS (Ghidra natively supports PEF)
- Commodore PET
- Dragon 32/64
- Jupiter Ace
- NeXT
- Oric
- MSX
- RISC OS AOF (ARM Object Format) and ALF (Acorn Library Format)
- SAM Coupé
- Sinclair ZX81
- Tandy Coco: .cas tape images
- Thomson MO, TO
- Timex Sinclair