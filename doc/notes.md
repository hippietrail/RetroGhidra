# Program file formats

## Commodore 8-bit

- `.PRG` is used for BASIC and machine code. The first two bytes are the load address. For BASIC programs, this address varies by system:
  - PET: `$0401` but varies if memory is expanded
  - VIC-20: `$0401`
  - Commodore 64: `$0801`
  - Commodore 128: `$1C01`

  .PRG seems to also be used for at least VIC-20 cartridges. 

# Disk Image FileSystems

## Apple II

- `.do` - DOS 3 but not always, also `.dsk`  
  No header, no format, sector dump but in various orders
- `.po` - ProDOS, but not always, also `.dsk`  
  No header, no format, sector dump but in various orders

## TRS-80

- `.DMK`, also `.DSK` for TRS-80 model 1/3, Tandy Coco, Dragon 32, MSX
- `.JV1`, also `.DSK`
  No header, no format, sector dump
- `.JV3`, also `.DSK`
  Has a header and a format, but no magic word

## ZX Spectrum

- `.DSK` for +3DOS for Spectrum +3 but based on format for Amstrad and CP/M
  Has a format with a header and magic word
  
  - DSK Magic: `MV - CPC` (8 bytes) (often but not always followed by `EMU Disk-File\r\nDisk-Info\r\n`, 26 bytes)  
  - EDSK Magic: `EXTENDED` (8 bytes) (often but not always followed by ` CPC DSK File\r\nDisk-Info\r\n`, 26 bytes)

- `.MGT`, also `.IMG` for DISCiPLE and +D
  No header, no format, sector dump

- `.SCL`
  Has a format with a header and magic word, a filesystem/directory/catalog images rather than a disk image
  Magic: `SINCLAIR` (8 bytes)

- `.TRD`
  No header, no format, sector dump
  
      Each sector is 256 bytes, each track contains 16 sectors.

      Tracks are arranged in the same order as "logical tracks" in TR-DOS: 0th track on 0th side, 0th track on 1st side, 1st track on 0th side, 1st track on 1st side, …
      
      If remaining sectors at the end of floppy are unused, the TRD file can be less than actual floppy size
