package retro;

import java.io.IOException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

public class Ti994LoaderHelper {

    public static final int TIF_OFF_FILE_STATUS_FLAGS = 0x0a;
    public static final int FIAD_OFF_FILE_STATUS_FLAGS = 0x0c;
    //public static final int TIF_OFF_NUM_L3_RECS = 0x0e; // same for tifiles? 18 = 0x12

    public static final int FLAG_DATA_PROGRAM = 1 << 0;
    public static final int FLAG_DIS_INT = 1 << 1;
    public static final int FLAG_PROTECTED = 1 << 3;
    public static final int TIF_FLAG_MODIFIED = 1 << 4;
    public static final int TIF_FLAG_NORMAL_EMULATED = 1 << 5;
    public static final int FLAG_FIX_VAR = 1 << 7;

    public static final int FLAG_TYPE_MASK = FLAG_DATA_PROGRAM | FLAG_DIS_INT | FLAG_FIX_VAR;

	public static final int DIS_FIX = 0;
	public static final int DIS_VAR = FLAG_FIX_VAR;
	public static final int INT_FIX = FLAG_DIS_INT;
	public static final int INT_VAR = FLAG_DIS_INT | FLAG_FIX_VAR;
    private enum Field {
        FIAD_FILENAME(10),
        FIAD_EXTENDED_RECORD_LENGTH(2),
        FIAD_FILLER(108),
        TIFILES_FILLER(112),
        TIFILES_MAGIC(8),
        END_OF_FILE_OFFSET(1),
        FILE_STATUS_FLAGS(1),
        LOGICAL_RECORD_LENGTH(1),
        NUMBER_OF_LEVEL_3_RECORDS_ALLOCATED(2),
        NUMBER_OF_RECS_SEC(1),
        NUMBER_OF_SECTORS_CURRENTLY_ALLOCATED(2);

        private final int size;

        Field(int size) {
            this.size = size;
        }

        public int getSize() {
            return size;
        }
        @Override
        public String toString() {
            return Stream.of(name().split("_"))
                .map(s -> s.equalsIgnoreCase("tifiles") || s.equalsIgnoreCase("fiad") ? s.toUpperCase() : s.toLowerCase())
                .collect(Collectors.joining(" "));
        }
    }

    // public enum StatusFlagType {
    // 	PROGRAM(false, false),
    //     DIS_FIX(false, false),
    //     DIS_VAR(false, true),
    //     INT_FIX(true, false),
    //     INT_VAR(true, true);

    //     private final boolean program;
    //     // display vs internal, fixed vs variable size records. DISPLAY and FIXED are the defaults (0)
    //     private final boolean internal;
    //     private final boolean variable;

    //     StatusFlagType(boolean program, boolean internal, boolean variable) {
    //         // if program is true, internal and variable are not used so setting them to true is invalid
    //         // if program is false, all combinations of internal and variable are valid
    //         if (program && (internal || variable)) {
    //             throw new IllegalArgumentException("Invalid combination of program, internal, and variable flags");
    //         }
    //         this.program = program;
    //         this.internal = internal; // true = internal, false = display
    //         this.variable = variable; // true = variable, false = fixed
    //     }

    //     public boolean isProgram() {
    //         return program;
    //     }
    //     public boolean isDisplay() {
    //         return !internal;
    //     }
    //     public boolean isInternal() {
    //         return internal;
    //     }
    //     public boolean isFixed() {
    //         return !variable;
    //     }
    //     public boolean isVariable() {
    //         return variable;
    //     }
    // }

    static void commentFiadOrTifilesHeader(Field[] fields, Program program, Address headerAddress, Address loadAddress, ByteProvider provider) throws Exception {
        BinaryReader reader = new BinaryReader(provider, false); // big-endian BUT little-endian needed for NUMBER OF LEVEL 3 RECORDS ALLOCATED
        Listing listing = program.getListing();
        Address ha = headerAddress;

        String statusFlagType = null;
        String statusFlagExtra = null;
        String logicalRecordLength = null;

        int numberOfSectorsCurrentlyAllocated = -1;
        int endOfFileOffset = -1;

        for (Field field : fields) {
            final int size = field.getSize();

            if (size == 1) {
                listing.createData(ha, ByteDataType.dataType);
            } else if (size == 2) {
                listing.createData(ha, UnsignedShortDataType.dataType);
            } else {
                switch (field) {
                    case FIAD_FILENAME:
                        listing.createData(ha, new StringDataType(), 10);
                        break;
                    case TIFILES_MAGIC:
                        listing.createData(ha, new PascalString255DataType());
                        break;
                    case FIAD_FILLER:
                    case TIFILES_FILLER:
                        listing.createData(ha, new ArrayDataType(ByteDataType.dataType, size));
                        break;
                    default:
                        Msg.info(Ti994LoaderHelper.class, "Unknown field. Field: " + field);
                        break;
                }
            }
            String comment = field.toString();
            switch (field) {
            case FILE_STATUS_FLAGS:
            	int sf = reader.readByte(ha.getOffset()) & 0xff;
                Map.Entry<String, String> typePair = parseStatusFlags(sf);
                statusFlagType = typePair.getKey();
                statusFlagExtra = typePair.getValue();
                comment += "\nType: " + statusFlagType;
                if (!statusFlagExtra.isEmpty()) {
                    comment += " (" + statusFlagExtra + ")";
                }
                break;
            case LOGICAL_RECORD_LENGTH:
                int lrl = reader.readByte(ha.getOffset()) & 0xff;
                logicalRecordLength = String.valueOf(lrl);
                break;
            case NUMBER_OF_SECTORS_CURRENTLY_ALLOCATED:
                numberOfSectorsCurrentlyAllocated = reader.readShort(ha.getOffset()) & 0xffff;
                break;
            case END_OF_FILE_OFFSET:
                endOfFileOffset = reader.readByte(ha.getOffset()) & 0xff;
                // EOF offset comes after num sectors in both FIAD and TIFILES
                if (numberOfSectorsCurrentlyAllocated != -1 && endOfFileOffset != -1) {
                    if (numberOfSectorsCurrentlyAllocated > 0) {
                        int trueFileLength = endOfFileOffset == 0
                            ? numberOfSectorsCurrentlyAllocated * 256
                            : ((numberOfSectorsCurrentlyAllocated - 1) * 256) + endOfFileOffset;
                        comment += "\nLength: 0x" + Integer.toHexString(trueFileLength)
                            + ", OFffset: 0x" + Long.toHexString(loadAddress.getOffset() + trueFileLength);
                    } else {
                        Msg.info(Ti994LoaderHelper.class, "True file length cannot be calculated because number of sectors currently allocated is " + numberOfSectorsCurrentlyAllocated);
                    }
                }
                break;
            case NUMBER_OF_LEVEL_3_RECORDS_ALLOCATED:
                int numL3 = (reader.readByte(ha.getOffset() + 1) << 8) | reader.readByte(ha.getOffset());
                if (numL3 > 0) comment += " (" + numL3 + ")";
                break;
            }
            listing.setComment(ha, CodeUnit.EOL_COMMENT, comment);
            ha = ha.add(size);
        }

        if (ha.compareTo(headerAddress.add(128)) != 0) {
            throw new Exception("Header not 128 bytes long. Delta: " + ha.subtract(headerAddress));
        }

        if (statusFlagType != null) {
            String comment = statusFlagType;
            if (statusFlagType.substring(4, 7).equals("FIX")) {
                if (logicalRecordLength != null) {
                    comment += " " + logicalRecordLength;
                } else {
                    comment += " ???";
                }
            }
            appendComment(listing, headerAddress, CodeUnit.PRE_COMMENT, comment);
		}
    }
    
    static Map.Entry<String, String> parseStatusFlags(int flags) {
        String typeString = "";
        String extraComment = "";
        final int type = flags & FLAG_TYPE_MASK;
        switch (type) {
            case FLAG_DATA_PROGRAM:
                typeString += "PROGRAM";
                break;
            case DIS_FIX:
                typeString += "DIS/FIX";
                break;
            case DIS_VAR:
                typeString += "DIS/VAR";
                break;
            case INT_FIX:
                typeString += "INT/FIX";
                break;
            case INT_VAR:
                typeString += "INT/VAR";
                break;
            default:
                typeString += "???"; // PROG + DIS/INT/FIX/VAR set = invalid as far as I know
        }
        List<String> protModNormEmu = new ArrayList<String>();
        if ((flags & FLAG_PROTECTED) != 0) protModNormEmu.add("protected");
        if ((flags & TIF_FLAG_MODIFIED) != 0) protModNormEmu.add("modified");
        if ((flags & TIF_FLAG_NORMAL_EMULATED) != 0) protModNormEmu.add("emulated");
        if (!protModNormEmu.isEmpty()) {
            extraComment = String.join(", ", protModNormEmu);
        }
        return new AbstractMap.SimpleEntry<>(typeString, extraComment);
    }

    // FDR, FIAD (V9T9), and TIFILES (XMODEM) headers are described here: https://hexbus.com/ti99geek/

    static void commentFiadHeader(Program program, Address headerAddress, Address loadAddress, ByteProvider provider) throws Exception {
    	commentFiadOrTifilesHeader(new Field[] {
            Field.FIAD_FILENAME,
            Field.FIAD_EXTENDED_RECORD_LENGTH,
            Field.FILE_STATUS_FLAGS,
            Field.NUMBER_OF_RECS_SEC,
            Field.NUMBER_OF_SECTORS_CURRENTLY_ALLOCATED,
            Field.END_OF_FILE_OFFSET,
            Field.LOGICAL_RECORD_LENGTH,
            Field.NUMBER_OF_LEVEL_3_RECORDS_ALLOCATED, // LE
            Field.FIAD_FILLER
        }, program, headerAddress, loadAddress, provider);
    }

    static void commentTiFilesHeader(Program program, Address headerAddress, Address loadAddress, ByteProvider provider) throws Exception {
    	commentFiadOrTifilesHeader(new Field[] {
            Field.TIFILES_MAGIC,
            Field.NUMBER_OF_SECTORS_CURRENTLY_ALLOCATED,
            Field.FILE_STATUS_FLAGS,
            Field.NUMBER_OF_RECS_SEC,
            Field.END_OF_FILE_OFFSET,
            Field.LOGICAL_RECORD_LENGTH,
            Field.NUMBER_OF_LEVEL_3_RECORDS_ALLOCATED, // LE
            Field.TIFILES_FILLER
        }, program, headerAddress, loadAddress, provider);
    }

    static void appendComment(Listing listing, Address addr, int type, String newComment) {
		String maybeOldComment = listing.getComment(type, addr);
		String oldComment = maybeOldComment == null ? "" : maybeOldComment + "\n";
		listing.setComment(addr, type, oldComment + newComment);
	}

	static void commentCode(Program program, Address addr, ByteProvider provider, int readerIndex, MessageLog log)
			throws CodeUnitInsertionException, IOException, MemoryAccessException {
		Listing listing = program.getListing();

        BinaryReader reader = new BinaryReader(provider, false);

        // The type of file is determined by looking at the first six to ten bytes

		reader.setPointerIndex(readerIndex);
        final int first = reader.readNextUnsignedShort() & 0xffff;
		final int second = reader.readNextUnsignedShort() & 0xffff;
		final int third = reader.readNextUnsignedShort() & 0xffff;

        // BASIC (Texas Instruments)
		if ((first ^ second) == third) {
            appendComment(listing, addr, CodeUnit.PRE_COMMENT, "XOR: BASIC (Texas Instruments)");
			listing.createData(addr, UnsignedShortDataType.dataType);
			listing.setComment(addr, CodeUnit.EOL_COMMENT, "check flag");
			listing.createData(addr.add(2), UnsignedShortDataType.dataType);
			listing.createData(addr.add(4), UnsignedShortDataType.dataType);
			listing.setComment(addr.add(4), CodeUnit.EOL_COMMENT, "BASIC (Texas Instruments)");
			listing.setComment(addr.add(4), CodeUnit.POST_COMMENT, " ");
        }

        // MEMORY IMAGE E/A MODULE (Texas Instruments)
		else if (first == 0xffff) {
            // can also be 0x0000 but that is the first word for a few formats
            appendComment(listing, addr, CodeUnit.PRE_COMMENT, "ffff: MEMORY IMAGE E/A MODULE (Texas Instruments)");
            listing.createData(addr, UnsignedShortDataType.dataType);
            listing.setComment(addr, CodeUnit.EOL_COMMENT, "more files will follow");
            listing.createData(addr.add(2), UnsignedShortDataType.dataType);
            listing.setComment(addr.add(2), CodeUnit.EOL_COMMENT, "total length of file (header + data)");
            listing.createData(addr.add(4), UnsignedShortDataType.dataType);
            listing.setComment(addr.add(4), CodeUnit.EOL_COMMENT, "load address (for the first file also the start address)");
            listing.setComment(addr.add(4), CodeUnit.POST_COMMENT, " ");
        }

        else if ((first & 0xff00) == 0xaa00)
            commentStandardHeader(program, addr, reader, readerIndex, log);
    }
    
    // "Standard header"
    // https://www.unige.ch/medecine/nouspikel/ti99/headers.htm
    // https://forums.atariage.com/topic/159642-assembly-guidance/
    static void commentStandardHeader(Program program, Address addr, BinaryReader reader, int readerIndex, MessageLog log)
    		throws CodeUnitInsertionException, IOException, MemoryAccessException {
        Listing listing = program.getListing();
        appendComment(listing, addr, CodeUnit.PRE_COMMENT, "AA: Standard header");
        listing.createData(addr, ByteDataType.dataType);
        listing.setComment(addr, CodeUnit.EOL_COMMENT, "Indicates a standard header");
        listing.createData(addr.add(1), ByteDataType.dataType);
        listing.setComment(addr.add(1), CodeUnit.EOL_COMMENT, "Version number");
        listing.createData(addr.add(2), ByteDataType.dataType);
        listing.setComment(addr.add(2), CodeUnit.EOL_COMMENT, "Number of programs (optional)");
        listing.createData(addr.add(3), ByteDataType.dataType);
        listing.setComment(addr.add(3), CodeUnit.EOL_COMMENT, "Not used");

        listing.createData(addr.add(4), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(4), CodeUnit.EOL_COMMENT, "Pointer to power-up list (can't use in cartridge ROM)");
        listing.createData(addr.add(6), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(6), CodeUnit.EOL_COMMENT, "Pointer to program list");
        listing.createData(addr.add(8), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(8), CodeUnit.EOL_COMMENT, "Pointer to DSR list"); // device service routine
        listing.createData(addr.add(10), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(10), CodeUnit.EOL_COMMENT, "Pointer to subprogram list");
        
        // TODO there can be another field in the standard header, Pointer to ISR list
        // TODO in cartridges this field does not exist and the program list can point to the area it would occupy

        // look at the first program. TODO look at the following programs and the other lists
        final int pointerToProgList = reader.readUnsignedShort(readerIndex + 6); // address >6006 = reader offset 6

        if (pointerToProgList != 0) {
            AddressSpace space = addr.getAddressSpace();
            Address firstProg = space.getAddress(pointerToProgList);

            // check if 'firstProg' is beyond the area we covered above in the createData/setComment calls
            // Standard Header is 12 bytes if it doesn not include an ISR list
            // Standard Header is 14 bytes if it includes an ISR list
            // Standard Header would be 16 bytes if the 'Next menu item' field is considered part of the Standard Header
            //   but this is probably an error and 'Next menu item' is part of each program entry in the program list
            final int STANDARD_HEADER_SIZE = 12;

            if (firstProg.compareTo(addr.add(STANDARD_HEADER_SIZE)) < 0) {
                Msg.error(Ti994LoaderHelper.class, "The 'First program' pointer points to a location within the header area we already covered.");
                Msg.error(Ti994LoaderHelper.class, " Area after defined header starts at 0x" + Integer.toHexString(pointerToProgList)
                    + ", first program pointer is 0x" + Long.toHexString(firstProg.getOffset()));
                return;
            }

            listing.createData(firstProg, UnsignedShortDataType.dataType);
            listing.setComment(firstProg, CodeUnit.PRE_COMMENT, " ");
            listing.setComment(firstProg, CodeUnit.EOL_COMMENT, "Next program");
            listing.createData(firstProg.add(2), UnsignedShortDataType.dataType);
            listing.setComment(firstProg.add(2), CodeUnit.EOL_COMMENT, "Program address");
            listing.createData(firstProg.add(4), PascalString255DataType.dataType);
            listing.setComment(firstProg.add(4), CodeUnit.EOL_COMMENT, "Program name");

            try {
                long programAddressOffset = firstProg.subtract(addr) + 2;
                int progAddr = reader.readUnsignedShort(readerIndex + programAddressOffset);
                Address programAddress = space.getAddress(progAddr);
	            
                SymbolTable st = program.getSymbolTable();
				st.createLabel(programAddress, "GPL_entry", SourceType.IMPORTED);
	            st.addExternalEntryPoint(programAddress);
    		} catch (Exception e) {
    			log.appendException(e);
    		}
            
            long nextProgramOffset = firstProg.subtract(addr); // the field before 'Program address'
            Msg.info(Ti994LoaderHelper.class, "Next program offset is 0x" + Long.toHexString(nextProgramOffset));
            // the next line gets 'Attempted to read bytes that were already read.' exception on some files
            // int nextProgAddr = reader.readUnsignedShort(readerIndex + nextProgramOffset);
            // Msg.info(Ti994LoaderHelper.class, "Next program address is 0x" + Integer.toHexString(nextProgAddr));
            // if (nextProgAddr != 0) {
            //     // TODO follow the 'Next program' pointers
            //     Msg.info(Ti994LoaderHelper.class, "Next program address is 0x" + Integer.toHexString(nextProgAddr));
            // } else {
            //     Msg.info(Ti994LoaderHelper.class, "No next program");
            // }
        }
    }

}
