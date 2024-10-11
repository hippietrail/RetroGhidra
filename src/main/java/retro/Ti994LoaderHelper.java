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
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import retro.Ti994BinLoader;

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
    
    // for FIAD and TIFILES headers, both based on FDR
    public enum HeaderField {
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

        HeaderField(int size) {
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

    /*
     * // public enum StatusFlagType {
    // 	PROGRAM(false, false),
    //     DIS_FIX(false, false),
    //     DIS_VAR(false, true),
    //     INT_FIX(true, false),
    //     INT_VAR(true, true);
    //
    //     private final boolean program;
    //     // display vs internal, fixed vs variable size records. DISPLAY and FIXED are the defaults (0)
    //     private final boolean internal;
    //     private final boolean variable;
    //
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
    //
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
    */
    static final Map<String, String> PROCESSOR_NAMES = Map.of(
        "9900", "TMS 9900 CPU",
        "GPL", "TI-99/4A GPL"
    );
    
    static void addLoadSpecs(AbstractProgramWrapperLoader loader, LanguageService languageService, List<LoadSpec> loadSpecs) {
        addLoadSpecsExt(loader, languageService, loadSpecs, new String[] { "9900", "GPL" });
    }

    static void addLoadSpecsExt(AbstractProgramWrapperLoader loader, LanguageService languageService, List<LoadSpec> loadSpecs, String[] processorIds) {
        for (String processorId : processorIds) {
            String name = PROCESSOR_NAMES.get(processorId);
            if (name == null) {
                Msg.error(loader, "Unknown processor ID: " + processorId);
            } else {
                LanguageCompilerSpecPair lcsp = new LanguageCompilerSpecPair(processorId + ":BE:16:default", "default");

                LanguageID languageID = lcsp.getLanguageID();

                try {
                    languageService.getLanguageDescription(languageID);
                    loadSpecs.add(new LoadSpec(loader, 0, lcsp, true));
                } catch (Exception e) {
                    Msg.warn(loader, name + " support not found. Find the extension on GitHub.");
                }
            }
        }
    }

    static boolean isGramKrackerHeader(int first, int second, int third) {
        // first: first byte is MF, second byte is Type
        // second: length; third: address
        final int mf = (first >> 8) & 0xff;
        final int type = first & 0xff;
        final int length = second;
        final int address = third;

        // MF can only be 0x00, 0x80, or 0xFF - no more files, load UTIL file next, more files to load
        // Type can only be 0x01 to 0x0a or 0x00 or 0xff:
		// >01 to >08 = GROM >0000 to >E000
		// >09, >0A = ROM1, ROM2 >6000
		// >00, >FF = RAM expansion
        final boolean validMf = mf == 0x00 || mf == 0x80 || mf == 0xff;
        final boolean validType = (type >= 0x01 && type <= 0x0a) || type == 0x00 || type == 0xff;
        final boolean isGramKrackerHeader = validMf && validType && length > 0 && address > 0;
        Msg.info(Ti994BinLoader.class, "Checking for GRAM Kracker header");
        Msg.info(Ti994BinLoader.class, "MF: 0x" + Integer.toHexString(mf));
        Msg.info(Ti994BinLoader.class, "Type: 0x" + Integer.toHexString(type));
        Msg.info(Ti994BinLoader.class, "Length: 0x" + Integer.toHexString(length));
        Msg.info(Ti994BinLoader.class, "Address: 0x" + Integer.toHexString(address));
        Msg.info(Ti994BinLoader.class, "isGramKrackerHeader: " + isGramKrackerHeader);
        // the length field does not include the 6-byte header
        // the file may be longer than this field but my test file is padded with zeroes from that point
        // the file cannot be shorter than this field (taking into account the size of the header)
        // the address here is not related to the address in the standard header. my test files has A000 here but 6000 in the standard header
        return isGramKrackerHeader;
    }
    
    static void commentFiadOrTifilesHeader(HeaderField[] fields, Program program, Address headerAddress, Address loadAddress, ByteProvider provider) throws Exception {
        BinaryReader reader = new BinaryReader(provider, false); // big-endian BUT little-endian needed for NUMBER OF LEVEL 3 RECORDS ALLOCATED
        Listing listing = program.getListing();
        Address ha = headerAddress;

        String statusFlagType = null;
        String statusFlagExtra = null;
        String logicalRecordLength = null;

        int numberOfSectorsCurrentlyAllocated = -1;
        int endOfFileOffset = -1;

        for (HeaderField field : fields) {
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
                        Msg.error(Ti994LoaderHelper.class, "Unknown field. Field: " + field);
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

    static void appendComment(Listing listing, Address addr, int type, String newComment) {
		String maybeOldComment = listing.getComment(type, addr);
		String oldComment = maybeOldComment == null ? "" : maybeOldComment + "\n";
		listing.setComment(addr, type, oldComment + newComment);
	}

	static void loadAndComment(Program program, Address addr, ByteProvider provider, long startOffset, MessageLog log)
			throws CodeUnitInsertionException, IOException {
		// Listing listing = program.getListing();

        BinaryReader reader = new BinaryReader(provider, false);

        // The type of file is determined by looking at the first six to ten bytes

		reader.setPointerIndex(startOffset);
        int first = reader.readNextUnsignedShort() & 0xffff;
		int second = reader.readNextUnsignedShort() & 0xffff;
		int third = reader.readNextUnsignedShort() & 0xffff;

        // BASIC (Texas Instruments)
		if ((first ^ second) == third) {
            handleTiBasic(program, addr, reader, third, log);
            return;
        }

        // MEMORY IMAGE E/A MODULE (Texas Instruments)
		else if (first == 0xffff) {
            handleEaModule(program, addr, reader, third, log);
            return;
        }

        // if there was a Gram Kracker header, we already skipped it

        if ((first & 0xff00) == 0xaa00)
            loadAndCommentStandardHeader(program, addr, reader, startOffset, log);
    }

    // "Standard header"
    // https://www.unige.ch/medecine/nouspikel/ti99/headers.htm
    // https://forums.atariage.com/topic/159642-assembly-guidance/
    static void loadAndCommentStandardHeader(Program program, Address addr, BinaryReader reader, long readerIndex, MessageLog log)
    		throws CodeUnitInsertionException, IOException {
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

        // TODO this documentation is inconsistent: https://www.unige.ch/medecine/nouspikel/ti99/headers.htm
        // summary says
        // >x006	Pointer to program list (>0000 if none)
        // >x008	Pointer the DSR list (>0000 if none)
        // >x00A	Pointer to subprogram list (>0000 if none)
        // but example says
        // >4006: >0000        Ptr to program list (none)
        // >4008: >4018        Ptr to subprogram list
        // >400A: >4030        Ptr to DSR list
        // PDF of official manual: http://ftp.whtech.com/datasheets%20and%20manuals/Specifications/gpl_programmers_guide-OCRed.pdf
        //
        // TABLE H.1
        // GROM HEADER
        // LOCATION SIZE            CONTENTS
        //     X000 byte            >AA valid identification
        //     X001 byte            version number
        //     X002 byte            number of program
        //     X003 byte            reserved
        //     X004 word (2 bytes)  address of first power up routine header
        //     X006 word            address of first user program header
        //     X008 word            address of first DSR header
        //     X00A word            address of first subroutine link header
        //     X00C word            address of first interrupt link
        //     X00E word            address of first. BASIC subprogram libraries

        listing.createData(addr.add(4), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(4), CodeUnit.EOL_COMMENT, "Pointer to power-up list (can't use in cartridge ROM)");
        listing.createData(addr.add(6), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(6), CodeUnit.EOL_COMMENT, "Pointer to program list");
        listing.createData(addr.add(8), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(8), CodeUnit.EOL_COMMENT, "Pointer to DSR list (or subprogram list?)");
        listing.createData(addr.add(10), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(10), CodeUnit.EOL_COMMENT, "Pointer to subprogram list (or DSR list?)");
        
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

    static void handleTiBasic(Program program, Address addr, BinaryReader reader, int readerIndex, MessageLog log) throws CodeUnitInsertionException {
        Listing listing = program.getListing();

        appendComment(listing, addr, CodeUnit.PRE_COMMENT, "XOR: BASIC (Texas Instruments)");
        listing.createData(addr, UnsignedShortDataType.dataType);
        listing.setComment(addr, CodeUnit.EOL_COMMENT, "check flag");
        listing.createData(addr.add(2), UnsignedShortDataType.dataType);
        listing.createData(addr.add(4), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(4), CodeUnit.EOL_COMMENT, "BASIC (Texas Instruments)");
        listing.setComment(addr.add(4), CodeUnit.POST_COMMENT, " ");
    }

    static void handleEaModule(Program program, Address addr, BinaryReader reader, int readerIndex, MessageLog log) throws CodeUnitInsertionException, AddressOutOfBoundsException {
        Listing listing = program.getListing();
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
    
}
