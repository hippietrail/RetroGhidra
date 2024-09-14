package retro;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;

public class Ti994LoaderHelper {

	static void appendComment(Listing listing, Address addr, int type, String newComment) {
		String maybeOldComment = listing.getComment(type, addr);
		String oldComment = maybeOldComment == null ? "" : maybeOldComment + "\n";
		listing.setComment(addr, type, oldComment + newComment);
	}

	static void commentCode(Program program, Address addr, ByteProvider provider, int startIndex) throws CodeUnitInsertionException, IOException {
		Listing listing = program.getListing();
		Address a = addr;

        BinaryReader reader = new BinaryReader(provider, false);

		reader.setPointerIndex(startIndex);
        final int first = reader.readNextUnsignedShort() & 0xffff;
		final int second = reader.readNextUnsignedShort() & 0xffff;
		final int third = reader.readNextUnsignedShort() & 0xffff;

        // BASIC (Texas Instruments)
		if ((first ^ second) == third) {
            appendComment(listing, a, CodeUnit.PRE_COMMENT, "XOR: BASIC (Texas Instruments)");
			listing.createData(a, UnsignedShortDataType.dataType);
			listing.setComment(a, CodeUnit.EOL_COMMENT, "check flag");
			listing.createData(a.add(2), UnsignedShortDataType.dataType);
			listing.createData(a.add(4), UnsignedShortDataType.dataType);
			listing.setComment(a.add(4), CodeUnit.EOL_COMMENT, "BASIC (Texas Instruments)");
			listing.setComment(a.add(4), CodeUnit.POST_COMMENT, " ");
        }

        // MEMORY IMAGE E/A MODULE (Texas Instruments)
		else if (first == 0xffff) {
            // can also be 0x0000 but that is the first word for a few formats
            appendComment(listing, a, CodeUnit.PRE_COMMENT, "ffff: MEMORY IMAGE E/A MODULE (Texas Instruments)");
            listing.createData(a, UnsignedShortDataType.dataType);
            listing.setComment(a, CodeUnit.EOL_COMMENT, "more files will follow");
            listing.createData(a.add(2), UnsignedShortDataType.dataType);
            listing.setComment(a.add(2), CodeUnit.EOL_COMMENT, "total length of file (header + data)");
            listing.createData(a.add(4), UnsignedShortDataType.dataType);
            listing.setComment(a.add(4), CodeUnit.EOL_COMMENT, "load address (for the first file also the start address)");
            listing.setComment(a.add(4), CodeUnit.POST_COMMENT, " ");
        }

        else if ((first & 0xff00) == 0xaa00)
            commentStandardHeader(program, a, reader, startIndex);
    }
    
    // "Standard header"
    // https://forums.atariage.com/topic/159642-assembly-guidance/
    // https://www.unige.ch/medecine/nouspikel/ti99/headers.htm
    static void commentStandardHeader(Program program, Address addr, BinaryReader reader, int startIndex) throws CodeUnitInsertionException, IOException {
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
        listing.createData(addr.add(12), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(12), CodeUnit.EOL_COMMENT, "Pointer to ISR list"); // interrupt service routine
        listing.createData(addr.add(14), UnsignedShortDataType.dataType);
        listing.setComment(addr.add(14), CodeUnit.EOL_COMMENT, "Next menu item");

        // look at the first program. later we'll look at the following programs and the other lists
        // BinaryReader reader = new BinaryReader(provider, false); // big-endian
        final int pointerToProgList = reader.readUnsignedShort(startIndex + 6);
        if (pointerToProgList != 0) {
            Address firstProg = program.getAddressFactory().getDefaultAddressSpace().getAddress(pointerToProgList);
            listing.createData(firstProg, UnsignedShortDataType.dataType);
            listing.setComment(firstProg, CodeUnit.PRE_COMMENT, " ");
            listing.setComment(firstProg, CodeUnit.EOL_COMMENT, "Next program");
            listing.createData(firstProg.add(2), UnsignedShortDataType.dataType);
            listing.setComment(firstProg.add(2), CodeUnit.EOL_COMMENT, "Program address");
            listing.createData(firstProg.add(4), PascalString255DataType.dataType);
            listing.setComment(firstProg.add(4), CodeUnit.EOL_COMMENT, "Program name");
        }
    }
}
