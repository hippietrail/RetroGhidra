package retro.UEF;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class UEFHeader implements StructConverter {
	public String magic;
	public byte minor;
	public byte major;
	
    private static final String BBC_UEF_MAGIC = "UEF File!";
	
	public UEFHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(10);
		
		if (!magic.equals(BBC_UEF_MAGIC)) {
			throw new UnknownError("Unknown file format: " + magic);
		}
		minor = reader.readNextByte();
		major = reader.readNextByte();
	}
	
	public DataType toDataType() {
		Structure struct = new StructureDataType("UEFHeader_t", 0);
		struct.add(STRING, 10, "magic", null);
		struct.add(BYTE, 1, "minor", null);
		struct.add(BYTE, 1, "major", null);
		
		return struct;
	}
}
