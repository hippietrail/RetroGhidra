package retro.UEF;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class UEFChunk implements StructConverter {
	public int chunk_id;
	public int chunk_length;
	public byte []data;
	
	public UEFChunk(BinaryReader reader) throws IOException {
		chunk_id = reader.readNextShort();
		chunk_length = reader.readNextInt();
		
		data = reader.readNextByteArray(chunk_length);
	}
	
	public DataType toDataType() {
		Structure struct = new StructureDataType("UEFChunkHeader_t", 0);
		struct.add(WORD, 2, "chunk_id", null);
		struct.add(DWORD, 4, "chunk_length", null);
		struct.add(BYTE, data.length, "chunk_data", null);
		
		return struct;
	}
}

