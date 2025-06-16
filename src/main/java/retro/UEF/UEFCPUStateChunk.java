package retro.UEF;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class UEFCPUStateChunk {
	public int PC, Cycles;
	public byte A, X, Y, S, PSR, IntStatus, NMIStatus, NMILock; 

	public UEFCPUStateChunk(byte[] data) throws IOException {
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(data), true);
		
		PC = reader.readNextShort();
		A  = reader.readNextByte();
		X  = reader.readNextByte();
		Y  = reader.readNextByte();
		S  = reader.readNextByte();
		PSR= reader.readNextByte();
		Cycles = reader.readNextInt();
		IntStatus = reader.readNextByte();
		NMIStatus = reader.readNextByte();
		NMILock = reader.readNextByte();
	}
}
