// UEF class - handles a UEF files

package retro.UEF;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;

public class UEF {
	public UEFHeader header;
	public ArrayList<UEFChunk> chunks;
	public UEFCPUStateChunk cpustate;
	public byte[] ram;
	public byte[] rom;
	
	private static final int UEF_CPU_CHUNK = 0x0460;
	private static final int UEF_RAM_CHUNK = 0x0462;
	private static final int UEF_ROM_CHUNK = 0x0464;

	public UEF(BinaryReader reader) throws IOException {
		header = new UEFHeader(reader);
		
		readAllChunks(reader);
		
		// Look for state chunks
		for (UEFChunk chunk : chunks) {
			if (chunk.chunk_id == UEF_CPU_CHUNK) {
				// This is a BeebEm CPU State chunk, we only care about PC as an entry point
				cpustate = new UEFCPUStateChunk(chunk.data);
			}
			if (chunk.chunk_id == UEF_RAM_CHUNK) {
				// This is a BeebEm Memory chunk, we'll use this to make the RAM memory area
				ram = Arrays.copyOf(chunk.data, chunk.data.length);
			}
			if (chunk.chunk_id == UEF_ROM_CHUNK) {
				// This is a BeebEm privileged memory chunk, we'll use this for ROM
				rom = Arrays.copyOf(chunk.data, chunk.data.length);
			}
		}
	}
	
	public ArrayList<UEFChunk> readAllChunks(BinaryReader reader) throws IOException {
		chunks = new ArrayList<UEFChunk>();
		
		while (reader.getPointerIndex() < reader.length()) {
			UEFChunk chunk = new UEFChunk(reader);
			chunks.add(chunk);
		}
		
		return chunks;
	}
}
