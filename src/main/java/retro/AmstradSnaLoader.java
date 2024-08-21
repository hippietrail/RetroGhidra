/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package retro;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Amstrad CPC Snapshot (SNA) files.
 */
public class AmstradSnaLoader extends AbstractProgramWrapperLoader {

	public static final String AMS_SNA_NAME = "Amstrad CPC Snapshot (SNA)";
	public static final int AMS_SNA_HEADER_LEN = 0x100;
	public static final long AMS_SNA_LENGTH_64K = AMS_SNA_HEADER_LEN + 64 * 1024;
	public static final long AMS_SNA_LENGTH_128K = AMS_SNA_HEADER_LEN + 1288 * 1024;
	public static final Long[] AMS_SNA_LENGTHS = {
		AMS_SNA_LENGTH_64K,
		AMS_SNA_LENGTH_128K,
	};
	public static final String AMS_SNA_MAGIC = "MV - SNA";
    public static final int AMS_SNA_OFF_VERSION = 0x10;
	public static final int AMS_SNA_OFF_SP = 0x21; // 16-bit
	public static final int AMS_SNA_OFF_PC = 0x23; // 16-bit
    public static final int AMS_SNA_OFF_CURR_RAM_CONFIG = 0x41;
	public static final int AMS_SNA_OFF_DUMP_SIZE = 0x6b; // 16-bit
	public static final int AMS_SNA_OFF_CPC_TYPE = 0x6d;
	public static final String[] AMS_SNA_CPC_TYPES = {
		"CPC 464", "CPC 664", "CPC 6128"
	};

	@Override
	public String getName() {
		return AMS_SNA_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		final long fileLength = reader.length();
        if (fileLength < AMS_SNA_HEADER_LEN) return loadSpecs;

		String magic = reader.readNextAsciiString(AMS_SNA_MAGIC.length());
		if (!magic.equals(AMS_SNA_MAGIC)) return loadSpecs;

        // prior to version 3, only two file lengths were possible
        // v3 introduced a variable number of optional 'chunks' at the end
        final int version = reader.readUnsignedByte(AMS_SNA_OFF_VERSION) & 0xff;
        if (version < 3 && !Arrays.stream(AMS_SNA_LENGTHS).anyMatch(length -> length.equals(fileLength))) return loadSpecs;

		final int sp = reader.readUnsignedShort(AMS_SNA_OFF_SP);
		final int pc = reader.readUnsignedShort(AMS_SNA_OFF_PC);
        final int currRamConfig = reader.readUnsignedByte(AMS_SNA_OFF_CURR_RAM_CONFIG) & 0xff;
		final int dumpSize = reader.readUnsignedShort(AMS_SNA_OFF_DUMP_SIZE); // in kb: 64 or 128
		final int cpcType = reader.readUnsignedByte(AMS_SNA_OFF_CPC_TYPE) & 0xff;

		Msg.info(this, "CPC: SNA version " + version
            + ", SP: 0x" + Integer.toHexString(sp)
			+ ", PC: 0x" + Integer.toHexString(pc)
            + ", RAM config: 0x" + Integer.toHexString(currRamConfig)
			+ ", dump size: 0x" + Integer.toHexString(dumpSize)
			+ " (" + dumpSize
			+ " bytes), CPC type: " + cpcType
			+ " (" + AMS_SNA_CPC_TYPES[cpcType] + ")");

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		BinaryReader reader = new BinaryReader(provider, true);

		final int sp = reader.readUnsignedShort(AMS_SNA_OFF_SP);
		final int pc = reader.readUnsignedShort(AMS_SNA_OFF_PC);
		final int dumpSize = reader.readUnsignedShort(AMS_SNA_OFF_DUMP_SIZE);
		final int cpcType = reader.readUnsignedByte(AMS_SNA_OFF_CPC_TYPE);

		// I don't know how the paging works, or the mapping from the snapshot's memory dump to physical RAM
		// the CPC has 64k of RAM so there must be paging of ROM and/or RAM even ignoring 128k snapshots for now

        // in version 3 the dump size can be 0, indicating MEM chunks will follow instead

		// let's try if it's a 64k snapshot
        if (dumpSize == 0) {
            Msg.info(this, "MEM chunks are not supported so far.");
            return;
        }
		if (dumpSize != 64) {
			Msg.info(this, "128k snapshots are not supported so far.");
			return;
		}

		// so load the 64k after the header until the end into address 0x0000
		final int start = 0x0000;
		Address startAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(start);
		Address spAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(sp);
		Address pcAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(pc);
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		SymbolTable st = program.getSymbolTable();

		try {
			program.getMemory().createInitializedBlock(
				"SNAPSHOT_64K",
				startAddress,
				fileBytes,
				AMS_SNA_HEADER_LEN,
				AMS_SNA_LENGTH_64K - AMS_SNA_HEADER_LEN,
				false
			);
			// TODO setWrite or not?

			st.createLabel(pcAddress, "entry", SourceType.IMPORTED);
			st.createLabel(spAddress, "stack", SourceType.IMPORTED);
			st.addExternalEntryPoint(pcAddress);

		} catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
