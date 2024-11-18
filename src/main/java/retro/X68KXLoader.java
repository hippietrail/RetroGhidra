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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Sharp X68000 .X files.
 */
public class X68KXLoader extends AbstractProgramWrapperLoader {

	public static final String XX_NAME = "Sharp X68000 .X";
	
	public static final int XX_OFF_BASE_ADDR = 0x04;
	public static final int XX_OFF_RUN_ADDR = 0x08;
	public static final int XX_OFF_TEXT_SIZE = 0x0C;
	public static final int XX_OFF_DATA_SIZE = 0x10;
	public static final int XX_OFF_BLOCK_SIZE = 0x14; // Block storage section size (Contains .comm .stack)
	public static final int XX_OFF_REALLOC_SIZE = 0x18;
	public static final int XX_OFF_SYMTAB_SIZE = 0x1C;
	public static final int XX_OFF_SCD_LINE_NO_TAB_SIZE = 0x20;
	public static final int XX_OFF_SCD_SYMTAB_SIZE = 0x24;
	public static final int XX_OFF_SCD_STR_TAB_SIZE = 0x28;
	// 16 bytes reserved 0x2c
	// Position from bound module list top-of-file 0x3c
	public static final int XX_HEADER_LEN = 0x40;

	public static final int XX_MAGIC_NORMAL = 0x48550000; // HU\0\0
	public static final int XX_MAGIC_SMALLEST = 0x48550001; // HU\0\1
	public static final int XX_MAGIC_HIGH = 0x48550002; // HU\0\2

	@Override
	public String getName() {
		return XX_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < XX_HEADER_LEN) return loadSpecs;

		BinaryReader reader = new BinaryReader(provider, false);

        long magic = reader.readUnsignedInt(0);
		if (magic != XX_MAGIC_NORMAL && magic != XX_MAGIC_SMALLEST && magic != XX_MAGIC_HIGH) return loadSpecs; 

		List<QueryResult> queryResults = QueryOpinionService.query(getName(), "68000", null);
		queryResults.stream().map(result -> new LoadSpec(this, 0, result)).forEach(loadSpecs::add);

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		Memory memory = program.getMemory();
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AddressSpace addresssSpace = program.getAddressFactory().getDefaultAddressSpace();
		BinaryReader reader = new BinaryReader(provider, false);

		try {
			Address headerAddress = AddressSpace.OTHER_SPACE.getAddress(0x0000);

			memory.createInitializedBlock(
				"HEADER",
				headerAddress,
				fileBytes,
				0,
				XX_HEADER_LEN,
				false);

			commentHeader(program, headerAddress);

			Address baseAddress = addresssSpace.getAddress(reader.readUnsignedInt(XX_OFF_BASE_ADDR));
			Address runAddress = addresssSpace.getAddress(reader.readUnsignedInt(XX_OFF_RUN_ADDR));
			Address dataAddress = baseAddress.add(reader.readUnsignedInt(XX_OFF_TEXT_SIZE));

			final long textSize = reader.readUnsignedInt(XX_OFF_TEXT_SIZE);
			final long dataSize = reader.readUnsignedInt(XX_OFF_DATA_SIZE);
			
			memory.createInitializedBlock(
				"TEXT",
				baseAddress,
				fileBytes,
				XX_HEADER_LEN,
				textSize,
				false
			);

			SymbolTable st = program.getSymbolTable();
			st.createLabel(runAddress, "entry", SourceType.ANALYSIS);
			st.addExternalEntryPoint(runAddress);

			memory.createInitializedBlock(
				"DATA",
				dataAddress,
				fileBytes,
				XX_HEADER_LEN + textSize,
				dataSize,
				false
			);

			memory.createInitializedBlock(
				"REST",
				dataAddress.add(dataSize),
				fileBytes,
				XX_HEADER_LEN + textSize + dataSize,
				reader.length() - XX_HEADER_LEN - textSize - dataSize,
				false
			);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
	void commentHeader(Program program, Address headerAddress) throws CodeUnitInsertionException {
		Listing listing = program.getListing();
		Address ha = headerAddress;
		listing.createData(ha, new StringDataType(), 2);
		listing.setComment(ha, CodeUnit.EOL_COMMENT, "magic");
		ha = ha.add(2);
		listing.createData(ha, ByteDataType.dataType);
		listing.setComment(ha, CodeUnit.EOL_COMMENT, "reserved");
		ha = ha.add(1);
		listing.createData(ha, ByteDataType.dataType);
		listing.setComment(ha, CodeUnit.EOL_COMMENT, "load mode");
		ha = ha.add(1);

		for (String name : new String[] {
			"base address",
			"run (execute) address",
			"text section size",
			"data section size",
			"block storage section size (contains .comm, .stack)",
			"reallocation (relocation?) info size",
			"symbol table size",
			"SCD line number table size",
			"SCD symbol table size",
			"SCD character string table size"
		}) {
			listing.createData(ha, UnsignedIntegerDataType.dataType);
			listing.setComment(ha, CodeUnit.EOL_COMMENT, name);
			ha = ha.add(4);
		}

		listing.createData(ha, new ArrayDataType(UnsignedIntegerDataType.dataType, 4));
		listing.setComment(ha, CodeUnit.EOL_COMMENT, "reserved");
		ha = ha.add(4 * 4);
		listing.createData(ha, UnsignedIntegerDataType.dataType);
		listing.setComment(ha, CodeUnit.EOL_COMMENT, "position from bound module list top-of-file");
	}
}