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
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import retro.RetroGhidra;

/**
 * A {@link Loader} for loading the TRS-80 Model 100 .co files.
 */
public class Trs80Model100CoLoader extends AbstractProgramWrapperLoader {

    public static final String CO_NAME = "TRS-80 Model 100 .co";
    public static final String CO_EXTENSION = ".co";
    public static final int CO_HEADER_LENGTH = 6;

	private int start;
	private int length;
	private int entry;

	@Override
	public String getName() {
		return CO_NAME;
	}

	// lower numbers have higher priority
	// 50 seems to be standard, raw uses 100
	// RetroGhidra Loaders that don't have magic numbers should use 60
    // @Override
    // public int getTierPriority() {
    //     return 60;
    // }

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

        if (provider.length() < CO_HEADER_LENGTH) return loadSpecs;

        String name = provider.getName();
        if (name.indexOf('.') < 0) return loadSpecs;
        String ext = name.substring(name.lastIndexOf('.'));
        if (!ext.equalsIgnoreCase(CO_EXTENSION)) return loadSpecs;

		BinaryReader reader = new BinaryReader(provider, true);

        start = reader.readNextUnsignedShort();
        length = reader.readNextUnsignedShort();
        entry = reader.readNextUnsignedShort();

		final int lengthIncludingHeader = length + CO_HEADER_LENGTH;
        final int end = start + length;

        if (provider.length() != lengthIncludingHeader) return loadSpecs;
        if (end > 0x10000) return loadSpecs;
        if (entry >= end) return loadSpecs;

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("8085:LE:16:default", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		try {
			RetroGhidra.createInitializedBlockFromByteProvider(program, provider, monitor,
				"memory", start, CO_HEADER_LENGTH, length).setWrite(true);

			Address entryAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry);
			SymbolTable st = program.getSymbolTable();
			st.createLabel(entryAddress, "entry", SourceType.ANALYSIS);
			st.addExternalEntryPoint(entryAddress);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
