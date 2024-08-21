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
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Tandy Color Computer .CCC cartridge files.
 */
public class CocoCccLoader extends AbstractProgramWrapperLoader {

    public static final String CCC_NAME = "Tandy Coco Cartridge (CCC)";
	public static final String CCC_EXTENSION = ".ccc";

	@Override
	public String getName() {
		return CCC_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		// must have .ccc extension
        String name = provider.getName();
        if (name.indexOf('.') < 0) return loadSpecs;
        String ext = name.substring(name.lastIndexOf('.'));
        if (!ext.equalsIgnoreCase(CCC_EXTENSION)) return loadSpecs;

		// no header, no magic word, just a raw dump
		// but must it be a certain size?
		// some say 8kb or 4kb but 2kb and odd-sized CCC files are common enough
		if (reader.length() != 2 * 1024
			&& reader.length() != 4 * 1024
			&& reader.length() != 8 * 1024)
			return loadSpecs;

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6809:LE:16:default", "default"), true));

        return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		try {
			Address loadAndEntryAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(0xc000);
			
			program.getMemory().createInitializedBlock(
				"CODE",  														// name
				loadAndEntryAddress,              								// start
				MemoryBlockUtils.createFileBytes(program, provider, monitor),	// filebytes
				0,             													// offset
				provider.length(),									            // size
				false
			);

			SymbolTable st = program.getSymbolTable();
			st.createLabel(loadAndEntryAddress, "entry", SourceType.ANALYSIS);

			st.addExternalEntryPoint(loadAndEntryAddress);
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