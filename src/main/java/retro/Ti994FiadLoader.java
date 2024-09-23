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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading TI-99/4A FIAD (V9T9) files.
 * "FIAD" stands for "Files In A Directory". "V9T9" stands was the emulator that originated the format.
 */
public class Ti994FiadLoader extends AbstractProgramWrapperLoader {

    public static final String FIAD_NAME = "TI-99/4A FIAD";
    public static final int FIAD_OFF_FILE_STATUS_FLAGS = 0x0c;
    public static final int FIAD_HEADER_LEN = 128;

	public static final int FIAD_LOAD_ADDR = 0x6000;

	@Override
	public String getName() {
		return FIAD_NAME;
	}

	// lower numbers have higher priority
	// 50 seems to be standard, raw uses 100
	// RetroGhidra Loaders that don't have magic numbers should use 60
    @Override
    public int getTierPriority() {
        return 60;
    }

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// can't be larger than header size + 64kb (TODO: there's probably a lower limit)
		if (provider.length() < FIAD_HEADER_LEN || provider.length() > FIAD_HEADER_LEN + 64 * 1024) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        // only bits 0, 1, 3, and 7 of file status flags are used according to https://hexbus.com/ti99geek/Doc/Ti99_dsk1_fdr.html
		// TIFILES supports two additional bits not support by FIAD (I think)
		int statusFlags = reader.readUnsignedByte(FIAD_OFF_FILE_STATUS_FLAGS);
		if ((statusFlags & ~0b1000_1011) != 0) return loadSpecs;

		// if bit 0 is set, "program", then bits 1 and 7 have no meaning so should be 0
		if ((statusFlags & 0b0000_0001) != 0 && ((statusFlags & 0b1000_0010) != 0)) return loadSpecs;

		// check that offset 0x20 up to 0x80 are all 0
        for (int i = 0x20; i < 0x80; i++) {
            int val = reader.readByte(i);
            if (val != 0) return loadSpecs;
        }

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("9900:BE:16:default", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		Memory memory = program.getMemory();
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		Address headerAddress = AddressSpace.OTHER_SPACE.getAddress(0x0000);
		AddressSpace addresssSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address loadAddress = addresssSpace.getAddress(FIAD_LOAD_ADDR);

		try {
			memory.createInitializedBlock(
				"FIAD",
				headerAddress,
				fileBytes,
				0,
				FIAD_HEADER_LEN,
				false);

			Ti994LoaderHelper.commentFiadHeader(program, headerAddress, loadAddress, provider);

            // last letter of the filename to determine where to load a file:
            // xxxxxC.BIN - loads as CPU cartridge ROM at >6000
            // xxxxxD.BIN - loads as banked CPU cartridge ROM at >6000, second bank (such as Extended BASIC or AtariSoft carts)
            // xxxxxG.BIN - loads as GROM cartridge at >6000 in GROM space
            // xxxxx3.BIN - Classic99 extension, loads as a 379/Jon Guidry style cartridge ROM at >6000
			// xxxxx8.BIN - A newer extension
			// xxxxx9.BIN - A newer extension
			memory.createInitializedBlock(
				"TMS9900",
				loadAddress,
				fileBytes,
				FIAD_HEADER_LEN,
				provider.length() - FIAD_HEADER_LEN,
				false);

			Ti994LoaderHelper.commentCode(program, loadAddress, provider, FIAD_HEADER_LEN, log);
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
