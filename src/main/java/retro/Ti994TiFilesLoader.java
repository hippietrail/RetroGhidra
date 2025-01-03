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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import retro.Ti994LoaderHelper.HeaderField;

/**
 * A {@link Loader} for loading TI-99/4A TIFILES (XMODEM) files.
 */
public class Ti994TiFilesLoader extends AbstractProgramWrapperLoader {

    public static final String TIF_NAME = "TI-99/4A TIFILES";
    public static final int TIF_OFF_FILE_STATUS_FLAGS = 0x0a;
    public static final int TIF_HEADER_LEN = 128;

    public static final String TIF_MAGIC = "\07TIFILES";

    public static final int TIF_LOAD_ADDR = 0x6000;

	@Override
	public String getName() {
		return TIF_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// can't be larger than header size + 64kb (TODO: there's probably a lower limit)
		// if (provider.length() < TIF_HEADER_LEN || provider.length() > TIF_HEADER_LEN + 64 * 1024) return loadSpecs;
		// Msg.info(this, "File size: 0x" + Long.toHexString(provider.length()));
		// Msg.info(this, "Max size: 0x" + Long.toHexString(TIF_HEADER_LEN + 64 * 1024));
		if (provider.length() < TIF_HEADER_LEN) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        String magic = reader.readAsciiString(0, 8);
        if (!magic.equals(TIF_MAGIC)) return loadSpecs;

        // only bits 0, 1, 3, and 7 of file status flags are used according to https://hexbus.com/ti99geek/Doc/Ti99_dsk1_fdr.html
        // but 'Archiver.bin' has the right signature but 0b0001_0001 in the file status flags
        // more bits are actually defined according to https://www.ninerpedia.org/wiki/TIFILES_format
         int statusFlags = reader.readUnsignedByte(TIF_OFF_FILE_STATUS_FLAGS);
         if ((statusFlags & ~0b1011_1011) != 0) return loadSpecs;

		// if bit 0 is set, "program", then bits 1 and 7 have no meaning so should be 0
		if ((statusFlags & 0b0000_0001) != 0 && ((statusFlags & 0b1000_0010) != 0)) return loadSpecs;

        // check that offset 16 up to 128 are all 0 or [0xca, 0x53]
		// TODO for FIAD filler starts at 20, but for TIFILES it starts at 16
		// TODO but 16 to 26 can also be the native filename
        // https://hexbus.com/ti99geek/Doc/Ti99_dsk1_fdr.html
        // TELCO fills these bytes up to 0x7f with 0xca53.
        for (int i = 26; i < 128; i += 2) {
            int val = reader.readUnsignedShort(i);
            if (val != 0 && val != 0xca53) return loadSpecs;
        }

		Ti994LoaderHelper.addLoadSpecs(this, getLanguageService(), loadSpecs);

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
		Address loadAddress = addresssSpace.getAddress(TIF_LOAD_ADDR);

		try {
			memory.createInitializedBlock(
				"TIFILES",
				headerAddress,
				fileBytes,
				0,
                TIF_HEADER_LEN,
				false);

		    // FDR, FIAD (V9T9), and TIFILES (XMODEM) headers are described here: https://hexbus.com/ti99geek/
			Ti994LoaderHelper.commentFiadOrTifilesHeader(new HeaderField[] {
				HeaderField.TIFILES_MAGIC,
				HeaderField.NUMBER_OF_SECTORS_CURRENTLY_ALLOCATED,
				HeaderField.FILE_STATUS_FLAGS,
				HeaderField.NUMBER_OF_RECS_SEC,
				HeaderField.END_OF_FILE_OFFSET,
				HeaderField.LOGICAL_RECORD_LENGTH,
				HeaderField.NUMBER_OF_LEVEL_3_RECORDS_ALLOCATED, // LE
				HeaderField.TIFILES_FILLER
			}, program, headerAddress, loadAddress, provider);

            // last letter of the filename to determine where to load a file:
            // xxxxxC.BIN - loads as CPU cartridge ROM at >6000
            // xxxxxD.BIN - loads as banked CPU cartridge ROM at >6000, second bank (such as Extended BASIC or AtariSoft carts)
            // xxxxxG.BIN - loads as GROM cartridge at >6000 in GROM space
            // xxxxx3.BIN - Classic99 extension, loads as a 379/Jon Guidry style cartridge ROM at >6000
            // xxxxx8.BIN - A newer extension
            // xxxxx9.BIN - A newer extension

			// TODO overflows with the INT/FIX 128 files "GPLMAN1", "GPLMAN2", and "RYTEDATA"
			memory.createInitializedBlock(
                "TMS9900",
                loadAddress,
                fileBytes,
                TIF_HEADER_LEN,
                provider.length() - TIF_HEADER_LEN,
                false);

                Ti994LoaderHelper.loadAndComment(program, loadAddress, provider, TIF_HEADER_LEN, log);
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
