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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class Apple2Dos3DskLoader extends AbstractProgramWrapperLoader {

	public static final String DO_NAME = "Apple II DOS 3 .DO/.DSK";
	public static final String DO_EXTENSION = ".do";
	public static final String DO_EXTENSION_DSK = ".dsk";
	public static final int DO_BYTES_PER_SECTOR = 256;
	public static final int DO_SECTORS_PER_TRACK = 16;
	public static final int DO_NUM_TRACKS = 35;

	@Override
	public String getName() {
		return DO_NAME;
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

        // check for .do or .dsk file extension
		// .do means DOS 3 order
		// .dsk is ambiguous because it can be DOS 3 or ProDOS
        String name = provider.getName();
        if (name.indexOf('.') < 0) return loadSpecs;
        String ext = name.substring(name.lastIndexOf('.'));
        if (!ext.equalsIgnoreCase(DO_EXTENSION) && !ext.equalsIgnoreCase(DO_EXTENSION_DSK)) return loadSpecs;

		if (provider.length() != DO_BYTES_PER_SECTOR * DO_SECTORS_PER_TRACK * DO_NUM_TRACKS) return loadSpecs;

		// loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
		// we can't load as 6502 because we want to load the whole disk, which is more than 64kb
		// so load using 32-bit Intel instead since it's the same endian
		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		SymbolTable symbolTable = program.getSymbolTable();

		try {
			MemoryBlock block = memory.createInitializedBlock(
				"DSK",
				addressSpace.getAddress(0),
				fileBytes,
				0,
				provider.length(),
				false);

			int offset = 0;
			for (int track = 0; track < DO_NUM_TRACKS; track++) {
				for (int sector = 0; sector < DO_SECTORS_PER_TRACK; sector++) {
					symbolTable.createLabel(addressSpace.getAddress(offset), "track_" + track + "_sector_" + sector, SourceType.ANALYSIS);
					offset += DO_BYTES_PER_SECTOR;
				}
			}
			
			for (int sec = 15; sec > 11; sec--) {
				final int offTrack17Sector15 = 17 * DO_SECTORS_PER_TRACK * DO_BYTES_PER_SECTOR + sec * DO_BYTES_PER_SECTOR;
				Address start = addressSpace.getAddress(offTrack17Sector15);
				
				for (int e = 0; e < 7; e++) {
					Address o = start.add(11 + 0x23 * e);
					
					int t = block.getByte(o) & 0xff;
					int s = block.getByte(o.add(1)) & 0xff;
					int typeAndFlags = block.getByte(o.add(2)) & 0xff;
					
					String filename = "";
					for (int i = 3; i <= 0x20; i++) {
						int n = block.getByte(o.add(i)) & 0xff;
						char c = (char) (n - 0x80);
						filename += c;
					}
		
					int size = (block.getByte(o.add(0x21)) & 0xff) + 256 * (block.getByte(o.add(0x22)) & 0xff);
					Msg.info(this,
							"track " + t
							+ " sector " + s
							+ " type 0x" + Integer.toHexString(typeAndFlags)
							+ " filename '" + filename.trim() + "'"
							+ " size " + size);
				}
			}
			
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
