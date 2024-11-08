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
public class Apple2ProDosDskLoader extends AbstractProgramWrapperLoader {

	public static final String DO_NAME = "Apple II ProDOS .DO/.DSK";
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

        final int prodos2raw[] = { 0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15 };
        final int raw2dos[] = { 0, 7, 14, 6, 13, 5, 12, 4, 11, 3, 10, 2, 9, 1, 8, 15 };
        // if you have a ProDOS filesystem on a ProDOS-ordered image, and you want to read block 1, you grab prodos2raw[2] and [3], which are 4 and 6.
        // You look up raw2prodos[4] and [6], which are 2 and 3. So you read from offset 2*256 and 3*256 to form your 512-byte block.
        //
        // If you have a ProDOS filesystem on a DOS-ordered image, and you want to read block 1, you do the same thing but with raw2dos, which returns 13 and 12
		try {
            int block = 0;
            while (true) {
                // we're dealing with a ProDOS disk image in DOS 3 order
                // so let's load each block in turn by figuring out the track and sector
                int rawA = prodos2raw[block * 2];
                int rawB = prodos2raw[block * 2 + 1];
                long dosA = raw2dos[rawA];
                long dosB = raw2dos[rawB];
                long offsetA = dosA * DO_BYTES_PER_SECTOR;
                long offsetB = dosB * DO_BYTES_PER_SECTOR;
                Msg.info(this, "Loading block " + block + " with offset 0x" + Long.toHexString(offsetA) + " and 0x" + Long.toHexString(offsetB));
                
                int tr = block / 8;
                
                memory.createInitializedBlock(
                    "Block" + block + "A",              // name
                    addressSpace.getAddress(block * 512),   // start
                    fileBytes,                          // filebytes
                    offsetA,                            // offset
                    DO_BYTES_PER_SECTOR,                // size
                    false);                             // overlay

                memory.createInitializedBlock(
                    "Block" + block + "B",              // name
                    addressSpace.getAddress(block * 512 + 256),   // start
                    fileBytes,                          // filebytes
                    offsetB,                            // offset
                    DO_BYTES_PER_SECTOR,                // size
                    false);                             // overlay

                block++;
                if (monitor.isCancelled()) {
                    break;
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
