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
import java.util.stream.IntStream;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Commodore PET, VIC-20, and C64 .PRG program files.
 */
public class CommodorePrgLoader extends AbstractProgramWrapperLoader {

    private static final String PRG_NAME = "Commodore 8-bit program (PRG)";
    private static final String PRG_EXTENSION = ".prg";
    private static final int PRG_VIC20_OFF_MAGIC = 2 + 4; // load address, warm start vector, another vector?
    private static final int[] PRG_VIC20_MAGIC = { 0x41, 0x30, 0xC3, 0xC2, 0xCD };

    public int load;
    public Optional<Integer> maybeWarmStart = Optional.empty();

    @Override
    public String getName() {
        return PRG_NAME;
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

        // .PRG is actually used for PET, VIC-20, C64, and C128. For both machine code and BASIC.
        // In the case of the VIC-20, it is also used for cartridges.

        // check for .prg file extension
        String name = provider.getName();
        if (name.indexOf('.') < 0) return loadSpecs;
        String ext = name.substring(name.lastIndexOf('.'));
        if (!ext.equalsIgnoreCase(PRG_EXTENSION)) return loadSpecs;

        final long romLen = provider.length();

        BinaryReader reader = new BinaryReader(provider, true);

        load = reader.readNextUnsignedShort();
        final int next = reader.readNextUnsignedShort();

        String guessedSystemName = "unknown";
        switch (load) {
            case 0x0401: guessedSystemName = "PET or VIC-20 BASIC program"; break;
            case 0x0801: guessedSystemName = "C64 BASIC program"; break;
            case 0x1c01: guessedSystemName = "C128 BASIC program"; break;
            case 0x2000: guessedSystemName = "4K/8K VIC-20 cartridge"; break;
            case 0x4000: guessedSystemName = "4K/8K VIC-20 cartridge"; break;
            case 0x6000: guessedSystemName = "4K/8K VIC-20 cartridge"; break;
            case 0xa000: guessedSystemName = "4K/8K VIC-20 cartridge"; break;
            case 0xc000: guessedSystemName = "4K VIC-20 cartridge"; break;
        }
        if (!guessedSystemName.equals("unknown")) {
            Msg.info(this, "Probably a " + guessedSystemName);
        }
        // in the vic-20 case we can only handle two sizes of rom, larger roms have proprietary layouts

        // https://www.ctrl-alt-dev.nl/Projects/VIC20-DIY-Cartridge/VIC20-DIY-Cartridge.html
        // if the cartridge is exactly 8192 bytes long, check for the 5-byte magic word at offset 4
        // if it's [41 30 C3 C2 CD] (65, 48, 195, 194, 205) then this is a VIC-20 cartridge and the 16-bit warm start address is at offset 2
        // the article doesn't mention 4K cartridges, but the above seems to hold true
        if (romLen == 8 * 1024 + 2 || romLen == 4 * 1024 + 2) {
            byte[] bytes = reader.readByteArray(PRG_VIC20_OFF_MAGIC, 5);
            int[] magic = IntStream.range(0, 5).map(i -> bytes[i] & 0xFF).toArray();

            if (Arrays.equals(magic, PRG_VIC20_MAGIC)) maybeWarmStart = Optional.of(next);
        }

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        try {
            Address loadAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(load);

            program.getMemory().createInitializedBlock(
                "CODE",                                                         // name
                loadAddress,                                                    // start
                MemoryBlockUtils.createFileBytes(program, provider, monitor),   // filebytes
                2,                                                              // offset
                provider.length() - 2,                                          // size
                false
            ).setWrite(true);

            if (maybeWarmStart.isPresent()) {
                Address warmStartAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(load + 0);
                Address magicAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(load + 4);
                Address entryAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(maybeWarmStart.get());

                SymbolTable st = program.getSymbolTable();
                st.createLabel(warmStartAddress, "warmstart", SourceType.ANALYSIS);
                st.createLabel(magicAddress, "magic", SourceType.ANALYSIS);
                st.createLabel(entryAddress, "entry", SourceType.ANALYSIS);

                st.addExternalEntryPoint(entryAddress);
            }
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}