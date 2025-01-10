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
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Atari 2600 cartridge images
 */
public class Atari2600Loader extends AbstractProgramWrapperLoader {

    public static final String VCS_NAME = "Atari 2600";
    public static final int VCS_RESET_VECTOR = 0xfffc;

    @Override
    public String getName() {
        return VCS_NAME;
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

        // check for .a26 or .rom file extension
        String name = provider.getName();
        if (name.indexOf('.') < 0) return loadSpecs;
        String ext = name.substring(name.lastIndexOf('.'));
        if (!ext.equalsIgnoreCase(".a26") && !ext.equalsIgnoreCase(".bin")) return loadSpecs;
        // we can only handle two sizes of rom, larger roms have proprietary layouts
        final long romLen = provider.length();
        if (romLen != 2 * 1024 && romLen != 4 * 1024) {
            if (ext.equalsIgnoreCase(".a26")) {
                Msg.warn(this, ".26s rom files > 4K can't be loaded without knowledge of the internal layout");
            }
            return loadSpecs;
        }

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        final long romLen = provider.length();
        AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
        FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
        Memory mem = program.getMemory();
        SymbolTable symTab = program.getSymbolTable();

        final int kb = (int) (romLen >> 10);

        try {
            int m = 1;
            for (int i = 0; i < 8; i++) {
                final int base = i * 8 * 1024;

                // includes some RAM, hardware registers, etc
                final int ramEtcAddress = base;
                final int ramLen = 4 * 1024;
                final int romAddress = base + 4 * 1024;

                // leave out the 0x0000 block, Ghidra fills it in
                if (i != 0) {
                    mem.createUninitializedBlock(
                        "RAM+" + (i != 8 ? "mirror_" + i : ""),
                        addrSpace.getAddress(ramEtcAddress),
                        ramLen, false
                    ).setWrite(true);
                }

                // 4k cartridges mirror the rom 8 times
                mem.createInitializedBlock(
                    "ROM" + kb + "K_" + (i != 8 ? "mirror_" + (m++) : ""),
                    addrSpace.getAddress(romAddress),
                    fileBytes, 0, romLen, false
                );
                if (kb != 2) continue;
                // 2k cartridges mirror the rom 16 times
                mem.createInitializedBlock(
                    "ROM" + kb + "K_" + (i != 8 ? "mirror_" + (m++) : ""),
                    addrSpace.getAddress(romAddress + 2 * 1024),
                    fileBytes, 0, romLen, false
                );
            }

            Address resetVec = addrSpace.getAddress(VCS_RESET_VECTOR);
            symTab.createLabel(resetVec, "RESET", SourceType.ANALYSIS);

            Address entryPoint = addrSpace.getAddress(mem.getShort(addrSpace.getAddress(VCS_RESET_VECTOR)));
            symTab.createLabel(entryPoint, "entry", SourceType.ANALYSIS);
            symTab.addExternalEntryPoint(entryPoint);

        } catch (Exception e) {
            log.appendException(e);
        }
    }
}