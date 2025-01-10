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
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Exidy Sorcerer Snapshot (SNP) files.
 */
public class ExidySnpLoader extends AbstractProgramWrapperLoader {

    private static final String SNP_NAME = "Exidy Sorcerer Snapshot (SNP)";
    private static final long SNP_LENGTH = 28 + 64 * 1024;
    private static final int SNP_OFF_IFF2 = 19; // 0x13
    private static final int SNP_OFF_SP = 23; // 0x17
    private static final int SNP_OFF_INT_MODE = 25; // 0x19
    private static final int SNP_OFF_PC = 26; // 0x1a
    private static final int SNP_HEADER_LEN = 0x1c;

    private static final int SNP_DISPLAY_START = 0xf080;
    private static final int SNP_DISPLAY_END = 0xf800;

    @Override
    public String getName() {
        return SNP_NAME;
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

        BinaryReader reader = new BinaryReader(provider, true);

        // use a temp since .length() can throw and .anyMatch() is a lambda (no 'throws' clause)
        final Long fileLength = reader.length();
        if (fileLength != SNP_LENGTH) return loadSpecs;

        // only 2 bits of this field are defined, 0x02 and 0x04. anything else probably a false positive
        final int iff2 = reader.readUnsignedByte(SNP_OFF_IFF2);
        if ((iff2 & ~0b0000_0110) != 0) return loadSpecs;

        // only 0 to 2 are valid, anything else probably a false positive
        final int interruptMode = reader.readUnsignedByte(SNP_OFF_INT_MODE);
        if (interruptMode > 2) return loadSpecs;

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, true);

        int sp = reader.readUnsignedShort(SNP_OFF_SP);
        int pc = reader.readUnsignedShort(SNP_OFF_PC);

        try {
            Address memoryAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0000);
            FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

            program.getMemory().createInitializedBlock(
                "memory",                       // name
                memoryAdd,                      // start
                fileBytes,                      // filebytes
                SNP_HEADER_LEN,                 // offset
                SNP_LENGTH - SNP_HEADER_LEN,    // size
                false);                         // overlay

            SymbolTable st = program.getSymbolTable();

            Address ep = program.getAddressFactory().getDefaultAddressSpace().getAddress(pc);
            st.createLabel(ep, "entry", SourceType.ANALYSIS);
            st.addExternalEntryPoint(ep);

            Address spAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(sp);
            st.createLabel(spAdd, "stack", SourceType.ANALYSIS);

            Address addr;
            addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(SNP_DISPLAY_START);
            st.createLabel(addr, "display", SourceType.ANALYSIS);

            addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(SNP_DISPLAY_END);
            st.createLabel(addr, "display_end", SourceType.ANALYSIS);
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}
