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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Sinclair ZX Spectrum Snapshot (SNA) files.
 */
public class SpectrumSnaLoader extends AbstractProgramWrapperLoader {

    public static final String ZX_SNA_NAME = "Sinclair ZX Spectrum Snapshot (SNA)";
    public static final long ZX_SNA_LENGTH_48K = 27 + 48 * 1024;
    public static final long ZX_SNA_LENGTH_128K_S = 27 + 48 * 1024 + 4 + 5 * 16 * 1024;
    public static final long ZX_SNA_LENGTH_128K_L = 27 + 48 * 1024 + 4 + 6 * 16 * 1024;
    public static final Long[] ZX_SNA_LENGTHS = {
        ZX_SNA_LENGTH_48K,
        ZX_SNA_LENGTH_128K_S, // short: no repeated 16k bank
        ZX_SNA_LENGTH_128K_L, // long: has repeated 16k bank
    };
    public static final int ZX_SNA_OFF_IFF2 = 0x13;
    public static final int ZX_SNA_OFF_SP = 0x17;
    public static final int ZX_SNA_OFF_INT_MODE = 0x19;
    public static final int ZX_SNA_OFF_BORDER = 0x1a;
    public static final int ZX_SNA_HEADER_LEN = 0x1b;

    public static final int ZX_SNA_ROM_PAGED_SPEC = 0x71;
    public static final int ZX_SNA_ROM_PAGED_INT1 = 0xc9;

    public static final int ZX_SNA_RAM_START = 0x4000; // 16384
    public static final int ZX_SNA_DISPLAY_START = ZX_SNA_RAM_START;
    public static final int ZX_SNA_DISPLAY_SIZE = 32 * 192;
    public static final int ZX_SNA_ATTR_START = ZX_SNA_DISPLAY_START + ZX_SNA_DISPLAY_SIZE;
    public static final int ZX_SNA_ATTR_SIZE = 32 * 24;
    public static final int ZX_SNA_RAM_END = 0x10000;

    @Override
    public String getName() {
        return ZX_SNA_NAME;
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
        if (!Arrays.stream(ZX_SNA_LENGTHS).anyMatch(length -> length.equals(fileLength))) return loadSpecs;

        // only 1 bit of this field is defined, anything else probably a false positive
        final int iff2 = reader.readUnsignedByte(ZX_SNA_OFF_IFF2);
        if ((iff2 & ~0b0000_0100) != 0) return loadSpecs;

        // stack pointer can't be in ROM, probably a false positive
        final int sp = reader.readUnsignedShort(ZX_SNA_OFF_SP);
        if (sp < ZX_SNA_RAM_START) Msg.warn(this, "Stack pointer in ROM");

        // only 0 to 2 are valid, anything else probably a false positive
        final int interruptMode = reader.readUnsignedByte(ZX_SNA_OFF_INT_MODE);
        if (interruptMode > 2) return loadSpecs;

        // .SNA was originally used by a hardware device. This field indicated Sinclair Interface 1 presence
        // As an emulator format, this field indicates border colour, only 0 to 7
        // Anything besides these 8 values probably a false positive
        final int borderColourOrInt1 = reader.readUnsignedByte(ZX_SNA_OFF_BORDER);
        if (borderColourOrInt1 > 7
                && borderColourOrInt1 != ZX_SNA_ROM_PAGED_SPEC && borderColourOrInt1 != ZX_SNA_ROM_PAGED_INT1)
            return loadSpecs;

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        if (provider.length() != ZX_SNA_LENGTH_48K) {
            Msg.error(this, "Only 48K SNA snapshots are supported so far.");
            return;
        }

        BinaryReader reader = new BinaryReader(provider, true);

        // in 48k snapshots, pc is on the stack
        // if sp is in rom, we can't get the pc from the stack since we don't include the rom
        int sp = reader.readUnsignedShort(ZX_SNA_OFF_SP);
        OptionalInt pc = OptionalInt.empty();
        if (sp >= ZX_SNA_RAM_START) {
            pc = OptionalInt.of(reader.readUnsignedShort(ZX_SNA_HEADER_LEN + sp - ZX_SNA_RAM_START));
            sp = (sp + 2) & 0xffff;
        }

        Msg.info(this, program.getName() + ": SP = " +
            Integer.toHexString(sp)
            + ", PC = " +
            (pc.isPresent() ? "0x" + Integer.toHexString(pc.getAsInt()) : "?")
        );

        try {
            Address ramAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(ZX_SNA_DISPLAY_START);
            FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

            MemoryBlock block = program.getMemory().createInitializedBlock(
                "display",                          // name
                ramAdd,                             // start
                fileBytes,                          // filebytes
                ZX_SNA_HEADER_LEN,                  // offset
                ZX_SNA_RAM_END - ZX_SNA_RAM_START,  // size
                false);                             // overlay
            block.setWrite(true);

            Address attrEnd = program.getAddressFactory().getDefaultAddressSpace().getAddress(ZX_SNA_DISPLAY_START + ZX_SNA_DISPLAY_SIZE + ZX_SNA_ATTR_SIZE);
            program.getMemory().split(block, attrEnd);

            Address displayEnd = program.getAddressFactory().getDefaultAddressSpace().getAddress(ZX_SNA_DISPLAY_START + ZX_SNA_DISPLAY_SIZE);
            program.getMemory().split(block, displayEnd);

            MemoryBlock[] blocks = program.getMemory().getBlocks();
            blocks[1].setName("attributes");
            blocks[2].setName("rest");

            if (pc.isPresent() && pc.getAsInt() >= ZX_SNA_RAM_START) {
                Address ep = program.getAddressFactory().getDefaultAddressSpace().getAddress(pc.getAsInt());
                SymbolTable st = program.getSymbolTable();
                st.createLabel(ep, "entry", SourceType.ANALYSIS);
                st.addExternalEntryPoint(ep);
            }

            if (sp >= ZX_SNA_RAM_START) {
                Address spAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(sp);
                SymbolTable st = program.getSymbolTable();
                st.createLabel(spAdd, "stack", SourceType.ANALYSIS);
            }
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}
