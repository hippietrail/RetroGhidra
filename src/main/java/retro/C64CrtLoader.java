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
 * A {@link Loader} for loading Commodore 64 .CRT cartridge files.
 */
public class C64CrtLoader extends AbstractProgramWrapperLoader {

    private static final String CRT_NAME = "Commodore 64 Cartridge (CRT)";
    private static final String CRT_MAGIC = "C64 CARTRIDGE   ";
    public final int[] CRT_C64_MAGIC = { 0xC3, 0xC2, 0xCD, '8', '0' }; // PETSCII 'CBM80'

    @Override
    public String getName() {
        return CRT_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // format, surprisingly, is big-endian
        BinaryReader reader = new BinaryReader(provider, false);

        if (reader.length() < 64) return loadSpecs;
        String magic = reader.readNextAsciiString(16);
        if (!magic.equals(CRT_MAGIC)) return loadSpecs;

        // [0x20 to 0x40) is name, padded with nulls
        String name = reader.readAsciiString(0x20, 0x20);
        Msg.info(this, ".CRT name: '" + name + "'");
        // point to offset 0x40 in case name was less than 0x20 bytes
        reader.setPointerIndex(0x40);

        // if we only get one CHIP section and the chip type is 0, we'll be able to load
        int chipCount = 0;
        int typeZeroCount = 0;
        long offset = -1;
        while (reader.getPointerIndex() < reader.length()) {
            String chip = reader.readNextAsciiString(4);
            if (!chip.equals("CHIP")) return loadSpecs;
            chipCount++;

            final long len = reader.readNextUnsignedInt();
            final int chipType = reader.readNextUnsignedShort();
            if (chipType == 0) typeZeroCount++;

            offset = reader.getPointerIndex() + 3 * 2;

            reader.setPointerIndex((int) (reader.getPointerIndex() + len));
        }

        // only trying to load the most straightforward type for now
        if (chipCount != 1 || typeZeroCount != 1) return loadSpecs;

        // check for the 5-byte signature at offset 0x04
        reader.setPointerIndex(offset + 4);
        byte[] bytes = reader.readNextByteArray(5);
        int[] signature = IntStream.range(0, 5).map(i -> bytes[i] & 0xFF).toArray();

        if (!Arrays.equals(CRT_C64_MAGIC, signature)) return loadSpecs;

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, false);

        // we only get this far if there's only one CHIP section and it's type 0x00 = ROM
        // seek to the first CHIP packets, skipping the fields until Starting load address
        reader.setPointerIndex(0x40 + 4 + 4 + 2 + 2);
        final int loadAdd = reader.readNextUnsignedShort();
        final int romSizeInBytes = reader.readNextUnsignedShort(); // typically 0x2000 or 0x4000
        final long offset = reader.getPointerIndex();

        try {
            Address loadAddressAndColdStart = program.getAddressFactory().getDefaultAddressSpace().getAddress(loadAdd);
            Address warmStart = program.getAddressFactory().getDefaultAddressSpace().getAddress(loadAdd + 2);
            Address magic = program.getAddressFactory().getDefaultAddressSpace().getAddress(loadAdd + 4);

            program.getMemory().createInitializedBlock(
                "CHIP",                                                         // name
                loadAddressAndColdStart,                                        // start
                MemoryBlockUtils.createFileBytes(program, provider, monitor),   // filebytes
                offset,                                                         // offset
                romSizeInBytes,                                                 // size
                false                                                           // overlay
            );

            SymbolTable st = program.getSymbolTable();
            st.createLabel(loadAddressAndColdStart, "coldstart", SourceType.ANALYSIS);
            st.createLabel(warmStart, "warmstart", SourceType.ANALYSIS);
            st.createLabel(magic, "magic", SourceType.IMPORTED);

            st.addExternalEntryPoint(loadAddressAndColdStart);
            st.addExternalEntryPoint(warmStart);
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}