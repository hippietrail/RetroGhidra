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
 * A {@link Loader} for the KC 85 .kcc file format.
 */
public class Kc85KccLoader extends AbstractProgramWrapperLoader {

    public static final String KCC_NAME = "KC 85 .kcc";
    public static final int KCC_NAME_LEN = 16;
    public static final int KCC_HEADER_SIZE = 128;

    private int numAddresses;
    private int loadAddress;
    private int endAddress; // end of code but data may follow
    private int execAddress;

    @Override
    public String getName() {
        return KCC_NAME;
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

        if (provider.length() < KCC_HEADER_SIZE) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, true);

        byte[] filename = reader.readNextByteArray(KCC_NAME_LEN);
        if (!isValidFilename(filename)) return loadSpecs;
        // load address, end address, execute address. assuming only the last is optional
        numAddresses = reader.readNextUnsignedByte();
        if (numAddresses < 2 || numAddresses > 3) return loadSpecs;
        loadAddress = reader.readNextUnsignedShort();
        endAddress = reader.readNextUnsignedShort();
        execAddress = reader.readNextUnsignedShort();
        if (endAddress <= loadAddress) return loadSpecs;
        if (execAddress != 0 && (execAddress < loadAddress || execAddress >= endAddress)) return loadSpecs;
        byte[] zeroes = reader.readNextByteArray(KCC_HEADER_SIZE - KCC_NAME_LEN - 1 - 6);
        if (IntStream.range(0, zeroes.length).anyMatch(i -> zeroes[i] != 0x00)) return loadSpecs;

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));

        return loadSpecs;
    }

    // filenames seem to be a pair of 8-char null-padded ASCII strings
    private static boolean isValidFilename(byte[] filename) {
        for (int i = 0; i < 2; i++) {
            boolean inPadding = false;
            for (int j = 0; j < 8; j++) {
                byte c = filename[i * 8 + j];
                // one or more 0x20 <= c <= 0x7E followed by only 0x00
                if (inPadding) {
                    if (c != 0x00) return false;
                } else {
                    if (c == 0x00) {
                        if (i == 0 && j == 0) return false; // assume empty filename isn't valid
                        inPadding = true;
                        continue;
                    }
                    if (c < 0x20 || c > 0x7E) return false;
                }
            }
        }
        Msg.info(Kc85KccLoader.class, "name '" + new String(filename, 0, 8) + "', ext '" + new String(filename, 8, 8) + "'");

        return true;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, true);
        reader.setPointerIndex(KCC_HEADER_SIZE);
        try {
            Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(loadAddress);
            program.getMemory().createInitializedBlock(
                    "CodeBlock",
                    start,
                    MemoryBlockUtils.createFileBytes(program, provider, monitor),
                    KCC_HEADER_SIZE,
                    provider.length() - KCC_HEADER_SIZE,
                    false
            );
            SymbolTable st = program.getSymbolTable();
            Address entryAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(execAddress);
            st.createLabel(entryAddress, "entry", SourceType.IMPORTED);
            st.addExternalEntryPoint(entryAddress);
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}
