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

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Sinclair ZX Spectrum TAP tape files.
 */
public class SpectrumTapLoader extends AbstractProgramWrapperLoader {

    private static final String TAP_NAME = "Sinclair ZX Spectrum TAP";
    private static final String TAP_EXTENSION = ".tap";
    private static final int TAP_FIRST_BLOCK_LEN = 0x13;

    @Override
    public String getName() {
        return TAP_NAME;
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

        String fname = provider.getName();
        if (fname.indexOf('.') < 0) return loadSpecs;
        String ext = fname.substring(fname.lastIndexOf('.'));
        if (!ext.equalsIgnoreCase(TAP_EXTENSION)) return loadSpecs;

        // a series of blocks preceded by a 16-bit little-endian size
        // the first should be 0x13 bytes so the file should be at least 0x15 bytes long
        // the last byte of the block is the xor checksum of all the bytes in the block
        // (the length bytes are not included in the checksum)

        if (provider.length() < TAP_FIRST_BLOCK_LEN + 2) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, true);

        final int firstBlockSize = reader.readUnsignedShort(0);
        if (firstBlockSize != TAP_FIRST_BLOCK_LEN) return loadSpecs;

        int blockChecksum = 0;
        for (int i = 0; i < firstBlockSize - 1; i++)
            blockChecksum ^= reader.readUnsignedByte(2 + i) & 0xFF;

        if (blockChecksum != (reader.readUnsignedByte(2 + firstBlockSize - 1) & 0xFF)) return loadSpecs;

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        // TODO: Load the bytes from 'provider' into the 'program'.
    }
}
