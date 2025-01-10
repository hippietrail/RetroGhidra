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
 * A {@link Loader} for loading Agon Light MOS .bin files.
 */
public class AgonMosBinLoader extends AbstractProgramWrapperLoader {

    public static final String MOS_NAME = "Agon Light MOS .bin";
    public static final int MOS_HEADER_OFFSET = 0x40;
    public static final int MOS_HEADER_LENGTH = 5;
    public static final String MOS_MAGIC = "MOS";
    public static final int MOS_VERSION = 0;
    public static final int MOS_FLAGS_ADL = 1; // not sure this field is named

    @Override
    public String getName() {
        return MOS_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        if (provider.length() < MOS_HEADER_OFFSET + MOS_HEADER_LENGTH) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, true);

        reader.setPointerIndex(MOS_HEADER_OFFSET);
        String magic = reader.readNextAsciiString(MOS_MAGIC.length());
        if (!magic.equals(MOS_MAGIC)) return loadSpecs;
        int headerVersion = reader.readNextUnsignedByte();
        if (headerVersion != 0) return loadSpecs;
        int flags = reader.readNextUnsignedByte(); // only 0 and 1 are used, 1 for ADL
        if ((flags & 0xf7) != 0) return loadSpecs;

        // TODO it's actually an eZ80 with a 24-bit address bus, but Ghidra doesn't support that yet
        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        // TODO Load the bytes from 'provider' into the 'program'.
        // TODO MOS programs are always loaded at 0x40000 but it uses an eZ80, which Ghidra doesn't support
        // TODO and normal Z80 only has a 16-bit address bus, so this address is not valid
    }
}
