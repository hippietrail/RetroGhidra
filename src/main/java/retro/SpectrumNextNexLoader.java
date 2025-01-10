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
 * A {@link Loader} for the Spectrum Next .nex format.
 */
public class SpectrumNextNexLoader extends AbstractProgramWrapperLoader {

    public static final String NEX_NAME = "Spectrum Next .nex";
    public static final int NEX_HEADER_LEN = 0x200;
    public static final String NEX_MAGIC = "Next";

    @Override
    public String getName() {
        return NEX_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        if (provider.length() < NEX_HEADER_LEN) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        String magic = reader.readNextAsciiString(NEX_MAGIC.length());
        if (!magic.equals(NEX_MAGIC)) return loadSpecs;
        String version = reader.readNextAsciiString(4); // "V1.0", "V1.1", etc
        if (version.charAt(0) != 'V') return loadSpecs;
        if (version.charAt(1) < '1' || version.charAt(1) > '9') return loadSpecs;
        if (version.charAt(2) != '.') return loadSpecs;
        if (version.charAt(3) < '0' || version.charAt(2) > '9') return loadSpecs;

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
