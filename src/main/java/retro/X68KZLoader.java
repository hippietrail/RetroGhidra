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
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing Sharp X68000 .Z files.
 */
public class X68KZLoader extends AbstractProgramWrapperLoader {

    private static final String XZ_NAME = "Sharp X68000 .Z";
    private static final int XZ_MAGIC_1 = 0x601a;
    private static final int XZ_MAGIC_2 = 0xffff;

    @Override
    public String getName() {
        return XZ_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        BinaryReader reader = new BinaryReader(provider, false);

        int magic1 = reader.readUnsignedShort(0x00);
        if (magic1 != XZ_MAGIC_1) return loadSpecs;

        int magic2 = reader.readUnsignedShort(0x1a);
        if (magic2 != XZ_MAGIC_2) return loadSpecs;

        List<QueryResult> queryResults = QueryOpinionService.query(getName(), "68000", null);
        queryResults.stream().map(result -> new LoadSpec(this, 0, result)).forEach(loadSpecs::add);

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        // TODO: Load the bytes from 'provider' into the 'program'.
    }
}