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
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Classic Macintosh resource forks.
 */
public class ClassicMacResourceForkLoader extends AbstractProgramWrapperLoader {

    public final static String RSRC_NAME = "Classic Macintosh Resource Fork";
    public final static int RSRC_HEADER_SIZE = 16;

	@Override
	public String getName() {
		return RSRC_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

        long fileSize = provider.length();
        if (fileSize < RSRC_HEADER_SIZE) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        int[] header = reader.readIntArray(0, 4);
        // no u32 in java, reinterpret as u32
        long dataOffset = header[0] & 0xFFFFFFFFL;
        long mapOffset = header[1] & 0xFFFFFFFFL;
        long dataLen = header[2] & 0xFFFFFFFFL;
        long mapLen = header[3] & 0xFFFFFFFFL;

        // header fields within the bounds of the file, otherwise false positive
        if (fileSize < dataOffset + dataLen
        		|| fileSize < mapOffset + mapLen
        		|| fileSize < mapOffset + RSRC_HEADER_SIZE)
            return loadSpecs;

        // header matches dupe header at offset mapOffset, otherwise false positive
        if (!Arrays.equals(header, reader.readIntArray(mapOffset, 4))) return loadSpecs;

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

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}