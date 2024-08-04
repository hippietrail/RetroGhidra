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
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Sinclair ZX Spectrum Snapshot (SNA) files.
 */
public class SpectrumSnaLoader extends AbstractProgramWrapperLoader {

	public static final String ZX_SNA_NAME = "Sinclair ZX Spectrum Snapshot (SNA)";
	public static final Long[] ZX_SNA_LENGTHS = {
		(long) (27 + 48 * 1024),
		(long) (27 + 48 * 1024 + 4 + 5 * 16 * 1024),
		(long) (27 + 48 * 1024 + 4 + 6 * 16 * 1024)
	};

	@Override
	public String getName() {
		return ZX_SNA_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		Long fileLength = reader.length();
		if (!Arrays.stream(ZX_SNA_LENGTHS).anyMatch(length -> length.equals(fileLength))) {
			return loadSpecs;
		}

		int iff2Byte = reader.readUnsignedByte(0x13);
		if ((iff2Byte & ~0x04) != 0) {
			return loadSpecs;
		}

		int interruptMode = reader.readUnsignedByte(0x19);
		if (interruptMode > 2) {
			return loadSpecs;
		}

		int borderColorOrInt1Byte = reader.readUnsignedByte(0x1A);
		if (borderColorOrInt1Byte > 7 && borderColorOrInt1Byte != 0x71 && borderColorOrInt1Byte != 0xC9) {
			return loadSpecs;
		}

		List<QueryResult> queryResults = QueryOpinionService.query(getName(), "z80", null);
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
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
