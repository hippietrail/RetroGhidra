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
 * A {@link Loader} for processing Arm Image Format (AIF) files.
 */
public class AifLoader extends AbstractProgramWrapperLoader {

	public final static String AIF_NAME = "Arm Image Format (AIF)";

	@Override
	public String getName() {
		return AIF_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		if (reader.length() < 64) return loadSpecs;
		int exitCode = reader.readInt(0x10); // serves as magic number
		int imageDebugType = reader.readInt(0x24); // just sanity check for now
		int flagsAndAddressSize = reader.readInt(0x30); // just sanity check for now but if 64 could change length
		boolean isStrongArm = (flagsAndAddressSize & 0x80000000) != 0;
		int addressSize = (int) (flagsAndAddressSize & 0x7fffffff);

		// arm opcode 'swi OS_Exit' serves as a magic number in *nix 'file'
		if (exitCode != 0xef000011) return loadSpecs;
		// sanity: imageDebugType is 0, 1, 2, or 3; otherwise treat as false positive, not really an AIF
		if (imageDebugType < 0 || imageDebugType > 3) return loadSpecs;
		// sanity: addressSize is 0, 16, 32, or 64; otherwise treat as false positive, not really an AIF
		switch (addressSize) {
			case 0, 26, 32, 64 -> { break; }
			default -> { return loadSpecs; }
		}
		List<QueryResult> queryResults =
			QueryOpinionService.query(getName(), "arm", null);

		queryResults.forEach(result -> loadSpecs.add(new LoadSpec(this, 0, result)));

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
