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
 * A @{link Loader} for loading single-file Apple II Binary II files.
 */
public class Apple2Binary2Loader extends AbstractProgramWrapperLoader {

	public static final String BIN2_NAME = "Apple II Binary II";
	public static final int BIN2_HEADER_LEN = 128;
	public static final String BIN2_MAGIC = "\nGL"; // Binary II was developed by Gary B. Little
	
	public static final int BIN2_OFF_ID_BYTE = 18; // always 0x00
	public static final int BIN2_OFF_RESERVED_2 = 88;
	public static final int BIN2_OFF_OSTYPE = 121; // we'll only accept ProDOS and DOS 3
	public static final int BIN2_OFF_NUM_FILES_TO_FOLLOW = 127; // we'll only wor with single-file archives
	
	public static final int BIN2_ID_BYTE = 0x02;
	public static final int BIN2_RESERVED_2_LEN = 23;
	public static final int BIN2_OSTYPE_PRODOS_OR_SOS = 0x00;
	public static final int BIN2_OSTYPE_DOS3 = 0x01;

	@Override
	public String getName() {
		return BIN2_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

        BinaryReader reader = new BinaryReader(provider, true);

		Long fileLength = reader.length();
		if (fileLength < BIN2_HEADER_LEN) return loadSpecs;
		String magic = reader.readAsciiString(0, 3);
		if (!magic.equals(BIN2_MAGIC)) return loadSpecs;
		// magic word is small, check some other fields to avoid false positives
		if (reader.readByte(BIN2_OFF_ID_BYTE) != BIN2_ID_BYTE) return loadSpecs;
		byte[] reserved2 = reader.readByteArray(BIN2_OFF_RESERVED_2, BIN2_RESERVED_2_LEN);
		if (IntStream.range(0, BIN2_RESERVED_2_LEN).map(i -> reserved2[i]).anyMatch(i -> i != 0x00)) return loadSpecs;
		final int osType = reader.readByte(BIN2_OFF_OSTYPE);
		if (osType != BIN2_OSTYPE_PRODOS_OR_SOS && osType != BIN2_OSTYPE_DOS3) return loadSpecs;
		final int numFilesToFollow = reader.readUnsignedByte(BIN2_OFF_NUM_FILES_TO_FOLLOW);
		if (numFilesToFollow != 0) {
			Msg.warn(this, "This Binary II archive contains " + (numFilesToFollow + 1) + " files. For now we'll only examine the first one.");
		}

        List<QueryResult> queryResults = QueryOpinionService.query(getName(), "6502", null);
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
