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
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Apple Lisa object files.
 */
public class AppleLisaObjectFileLoader extends AbstractProgramWrapperLoader {

    public static final String LISA_NAME = "Apple Lisa Object File";

        // InterfLoc is misprinted in http://pascal.hansotten.com/uploads/lisa/Lisa_Develpment_System_Internals_Documentation_198402.pdf
        // 86 and 92 are given in different places, but both are used for other things.
        private static final Map<Integer, String> TYPE_NAMES = Map.ofEntries(
         Map.entry(0x00, "EOFMark"),
         Map.entry(0x80, "ModuleName"),
         Map.entry(0x81, "EndBlock"),
         Map.entry(0x82, "EntryPoint"),
         Map.entry(0x83, "External"),
         Map.entry(0x84, "StartAddress"),
         Map.entry(0x85, "CodeBlock"),
         Map.entry(0x86, "Relocation"),
        //  Map.entry(0x86, "InterfLoc"),
         Map.entry(0x87, "CommonReloc"),
         Map.entry(0x89, "ShortExternal"),
         Map.entry(0x92, "UnitBlock"),
         Map.entry(0x98, "Executable"),
         Map.entry(0x99, "VersionCtrl"),
         Map.entry(0x9A, "SegmentTable"),
         Map.entry(0x9B, "UnitTable"),
         Map.entry(0x9C, "SegLocation"),
         Map.entry(0x9D, "UnitLocation"),
         Map.entry(0x9E, "FilesBlock")
     );

    String getTypeName(int type) {
        String hex = String.format("0x%02X", type);
        String name = TYPE_NAMES.get(type);
        return name == null ? hex + " ???" : hex + " '" + name + "'";
    }

	@Override
	public String getName() {
		return LISA_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

        BinaryReader reader = new BinaryReader(provider, false); // big-endian

        long off = 0;
        while (true) {
            if (reader.length() - off < 4) return loadSpecs;
            final int type = reader.readNextByte() & 0xff;
            String name = getTypeName(type);
            final long len = reader.readNextUnsignedValue(3);
            Msg.info(this, String.format("Lisa: offset=%06X, type=%s, len=%d", off, name, len));

            if (len < 4) return loadSpecs;

            if (reader.length() - off < len) return loadSpecs;
            off += len;
            reader.setPointerIndex(off);

            if (type == 0) break;
        }

        final int bytesRemaining = Math.toIntExact(reader.length() - off);
        if (bytesRemaining == 0) {
            Msg.info(this, "Lisa: end of file");
        } else {
            Msg.info(this, "Lisa: not at end of file. bytes remaining: 0x" + Integer.toHexString(bytesRemaining) + " (" + bytesRemaining + " bytes)");
            // both the number of zero bytes and the total file length are arbitrary, not rounded up to a block or sector size
            byte[] remainder = reader.readByteArray(off, bytesRemaining);
            if (IntStream.range(0, remainder.length).map(i -> remainder[i]).anyMatch(i -> i != 0x00)) {
                Msg.info(this, "   remainder is not all 0x00");
                return loadSpecs;
            }
			Msg.info(this, "   remainder is all 0x00");
        }

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));

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
