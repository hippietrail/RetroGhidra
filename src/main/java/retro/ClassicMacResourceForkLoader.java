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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
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

        final long fileSize = provider.length();
        if (fileSize < RSRC_HEADER_SIZE) return loadSpecs;

        final BinaryReader reader = new BinaryReader(provider, false);

        int[] header = reader.readIntArray(0, 4);
        // no u32 in java, reinterpret as u32
        final long dataOffset = header[0] & 0xFFFFFFFFL;
        final long mapOffset = header[1] & 0xFFFFFFFFL;
        final long dataLen = header[2] & 0xFFFFFFFFL;
        final long mapLen = header[3] & 0xFFFFFFFFL;

        // header fields within the bounds of the file, otherwise false positive
        if (fileSize < dataOffset + dataLen
        		|| fileSize < mapOffset + mapLen
        		|| fileSize < mapOffset + RSRC_HEADER_SIZE)
            return loadSpecs;

        // header matches dupe header at offset mapOffset, otherwise false positive
        if (!Arrays.equals(header, reader.readIntArray(mapOffset, 4))) return loadSpecs;

        reader.setPointerIndex(mapOffset + RSRC_HEADER_SIZE + 8);
        final int typeListOffset = reader.readNextUnsignedShort();
        reader.setPointerIndex(mapOffset + typeListOffset);
        int typeCount = reader.readNextUnsignedShort();
        typeCount = (typeCount == 0xffff) ? 0 : typeCount + 1;

        reader.setPointerIndex(mapOffset + typeListOffset + 2);

        for (int i = 0; i < typeCount; i++) {
            reader.setPointerIndex(mapOffset + typeListOffset + 2 + i * 8);
            if (reader.readNextAsciiString(4).equals("CODE")) {
                List<QueryResult> queryResults = QueryOpinionService.query(getName(), "68000", null);
                queryResults.stream().map(result -> new LoadSpec(this, 0, result)).forEach(loadSpecs::add);
                break;
            }
        }

        return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

        int nextLoadAddress = 0x0000;

        final BinaryReader reader = new BinaryReader(provider, false);

        final int[] header = reader.readIntArray(0, 4);
        // no u32 in java, this is how to reinterpret as u32
        final long dataOffset = header[0] & 0xFFFFFFFFL;
        final long mapOffset = header[1] & 0xFFFFFFFFL;
        // final long dataLen = header[2] & 0xFFFFFFFFL;
        // final long mapLen = header[3] & 0xFFFFFFFFL;

        reader.setPointerIndex(mapOffset + RSRC_HEADER_SIZE + 8);
        final int typeListOffset = reader.readNextUnsignedShort();

        final long resourceTypeListOffset = mapOffset + typeListOffset;

        reader.setPointerIndex(resourceTypeListOffset);
        int typeCount = reader.readNextUnsignedShort();
        typeCount = (typeCount == 0xffff) ? 0 : typeCount + 1;

        reader.setPointerIndex(resourceTypeListOffset + 2);

        // each different resource type
        for (int i = 0; i < typeCount; i++) {
            final long typeListEntryOffset = resourceTypeListOffset + 2 + i * 8;
            reader.setPointerIndex(typeListEntryOffset);
            final String typeCode = reader.readNextAsciiString(4);
            if (typeCode.equals("CODE")) {

                final int count = reader.readNextUnsignedShort();
                final int resListOffset = reader.readNextUnsignedShort();

                // each resource of that type. note <= since the count field is one less than the number of resources
                // but will never be 0xffff to indicate that there are no resources
                for (int j = 0; j <= count; j++) {
                    final long resListEntryOffset = resourceTypeListOffset + resListOffset + j * 12;
                    reader.setPointerIndex(resListEntryOffset);
                    final int id = reader.readNextUnsignedShort();

                    reader.setPointerIndex(resListEntryOffset + 5);
                    final int offsetToResDataHi16 = reader.readNextUnsignedShort();
                    final int offsetToResDataLo8 = reader.readNextUnsignedByte();
                    final int offsetToResData = (offsetToResDataHi16 << 8) | offsetToResDataLo8;

                    reader.setPointerIndex(dataOffset + offsetToResData);
                    final long resourceLen = reader.readNextUnsignedInt();

                    final int offsetOf1stJumpTableEntry = reader.readNextUnsignedShort();

                    if (offsetOf1stJumpTableEntry == 0xffff) {
                        Msg.error(this, "Far model not supported yet.");
                        continue;
                    }

                    // this does not include the 32-bit length field, which already omits itself
                    // CODE0 is special and is the jumptable. it has a 32 byte header we do include
                    // because the jump table mixes data and code. each entry has a data field
                    // indicating the offset to the code address it refers to followed by
                    // the code to PUSH the CODE id followed by the A-line trap to LoadSeg
                    final int headerSize = id == 0 ? 0 : 4;
                    final int footerSize = 0;

                    final long codeOffset = dataOffset + offsetToResData + 4 + headerSize;
                    final long codeLen = resourceLen - headerSize - footerSize;

                    try {
                        final Address ramAdd = program.getAddressFactory().getDefaultAddressSpace().getAddress(nextLoadAddress);
                        final FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
                        
                        final MemoryBlock block = program.getMemory().createInitializedBlock(
                            "CODE " + id,   					// name
                            ramAdd, 							// start
                            fileBytes,							// filebytes
                            codeOffset,                         // offset
                            codeLen,	                        // size
                            false);								// overlay
                        block.setWrite(true);
                    } catch (Exception e) {
                        log.appendException(e);
                    }
        
                    // I could round up to the next 1k. I don't know what's usual in Ghidra
                    nextLoadAddress += codeLen;
                }
            }
        }
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