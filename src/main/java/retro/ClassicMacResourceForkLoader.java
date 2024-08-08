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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Classic Macintosh resource forks.
 */
public class ClassicMacResourceForkLoader extends AbstractProgramWrapperLoader {

    public final static String RSRC_NAME = "Classic Macintosh Resource Fork";
    public final static int RSRC_HEADER_SIZE = 16;
    public final static int RSRC_MAP_HEADER_OFFSET_TO_TYPE_LIST_OFFSET = 8;
    public final static int RSRC_TYPE_LIST_ENTRY_SIZE = 8;
    public final static int RSRC_RESOURCE_LIST_ENTRY_SIZE = 12;
    public final static int RSRC_CODE_NEAR_HEADER_SIZE = 4;
    public final static int RSRC_CODE0_HEADER_SIZE = 0;

    public boolean hasFindSupportedLoadSpecsBeenCalled = false;
    public boolean hasLoadBeenCalled = false;

	@Override
	public String getName() {
		return RSRC_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

        final long fileSize = provider.length();
        if (fileSize < RSRC_HEADER_SIZE) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        // 1.12 Resource header
        int[] header = reader.readNextIntArray(4);
        // no u32 in java, reinterpret as u32
        // 1.12 Offset from beginning of resource fork to resource data: 4
        final long dataOffset = header[0] & 0xFFFFFFFFL;
        // 1.12 Offset from beginning of resource fork to resource map: 4
        final long mapOffset = header[1] & 0xFFFFFFFFL;
        // 1.12 Length of resource data: 4
        final long dataLen = header[2] & 0xFFFFFFFFL;
        // 1.12 Length of resource map: 4
        final long mapLen = header[3] & 0xFFFFFFFFL;

        // header fields within the bounds of the file, otherwise false positive
        if (fileSize < dataOffset + dataLen
        		|| fileSize < mapOffset + mapLen
        		|| fileSize < mapOffset + RSRC_HEADER_SIZE)
            return loadSpecs;

        // header matches dupe header at offset mapOffset, otherwise false positive
        if (!Arrays.equals(header, reader.readIntArray(mapOffset, 4))) return loadSpecs;

        // 1.14 Skip copy of resource header
        // 1.14   and handle to next resource map, file reference number, Resource fork attributes
        reader.setPointerIndex(mapOffset + RSRC_HEADER_SIZE + RSRC_MAP_HEADER_OFFSET_TO_TYPE_LIST_OFFSET);
        // 1.14 Offset from beginning of map to resource type list
        final int typeListOffset = reader.readNextUnsignedShort();

        // In figure 1.14 this is *before* the type list, *not* part of it
        //   but adding the offsets from 1.12 and 1.14 brings us here
        final long resourceTypeListOffset = mapOffset + typeListOffset;

        // 1.14 Number of types in the map minus 1
        reader.setPointerIndex(resourceTypeListOffset);
        final int typeCount = readAndIncNextUnsignedShort(reader);

        // each different resource type
        for (int i = 0; i < typeCount; i++) {
            // + 2 to skip the number of types field
            reader.setPointerIndex(mapOffset + typeListOffset + 2 + i * RSRC_TYPE_LIST_ENTRY_SIZE);
            // 1.15 Resource type
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

        long countOfCodeResources = 0;

        OptionalLong maybeOffsetOfCode0Resource = OptionalLong.empty();
        int nextLoadAddress = 0x0000;
        // a map/dictionary/associative array from a resource ID to a loadAddress
        Map<Integer, Integer> resourceIdToLoadAddress = new HashMap<>();

        BinaryReader reader = new BinaryReader(provider, false);
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();

        // 1.12 Resource header
        int[] header = reader.readNextIntArray(4);
        // no u32 in java, reinterpret as u32
        // 1.12 Offset from beginning of resource fork to resource data: 4
        final long dataOffset = header[0] & 0xFFFFFFFFL;
        // 1.12 Offset from beginning of resource fork to resource map: 4
        final long mapOffset = header[1] & 0xFFFFFFFFL;
        // 1.12 Length of resource data: 4
        // final long dataLen = header[2] & 0xFFFFFFFFL;
        // 1.12 Length of resource map: 4
        // final long mapLen = header[3] & 0xFFFFFFFFL;

        // 1.14 Skip copy of resource header
        // 1.14   and handle to next resource map, file reference number, Resource fork attributes
        reader.setPointerIndex(mapOffset + RSRC_HEADER_SIZE + RSRC_MAP_HEADER_OFFSET_TO_TYPE_LIST_OFFSET);
        // 1.14 Offset from beginning of map to resource type list
        final int typeListOffset = reader.readNextUnsignedShort();

        // In figure 1.14 this is *before* the type list, *not* part of it
        //   but adding the offsets from 1.12 and 1.14 brings us here
        final long resourceTypeListOffset = mapOffset + typeListOffset;

        // 1.14 Number of types in the map minus 1
        reader.setPointerIndex(resourceTypeListOffset);
        final int typeCount = readAndIncNextUnsignedShort(reader);

        // each different resource type
        for (int rti = 0; rti < typeCount; rti++) {
            // + 2 to skip the number of types field
            reader.setPointerIndex(
                resourceTypeListOffset + 2
                + rti * RSRC_TYPE_LIST_ENTRY_SIZE);
            // 1.15 Resource type
            if (!reader.readNextAsciiString(4).equals("CODE")) continue;

            // 1.15 Number of resources of this type in map minus 1
            final int count = readAndIncNextUnsignedShort(reader);

            // Offset from beginning of resource type list to reference list for this type
            final int resListOffset = reader.readNextUnsignedShort();
            final long resListEntriesOffset = resourceTypeListOffset + resListOffset;

            countOfCodeResources = count;

            for (int ri = 0; ri < count; ri++) {
                final long resListEntryOffset = resListEntriesOffset + ri * RSRC_RESOURCE_LIST_ENTRY_SIZE;
                // 1.16 Resource ID
                reader.setPointerIndex(resListEntryOffset);
                final int id = reader.readNextUnsignedShort();

                // skip Offset from beginning of resource name list to resource name
                //   and Resource attributes
                reader.setPointerIndex(resListEntryOffset + 5); // TODO make a constant for this
                // 1.16 Offset from beginning of resource data to data for this resource
                final int offsetToResData = readNextUnsigned24(reader);

                reader.setPointerIndex(dataOffset + offsetToResData);
                // 1.18 Length of resource data for a single resource
                final long resourceLen = reader.readNextUnsignedInt();

                // We are now at the start of the 'CODE' resource data
                // 'CODE' id 0 has a different format to other 'CODE' resources

                if (id == 0) {
                    maybeOffsetOfCode0Resource = OptionalLong.of(dataOffset + offsetToResData);
                } else {                        
                    final int offsetOf1stJumpTableEntry = reader.readNextUnsignedShort();

                    if (offsetOf1stJumpTableEntry == 0xffff) {
                        Msg.error(this, "Far model not supported yet.");
                        continue;
                    }
                }

                // this does not include the 32-bit length field, which already omits itself
                // CODE0 is special and is the jumptable. it has a 32 byte header we do include
                // because the jump table mixes data and code. each entry has a data field
                // indicating the offset to the code address it refers to followed by
                // the code to PUSH the CODE id followed by the A-line trap to LoadSeg
                final int thisResHeaderSize = id == 0 ? RSRC_CODE0_HEADER_SIZE : RSRC_CODE_NEAR_HEADER_SIZE;
                final int thisResFooterSize = 0;

                // the + 4 is to skip the 32-bit resource length field
                final long codeOffset = dataOffset + offsetToResData + 4 + thisResHeaderSize;
                final long codeSize = resourceLen - thisResHeaderSize - thisResFooterSize;

                try {
                    Address ramAdd = addressSpace.getAddress(nextLoadAddress);
                    FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
                    
                    MemoryBlock block = program.getMemory().createInitializedBlock(
                        "CODE " + id,   					// name
                        ramAdd, 							// start
                        fileBytes,							// filebytes
                        codeOffset,                         // offset
                        codeSize,	                        // size
                        false);								// overlay
                    block.setWrite(true);
                } catch (Exception e) {
                    log.appendException(e);
                }
    
                resourceIdToLoadAddress.put(id, nextLoadAddress);
                
                // round up to the next 16-bit / 2-byte boundary
                nextLoadAddress += (codeSize + 0x01) & ~0x01;
            }

            // all code resources have been analysed. now we need to use
            // the CODE0 jump table to find the exported function addresses
            // the first one is the entry point. some are invalid / zeroed.

            if (maybeOffsetOfCode0Resource.isEmpty()) continue;

            long code0Offset = maybeOffsetOfCode0Resource.getAsLong();
            reader.setPointerIndex(code0Offset);
            final long sizeInBytes = reader.readNextUnsignedInt();
            final int numEntries = (int) (sizeInBytes - 4 * 4) / 8;

            reader.readNextUnsignedInt();
            reader.readNextUnsignedInt();
            reader.readNextUnsignedInt();
            reader.readNextUnsignedInt();

            // each entry in the jump table
            for (int j = 0; j < numEntries; j++) {
                // skip 32-bit length field, 4x 32-bit header fields + ?
                reader.setPointerIndex(code0Offset + 4 + 4 * 4 + 8 * j);
                final long offsetToCode = reader.readNextUnsignedShort() & 0xFFFFL;
                final int pushOpcode = reader.readNextUnsignedShort();
                final int jumptableID = reader.readNextUnsignedShort();
                final int trapOpcode = reader.readNextUnsignedShort();

                if (pushOpcode != 0x3f3c || trapOpcode != 0xa9f0) continue;
            
                // TODO before we an add the symbol we have to find the CODE resource
                // TODO this entry refers to, get its offset field, and add this offset field
                for (int cri = 0; cri < countOfCodeResources; cri++) {
                    final long resListEntryOffset2 = resListEntriesOffset + cri * RSRC_RESOURCE_LIST_ENTRY_SIZE;
                    // 1.16 Resource ID
                    reader.setPointerIndex(resListEntryOffset2);
                    final int resourceID = reader.readNextUnsignedShort();
                    if (resourceID != jumptableID) continue;

                    // skip Offset from beginning of resource name list to resource name
                    //   and Resource attributes
                    reader.setPointerIndex(resListEntryOffset2 + 5);
                    
                    // get the load address for this resource id from the map
                    long loadAddress = resourceIdToLoadAddress.get(resourceID);

                    Address codeAddr = addressSpace.getAddress(loadAddress + offsetToCode);
                    SymbolTable st = program.getSymbolTable();

                    try {
                        st.addExternalEntryPoint(codeAddr);
                        st.createLabel(
                            codeAddr,
                            j == 0 ? "entry" : "export_" + j + "_CODE_" + jumptableID,
                            SourceType.ANALYSIS
                        );
                    } catch (Exception e) {
                        log.appendException(e);
                    }

                    break;
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

    private static int readAndIncNextUnsignedShort(BinaryReader reader) throws IOException {
        final int val = reader.readNextUnsignedShort();
        return (val == 0xffff) ? 0 : val + 1;
    }

    private static int readNextUnsigned24(BinaryReader reader) throws IOException {
        final int offsetToResDataHi16 = reader.readNextUnsignedShort();
        final int offsetToResDataLo8 = reader.readNextUnsignedByte();
        return (offsetToResDataHi16 << 8) | offsetToResDataLo8;
    }
}