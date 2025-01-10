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
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
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

    public static final String RSRC_NAME = "Classic Macintosh Resource Fork";
    public static final int RSRC_HEADER_LEN = 16;
    public static final int RSRC_MAP_HEADER_OFFSET_TO_TYPE_LIST_OFFSET = 8;
    public static final int RSRC_TYPE_LIST_ENTRY_SIZE = 8;
    public static final int RSRC_RESOURCE_LIST_ENTRY_SIZE = 12;
    public static final int RSRC_CODE_NEAR_HEADER_SIZE = 4;

    // store these in findSupportedLoadSpecs() for use in load()
    long dataOffset = -1;
    long resourceTypeListOffset = -1;
    long resourceTypeListCodeResourceOffset = -1;

    @Override
    public String getName() {
        return RSRC_NAME;
    }

    // lower numbers have higher priority
    // 50 seems to be standard, raw uses 100
    // RetroGhidra Loaders that don't have magic numbers should use 60
    @Override
    public int getTierPriority() {
        return 60;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        final long fileSize = provider.length();
        if (fileSize < RSRC_HEADER_LEN) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        // 1.12 Resource header
        int[] header = reader.readNextIntArray(4);
        // no u32 in java, reinterpret as u32
        // 1.12 Offset from beginning of resource fork to resource data: 4
        this.dataOffset = header[0] & 0xFFFFFFFFL;
        // 1.12 Offset from beginning of resource fork to resource map: 4
        final long mapOffset = header[1] & 0xFFFFFFFFL;
        // 1.12 Length of resource data: 4
        final long dataLen = header[2] & 0xFFFFFFFFL;
        // 1.12 Length of resource map: 4
        final long mapLen = header[3] & 0xFFFFFFFFL;

        // header fields within the bounds of the file, otherwise false positive
        if (fileSize < dataOffset + dataLen
                || fileSize < mapOffset + mapLen
                || fileSize < mapOffset + RSRC_HEADER_LEN)
            return loadSpecs;

        // header matches dupe header at offset mapOffset, otherwise false positive
        if (!Arrays.equals(header, reader.readIntArray(mapOffset, 4))) return loadSpecs;

        // 1.14 Skip copy of resource header
        // 1.14   and handle to next resource map, file reference number, Resource fork attributes
        reader.setPointerIndex(mapOffset + RSRC_HEADER_LEN + RSRC_MAP_HEADER_OFFSET_TO_TYPE_LIST_OFFSET);
        // 1.14 Offset from beginning of map to resource type list
        final int typeListOffset = reader.readNextUnsignedShort();

        // In figure 1.14 this is *before* the type list, *not* part of it
        //   but adding the offsets from 1.12 and 1.14 brings us here
        this.resourceTypeListOffset = mapOffset + typeListOffset;

        // 1.14 Number of types in the map minus 1
        reader.setPointerIndex(resourceTypeListOffset);
        final int typeCount = readAndIncNextUnsignedShort(reader);

        // each different resource type
        for (int i = 0; i < typeCount; i++) {
            // 1.15 Item in a resource type list
            // + 2 to skip the number of types field
            long resourceTypeListEntryOffset = mapOffset + typeListOffset + 2 + i * RSRC_TYPE_LIST_ENTRY_SIZE;
            reader.setPointerIndex(resourceTypeListEntryOffset);
            // 1.15 Resource type
            if (!reader.readNextAsciiString(4).equals("CODE")) continue;

            this.resourceTypeListCodeResourceOffset = resourceTypeListEntryOffset;

            // 68020 etc are treated as 'variants'
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));
            break;
        }

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        OptionalLong maybeOffsetOfCode0Resource = OptionalLong.empty();
        int nextLoadAddress = 0x0000;
        // a map/dictionary/associative array from a resource ID to a loadAddress
        Map<Integer, Integer> resourceIdToLoadAddress = new HashMap<>();

        BinaryReader reader = new BinaryReader(provider, false);
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();

        // go straight to the CODE resource, skipping the type field
        reader.setPointerIndex(this.resourceTypeListCodeResourceOffset + 4);

        // 1.15 Number of resources of this type in map minus 1
        long countOfCodeResources = readAndIncNextUnsignedShort(reader);

        // 1.15 Offset from beginning of resource type list to reference list for this type
        final int resListOffset = reader.readNextUnsignedShort();
        final long resListEntriesOffset = this.resourceTypeListOffset + resListOffset;

        // each CODE resource
        for (int ri = 0; ri < countOfCodeResources; ri++) {
            // 1.16 Entry in the reference list for a resource type
            reader.setPointerIndex(resListEntriesOffset + ri * RSRC_RESOURCE_LIST_ENTRY_SIZE);
            // 1.16 Resource ID
            final int id = reader.readNextUnsignedShort();

            // skip Offset from beginning of resource name list to resource name
            //   and Resource attributes
            reader.readNextByteArray(3);

            // 1.16 Offset from beginning of resource data to data for this resource
            final int offsetToResData = readNextUnsigned24(reader);

            reader.setPointerIndex(this.dataOffset + offsetToResData);
            // 1.18 Length of resource data for a single resource
            final long resourceLen = reader.readNextUnsignedInt();

            // We are now at the start of the 'CODE' resource data
            // 'CODE' id 0 has a different format to other 'CODE' resources

            if (id == 0) {
                maybeOffsetOfCode0Resource = OptionalLong.of(dataOffset + offsetToResData);
                continue;
            }

            // offset of 1st jump table entry for near model, or 0xffff for far model
            if (reader.readNextUnsignedShort() == 0xffff) {
                Msg.error(this, "Far model not supported yet.");
                continue;
            }

            final int thisResHeaderSize = RSRC_CODE_NEAR_HEADER_SIZE;
            final int thisResFooterSize = 0;

            long codeSize = resourceLen - thisResHeaderSize - thisResFooterSize;

            try {
                FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

                MemoryBlock block = program.getMemory().createInitializedBlock(
                    "CODE " + id,                                           // name
                    addressSpace.getAddress(nextLoadAddress),               // start
                    fileBytes,                                              // filebytes
                    dataOffset + offsetToResData + 4 + thisResHeaderSize,   // offset
                    codeSize,                                               // size
                    false);                                                 // overlay
                block.setWrite(true);
            } catch (Exception e) {
                log.appendException(e);
            }

            // we need this later when we process the jump table
            resourceIdToLoadAddress.put(id, nextLoadAddress);

            // round up to the next 16-bit / 2-byte boundary
            nextLoadAddress += (codeSize + 0x01) & ~0x01;
        }

        // all code resources have been analysed. now we need to use
        // the CODE0 jump table to find the exported function addresses
        // the first one is the entry point. (some are invalid / zeroed)

        // we need CODE0 for the jump table and at least one normal CODE resource
        if (countOfCodeResources < 2 || maybeOffsetOfCode0Resource.isEmpty()) return;

        long code0Offset = maybeOffsetOfCode0Resource.getAsLong();
        reader.setPointerIndex(code0Offset);
        final long sizeInBytes = reader.readNextUnsignedInt();
        final int numEntries = (int) (sizeInBytes - 4 * 4) / 8;

        // CODE0 header
        reader.readNextIntArray(4);

        // each entry in the jump table
        for (int j = 0; j < numEntries; j++) {
            // skip 32-bit length field, 4x 32-bit header fields + TODO
            reader.setPointerIndex(code0Offset + 4 + (4 * 4) + 8 * j);
            final long offsetToCode = reader.readNextUnsignedShort() & 0xFFFFL;
            final int pushOpcode = reader.readNextUnsignedShort();
            final int jumptableID = reader.readNextUnsignedShort();
            final int trapOpcode = reader.readNextUnsignedShort();

            if (pushOpcode != 0x3f3c || trapOpcode != 0xa9f0) continue;

            // before we can add the symbol we have to find the CODE resource
            // this entry refers to, get its offset field, and add this offset field
            for (int cri = 0; cri < countOfCodeResources; cri++) {
                final long resListEntryOffset2 = resListEntriesOffset + cri * RSRC_RESOURCE_LIST_ENTRY_SIZE;
                // 1.16 Resource ID
                reader.setPointerIndex(resListEntryOffset2);
                final int resourceID = reader.readNextUnsignedShort();
                if (resourceID != jumptableID) continue;

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