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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing Atari 8-bit .XEX files.
 */
public class Atari8BitXexLoader extends AbstractProgramWrapperLoader {

    public static final String XEX_NAME = "Atari 8-bit program (XEX)";
    public static final String XEX_EXTENSION = ".xex";
    public static final int XEX_HEAD = 0xffff;
    public static final int XEX_RUNAD = 0x02e0;
    public static final int XEX_INITAD = 0x02e2;

    @Override
    public String getName() {
        return XEX_NAME;
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

        BinaryReader reader = new BinaryReader(provider, true);

        // check for .xex file extension
        String name = provider.getName();
        if (name.indexOf('.') < 0) return loadSpecs;
        String ext = name.substring(name.lastIndexOf('.'));
        if (!ext.equalsIgnoreCase(XEX_EXTENSION)) return loadSpecs;

        // at least: $ffff, first address, last address
        if (reader.length() < 6) return loadSpecs;

        final int magic = reader.readUnsignedShort(0);
        if (magic != XEX_HEAD) return loadSpecs;

        // TODO we could iterate through the first few blocks to check that the start < the end
        // TODO if false positives prove to be a problem

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, true);
        reader.setPointerIndex(0);

        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        Memory memory = program.getMemory();
        FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

        int blockNum = 0;

        while (true) {
            if (reader.getPointerIndex() == reader.length()) break; // ends normally
            if (reader.getPointerIndex() > reader.length()) break; // abort

            int thisStart;
            // boolean hasHeader = false;

            if (reader.length() - reader.getPointerIndex() < 2) break; // abort
            final int headOrStart = reader.readNextUnsignedShort();
            if (headOrStart != XEX_HEAD) {
                thisStart = headOrStart;
            } else {
                // hasHeader = true;
                if (reader.length() - reader.getPointerIndex() < 2) break; // abort
                thisStart = reader.readNextUnsignedShort();
            }

            final int thisEnd = reader.readNextUnsignedShort();
            final int numBytes = (thisEnd - thisStart) + 1;
            // Msg.info(this, (blockNum + " ") + (hasHeader ? "[0xffff] " : "") + "0x" + Long.toHexString(thisStart) + " - 0x" + Long.toHexString(thisEnd) + " = 0x" + Long.toHexString(numBytes) + " (" + numBytes + " bytes)");

            if (reader.length() - reader.getPointerIndex() < numBytes) break; // abort

            boolean isOverlay = false;

            for (MemoryBlock block : program.getMemory().getBlocks()) {
                long thatStart = block.getStart().getOffset();
                long thatEnd = block.getEnd().getOffset();
                if (thisStart > thatEnd || thisEnd < thatStart) continue;

                // is this an exact overlap? (same block twice)
                if (thisStart == thatStart && thisEnd == thatEnd)
                    Msg.info(this, blockNum + " EXACT OVERLAP: 0x" + Long.toHexString(thisStart) + " - 0x" + Long.toHexString(thisEnd) + " vs. 0x" + Long.toHexString(thatStart) + " - 0x" + Long.toHexString(thatEnd));
                // is this a partial overlap? (blocks cross over at one or both ends)
                else if (thisStart <= thatEnd || thisEnd >= thatStart)
                    Msg.info(this, blockNum + " PARTIAL OVERLAP: 0x" + Long.toHexString(thisStart) + " - 0x" + Long.toHexString(thisEnd) + " vs. 0x" + Long.toHexString(thatStart) + " - 0x" + Long.toHexString(thatEnd));
                // otherwise it's just a normal overlap (this block is inside a previous block)
                else
                    Msg.info(this, blockNum + " NORMAL OVERLAP: 0x" + Long.toHexString(thisStart) + " - 0x" + Long.toHexString(thisEnd) + " vs. 0x" + Long.toHexString(thatStart) + " - 0x" + Long.toHexString(thatEnd));

                isOverlay = true;
                break;
            }

            // now check if this block hits RUNAD or INITAD exactly
            if (thisStart == XEX_RUNAD && thisEnd == XEX_RUNAD + 1)
                Msg.info(this, blockNum + " EXACT RUNAD");
            else if (thisStart == XEX_INITAD && thisEnd == XEX_INITAD + 1)
                Msg.info(this, blockNum + " EXACT INITAD");

            // if not check if this block covered RUNAD, INITAD, or both (they are adjacent)
            else {
                if (thisStart <= XEX_RUNAD && thisEnd >= XEX_RUNAD + 1)
                    Msg.info(this, blockNum + " COVERS RUNAD");
                if (thisStart <= XEX_INITAD && thisEnd >= XEX_INITAD + 1)
                    Msg.info(this, blockNum + " COVERS INITAD");
            }

            try {
                memory.createInitializedBlock(
                    "Block " + blockNum,                // name
                    addressSpace.getAddress(thisStart), // start
                    fileBytes,                          // filebytes
                    reader.getPointerIndex(),           // offset
                    numBytes,                           // size
                    isOverlay);                         // overlay
                reader.setPointerIndex(reader.getPointerIndex() + numBytes);

                SymbolTable st = program.getSymbolTable();

                // TODO doesn't label overlays and INITAD often is in several overlays
                st.createLabel(addressSpace.getAddress(XEX_RUNAD), "RUNAD", SourceType.ANALYSIS);
                st.createLabel(addressSpace.getAddress(XEX_INITAD), "INITAD", SourceType.ANALYSIS);

            } catch (Exception e) {
                log.appendException(e);
            }
            blockNum++;
        }
    }
}