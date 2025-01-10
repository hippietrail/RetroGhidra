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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Apple Lisa object files.
 */
public class AppleLisaObjectFileLoader extends AbstractProgramWrapperLoader {

    private static final String LISA_NAME = "Apple Lisa Object File";

    private static final int LISA_TAG_EOF_MARK = 0x00;
    private static final int LISA_TAG_MODULE_NAME = 0x80;
    private static final int LISA_TAG_END_BLOCK = 0x81;
    private static final int LISA_TAG_ENTRY_POINT = 0x82;
    private static final int LISA_TAG_EXTERNAL = 0x83;
    private static final int LISA_TAG_START_ADDRESS = 0x84;
    private static final int LISA_TAG_CODE_BLOCK = 0x85;
    private static final int LISA_TAG_RELOCATION = 0x86;
    private static final int LISA_TAG_COMMON_RELOC = 0x87;
    private static final int LISA_TAG_SHORT_EXTERNAL = 0x89;
    private static final int LISA_TAG_UNIT_BLOCK = 0x92;
    private static final int LISA_TAG_EXECUTABLE = 0x98;
    private static final int LISA_TAG_VERSION_CTRL = 0x99;
    private static final int LISA_TAG_SEGMENT_TABLE = 0x9A;
    private static final int LISA_TAG_UNIT_TABLE = 0x9B;
    private static final int LISA_TAG_SEG_LOCATION = 0x9C;
    private static final int LISA_TAG_UNIT_LOCATION = 0x9D;
    private static final int LISA_TAG_FILES_BLOCK = 0x9E;

    // InterfLoc is misprinted in http://pascal.hansotten.com/uploads/lisa/Lisa_Develpment_System_Internals_Documentation_198402.pdf
    // 86 and 92 are given in different places, but both are used for other things.
    private static final Map<Integer, String> TYPE_NAMES = Map.ofEntries(
        Map.entry(LISA_TAG_EOF_MARK, "EOFMark"),
        Map.entry(LISA_TAG_MODULE_NAME, "ModuleName"),
        Map.entry(LISA_TAG_END_BLOCK, "EndBlock"),
        Map.entry(LISA_TAG_ENTRY_POINT, "EntryPoint"),
        Map.entry(LISA_TAG_EXTERNAL, "External"),
        Map.entry(LISA_TAG_START_ADDRESS, "StartAddress"),
        Map.entry(LISA_TAG_CODE_BLOCK, "CodeBlock"),
        Map.entry(LISA_TAG_RELOCATION, "Relocation"),
        //Map.entry(LISA_TAG_INTERF_LOC, "InterfLoc"),
        Map.entry(LISA_TAG_COMMON_RELOC, "CommonReloc"),
        Map.entry(LISA_TAG_SHORT_EXTERNAL, "ShortExternal"),
        Map.entry(LISA_TAG_UNIT_BLOCK, "UnitBlock"),
        Map.entry(LISA_TAG_EXECUTABLE, "Executable"),
        Map.entry(LISA_TAG_VERSION_CTRL, "VersionCtrl"),
        Map.entry(LISA_TAG_SEGMENT_TABLE, "SegmentTable"),
        Map.entry(LISA_TAG_UNIT_TABLE, "UnitTable"),
        Map.entry(LISA_TAG_SEG_LOCATION, "SegLocation"),
        Map.entry(LISA_TAG_UNIT_LOCATION, "UnitLocation"),
        Map.entry(LISA_TAG_FILES_BLOCK, "FilesBlock")
    );

    private Long codeBlockOffset = null;

    String getTypeName(int type) {
        String name = TYPE_NAMES.get(type);
        return String.format("0x%02X", type) + ' ' + (name == null ? "???" : name);
    }

    @Override
    public String getName() {
        return LISA_NAME;
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

        BinaryReader reader = new BinaryReader(provider, false); // big-endian

        long off = 0;
        while (true) {
            if (reader.length() - off < 4) return loadSpecs;
            final int type = reader.readNextByte() & 0xff;
            String name = getTypeName(type);
            final long len = reader.readNextUnsignedValue(3);
            if (len < 4) return loadSpecs;
            if (reader.length() - off < len) return loadSpecs;

            Msg.info(this, String.format("Lisa: offset=%06X, type=%s, len=%d", off, name, len));

            if (type == LISA_TAG_CODE_BLOCK) {
                if (codeBlockOffset == null) {
                    codeBlockOffset = off;
                } else {
                    Msg.warn(this, "Lisa: multiple code block offsets: 0x" + Long.toHexString(codeBlockOffset) + " and 0x" + Long.toHexString(off));
                }
            }

            off += len;
            reader.setPointerIndex(off);

            if (type == 0) break;
        }

        if (codeBlockOffset == null) return loadSpecs;

        final int bytesRemaining = Math.toIntExact(reader.length() - off);
        if (bytesRemaining > 0) {
            Msg.info(this, "Lisa: Bytes remaining: 0x" + Integer.toHexString(bytesRemaining) + " (" + bytesRemaining + " bytes)");
            // both the number of zero bytes and the total file length are arbitrary, not rounded up to a block or sector size
            byte[] remainder = reader.readByteArray(off, bytesRemaining);
            if (IntStream.range(0, remainder.length).map(i -> remainder[i]).anyMatch(i -> i != 0x00)) {
                Msg.info(this, "   remainder is not all 0x00");
                return loadSpecs;
            }
        }

        // No other 680x0 has ever been used, so we can hard code this
        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        // TODO: Load the bytes from 'provider' into the 'program'.
        if (codeBlockOffset == null) {
            Msg.warn(this, "Lisa: no code block found");
            return;
        }
        Msg.info(this, "Lisa: code block at offset 0x" + Long.toHexString(codeBlockOffset));

        BinaryReader reader = new BinaryReader(provider, false); // big-endian
        reader.setPointerIndex(codeBlockOffset);
        reader.readNextByte();                              // record type: code block
        final long len1 = reader.readNextUnsignedValue(3);  // record length in bytes
        final long len2 = reader.readNextUnsignedInt();     // code block length in bytes (doesn't match the record length)
        final long addr = reader.readNextUnsignedInt();     // address to load code block
        Msg.info(this, "Lisa: code block length 0x" + Long.toHexString(len1) + ", 0x" + Long.toHexString(len2) + ", 0x" + Long.toHexString(addr));

        try {
            Address startAndEntryPoint = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);

            program.getMemory().createInitializedBlock(
                "CodeBlock",
                startAndEntryPoint,
                MemoryBlockUtils.createFileBytes(program, provider, monitor),
                codeBlockOffset + 4 + 4 + 4,
                len1 - (4 + 4 + 4),
                false
            );

            SymbolTable st = program.getSymbolTable();
            st.createLabel(startAndEntryPoint, "entry", SourceType.ANALYSIS);
            st.addExternalEntryPoint(startAndEntryPoint);
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}
