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
 * A {@link Loader} for loading Atari ST executable files.
 */
public class AtariStLoader extends AbstractProgramWrapperLoader {

    // normal extensions: .prg (executable program), .tos (TOS program), .ttp (TOS program that takes parameters)
    // other extensions: .app (multiTOS application), .ovl ("recovery executable"? probably overlay), .acc (desk accessory)
    // more extensions: .cpx (control panel)
    public static final String ST_NAME = "Atari ST";
    // ST_OFF_MAGIC = 0x00;
    public static final int ST_OFF_TSIZE = 0x02; // size of text segment
    public static final int ST_OFF_DSIZE = 0x06; // size of data segment
    public static final int ST_OFF_BSIZE = 0x0a; // size of bss segment
    public static final int ST_OFF_SSIZE = 0x0e; // size of symbol table
    public static final int ST_OFF_RESRV = 0x12; // reserved
    public static final int ST_OFF_FLAGS = 0x16; // flags
    // ST_OFF_ABSFLAGS = 0x1a; // absolute flags
    public static final int ST_HEADER_LEN = 0x1c;

    public static final int ST_MAGIC = 0x601a; // bra.s +26
    public static final int ST_MAGIC_2 = 0x601b; // bra.s +27 "If data and BSS are not contiguous"

    public static final long ST_LOAD_ADDRESS = 0x10000;    // arbitrary, same as Python ST loader uses

    @Override
    public String getName() {
        return ST_NAME;
    }

    // lower numbers have higher priority
    // 50 seems to be standard, raw uses 100
    // RetroGhidra Loaders that don't have proper magic numbers should use 60
    @Override
    public int getTierPriority() {
        return 60;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        if (provider.length() < ST_HEADER_LEN) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        final long magic = reader.readUnsignedShort(0);
        if (magic != ST_MAGIC && magic != ST_MAGIC_2) return loadSpecs;
        if (reader.readUnsignedInt(ST_OFF_RESRV) != 0) return loadSpecs;
        if ((reader.readUnsignedInt(ST_OFF_FLAGS) & ~0b00000000_00110111) != 0) return loadSpecs;

        // 68020 etc are treated as 'variants'
        List<QueryResult> queryResults = QueryOpinionService.query(getName(), "68000", null);
        queryResults.stream().map(result -> new LoadSpec(this, 0, result)).forEach(loadSpecs::add);

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, false);
        final long textSegmentSize = reader.readUnsignedInt(ST_OFF_TSIZE);
        final long dataSegmentSize = reader.readUnsignedInt(ST_OFF_DSIZE);
        final long bssSegmentSize = reader.readUnsignedInt(ST_OFF_BSIZE);
        final long symbolsSize = reader.readUnsignedInt(ST_OFF_SSIZE);

        try {
            Memory memory = program.getMemory();
            AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
            FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

            long textOffset = ST_HEADER_LEN;
            long dataOffset = textOffset + textSegmentSize;
            long symbolOffset = dataOffset + dataSegmentSize;
            long fixupOffset = symbolOffset + symbolsSize;

            Address textAddress = addressSpace.getAddress(ST_LOAD_ADDRESS + textOffset);
            Address dataAddress = textAddress.add(textSegmentSize);
            Address bssAddress = dataAddress.add(dataSegmentSize);

            memory.createInitializedBlock(
                "TEXT",
                textAddress,
                fileBytes,
                textOffset,
                textSegmentSize,
                false
            );

            SymbolTable st = program.getSymbolTable();
            st.createLabel(textAddress, "entry", SourceType.ANALYSIS);
            st.addExternalEntryPoint(textAddress);

            if (dataSegmentSize > 0) {
                memory.createInitializedBlock(
                    "DATA",
                    dataAddress,
                    fileBytes,
                    ST_HEADER_LEN + textSegmentSize,
                    dataSegmentSize,
                    false
                );
            }

            if (bssSegmentSize > 0) {
                memory.createInitializedBlock(
                    "BSS",
                    bssAddress,
                    bssSegmentSize,
                    (byte) 0,
                    monitor,
                    false
                );
            }

            if (symbolsSize > 0) {
                memory.createInitializedBlock(
                    "SYMBOLS",
                    AddressSpace.OTHER_SPACE.getAddress(0x10000000),
                    fileBytes,
                    symbolOffset,
                    symbolsSize,
                    false
                );
            }

            if (reader.length() - fixupOffset > 0) {
                reader.setPointerIndex(fixupOffset);
                long offs = reader.readNextUnsignedInt();

                Address a = textAddress.add(offs);
                long v = memory.getInt(a) & 0xffff_ffff;
                memory.setInt(a, (int)(v + ST_LOAD_ADDRESS + ST_HEADER_LEN));

                while (true) {
                    final int delta = reader.readNextUnsignedByte();

                    if (delta == 0) break;
                    if (delta == 1) {
                        offs += 254;
                        continue;
                    }
                    offs += delta;

                    a = textAddress.add(offs);
                    v = memory.getInt(a) & 0xffff_ffff;
                    memory.setInt(a, (int)(v + ST_LOAD_ADDRESS + ST_HEADER_LEN));
                }
            }
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}