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
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading TRS-80 /CMD files (load modules).
 *
 * TODO: /REL files too?
 */
public class Trs80Loader extends AbstractProgramWrapperLoader {

    public static final String TRS_NAME = "TRS-80 /CMD";
    public static final int TRS_TYPE_OBJECT_CODE = 0x01;    // "object code" (load block) - aka "data"
    public static final int TRS_TYPE_TRANSFER = 0x02;       // "transfer address" - aka "jump address"
    public static final int TRS_TYPE_END = 0x04;            // "end of partitioned data set member"
    public static final int TRS_TYPE_HEADER = 0x05;         // "load module header" - aka "header"
    public static final int TRS_TYPE_MEMBER = 0x06;         // "partitioned data set member"
    public static final int TRS_TYPE_PATCH = 0x07;          // "patch name header" (LDOS)
    public static final int TRS_TYPE_ISAM = 0x08;           // "ISAM directory entry"
    public static final int TRS_TYPE_END_ISAM = 0x0a;       // "end of ISAM directory"
    public static final int TRS_TYPE_PDS = 0x0c;            // "PDS directory entry"
    public static final int TRS_TYPE_END_PDS = 0x0e;        // "end of PDS directory"
    public static final int TRS_TYPE_YANK = 0x10;           // "yanked load block"
    public static final int TRS_TYPE_COPYRIGHT = 0x1f;      // "copyright block" (LDOS and DOSPLUS)
    public static final int[] TRS_TYPE_CODES = {
        TRS_TYPE_OBJECT_CODE, TRS_TYPE_TRANSFER, TRS_TYPE_END, TRS_TYPE_HEADER, TRS_TYPE_MEMBER,
        TRS_TYPE_PATCH, TRS_TYPE_ISAM, TRS_TYPE_END_ISAM, TRS_TYPE_PDS, TRS_TYPE_END_PDS, 
        TRS_TYPE_YANK, TRS_TYPE_COPYRIGHT,
    };

    // TODO make this an optional, how to add as comment / program name in Ghidra?
    String filename = "";

	@Override
	public String getName() {
        return TRS_NAME;
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

        int offset = 0; // byte index
        boolean seenTransferAddress = false;
        loop: while (true) {
            if (offset + 1 > reader.length()) {
                // hit EOF after processing load records, all went well
                if (seenTransferAddress) break loop;
                // hit EOF before processing a 'transfer address' record, probably not a TRS-80 file
				return loadSpecs;
            }
            byte typeCode = (byte) reader.readNextUnsignedByte();
            offset++;
            // Any code above X'1F' is invalid as a record type. In addition, any code
            // not listed in the above table is reserved for future use
            if (!Arrays.stream(TRS_TYPE_CODES).anyMatch(x -> x == typeCode)) {
                // hit garbage after processing load records, all went well
                if (seenTransferAddress) break loop;
                // unknown record - not a /CMD file
                return loadSpecs;
            }

            switch (typeCode) {
                case TRS_TYPE_OBJECT_CODE -> { /* 1 */
                    // data / object code / load block
                    if (offset + 2 > reader.length()) return loadSpecs;
                    int lengthByte = reader.readNextUnsignedByte() & 0xFF;
                    int len = lengthByte < 3 ? 256 + lengthByte : lengthByte;
                    offset++;
                    // first 2 bytes of the len bytes following are the load address
                    if (offset + len > reader.length()) return loadSpecs;
                    reader.readNextByteArray(len);
                    offset += len;
                    break;
                }
                case TRS_TYPE_TRANSFER -> { /* 2 */
                    // transfer address does not use the special length values, should always be '2'
                    if (offset + 2 > reader.length()) return loadSpecs;
                    final int len = reader.readNextUnsignedByte() & 0xFF;
                    offset += 1;
                    if (len != 2) return loadSpecs;
                    if (offset + len > reader.length()) return loadSpecs;
                    reader.readNextByteArray(len);
                    offset += len;
                    seenTransferAddress = true;
                    break;
                }
                case TRS_TYPE_HEADER -> { /* 5 */
                    if (offset + 1 > reader.length()) return loadSpecs;
                    final int lengthByte = reader.readNextUnsignedByte() & 0xFF;
                    final int len = lengthByte < 3 ? 256 + lengthByte : lengthByte;
                    offset += 1;
                    if (offset + len > reader.length()) return loadSpecs;
                    this.filename = reader.readNextAsciiString(len);
                    // TODO use this filename as a comment / program name in Ghidra?
                    offset += len;
                    break;
                }
                default -> {
                    // known type, but not implemented, ignore and continue
                    if (offset + 1 > reader.length()) return loadSpecs;
                    final int lengthByte = reader.readNextUnsignedByte() & 0xFF;
                    final int len = lengthByte < 3 ? 256 + lengthByte : lengthByte;
                    offset += 1;
                    if (offset + len > reader.length()) return loadSpecs;
                    reader.readNextByteArray(len);
                    offset += len;
                    break;
                }
            }
        }

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, true);

        int ramNum = 0;
        
        int offset = 0;
        boolean seenTransferAddress = false;
        loop: while (true) {
            if (offset + 1 > reader.length()) {
                // EOF and we've seen a transfer address, all went well
                if (seenTransferAddress) break loop;
                return;
            }

            int typeCode = reader.readNextUnsignedByte();
            offset++;

            if (!Arrays.stream(TRS_TYPE_CODES).anyMatch(x -> x == typeCode)) {
                // trailing garbage but we've seen a transfer address, all went well
                if (seenTransferAddress) break loop;
                return;
            }

            switch (typeCode) {
                case TRS_TYPE_OBJECT_CODE -> { /* 1 */
                    // data / object code / load block
                    final int rawLen = reader.readNextUnsignedByte() & 0xFF;
                    final int len = rawLen < 3 ? 256 + rawLen : rawLen;
                    offset++;
                    final int address = reader.readNextUnsignedShort();
                    offset += 2;

                    try {
                        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
                        FileBytes bytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

                        MemoryBlock block = program.getMemory().createInitializedBlock(
                            "RAM " + ramNum++,  // name
                            start,              // start
                            bytes,              // filebytes
                            offset,             // offset
                            len - 2,            // size
                            false);             // overlay
                        block.setWrite(true);
                    } catch (Exception e) {
                        log.appendException(e);
                    }

                    reader.readNextByteArray(len - 2);
                    offset += len - 2;
                    break;
                }
                case TRS_TYPE_TRANSFER -> { /* 2 */
                    // transfer address does not use the special length values, should always be '2'
                    final int len = reader.readNextUnsignedByte() & 0xFF;
                    offset += 1;
                    final int address = reader.readNextUnsignedShort();
                    offset += len;
                    seenTransferAddress = true;

                    try {
	                    Address entryPoint = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
	                    SymbolTable st = program.getSymbolTable();
	                    st.createLabel(entryPoint, "entry", SourceType.ANALYSIS);
	                    st.addExternalEntryPoint(entryPoint);
                    } catch (Exception e) {
                        log.appendException(e);
                    }

                    break;
                }
                default -> {
                    // known type, but not implemented, ignore and continue
                    final int rawLen = reader.readNextUnsignedByte() & 0xFF;
                    final int len = rawLen < 3 ? 256 + rawLen : rawLen;
                    offset += 1;
                    reader.readNextByteArray(len);
                    offset += len;
                    break;
                }
            }
        }
	}
}