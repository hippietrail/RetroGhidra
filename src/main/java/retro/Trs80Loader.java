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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading TRS-80 /CMD files, /REL files too?
 */
public class Trs80Loader extends AbstractProgramWrapperLoader {

    public final static String TRS_NAME = "TRS-80 /CMD";
    public static final int TRS_TYPE_DATA = 0x01;       // "object code" (load block) - aka "data"
    public static final int TRS_TYPE_JUMP = 0x02;       // "transfer address" - aka "jump address"
    public static final int TRS_TYPE_END = 0x04;        // "end of partitioned data set member"
    public static final int TRS_TYPE_HEADER = 0x05;     // "load module header" - aka "header"
    public static final int TRS_TYPE_MEMBER = 0x06;     // "partitioned data set member"
    public static final int TRS_TYPE_PATCH = 0x07;      // "patch name header"
    public static final int TRS_TYPE_ISAM = 0x08;       // "ISAM directory entry"
    public static final int TRS_TYPE_END_ISAM = 0x0a;   // "end of ISAM directory"
    public static final int TRS_TYPE_PDS = 0x0c;        // "PDS directory entry"
    public static final int TRS_TYPE_END_PDS = 0x0e;    // "end of PDS directory"
    public static final int TRS_TYPE_YANK = 0x10;       // "yanked load block"
    public static final int TRS_TYPE_COPYRIGHT = 0x1f;  // "copyright block"

    // TODO make optional, how to add as comment / program name in Ghidra?
    String filename = "";

	@Override
	public String getName() {
        return TRS_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

        BinaryReader reader = new BinaryReader(provider, true);

        int byte_index = 0;
        int tag_index = 0;
        boolean seen_jump = false;
        loop: while (true) {
            if (byte_index + 1 > reader.length()) {
                if (seen_jump) {
                    Msg.info(this, "hit EOF after processing load records, all went well");
                    break loop;
                }
				Msg.info(this, "hit EOF before processing a 'jump' record, maybe not a TRS-80 file");
				return loadSpecs;
            }
            byte record_type = (byte) reader.readNextUnsignedByte();
            Msg.info(this, "0x" + HexFormat.of().toHexDigits(byte_index) + " record_type[" + tag_index + "] = 0x" + HexFormat.of().toHexDigits(record_type));
            byte_index++;
            tag_index++;
            // Any code above X'1F' is invalid as a record type.  In addition, any  code
            // not listed in the above table is reserved for  future  use
            switch (record_type) {
                // this is basically 'if record not known type'
                case TRS_TYPE_DATA, TRS_TYPE_JUMP, TRS_TYPE_END, TRS_TYPE_HEADER,
                    TRS_TYPE_MEMBER, TRS_TYPE_PATCH, TRS_TYPE_ISAM,
                    TRS_TYPE_END_ISAM, TRS_TYPE_PDS, TRS_TYPE_END_PDS, 
                    TRS_TYPE_YANK, TRS_TYPE_COPYRIGHT -> { break; }
                default -> {
                    if (seen_jump) {
                        Msg.info(this, "  hit garbage after processing load records, all went well");
                        break loop;
                    }
					Msg.info(this, "  unknown record - not a TRS-80 file");
                    return loadSpecs;
                }
            }

            // this is the real switch
            switch (record_type) {
                case TRS_TYPE_DATA -> { /* 1 */
                    Msg.info(this, "  data / object code / load block");
                    if (byte_index + 2 > reader.length()) return loadSpecs;
                    int rawLen = reader.readNextUnsignedByte() & 0xFF;
                    int len = rawLen < 3 ? 256 + rawLen : rawLen;
                    Msg.info(this, "    len = " + rawLen + " -> " + len);
                    byte_index++;
                    // first 2 bytes of the len bytes following are the load address
                    if (byte_index + len > reader.length()) return loadSpecs;
                    int address = reader.readNextUnsignedShort();
                    reader.readNextByteArray(len - 2);
                    Msg.info(this, "    load address = 0x" + Integer.toHexString(address));
                    byte_index += len;
                    break;
                }
                case TRS_TYPE_JUMP -> { /* 2 */
                    if (byte_index + 2 > reader.length()) return loadSpecs;
                    final int len = reader.readNextUnsignedByte() & 0xFF;
                    Msg.info(this, "  jump [" + len + "]");
                    byte_index += 1;
                    if (byte_index + len > reader.length()) return loadSpecs;
                    int address = reader.readNextUnsignedShort();
                    Msg.info(this, "    address = 0x" + Integer.toHexString(address));
                    if (len != 2) {
                        Msg.info(this, "  warning - jump length is not 2 bytes");
                        reader.readNextByteArray(len - 2);
                    }
                    byte_index += len;
                    seen_jump = true;
                    break;
                }
                case TRS_TYPE_HEADER -> { /* 5 */
                    if (byte_index + 1 > reader.length()) return loadSpecs;
                    final int rawLen = reader.readNextUnsignedByte() & 0xFF;
                    final int len = rawLen < 3 ? 256 + rawLen : rawLen;
                    Msg.info(this, "  header [" + rawLen + " -> " + len + "]");
                    byte_index += 1;
                    if (byte_index + len > reader.length()) return loadSpecs;
                    this.filename = reader.readNextAsciiString(len);
                    Msg.info(this, "   filename = '" + this.filename + "'");
                    byte_index += len;
                    break;
                }
                default -> {
                    Msg.info(this, "  known type, but not implemented, ignore and continue");
                    break loop;
                }
            }
        }

        List<QueryResult> queryResults = QueryOpinionService.query(getName(), "z80", null);
		queryResults.stream().map(result -> new LoadSpec(this, 0, result)).forEach(loadSpecs::add);

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, true);

        int ramNum = 0;
        
        int byte_index = 0;
        boolean seen_jump = false;
        loop: while (true) {
            if (byte_index + 1 > reader.length()) {
                // EOF and we've seen a jump, all went well
                if (seen_jump) break loop;
                return;
            }

            int record_type = reader.readNextUnsignedByte();
            byte_index++;

            switch (record_type) {
                case TRS_TYPE_DATA, TRS_TYPE_JUMP, TRS_TYPE_END, TRS_TYPE_HEADER,
                    TRS_TYPE_MEMBER, TRS_TYPE_PATCH, TRS_TYPE_ISAM,
                    TRS_TYPE_END_ISAM, TRS_TYPE_PDS, TRS_TYPE_END_PDS, 
                    TRS_TYPE_YANK, TRS_TYPE_COPYRIGHT -> { break; }
                default -> {
                    // trailing garbage but we've seen a jump, all went well
                    if (seen_jump) break loop;
                    return;
                }
            }

            switch (record_type) {
                case TRS_TYPE_DATA -> { /* 1 */
                    final int rawLen = reader.readNextUnsignedByte() & 0xFF;
                    final int len = rawLen < 3 ? 256 + rawLen : rawLen;
                    byte_index++;
                    final int address = reader.readNextUnsignedShort();
                    byte_index += 2;

                    try {
                        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
                        FileBytes bytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

                        MemoryBlock block = program.getMemory().createInitializedBlock(
                            "RAM " + ramNum++,  // name
                            start,              // start
                            bytes,              // filebytes
                            byte_index,         // offset
                            len - 2,            // size
                            false);             // overlay
                        block.setWrite(true);
                    } catch (Exception e) {
                        log.appendException(e);
                    }

                    reader.readNextByteArray(len - 2);
                    byte_index += len - 2;
                    break;
                }
                case TRS_TYPE_JUMP -> { /* 2 */
                    // jump does not use the special values, it should always be '2'
                    final int len = reader.readNextUnsignedByte() & 0xFF;
                    byte_index += 1;
                    final int address = reader.readNextUnsignedShort();
                    byte_index += len;
                    seen_jump = true;

                    try {
	                    Address entry_point = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
	                    SymbolTable st = program.getSymbolTable();
	                    st.createLabel(entry_point, "entry", SourceType.ANALYSIS);
	                    st.addExternalEntryPoint(entry_point);
                    } catch (Exception e) {
                        log.appendException(e);
                    }

                    break;
                }
                default -> { /* known type, but not implemented */
                    final int rawLen = reader.readNextUnsignedByte() & 0xFF;
                    final int len = rawLen < 3 ? 256 + rawLen : rawLen;
                    byte_index += 1;
                    reader.readNextByteArray(len);
                    byte_index += len;
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
}