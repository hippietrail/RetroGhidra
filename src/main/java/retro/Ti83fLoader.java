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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading TI83F .8xp files for Z80-based TI calculators such as the TI-84.
 *
 * TI83F is the magic number used in this exact format.
 * .8xp is the file extension used by this exact format.
 *
 * There's a whole bunch of related file formats, magic numbers, and file extensions.
 * It's hard to know which should be supported in the same loader.
 * So for now starting with the one used in the "Matrix Rain" YouTube video: https://github.com/bchiha/Ready-Z80/tree/main/17-TI-84_Programming
 */
public class Ti83fLoader extends AbstractProgramWrapperLoader {

    public static final String TI83F_NAME = "TI .8xp";
    public static final String TI83F_MAGIC = "**TI83F*";
    //public static final String TI83F_EXTENSION = ".8xp"; // "TI-83+ program"
    public static final byte[] TI83F_MAGIC_BYTES = { 0x1a, 0x0a };
    public static final int TI83F_OFF_COMMENT = 11;
    public static final int TI83F_COMMENT_LEN = 42;
    public static final int TI83F_HEADER_LEN = 55;
    public static final int TI83F_METADATA_LEN = 19;
    public static final int TI83F_FILETYPE_PROGRAM = 0x05;
    public static final int TI83F_FILETYPE_EDIT_LOCKED_PROGRAM = 0x06;
    public static final int TI83F_FILETYPE_FLASH_PROGRAM = 0x24;
    public static final int TI83F_PROGRAM_FLAG_ASM_SOURCE = 0x6cbb;
    public static final int TI83F_PROGRAM_FLAG_MACHINE_CODE = 0x6dbb;
    public static final int TI83F_START_ADDRESS = 0x9d95;

    @Override
    public String getName() {
        return TI83F_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        BinaryReader reader = new BinaryReader(provider, true);

        if (reader.length() < TI83F_HEADER_LEN + TI83F_METADATA_LEN) return loadSpecs;

        String magic = reader.readNextAsciiString(TI83F_MAGIC.length());
        if (!magic.equals(TI83F_MAGIC)) return loadSpecs;
        byte[] magicBytes = reader.readNextByteArray(TI83F_MAGIC_BYTES.length);
        if (!Arrays.equals(magicBytes, TI83F_MAGIC_BYTES)) return loadSpecs;
        // then a byte that is apparently always either 0x00 or 0x0a

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, true);

        // rest of "header", not including "metadata"

        reader.setPointerIndex(TI83F_OFF_COMMENT);
        String comment = reader.readNextAsciiString(TI83F_COMMENT_LEN);

        final int lengthOfVariableData = reader.readNextUnsignedShort();

        // "metadata" is a separate section than "header" in the docs

        final int alwaysBorD = reader.readNextUnsignedShort(); // aka "flag" and "unknown"
        // could throw an exception if this is not 0x0b or 0x0d
        final int variableDataLength = reader.readNextUnsignedShort(); // aka "body and checksum length"
        final int variableType = reader.readNextByte(); // almost always 0x06 for 'edit-locked' programs, 0x24 for 'flash' programs
        // could throw an exception if this is not 0x05, 0x06, or 0x24
        String variableName = reader.readNextAsciiString(8);

        final int version = reader.readNextByte(); // "present" if "flag" above is 0x0d
        final int flag = reader.readNextByte(); // "present" if other "flag" above is 0x0d
        // could throw an exception if this is not 0x80 or 0x00

        final int variableDataLengthDupe = reader.readNextUnsignedShort(); // same as "variableDataLength"
        // TODO throw an exception if this is not the same as "variableDataLength"

        // "body"

        final int bodyLength = reader.readNextUnsignedShort();

        if (variableType == TI83F_FILETYPE_FLASH_PROGRAM) {
            Msg.error(this, "TI 83F: flash apps are not supported"); // TODO throw an exception?
            return;
        } else if (variableType != TI83F_FILETYPE_PROGRAM && variableType != TI83F_FILETYPE_EDIT_LOCKED_PROGRAM) {
            Msg.error(this, "TI 83F: not a program or locked program"); // TODO throw an exception?
            return;
        }

        // program

        final int programFlag = reader.readNextUnsignedShort();
        if (programFlag != TI83F_PROGRAM_FLAG_MACHINE_CODE) {
            Msg.error(this, "TI 83F: Not a machine code program"); // TODO throw an exception?
            return;
        }

        Address startAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(TI83F_START_ADDRESS);
        SymbolTable st = program.getSymbolTable();

        program.getListing().setComment(startAddress, CodeUnit.PRE_COMMENT, "Name: " + variableName + "\n" + "Comment: " + comment);

        try {
            program.getMemory().createInitializedBlock(
                "ti",
                startAddress,
                MemoryBlockUtils.createFileBytes(program, provider, monitor),
                reader.getPointerIndex(),
                bodyLength - 2, // don't include the checksum
                false
            );

            st.createLabel(startAddress, "entry", SourceType.IMPORTED);
            st.addExternalEntryPoint(startAddress);
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}
