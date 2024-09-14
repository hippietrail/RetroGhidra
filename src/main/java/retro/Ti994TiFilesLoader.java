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
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading TI-99/4A TIFILES (XMODEM) files.
 */
public class Ti994TiFilesLoader extends AbstractProgramWrapperLoader {

    public static final String TIF_NAME = "TI-99/4A TIFILES";
    public static final int TIF_OFF_FILE_STATUS_FLAGS = 0x0a;
    public static final int TIF_OFF_NUM_L3_RECS = 0x0e;
    public static final int TIF_HEADER_LEN = 128;

    public static final int TIF_FLAG_DATA_PROGRAM = 1 << 0;
    public static final int TIF_FLAG_DIS_INT = 1 << 1;
    public static final int TIF_FLAG_PROTECTED = 1 << 3;
    public static final int TIF_FLAG_MODIFIED = 1 << 4;
    public static final int TIF_FLAG_NORMAL_EMULATED = 1 << 5;
    public static final int TIF_FLAG_FIX_VAR = 1 << 7;
	public static final int TIF_FLAG_TYPE_MASK = TIF_FLAG_DATA_PROGRAM | TIF_FLAG_DIS_INT | TIF_FLAG_FIX_VAR;
	public static final int TIF_DIS_FIX = 0;
	public static final int TIF_DIS_VAR = TIF_FLAG_FIX_VAR;
	public static final int TIF_INT_FIX = TIF_FLAG_DIS_INT;
	public static final int TIF_INT_VAR = TIF_FLAG_DIS_INT | TIF_FLAG_FIX_VAR;

    public static final String TIF_MAGIC = "\07TIFILES";

    public static final int TIF_LOAD_ADDR = 0x6000; // TODO this is a guess!

	@Override
	public String getName() {
		return TIF_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < TIF_HEADER_LEN) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, false);

        String magic = reader.readAsciiString(0, 8);
        if (!magic.equals(TIF_MAGIC)) return loadSpecs;

        // only bits 0, 1, 3, and 7 of file status flags are used according to https://hexbus.com/ti99geek/Doc/Ti99_dsk1_fdr.html
        // but 'Archiver.bin' has the right signature but 0b0001_0001 in the file status flags
        // more bits are actually defined according to https://www.ninerpedia.org/wiki/TIFILES_format
         int statusFlags = reader.readUnsignedByte(TIF_OFF_FILE_STATUS_FLAGS);
         if ((statusFlags & ~0b1011_1011) != 0) return loadSpecs;

        // check that offset 0x20 up to 0x80 are all 0 or [0xca, 0x53]
        // https://hexbus.com/ti99geek/Doc/Ti99_dsk1_fdr.html
        // TELCO fills these bytes up to 0x7f with 0xca53.
        for (int i = 0x20; i < 0x80; i += 2) {
            int val = reader.readUnsignedShort(i);
            if (val != 0 && val != 0xca53) return loadSpecs;
        }

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("9900:BE:16:default", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		Memory memory = program.getMemory();
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		Address headerAddress = AddressSpace.OTHER_SPACE.getAddress(0x0000);
        AddressSpace addresssSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address loadAddress = addresssSpace.getAddress(TIF_LOAD_ADDR);

		try {
			memory.createInitializedBlock(
				"TIFILES",
				headerAddress,
				fileBytes,
				0,
                TIF_HEADER_LEN,
				false);

            commentHeader(program, headerAddress, provider);

            // last letter of the filename to determine where to load a file:
            // xxxxxC.BIN - loads as CPU cartridge ROM at >6000
            // xxxxxD.BIN - loads as banked CPU cartridge ROM at >6000, second bank (such as Extended BASIC or AtariSoft carts)
            // xxxxxG.BIN - loads as GROM cartridge at >6000 in GROM space
            // xxxxx3.BIN - Classic99 extension, loads as a 379/Jon Guidry style cartridge ROM at >6000
            memory.createInitializedBlock(
                "TMS9900",
                loadAddress,
                fileBytes,
                TIF_HEADER_LEN,
                provider.length() - TIF_HEADER_LEN,
                false);

                Ti994LoaderHelper.commentCode(program, loadAddress, provider, TIF_HEADER_LEN);
            } catch (Exception e) {
			log.appendException(e);
		}
	}

    void commentHeader(Program program, Address headerAddress, ByteProvider provider) throws CodeUnitInsertionException, IOException {
        BinaryReader reader = new BinaryReader(provider, true); // little-endian needed for 1 header field!
        Listing listing = program.getListing();
        Address ha = headerAddress;
        listing.createData(ha, PascalString255DataType.dataType);
        listing.setComment(ha, CodeUnit.EOL_COMMENT, "Signature");
        ha = ha.add(8);
        listing.createData(ha, UnsignedShortDataType.dataType);
        listing.setComment(ha, CodeUnit.EOL_COMMENT, "Total number of sectors");
        ha = ha.add(2);
        listing.createData(ha, ByteDataType.dataType);
        final int flags = reader.readUnsignedByte(TIF_OFF_FILE_STATUS_FLAGS) & 0xff;
        String flagsStr = "Flags: "
            + ((flags & TIF_FLAG_DATA_PROGRAM) == 0 ? "Data" : "Program")
            + ", "
            + ((flags & TIF_FLAG_DIS_INT) == 0 ? "DIS" : "INT") // "Display", "Internal", aka "ASCII", "Binary"
            + ", "
            + ((flags & TIF_FLAG_PROTECTED) == 0 ? "Unp" : "P")
            + "rotected,\n"
            + ((flags & TIF_FLAG_MODIFIED) == 0 ? "Unm" : "M") // new field not in FIAD
            + "odified, "
            + ((flags & TIF_FLAG_NORMAL_EMULATED) == 0 ? "Normal" : "emulated File") // new field: https://www.ninerpedia.org/wiki/Emulate_File_format
            + ", "
            + ((flags & TIF_FLAG_FIX_VAR) == 0 ? "Fixed" : "Variable") // "FIX", "VAR")
            + " length records";
        final int type = flags & TIF_FLAG_TYPE_MASK;
        switch (type) {
            case TIF_FLAG_DATA_PROGRAM:
                flagsStr += "\nType: PROGRAM";
                break;
            case TIF_DIS_FIX:
                flagsStr += "\nType: DIS/FIX";
                break;
            case TIF_DIS_VAR:
                flagsStr += "\nType: DIS/VAR";
                break;
            case TIF_INT_FIX:
                flagsStr += "\nType: INT/FIX";
                break;
            case TIF_INT_VAR:
                flagsStr += "\nType: INT/VAR";
                break;
            default:
                flagsStr += "\nType: ???";
        }
        listing.setComment(ha, CodeUnit.EOL_COMMENT, flagsStr);
        ha = ha.add(1);
        listing.createData(ha, ByteDataType.dataType);
        listing.setComment(ha, CodeUnit.EOL_COMMENT, "#Rec/Sect");
        ha = ha.add(1);
        listing.createData(ha, ByteDataType.dataType);
        listing.setComment(ha, CodeUnit.EOL_COMMENT, "EOF offset");
        ha = ha.add(1);
        listing.createData(ha, ByteDataType.dataType);
        listing.setComment(ha, CodeUnit.EOL_COMMENT, "Rec length");
        ha = ha.add(1);
        listing.createData(ha, UnsignedShortDataType.dataType);
        // this field is actually little-endian, let's convert it and add it to the comment
        final int l3r = reader.readUnsignedShort(TIF_OFF_NUM_L3_RECS);
        listing.setComment(ha, CodeUnit.EOL_COMMENT, "#Level-3 records: " + l3r); // https://www.ninerpedia.org/wiki/TIFILES_format#Level-3_records
        ha = ha.add(2);
        listing.createData(ha, new ArrayDataType(UnsignedShortDataType.dataType, 0x70 / 2));
        listing.setComment(ha, CodeUnit.EOL_COMMENT, "unused");

        // TODO creation and update times are present if the extended header field is set to 0xffff
        // TODO I'm not sure about when the filename and MXT fields are present

        // listing.createData(ha, new StringDataType(), 10);
        // listing.setComment(ha, CodeUnit.EOL_COMMENT, "File name");
        // ha = ha.add(10);
        // listing.createData(ha, ByteDataType.dataType);
        // listing.setComment(ha, CodeUnit.EOL_COMMENT, "MXT");
        // ha = ha.add(1);
        // listing.createData(ha, ByteDataType.dataType);
        // listing.setComment(ha, CodeUnit.EOL_COMMENT, "reserved");
        // ha = ha.add(1);
        // listing.createData(ha, UnsignedShortDataType.dataType);
        // listing.setComment(ha, CodeUnit.EOL_COMMENT, "Extended header");
        // ha = ha.add(2);
        // listing.createData(ha, UnsignedIntegerDataType.dataType);
        // listing.setComment(ha, CodeUnit.EOL_COMMENT, "Creation time");
        // ha = ha.add(4);
        // listing.createData(ha, UnsignedIntegerDataType.dataType);
        // listing.setComment(ha, CodeUnit.EOL_COMMENT, "Update time");
        // ha = ha.add(4);
        // // this should actually be an array of ? bytes up until offset 0x80
        // listing.createData(ha, UnsignedShortDataType.dataType);
        // listing.setComment(ha, CodeUnit.EOL_COMMENT, "Unused");
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
