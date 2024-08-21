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
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading Apple II Binary II files.
 */
public class Apple2Binary2Loader extends AbstractProgramWrapperLoader {

	public static final String BIN2_NAME = "Apple II Binary II";
	public static final int BIN2_HEADER_LEN = 128;
	public static final String BIN2_MAGIC = "\nGL"; // Binary II was developed by Gary B. Little
	
	public static final int BIN2_OFF_ACCESS_CODE = 3;
	public static final int BIN2_OFF_FILETYPE_CODE = 4;
	public static final int BIN2_OFF_AUX_TYPE_CODE = 5; // 16-bit
	public static final int BIN2_OFF_STORAGE_TYPE_CODE = 7;
	public static final int BIN2_OFF_SIZE_IN_BLOCKS = 8; // 16-bit
	public static final int BIN2_OFF_ID_BYTE = 18; // always 0x00
	public static final int BIN2_OFF_EOF_POSITION = 20; // 24-bit
	public static final int BIN2_OFF_FILENAME_LEN = 23; // (or partial pathname)
	public static final int BIN2_OFF_FILENAME = 24; // 64 bytes (or partial pathname)
	public static final int BIN2_OFF_RESERVED_2 = 88;
	public static final int BIN2_OFF_PRODOS_16_FILETYPE = 111; // should all be 0
	public static final int BIN2_OFF_SPACE_NEEDED = 117;
	public static final int BIN2_OFF_OSTYPE = 121; // we'll only accept ProDOS and DOS 3
	public static final int BIN2_OFF_NATIVE_FILETYPE_CODE = 122; // 16-bit, used by DOS 3
	public static final int BIN2_OFF_DATA_FLAGS = 125;
	public static final int BIN2_OFF_VERSION = 126; // only 0 & 1
	public static final int BIN2_OFF_NUM_FILES_TO_FOLLOW = 127; // we'll only work with single-file archives
	public static final int BIN2_ID_BYTE = 0x02;
	public static final int BIN2_FILETYPE_TXT = 0x04;
	public static final int BIN2_FILETYPE_BIN = 0x06;
	public static final int BIN2_FILETYPE_INT = 0xfa;
	public static final int BIN2_FILETYPE_BAS = 0xfc;
	public static final int BIN2_FILETYPE_REL = 0xfe;
	public static final int BIN2_FILETYPE_SUBDIR = 15; // 0x0f
	public static final int BIN2_MAX_FILENAME_LEN = 64;
	public static final int BIN2_RESERVED_2_LEN = 23;
	public static final int BIN2_PRODOS_16_FIELDS_LEN = 6;
	public static final int BIN2_OSTYPE_PRODOS_OR_SOS = 0x00;
	public static final int BIN2_OSTYPE_DOS3 = 0x01;
	public static final int BIN2_DATA_FLAG_COMPRESSED = 1 << 7;
	public static final int BIN2_DATA_FLAG_ENCRYPTED = 1 << 6;
	public static final int BIN2_DATA_FLAG_PACKED = 1 << 0;

	@Override
	public String getName() {
		return BIN2_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

        BinaryReader reader = new BinaryReader(provider, true);

		Long fileLength = reader.length();
		if (fileLength < BIN2_HEADER_LEN) return loadSpecs;
		String magic = reader.readAsciiString(0, 3);
		if (!magic.equals(BIN2_MAGIC)) return loadSpecs;
		// magic word is small, check some other fields to avoid false positives
		if (reader.readByte(BIN2_OFF_ID_BYTE) != BIN2_ID_BYTE) return loadSpecs;
		// filename has maximum length
		if (reader.readByte(BIN2_OFF_FILENAME_LEN) > BIN2_MAX_FILENAME_LEN) return loadSpecs;

		byte[] reserved2 = reader.readByteArray(BIN2_OFF_RESERVED_2, BIN2_RESERVED_2_LEN);
		if (IntStream.range(0, BIN2_RESERVED_2_LEN).map(i -> reserved2[i]).anyMatch(i -> i != 0x00)) return loadSpecs;
		// ProDOS 16 was a temporary OS for the IIGS and these fields were never used
		byte[] prodos16Fields = reader.readByteArray(BIN2_OFF_PRODOS_16_FILETYPE, BIN2_PRODOS_16_FIELDS_LEN);
		if (IntStream.range(0, BIN2_PRODOS_16_FIELDS_LEN).map(i -> prodos16Fields[i]).anyMatch(i -> i != 0x00)) return loadSpecs;
		
		final int osType = reader.readByte(BIN2_OFF_OSTYPE);
		if (osType != BIN2_OSTYPE_PRODOS_OR_SOS && osType != BIN2_OSTYPE_DOS3) return loadSpecs;
		if (reader.readUnsignedByte(BIN2_OFF_VERSION) > 1) return loadSpecs;

		// we could check FILETYPE_CODE == BIN2_FILETYPE_BIN and NUM_FILES_TO_FOLLOW == 0 to see if there's more than one file
		// and only handle Binary II archives with a single file since it's a useful wrapper providing the missing fields
		// but for now we're going to go through and find the first binary entry

		int off = 0;
		while (true) {
			if (reader.readUnsignedByte(off + BIN2_OFF_FILETYPE_CODE) == BIN2_FILETYPE_BIN) {
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
				break;
			}
			final int eofPos = reader.readUnsignedShort(off + BIN2_OFF_EOF_POSITION)
				| (reader.readUnsignedByte(off + BIN2_OFF_EOF_POSITION + 2) << 16);
			int dataBlocks = eofPos / 128;
			if (eofPos % 128 != 0) dataBlocks++;

			int endOffset = off +BIN2_HEADER_LEN + dataBlocks * 128;
			if (endOffset >= fileLength) break;
			off = endOffset;
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

        BinaryReader reader = new BinaryReader(provider, true);

		int off = 0;
		int binNum = 0;

		while (true) {
			final int filetypeCode = reader.readUnsignedByte(off + BIN2_OFF_FILETYPE_CODE);
			final int auxTypeCode = reader.readUnsignedShort(off + BIN2_OFF_AUX_TYPE_CODE);
			final int eofPos = reader.readUnsignedShort(off + BIN2_OFF_EOF_POSITION)
				| (reader.readUnsignedByte(off + BIN2_OFF_EOF_POSITION + 2) << 16);
			final int dataFlags = reader.readUnsignedByte(off + BIN2_OFF_DATA_FLAGS);

			// text is not interesting, we definitely care about binaries, the others are rare
			// so let's dump their info if we see them
			if (filetypeCode != BIN2_FILETYPE_TXT) {
				if (filetypeCode == BIN2_FILETYPE_BIN) {
					Msg.info(this, "FILETYPE_CODE == BIN: DATA_FLAGS == 0x" + Integer.toHexString(dataFlags));
				} else {
					Msg.info(this, "FILETYPE_CODE == " + filetypeCode);

					final int accessCode = reader.readUnsignedByte(off + BIN2_OFF_ACCESS_CODE);
					final int storageTypeCode = reader.readUnsignedByte(off + BIN2_OFF_STORAGE_TYPE_CODE);
					final int sizeInBlocks = reader.readUnsignedShort(off + BIN2_OFF_SIZE_IN_BLOCKS);
					final int filenameLen = reader.readUnsignedByte(off + BIN2_OFF_FILENAME_LEN);
					final String filename = reader.readAsciiString(off + BIN2_OFF_FILENAME, filenameLen);
					final long spaceNeeded = reader.readUnsignedInt(off + BIN2_OFF_SPACE_NEEDED);
						
					Msg.info(this, "Access code: " + accessCode);
					Msg.info(this, "Filetype code: " + filetypeCode);
					Msg.info(this, "Aux type code: " + auxTypeCode);
					Msg.info(this, "Storage type code: " + storageTypeCode);
					Msg.info(this, "Size in 512-byte blocks: " + sizeInBlocks + " blocks, " + sizeInBlocks * 512 + " bytes");
					Msg.info(this, "EOF position: " + eofPos);
					Msg.info(this, "Filename length: " + filenameLen);
					Msg.info(this, "Filename: " + filename);
					Msg.info(this, "Space needed: " + spaceNeeded + " 512-byte blocks, " + spaceNeeded * 512 + " bytes\n");
				}
				if (filetypeCode == BIN2_FILETYPE_BIN) {
					if (dataFlags != 0x00) {
						Msg.info(this, "DATA_FLAGS != 0x00: " + Integer.toHexString(dataFlags) + ", compression, encryption, and packing not supported");
					} else {
						final int startOffset = off + BIN2_HEADER_LEN;
						final int loadAndJumpAddress = auxTypeCode;

						try {
							Address startAndEntryPoint = program.getAddressFactory().getDefaultAddressSpace().getAddress(loadAndJumpAddress);
							
							program.getMemory().createInitializedBlock(
								"CODE",  														// name
								startAndEntryPoint,              								// start
								MemoryBlockUtils.createFileBytes(program, provider, monitor),	// filebytes
								startOffset,             										// offset
								eofPos, 											            // size
								false
							).setWrite(true);

							SymbolTable st = program.getSymbolTable();
							st.createLabel(startAndEntryPoint, "entry", SourceType.ANALYSIS);
							st.addExternalEntryPoint(startAndEntryPoint);
						} catch (Exception e) {
							log.appendException(e);
						}

						return;
					}
					binNum++;
				}
			}
			int dataBlocks = eofPos / 128;
			if (eofPos % 128 != 0) dataBlocks++;

			int endOffset = off +BIN2_HEADER_LEN + dataBlocks * 128;

			if (endOffset >= provider.length()) break;
			off = endOffset;
		}
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
