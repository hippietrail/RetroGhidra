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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class BnyEntry {
	public final String name;
	public final long offset;
	public final long size;
	public final int filetypeCode;
	public final int auxTypeCode;

	BnyEntry(String name, long offset, long size,
			int filetypeCode, int auxTypeCode) {
		this.name = name;
		this.offset = offset;
		this.size = size;

		this.filetypeCode = filetypeCode;
		this.auxTypeCode = auxTypeCode;
	}
}

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = "bny", // ([a-z0-9]+ only)
		description = "Apple II Binary II", factory = Apple2Binary2FileSystemFactory.class)
public class Apple2Binary2FileSystem extends AbstractFileSystem<BnyEntry> {

	// https://wiki.preterhuman.net/Apple_II_Binary_File_Format
	public static final int BNY_OFF_FILETYPE_CODE = 4;
	public static final int BNY_OFF_AUX_TYPE_CODE = 5; // 16-bit
	public static final int BNY_OFF_EOF_POSITION = 20; // 24-bit
	public static final int BNY_OFF_FILENAME_LEN = 23; // (or partial pathname)
	public static final int BNY_OFF_FILENAME = 24; // 64 bytes (or partial pathname)
	public static final int BNY_HEADER_LEN = 128;

	public static final int BNY_MAX_FILENAME_LEN = 64;

	private ByteProvider provider;

	/**
	 * File system constructor.
	 * 
	 * @param fsFSRL The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	public Apple2Binary2FileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		super(fsFSRL, FileSystemService.getInstance());
		this.provider = provider;
	}

	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 * @throws IOException 
	 */
	public void mount(TaskMonitor monitor) throws IOException {
		monitor.setMessage("Opening " + Apple2Binary2FileSystem.class.getSimpleName() + "...");

	    BinaryReader reader = new BinaryReader(provider, true);
		long off = 0;
		int i = 0;
		while (off < reader.length() && monitor.isCancelled() == false) {
			final int filetypeCode = reader.readUnsignedByte(off + BNY_OFF_FILETYPE_CODE);
			final int auxTypeCode = reader.readUnsignedShort(off + BNY_OFF_AUX_TYPE_CODE);
			// 'end of file position' is what it's called in the documentation, but it is the file length
			// this can seem confusing today but in that era files were often measured in sectors or blocks
			final long eofPos = reader.readUnsignedValue(off + BNY_OFF_EOF_POSITION, 3);

			final int filenameLen = reader.readUnsignedByte(off + BNY_OFF_FILENAME_LEN);
			final String filename = reader.readAsciiString(off + BNY_OFF_FILENAME, filenameLen);

			long dataBlocks = eofPos / 128;
			if (eofPos % 128 != 0) dataBlocks++;
			long endOffset = off + BNY_HEADER_LEN + dataBlocks * 128;

			// TODO would be nice to have an option to include the headers or not
			// NOTE that in BNY the magic word exists in every entry
			// NOTE there are only entry headers, there is no overall header
			// NOTE so an archive is simply a concatenation of files with entry headers
			String filetype = (filetypeCode == 4) ? "text" : (filetypeCode == 6) ? "binary" : "0x" + Integer.toHexString(filetypeCode);
			Msg.info(this, i + ": " + filename + " ; type:" + filetype + " ; offset:0x" + Long.toHexString(off) + " ; aux:0x" + Integer.toHexString(auxTypeCode));
			
			fsIndex.storeFile(
					filename,					// path
					i++,						// file index
					false,						// is directory
					eofPos,						// length

					new BnyEntry(
						filename,				// name
						off + BNY_HEADER_LEN,	// offset
						eofPos,					// name is confusing, it's just the size

						filetypeCode,			// filetype code
						auxTypeCode				// aux type code
					)
			);

			if (filetypeCode == 6) {
				// a NAPS suffix is '#' followed by 6 hex digits, the first two are the filetype, the other four are the aux
				// e.g. '#069e00' means filetype 6, aux 0x9e00
				String napsSuffix = String.format("#06%04x", auxTypeCode);
				//Msg.info(this, napsSuffix + " ->" + i + ": " + filename + " : " + filetype + " : 0x" + Long.toHexString(off));

				fsIndex.storeFile(
						filename + napsSuffix,		// path
						i++ + 2000,					// file index
						false,						// is directory
						eofPos,						// name is confusing, it's just the size

						new BnyEntry(
							filename + napsSuffix,	// name
							off + BNY_HEADER_LEN,	// offset
							eofPos,					// length, as above

							filetypeCode,			// filetype code
							auxTypeCode				// aux type code
						)
				);
			}

			off = endOffset;
			// i++;
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndex.clear();
		if (provider != null) {
			provider.close();
			provider = null;
		}
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		BnyEntry metadata = fsIndex.getMetadata(file);
		return (metadata != null)
				? new ByteProviderWrapper(provider, metadata.offset, metadata.size, file.getFSRL())
				: null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		BnyEntry metadata = fsIndex.getMetadata(file);
		FileAttributes result = new FileAttributes();
		if (metadata != null) {
			result.add(FileAttributeType.NAME_ATTR, metadata.name);
			result.add(FileAttributeType.SIZE_ATTR, metadata.size);
			String filetypeString = (metadata.filetypeCode == 4) ? "text" : (metadata.filetypeCode == 6) ? "binary" : "0x" + Integer.toHexString(metadata.filetypeCode);
			String auxTypeString = (metadata.filetypeCode == 6) ? String.format("0x%04x", metadata.auxTypeCode) : Integer.toString(metadata.auxTypeCode);
			result.add("Filetype", filetypeString);
			result.add("Aux Type", auxTypeString);
		}
		return result;
	}

}
