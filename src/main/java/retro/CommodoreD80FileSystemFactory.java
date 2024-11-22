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
import java.util.Arrays;
import java.util.stream.IntStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CommodoreD80FileSystemFactory implements GFileSystemFactoryByteProvider<CommodoreD80FileSystem>, GFileSystemProbeByteProvider {

	public static final int D80_FILE_SIZE = 533248;
    public static final int D80_TRACK_39_OFFSET = 0x44E00;

    @Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

        if (byteProvider.length() != D80_FILE_SIZE) return false;

        BinaryReader reader = new BinaryReader(byteProvider, true);
        reader.setPointerIndex(D80_TRACK_39_OFFSET);

        // T/S pointer to first BAM sector (38/0)
        if (reader.readNextUnsignedShort() != 38) return false;
        // $43 'C' is for DOS format version
        if (reader.readNextUnsignedByte() != 'C') return false;
        // Reserved
        if (reader.readNextUnsignedByte() != 0) return false;
        // Unused
        int unused = reader.readNextUnsignedShort();
        // not always 0: https://milasoft64.itch.io/petaxian = 0x0xA0A0

        // $06-$16	Disk name, padded with 0xA0
        final byte[] name = reader.readNextByteArray(0x11);
        int len = -1;
        for (int i = 0; i < name.length; i++) {
        	int c = name[i] & 0xff;
            if (len == -1) {
                if (c == 0xA0) {
                	len = i;
                	break;
                } else if (!isPrintable(name[i])) return false;
            } else if (c != 0xA0) return false;
        }
        String nameString = new String(Arrays.copyOfRange(name, 0, len));
        // may be empty: https://milasoft64.itch.io/petaxian 
        //Msg.info(this, "D80 file format has disk name: '" + nameString + "', image file name: '" + byteProvider.getName() + "'");

        // 0xA0
        if (reader.readNextUnsignedByte() != 0xA0) return false;
        // Disk ID
        reader.readNextShort(); // any value will do
        // 0xA0
        if (reader.readNextUnsignedByte() != 0xA0) return false;
        // DOS version bytes "2C"
        final String dosVersionString = reader.readNextAsciiString(2);
        if (!dosVersionString.equals("2C")) return false;
        // $1D-$20 0xA0
        final byte[] a0Bytes = reader.readNextByteArray(4);
        // not always 4x 0xA0: https://milasoft64.itch.io/petaxian = 4x 0x00
        if (IntStream.range(0, a0Bytes.length).anyMatch(i -> (a0Bytes[i] & 0xff) != 0xA0)) {
            if (IntStream.range(0, a0Bytes.length).anyMatch(i -> (a0Bytes[i] & 0xff) != 0x00)) return false;
        }
        // $21-$FF Unused
        final byte[] unusedBytes = reader.readNextByteArray(0xFF - 0x21 + 1);
        if (IntStream.range(0, unusedBytes.length).anyMatch(i -> unusedBytes[i] != 0x00)) return false;

        return true;
    }

    // May have to customize for PETSCII etc
	private boolean isPrintable(final int dosFormatVersion) {
		return dosFormatVersion >= ' ' && dosFormatVersion <= '~';
	}

    @Override
    public GFileSystem create(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {

        CommodoreD80FileSystem fs = new CommodoreD80FileSystem(fsFSRL, provider);
        fs.mount(monitor);
        return fs;
    }

}
