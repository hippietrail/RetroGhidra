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

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BinHex4FileSystemFactory implements GFileSystemFactoryByteProvider<BinHex4FileSystem>, GFileSystemProbeBytesOnly {

    private static final String BH_MAGIC = "(This file must be converted with BinHex 4.0)";
    public static final int BH_START_BYTES_REQUIRED = BH_MAGIC.length();// + 43; // TODO share with BinHex4FileSystem.java somehow

    @Override
    public int getBytesRequired() {
        return BH_START_BYTES_REQUIRED;
    }

    @Override
    public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
        byte[] magicBytes = BH_MAGIC.getBytes();
        if (startBytes.length < magicBytes.length) return false;
        return Arrays.equals(Arrays.copyOfRange(startBytes, 0, magicBytes.length), magicBytes);
    }

@Override
    public GFileSystem create(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {

        BinHex4FileSystem fs = new BinHex4FileSystem(fsFSRL, provider);
        fs.mount(monitor);
        return fs;
    }

}
