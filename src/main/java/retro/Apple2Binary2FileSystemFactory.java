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

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Apple2Binary2FileSystemFactory implements GFileSystemFactoryByteProvider<Apple2Binary2FileSystem>, GFileSystemProbeBytesOnly {

    private static final int BIN2_START_BYTES_REQUIRED = 3;

    private static final String BIN2_MAGIC = "\nGL"; // Binary II was developed by Gary B. Little

    @Override
    public int getBytesRequired() {
        return BIN2_START_BYTES_REQUIRED;
    }

    @Override
    public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
        return startBytes[0] == BIN2_MAGIC.charAt(0) && startBytes[1] == BIN2_MAGIC.charAt(1) && startBytes[2] == BIN2_MAGIC.charAt(2);
    }

    @Override
    public GFileSystem create(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {

        Apple2Binary2FileSystem fs = new Apple2Binary2FileSystem(fsFSRL, provider);
        fs.mount(monitor);
        return fs;
    }

}
