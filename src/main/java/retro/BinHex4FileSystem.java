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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.FileSystemService.DerivedStreamPushProducer;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class HqxEntry {
    // standard attributes
    String name;
    long size;

    HqxEntry(String name, long size) {
        this.name = name;
        this.size = size;
    }
}

/**
 * A {@link GFileSystem} implementation of BinHex 4.0 (.hqx).
 */
@FileSystemInfo(type = BinHex4FileSystem.FS_TYPE, description = "BinHex 4.0",
        factory = BinHex4FileSystemFactory.class)
public class BinHex4FileSystem extends AbstractFileSystem<HqxEntry> {

    public static final String FS_TYPE = "hqx"; // ([a-z0-9]+ only)

    private static final String ALPHABET = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

    private ByteProvider provider;

    /**
     * File system constructor.
     * 
     * @param fsFSRL The root {@link FSRL} of the file system.
     * @param provider The file system provider.
     */
    public BinHex4FileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
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
        monitor.setMessage("Opening " + BinHex4FileSystem.class.getSimpleName() + "...");

        BinaryReader reader = new BinaryReader(provider, true);

        // TODO
        fsIndex.storeFile(
            "unbinhexed", 0,    // path, unique id
            false, 6969,        // isDirectory, size
            new HqxEntry(
                "unbinhexed",   // name
                6969            // size
            )
        );
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
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
        FSRL payloadFSRL = file.getFSRL();
        FSRL containerFSRL = provider.getFSRL();
        String derivedFileName = "decoded";
        long derivedFileSize = -1;

        // Define the DerivedStreamPushProducer separately
        DerivedStreamPushProducer producer = new DerivedStreamPushProducer() {
            @Override
            public void push(OutputStream os) throws IOException, CancelledException {
                // Implement your decoding logic here
                // try (InputStream inputStream = provider.getInputStream(0)) {
                //     // Read and decode the input bytes, then write the decoded bytes to the OutputStream
                //     byte[] buffer = new byte[8192];
                //     int bytesRead;
                //     while ((bytesRead = inputStream.read(buffer)) != -1) {
                //         // Decode the buffer content
                //         // byte[] decodedBytes = decode(buffer, bytesRead);
                //         /*// Example decode method that transforms the bytes
                //         private byte[] decode(byte[] input, int length) {
                //             // Implement your decoding logic here
                //             byte[] output = new byte[length];
                //             for (int i = 0; i < length; i++) {
                //                 output[i] = (byte) (input[i] ^ 0xFF); // Example transformation (XOR with 0xFF)
                //             }
                //             return output;
                //         }*/
            	//
                //         os.write(decodedBytes);
                //     }
                // }
                BinaryReader reader = new BinaryReader(provider, true);
                reader.setPointerIndex(BinHex4FileSystemFactory.BH_START_BYTES_REQUIRED);
                
                int buf24 = 0; // signed 32-bit buffer, but we only need 24 bits, so sign doesn't matter

                // for testing purpose, just output a test string for now...
                os.write("test".getBytes());
            }
        };

        // Call getDerivedByteProviderPush with the defined producer
        return fsService.getDerivedByteProviderPush(containerFSRL, payloadFSRL, derivedFileName, derivedFileSize, producer, monitor);
    }

//     //@Override
//     public ByteProvider oldgetByteProvider(GFile file, TaskMonitor monitor)
//             throws IOException, CancelledException {
//         HqxEntry metadata = fsIndex.getMetadata(file);
// //         DerivedStreamPushProducer dspp = new DerivedStreamPushProducer() {
// //         	@Override
// //			public void push(OutputStream os) throws IOException, CancelledException {
// //				// TODO Auto-generated method stub
// //         		
// //				
// //			}
// //         };
// //         ByteProvider dbpp = fsService.getDerivedByteProviderPush(
// //         		provider.getFSRL(),	// container fsrl
// //         		fsFSRL,				// derived fsrl
// //         		null,				// derived name
// //         		0,					// size hint
// ////         		dspp,				// pusher
// //         		() -> new DerivedStreamPushProducer() {
// //             		
// //         		},
// //         		monitor);			// monitor
// //         provider = dbpp;
// //         provider.push(monitor);

//         BinaryReader reader = new BinaryReader(provider, true);
//         reader.setPointerIndex(BinHex4FileSystemFactory.BH_START_BYTES_REQUIRED);
        
//         int buf24 = 0; // signed 32-bit buffer, but we only need 24 bits, so sign doesn't matter

//         // skip \n and \r until we see ':'
//         loop1: while (true) {
//             switch (reader.readNextByte()) {
//                 case '\n', '\r' -> { continue; } // Skip new line and carriage return
//                 case ':' -> { break loop1; } // Break out of the loop when we find ':'
//                 default -> throw new IOException("Unexpected byte");
//             }
//         }        

//         // TODO implement the logic blah blah
//         // now loop again until we see a ':'
//         // skip all \n and \r
//         // every 4 cycles, output the 3-byte buf
//         int i = 0;
//         loop2: while (true) {
//         	int b = reader.readNextByte();
//         	switch (b) {
//                 case '\n', '\r' -> { continue; } // Skip new line and carriage return
//                 case ':' -> { break loop2; } // Break out of the loop when we find ':'
//                 default -> {
//                     // look up b in ALPHABET
//                     int a = ALPHABET.indexOf(b);
//                     if (a == -1) throw new IOException("Unexpected byte");
//                     buf24 = (buf24 << 6) | a;
//                     i++;
//                     if (i % 4 == 0) {
//                         // TODO output the 3-byte buf
//                         int b1 = (buf24 >> 16) & 0xff;
//                         int b2 = (buf24 >> 8) & 0xff;
//                         int b3 = buf24 & 0xff;
//                         // output those bytes
//                         // TODO
//                         // call os.write() where os is the output stream from getDerivedByteProviderPush()



//                         // reset the buf
//                         buf24 = 0;
//                     }
//                 }
//         	}
//         }
//         	// is there stuff in 
        

        
        
//         // TODO just return a ByteArrayProvider for now
//         return null;
//     }

    // // function to read the next valid binhex ascii character or final ':'
    // private int readChar(BinaryReader reader) throws IOException {
    //     int b;
    //     do {
    //         b = reader.readNextByte();
    //         if (b == '\n' || b == '\r') continue;
    //         else if (b == ':') return -1;
    //         else if (ALPHABET.indexOf(b) != -1) return b;
    //         else throw new IOException("Unexpected character: " + b);
    //     } while (true);
    // }

//    /*@Override
//    public ByteProvider oldgetByteProvider(GFile file, TaskMonitor monitor)
//            throws IOException, CancelledException {
//
//        HqxEntry metadata = fsIndex.getMetadata(file);
//
//        // TODO look at Trs80Model100RlcLoader.java
//        // TODO use ByteArrayOutputStream for output
//        // TODO use for input:
//        // TODO BufferedReader br = new BufferedReader(new InputStreamReader(provider.getInputStream(endOfHeaderOffset), "US-ASCII"));
//        // TODO oh and ByteArrayProvider of course!
//        // A BinHex stream is composed of the character set `!"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr`
//        // every 4 encoded characters produces 3 decoded bytes
//        // each encoded character stores 6 bits of data, which are then converted to 8-bit bytes. Each encoded character is mapped to a 6-bit output value
//
//        // BufferedReader br = new BufferedReader(new InputStreamReader(provider.getInputStream(0), "US-ASCII"));
//        BinaryReader br = new BinaryReader(provider, false);
//        // br.setPointerIndex(43); // BH_START_BYTES_REQUIRED from BinHex4FileSystemFactory - how best to share?
//        br.setPointerIndex(BinHex4FileSystemFactory.BH_START_BYTES_REQUIRED);
//        
//        // read char
//        // which of the 64 chars is it?
//        // 0-63 is binary 00111111, six bits
//        // TODO output some kind of bit stream?
//        // TODO use shifts and masks to output?
//        // TODO or read 4 chars to get 4 x 6 bits = 24 bits and outbut 3 bytes
//        // TODO but then what do do when the input is not a multiple of 4?
//
//        // int a = br.read() & 0xFF;
//        // a = ALPHABET.indexOf(a);
//        // int u24 = a;
//        
//        // u24 <<= 6;
//        // int b = br.read() & 0xFF;
//        // b = ALPHABET.indexOf(b);
//        // u24 |= b;
//        
//        // u24 <<= 6;
//        // int c = br.read() & 0xFF;
//        // c = ALPHABET.indexOf(c);
//        // u24 |= c;
//        
//        // u24 <<= 6;
//        // int d = br.read() & 0xFF;
//        // d = ALPHABET.indexOf(d);
//        // u24 |= d;
//
//        // read line by line and print how long each line was
//
//        // I've seen /n or /r or /n/n between the signature and the initial :
//        // best to allow any number of either
//        // TODO should probably check for unexpected eof
//        do {
//            int c = br.readNextByte();
//            if (c != '\n' && c != '\r') {
//                br.setPointerIndex(br.getPointerIndex() - 1); // Set the pointer back for further processing
//                break; // Exit the loop if a non-newline character is found
//            }
//        } while (true);
//
//        // the next character must be a ':'
//        if (br.readNextByte() != ':') throw new IOException("Missing inital :");
//
//        boolean sawFinalColon = false;
//        for (int i = 0; /* no check */; i++) {
//            String line = myReadNextAsciiLine(br);
//            if (line == null) break;
//            sawFinalColon = line.endsWith(":");
//            // Msg.info(this, i + ": " + line.length());
//            // let's also print whether the line lenght is a multiple of 4, and also a multiple of 2 just for fun
//            // Msg.info(this, i + ": " + line.length() + " " + (line.length() % 4 == 0) + " " + (line.length() % 2 == 0));
//            if (line.length() % 4 == 0) {
//                long long u64 = 0;
//                
//            }
//        }
//
//        // the next character must be a ':'
//        if (!sawFinalColon) throw new IOException("Missing final :");
//
//        return null;
//    }*/

    private static String myReadNextAsciiLine(BinaryReader br) throws IOException {
        final long brl = br.length();
        if (br.getPointerIndex() == brl - 1) return null;

        StringBuilder line = new StringBuilder();
        while (true) {
            if (br.getPointerIndex() == brl - 1) return line.toString();
            int c = br.readNextByte();
            
            // Check for end of line characters
            if (c == '\n') return line.toString();
            if (c == '\r') {
                // Check for CRLF (carriage return followed by line feed)
                if (br.readNextByte() == '\n') return line.toString();
                // If it's just CR, we should set the pointer back
                br.setPointerIndex(br.getPointerIndex() - 1);
                return line.toString();
            }
            
            // Check for 7-bit printable ASCII (0x20 to 0x7E)
            if (c < 0x20 || c > 0x7E) throw new IOException("Non-ASCII character encountered: " + c);
            line.append((char) c);
        }
    }

    public HqxEntry getMetadata(GFile file) {
        return fsIndex.getMetadata(file);
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        HqxEntry metadata = fsIndex.getMetadata(file);
        FileAttributes result = new FileAttributes();
        if (metadata != null) {
            result.add(FileAttributeType.NAME_ATTR, metadata.name);
        }
        return result;
    }

}