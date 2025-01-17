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
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading TI-99/4A .bin files with no FIAD (V9T9) or TIFILES (XMODEM) headers.
 */
public class Ti994BinLoader extends AbstractProgramWrapperLoader {

    private static enum BinExtType {
        CPU_CARTRIDGE_ROM,
        BANKED_CPU_CARTRIDGE_ROM,
        GROM_CARTRIDGE,
        CARTRIDGE_ROM_3,
        CARTRIDGE_ROM_8,
        CARTRIDGE_ROM_9,
        NONE
    }

    private static final String BIN_NAME = "TI-99/4A BIN";
    private static final int BIN_LOAD_ADDR = 0x6000;

    private BinExtType binExtType = BinExtType.NONE;
    private boolean hasBinExtension = false;

    private boolean hasGramKrackerHeader = false;

    @Override
    public String getName() {
        return BIN_NAME;
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

        // can't be larger than 64kb (TODO: there's probably a lower limit)
        if (provider.length() > 64 * 1024) return loadSpecs;

        // we can detect many file types based on the first 6 to 10 bytes of the file.
        // we can't actually rely on the file extension or the last character of the file name
        // but we can use them as hints.
        String name = provider.getName();
        final int dotIndex = name.lastIndexOf('.');
        if (dotIndex > 0) {
            String ext = name.substring(dotIndex + 1);
            if (ext.equalsIgnoreCase("bin")) hasBinExtension = true;
            name = name.substring(0, dotIndex);

            // xxxxxC.BIN - loads as CPU cartridge ROM at >6000
            //              up to 960kb?
            // xxxxxD.BIN - loads as banked CPU cartridge ROM at >6000, second bank (such as Extended BASIC or AtariSoft carts)
            //              exactly 8kb?
            // xxxxxG.BIN - loads as GROM cartridge at >6000 in GROM space
            //              up to 40kb?
            // xxxxx3.BIN - Classic99 extension, loads as a 379/Jon Guidry style cartridge ROM at >6000 - deprecated!
            // xxxxx8.BIN - A newer extension
            // xxxxx9.BIN - A newer extension
            switch (Character.toString(name.charAt(name.length() - 1)).toLowerCase()) {
            case "c":
                binExtType = BinExtType.CPU_CARTRIDGE_ROM;
                break;
            case "d":
                binExtType = BinExtType.BANKED_CPU_CARTRIDGE_ROM;
                break;
            case "g":
                binExtType = BinExtType.GROM_CARTRIDGE;
                break;
            case "3":
                binExtType = BinExtType.CARTRIDGE_ROM_3;
                break;
            case "8":
                binExtType = BinExtType.CARTRIDGE_ROM_8;
                break;
            case "9":
                binExtType = BinExtType.CARTRIDGE_ROM_9;
                break;
            }
        }

        // Cartridges start with a 16-byte header starting with >AA, the "GROM header" or "Standard header"
        // but "dump files" may have their own header preceding it, such as the so-called "GRAM KRACKER header"
        // https://forums.atariage.com/topic/159642-assembly-guidance/
        if (binExtType == BinExtType.NONE) {
            BinaryReader reader = new BinaryReader(provider, false);

            boolean hasStandardHeaderSignature = false;

            final int first = reader.readNextUnsignedShort() & 0xffff;
            final int second = reader.readNextUnsignedShort() & 0xffff;
            final int third = reader.readNextUnsignedShort() & 0xffff;
            final int aa = reader.readNextByte() & 0xFF;

            // Standard header followed by GK header?
            if ((first >> 8) == 0xAA) {
                hasStandardHeaderSignature = true;
            }

            // GK header followed by Standard header?
            else if (Ti994LoaderHelper.isGramKrackerHeader(first, second, third)) {
                hasGramKrackerHeader = true;
                if (aa == 0xAA) {
                    hasStandardHeaderSignature = true;
                }
            }

            if (!hasStandardHeaderSignature) return loadSpecs;
        }

        // filename ended with one of the special letters followed by .bin, or file has appropriate headers
        Ti994LoaderHelper.addLoadSpecs(this, getLanguageService(), loadSpecs);

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        Memory memory = program.getMemory();
        Address loadAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(BIN_LOAD_ADDR);
        FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

        try {
            long startOffset = 0;
            long length = provider.length();
            if (BIN_LOAD_ADDR + provider.length() > 0x10000) {
                Msg.warn(this, "File too large to load 0x" + Long.toHexString(length)
                    + " bytes at 0x" + Integer.toHexString(BIN_LOAD_ADDR)
                    + ", truncating to 0x" + Integer.toHexString(0x10000 - BIN_LOAD_ADDR));
                length = 0x10000 - BIN_LOAD_ADDR;
            }

            if (hasGramKrackerHeader) {
                startOffset = 6;
                length -= 6;
            }

            memory.createInitializedBlock("BIN", loadAddress, fileBytes, startOffset, length, false);

            String initialComment = "Has .bin suffix: " + (hasBinExtension ? "yes" : "no");
            switch (binExtType) {
                case CPU_CARTRIDGE_ROM:
                    initialComment += "\nxxxxxC.bin: loads as CPU cartridge ROM at >6000";
                    break;
                case BANKED_CPU_CARTRIDGE_ROM:
                    initialComment += "\nxxxxxD.bin: loads as banked CPU cartridge ROM at >6000, second bank (such as Extended BASIC or AtariSoft carts)";
                    break;
                case GROM_CARTRIDGE:
                    initialComment += "\nxxxxxG.bin: loads as GROM cartridge at >6000 in GROM space";
                    break;
                case CARTRIDGE_ROM_3:
                    initialComment += "\nxxxxx3.bin: Classic99 extension, loads as a 379/Jon Guidry style cartridge ROM at >6000";
                    break;
                default:
                    break;
            }
            initialComment += "\nHas GRAM Kracker header: " + (hasGramKrackerHeader ? "yes" : "no");
            program.getListing().setComment(loadAddress, CodeUnit.PRE_COMMENT, initialComment);

            Ti994LoaderHelper.loadAndComment(program, loadAddress, provider, startOffset, log);
        } catch (Exception e) {
            log.appendException(e);
        }
    }
}
