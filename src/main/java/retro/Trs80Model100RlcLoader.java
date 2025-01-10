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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading TRS-80 Model 100 RLC files.
 *
 * https://bitchin100.com/wiki/index.php?title=Relocating_Loader_(RLC)_Format
 */
public class Trs80Model100RlcLoader extends AbstractProgramWrapperLoader {

    private static final String RLC_NAME = "TRS-80 Model 100 RLC";
    private static final int RLC_MIN_HEADER_LINE_LENGTH = 7;    // " 1  0 \n"
    //private static final int RLC_MAX_HEADER_LINE_LENGTH = 16; // " 65536  65535 \r\n" - but this fact isn't easy to make use of
    private static final String RLC_HEX = "0123456789:;<=>?";
    private static final String RLC_START_OPTION_NAME = "Start address";
    private static final int RLC_DEFAULT_START_OPTION = 0x0000;

    private long endOfHeaderOffset;

    private int length; // the number of bytes in the RLC file
    private int entry;  // the offset within the image to the entry point (in all RLC file I've seen, this is always 0)

    @Override
    public String getName() {
        return RLC_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        if (provider.length() < RLC_MIN_HEADER_LINE_LENGTH) return loadSpecs;
        //if (provider.length() > RLC_MAX_HEADER_LINE_LENGTH) return loadSpecs;

        BinaryReader reader = new BinaryReader(provider, true);

        if (reader.readNextByte() != ' ') return loadSpecs;

        int c;
        while (true) {
            c = reader.readNextByte();
            if (c == ' ') break;
            if (c < '0' || c > '9') return loadSpecs;
            length = length * 10 + c - '0';
        }

        if (c != ' ') return loadSpecs;
        if (reader.readNextByte() != ' ') return loadSpecs;

        // normally there's a single space after the length and entry, but
        // some don't have this final space: "Lib-08-TECH-PROGRAMMING/RAM4TH.RLC"

        while (true) {
            c = reader.readNextByte();
            if (c == ' ' || c == '\n' || c == '\r') break;
            if (c < '0' || c > '9') return loadSpecs;
            entry = entry * 10 + c - '0';
        }

        if (c == ' ') c = reader.readNextByte();
        if (c == '\r') c = reader.readNextByte();
        if (c != '\n') return loadSpecs;

        endOfHeaderOffset = reader.getPointerIndex();

        List<String> processorIds = List.of("8085"/*, "z80"*/);
        for (String processorId : processorIds) {
            LanguageCompilerSpecPair lcsp = new LanguageCompilerSpecPair(processorId + ":LE:16:default", "default");
            loadSpecs.add(new LoadSpec(this, 0, lcsp, true));
        }

        return loadSpecs;
    }

    @Override
    public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

        int loadAddress = OptionUtils.getOption(RLC_START_OPTION_NAME, options, RLC_DEFAULT_START_OPTION);

        BufferedReader br = new BufferedReader(new InputStreamReader(provider.getInputStream(endOfHeaderOffset), "US-ASCII"));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        // header and footer normally have a single space at the end, but a few files are missing this
        // "Lib-08-TECH-PROGRAMMING/RAM4TH.RLC" again for example
        // Pattern headPattern =  Pattern.compile("^ ([0-9]+)  ([0-9]+) ?$");
        Pattern footPattern =  Pattern.compile("^ ([0-9]+) ?$");
        Pattern digitPattern = Pattern.compile("[0-9:;<=>?]");
        Pattern bytePattern =  Pattern.compile(digitPattern.pattern() + digitPattern.pattern());
        Pattern shortPattern = Pattern.compile(bytePattern.pattern() + bytePattern.pattern());
        Pattern unitPattern =  Pattern.compile("(?:" + bytePattern.pattern() + "|@" + shortPattern.pattern() + ")");
        Pattern linePattern =  Pattern.compile("(" + unitPattern.pattern() + "+)");
        String line;
        int lineNum = 0;
        Matcher m;

        int sum = 0;

        for (; (line = br.readLine()) != null; lineNum++) {
            m = linePattern.matcher(line);
            if (m.matches()) {
                String hex = m.group(1);
                m = unitPattern.matcher(hex);

                int pos = 0;

                while (m.find(pos)) {
                    String unit = m.group();

                    if (m.group().startsWith("@")) {
                        int offset = RLC_HEX.indexOf(unit.charAt(1));
                        offset <<= 4;
                        offset += RLC_HEX.indexOf(unit.charAt(2));
                        offset <<= 4;
                        offset += RLC_HEX.indexOf(unit.charAt(3));
                        offset <<= 4;
                        offset += RLC_HEX.indexOf(unit.charAt(4));

                        sum += offset;

                        int address = loadAddress + offset;

                        // we read the hex in big-endian but we write the 8085 binary in little-endian
                        bos.write(address & 0xFF);
                        bos.write(address >> 8);
                    } else {
                        int octet = RLC_HEX.indexOf(unit.charAt(0));
                        octet <<= 4;
                        octet += RLC_HEX.indexOf(unit.charAt(1));

                        sum += octet;

                        bos.write(octet);
                    }

                    pos = m.end();
                }

                continue;
            }

            m = footPattern.matcher(line);
            if (m.matches()) {
                int checksum = Integer.parseInt(m.group(1));
                if (checksum != sum) {
                    Msg.info(this, String.format("Checksum BAD: %d / 0x%x vs %d / 0x%x", checksum, checksum, sum, sum));
                } else {
                    Msg.info(this, String.format("Checksum OK: %d / 0x%x", checksum, checksum));
                }
                continue;
            }

            Msg.info(this, String.format("%d Unrecognized: '%s'", lineNum, line));
        }

        try {
            Address startAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(loadAddress);

            MemoryBlock block = program.getMemory().createInitializedBlock(
                "memory",
                startAddress,
                new ByteArrayInputStream(bos.toByteArray()),
                bos.size(),
                monitor,
                false
            );
            block.setWrite(true);

            SymbolTable st = program.getSymbolTable();
            Address entryAddress = startAddress.add(entry);
            st.createLabel(entryAddress, "entry", SourceType.ANALYSIS);
            st.addExternalEntryPoint(entryAddress);
        } catch (Exception e) {
            log.appendException(e);
        }
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean isLoadIntoProgram) {
        List<Option> list =
            super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

        // start is the load address, not the entry point
        list.add(new Option(RLC_START_OPTION_NAME, RLC_DEFAULT_START_OPTION));

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

        // The system only allows you to enter decimal or hex starting with 0x
        if (options != null) {
            for (Option option : options) {
                String name = option.getName();
                if (name.equals(RLC_START_OPTION_NAME)) {
                    int val = (Integer) option.getValue();
                    if (val < 0 || val > 0xFFFF) {
                        return "Invalid value for option: " + name + " - " + val;
                    }
                }
            }
        }

        return super.validateOptions(provider, loadSpec, options, program);
    }
}
