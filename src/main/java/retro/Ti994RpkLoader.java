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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.xml.sax.InputSource;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for loading TI-99/4A RPK cartridge files.
 */
public class Ti994RpkLoader extends AbstractProgramWrapperLoader {

    public static final String RPK_NAME = "TI-99/4A RPK";
    public static final String RPK_EXTENSION = ".rpk";
    public static final long RPK_LOAD_ADDRESS = 0x6000;

    public List<String> binFiles = new ArrayList<>();

    @Override
    public String getName() {
        return RPK_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        if (provider.readByte(0) != 'P' || provider.readByte(1) != 'K') return loadSpecs;

        String fname = provider.getName();
        if (fname.indexOf('.') < 0) return loadSpecs;
        String ext = fname.substring(fname.lastIndexOf('.'));
        if (!ext.equalsIgnoreCase(RPK_EXTENSION)) return loadSpecs;

        boolean hasLayoutXml = false;

        File file = provider.getFile();
        ZipFile zip = new ZipFile(file);
        Enumeration<? extends ZipEntry> entries = zip.entries();
        List<String> processorIds = new ArrayList<>();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String ename = entry.getName();
            final int dotIdx = ename.lastIndexOf('.');

            if (ename.equals("layout.xml")) {
                hasLayoutXml = true;
            } else if (dotIdx > 0 && ename.substring(dotIdx).equalsIgnoreCase(".bin")) {
                binFiles.add(ename);

                switch (ename.charAt(dotIdx - 1)) {
                case 'c':
                case 'd':
                    processorIds.add("9900");
                    break;
                case 'g':
                    processorIds.add("GPL");
                    break;
                case '3':
                case '8':
                case '9':
                    Msg.warn(this, "TODO: Does '" + ename.charAt(dotIdx - 1) + "' mean TMS-9900 or GPL code?");
                    break;
                default:
                    Msg.warn(this, "Character before .bin not known: '" + ename.charAt(dotIdx - 1) + "'");
                    break;
                }
            }
        }
        zip.close();

        // current RPKs often contain but do not seem to need or use any of:
        // meta-inf.xml, META-INF/, MANIFEST.MF, or softlist.xml
        if (!hasLayoutXml || binFiles.isEmpty()) return loadSpecs;

        // TODO if we know there's TMS-9900 or GPL code, add loadSpecs for those we know about
        // TODO but if we don't know, add both and let the user choose
        //Ti994LoaderHelper.addLoadSpecs(this, getLanguageService(), loadSpecs);
        Ti994LoaderHelper.addLoadSpecsExt(this, getLanguageService(), loadSpecs, processorIds.toArray(new String[0]));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        File file = provider.getFile();
        ZipFile zip = new ZipFile(file);

        ZipEntry xmlEntry = zip.getEntry("layout.xml");
        if (xmlEntry == null) {
            // impossible unless we change the check in findSupportedLoadSpecs()
            zip.close();
            throw new IOException("Missing layout.xml");
        }

        String pcbType = null;

        InputStream zis = zip.getInputStream(xmlEntry);
        String layoutXml = new String(zis.readAllBytes(), Charset.forName("UTF-8"));
        try {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(layoutXml)));

            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            String formattedXml = impl.createLSSerializer().writeToString(doc);

            Ti994LoaderHelper.appendComment(
                program.getListing(),
                program.getAddressFactory().getDefaultAddressSpace().getAddress(RPK_LOAD_ADDRESS),
                CodeUnit.PRE_COMMENT, formattedXml
            );

            NodeList pcbs = doc.getElementsByTagName("pcb");
            pcbType = pcbs.getLength() > 0 ? pcbs.item(0).getAttributes().getNamedItem("type").getNodeValue() : null;

            Msg.info(this, "pcbType: " + pcbType);

        } catch (Exception e) {
            log.appendException(e);
        }

        // https://www.ninerpedia.org/wiki/MESS_cartridge_handling
        // known values: standard, paged, minimem, super, mbx, paged379i, paged378, paged377, pagedcru, gromemu
        if (pcbType.equals("standard")) {
            Iterator<String> bfit = binFiles.iterator();
            while (bfit.hasNext()) {
                monitor.checkCanceled(); // TODO deprecated
                String entryName = bfit.next();

                final int dotIdx = entryName.lastIndexOf('.');

                if (dotIdx > 0 && entryName.substring(dotIdx).equalsIgnoreCase(".bin")) {
                    String binName = entryName.substring(0, dotIdx);

                    try {
                        // choose comment based on last letter of binName (ignore case)
                        // https://forums.atariage.com/topic/372380-understanding-how-cartridges-load-and-run/#comment-5532254
                        // ’s Classic99 still honors it, the ‘3’ terminator is deprecated in favor of
                        // ‘9’ for the 379 inverted-bank implementation and ‘8’ for the 378 non-inverted-bank implementation.
                        // xxxxxC.BIN - loads as CPU cartridge ROM at >6000
                        // xxxxxD.BIN - loads as banked CPU cartridge ROM at >6000,
                        //              second bank (such as Extended BASIC or AtariSoft carts)
                        // xxxxxG.BIN - loads as GROM cartridge at >6000 in GROM space
                        // xxxxx3.BIN - Classic99 extension, loads as a 379/Jon Guidry style cartridge ROM at >6000 - deprecated!
                        // xxxxx8.BIN - Classic99 extension, loads as a 378 non-inverted-bank style cartridge ROM at >6000
                        // xxxxx9.BIN - Classic99 extension, loads as a 379 inverted-bank style cartridge ROM at >6000
                        String binTypeComment = null;
                        String binType = Character.toString(binName.charAt(binName.length() - 1)).toLowerCase();
                        switch (binType) {
                            case "c": binTypeComment = "c: CPU cartridge ROM"; break;
                            case "d": binTypeComment = "d: banked CPU cartridge ROM"; break;
                            case "g": binTypeComment = "g: GROM cartridge"; break;
                            case "3": binTypeComment = "3: Classic99 extension"; break; // deprecated
                            case "8": binTypeComment = "8: Classic99 extension"; break;
                            case "9": binTypeComment = "9: Classic99 extension"; break;
                            default: binTypeComment = binType + ": not a known .bin final char (c/d/g/3/8/9)"; break;
                        }

                        String[] validBinTypes = { "c", "d", "g" };

                        AddressSpace addressSpace = Arrays.asList(validBinTypes).contains(binType)
                            ? program.getAddressFactory().getDefaultAddressSpace()
                            : AddressSpace.OTHER_SPACE;

                        ZipEntry entry = zip.getEntry(entryName);

                        long size = entry.getSize();

                        if (RPK_LOAD_ADDRESS + size > 0x10000) {
                            Msg.warn(this, "File too large to load 0x" + Long.toHexString(size)
                                + " bytes at 0x" + Long.toHexString(RPK_LOAD_ADDRESS)
                                + ", truncating to 0x" + Long.toHexString(0x10000 - RPK_LOAD_ADDRESS));
                            size = 0x10000 - RPK_LOAD_ADDRESS;
                        } else {
                            Msg.info(this, "Loading 0x" + Long.toHexString(size)
                                + " bytes at 0x" + Long.toHexString(RPK_LOAD_ADDRESS));
                        }

                        Address loadAddress = addressSpace.getAddress(RPK_LOAD_ADDRESS);

                        program.getMemory().createInitializedBlock(
                            entryName,
                            loadAddress,
                            zip.getInputStream(entry),
                            size,
                            monitor, false
                        );

                        Ti994LoaderHelper.appendComment(
                            program.getListing(),
                            loadAddress,
                            CodeUnit.PRE_COMMENT, binTypeComment
                        );
                        Ti994LoaderHelper.loadAndComment(
                            program,
                            loadAddress,
                            new InputStreamByteProvider(zip.getInputStream(entry), entry.getSize()),
                            0,
                            log
                        );

                    } catch (Exception e) {
                        log.appendException(e);
                    }
                }
            }
        } else {
            Msg.error(this, "The RPK Loader only supports the 'standard' PCB Type. This RPK file has a '" + pcbType + "' PCB Type.");
        }

        zip.close();
    }
}