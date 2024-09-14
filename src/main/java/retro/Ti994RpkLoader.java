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
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.xml.sax.InputSource;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
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
		int numBinFiles = 0;

		File file = provider.getFile();
		ZipFile zip = new ZipFile(file);
		Enumeration<? extends ZipEntry> entries = zip.entries();
		while (entries.hasMoreElements()) {
			ZipEntry entry = entries.nextElement();
			String ename = entry.getName();
			final int dotIdx = ename.lastIndexOf('.');

			Msg.info(this, ename);
			if (ename.equals("layout.xml")) {
				hasLayoutXml = true;
			} else if (dotIdx > 0 && ename.substring(dotIdx).equalsIgnoreCase(".bin")) {
				numBinFiles ++;
			}
		}
		zip.close();

		// current RPKs do not seem to need any of:
		// meta-inf.xml, META-INF/, MANIFEST.MF, or softlist.xml
		if (!hasLayoutXml || numBinFiles == 0) return loadSpecs;

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("9900:BE:16:default", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		File file = provider.getFile();
		ZipFile zip = new ZipFile(file);
		Enumeration<? extends ZipEntry> entries = zip.entries();
		// long nextAddr = 0x0000;
		while (entries.hasMoreElements()) {
			ZipEntry entry = entries.nextElement();
			String entryName = entry.getName();
			final int dotIdx = entryName.lastIndexOf('.');

			Msg.info(this, entryName);
			if (entryName.equals("layout.xml")) {
				InputStream zis = zip.getInputStream(entry);
				String layoutXml = new String(zis.readAllBytes(), Charset.forName("UTF-8"));

				try {
					Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(layoutXml)));

					final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
					final DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");

					Ti994LoaderHelper.appendComment(
						program.getListing(),
						program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0000),
						CodeUnit.PRE_COMMENT, impl.createLSSerializer().writeToString(doc)
					);
				} catch (Exception e) {
					log.appendException(e);
				}
			} else if (dotIdx > 0 && entryName.substring(dotIdx).equalsIgnoreCase(".bin")) {
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
						default: break;
					}

					// TODO in the case of a GROM we shouldn't use the default address space
					// TODO GROMs use the GROM space - we probably need to create a new space for this with some API?

					// AddressSpace addresssSpace = program.getAddressFactory().getDefaultAddressSpace();
					// TODO make a new addressSpace 'GROM' if bineType is 'g', use the default address space otherwise
					// TODO this seems to be nontrivial to do from a Loader
					AddressSpace addressSpace = binType.equals("g")
						? AddressSpace.OTHER_SPACE
						: program.getAddressFactory().getDefaultAddressSpace();

					// TODO could it be that the address factory doesn't know about the GROM space?
					// TODO how do we let it know?
					// program.getAddressFactory().addAddressSpace(addressSpace);
					// DefaultAddressFactory defaultAddressFactory = program.getAddressFactory();
					// defaultAddressFactory.addAddressSpace(addressSpace);
					// ProgramAddressFactory programAddressFactory = program.getAddressFactory();
					// programAddressFactory.addAddressSpace(addressSpace);
					// GromAddressFactory gromAddressFactory = new GromAddressFactory();
					// gromAddressFactory.createNewGromSpace();

					Address loadAddress = addressSpace.getAddress(RPK_LOAD_ADDRESS);

					program.getMemory().createInitializedBlock(
						entryName,
						loadAddress,
						zip.getInputStream(entry),
						entry.getSize(),
						monitor, false
					);

					Ti994LoaderHelper.appendComment(
						program.getListing(),
						loadAddress,
						CodeUnit.PRE_COMMENT, binTypeComment
					);
					Ti994LoaderHelper.commentCode(
						program,
						loadAddress,
						new InputStreamByteProvider(zip.getInputStream(entry), entry.getSize()),
						0
					);

					// point nextAddr to the next multiple of 0x1000 greater than the end of this block
					// nextAddr = (nextAddr + entry.getSize() + 0xfff) & 0xfffff000;
				} catch (Exception e) {
					log.appendException(e);
				}
			}
		}
		zip.close();
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