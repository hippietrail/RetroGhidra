// Abstract helper class for a label to be loaded from a JSON file via GSON
package retro;

public class GhidraLabel {
	// JOSN doesn't support hex numbers, so need to parse them as a string
	private String address;
	private String name;
	private String type;
	
	public GhidraLabel(String address, String name, String type) {
		this.address=address;
		this.name=name;
		this.type=type;
	}
	public long getAddress() { return Integer.parseInt(address, 16); }
	public void setAddress(String address) { this.address = address; }
	public String getName() { return name; }
	public void setName(String name) { this.name = name; }
	public String getType() { return type; }
	public void setType(String type) { this.type = type; }
}
