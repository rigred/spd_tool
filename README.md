# **SPD Tool for DDR3 Memory**

A modular command-line tool in Python for inspecting, comparing, and patching Serial Presence Detect (SPD) data from DDR3 memory modules. This tool is intended for hardware enthusiasts, hackers, and system builders who need to verify, troubleshoot, or modify memory module firmware.  
It provides detailed decoding of JEDEC standards, high-performance XMP profiles, and module-specific data for Unbuffered, Registered, and Load-Reduced DIMMs. Its modular architecture is designed for extension to support other memory standards like DDR4/DDR5.

## **Features**

* **DDR3 SPD Decoding:**  
  * **JEDEC Standards:** Decodes standard timing parameters, capacity, and organization.  
  * **Intel XMP 1.3:** Decodes high-performance overclocking profiles, including voltage, timings, and command rate. (Not working right)
  * **Module Types:** Parses specific data for **UDIMM**, **SO-DIMM**, **RDIMM**, and **LRDIMM** modules.  
  * **Manufacturer Identification:** Decodes JEDEC JEP-106 codes to show manufacturer names (e.g., SK hynix, Corsair, Kingston). (Missing many vendors)
* **Analysis & Verification:**  
  * **Timing Analysis:** Displays timings in both nanoseconds (ns) and clock cycles, with sanity checks for inconsistencies.  
  * **Down-clock Profiles:** Calculates and displays standard JEDEC timings for lower clock speeds.  
  * **CRC Validation:** Performs a CRC-16 check and automatically tests alternate coverage rules to validate data integrity.  
  * **HP SmartMemory Detection:** Identifies and decodes the HPT block found on HP server memory. (Still testing)
* **Command-Line Interface:**  
  * **dump:** Provides a detailed, human-readable view of a single SPD file.  
  * **diff:** Shows a byte-level comparison of two SPD files.  
  * **patch:** A validated method for copying data between SPD files.  
  * **Programmer Mode:** An optional \--programmer flag for the dump command shows byte/bit offsets and raw hex values.  
  * **JSON Export:** Exports all decoded data to a structured JSON file.  
* **Modular Design & Safety:**  
  * **Patching Safeguards:** The patch command includes warnings and checks to prevent errors like module type mismatches or creating a file with an invalid CRC.  
  * **Extensible Architecture:** The core decoding logic is separated from the UI, allowing for the addition of new memory type decoders (e.g., ddr4\_decoder.py).

## **File Structure**

The tool is organized into a modular structure:

* **spd\_tool.py**: The main entry point and command-line interface.  
* **spd\_library.py**: The core library that handles file loading and orchestrates the decoding process.  
* **ddr3\_decoder.py**: A dedicated module containing all logic for decoding DDR3 SPD files.  
* **utils/**: A directory for helper and utility scripts.

## **Requirements**

* Python 3.x

## **Usage**

### **Dump (Inspect a single SPD file)**

The dump command provides a summary of an SPD file.  
**Standard View:**  

```sh
python spd_tool.py dump --spd my_module.bin
```

**Programmer** View (with offsets and hex **values):**  

```sh
python spd_tool.py dump --spd my_module.bin --programmer
```

**JSON Export:**  

```sh
python spd_tool.py dump --spd my_module.bin --json output.json
```

### **Diff (Compare two SPD files)**

The diff command shows a byte-for-byte comparison of two files.  

```sh
python spd_tool.py diff --file-a original.bin --file-b modified.bin
```

### **Patch (Modify an SPD file)**

The patch command copies data from a source file to a target file and writes the result to a new file. The CRC is automatically recalculated and validated.  
**Example: Copying an HP SmartMemory block:**  

```sh
python spd_tool.py patch --source hp_module.bin --target generic_module.bin --out patched_module.bin --copy-hpt --force
```

## **Utility Scripts**

### **utils/spd\_csv\_to\_bin.py**

This utility converts SPD data from a CSV format, like those provided by manufacturers such as Micron, into a raw binary .bin file that can be used with this tool.  
**Features:**

* Parses CSV files with decimal indices and value columns.  
* Supports ranges in the index column (e.g., "60 \- 76").  
* Validates that the length of the provided value (hex run or string) matches the length of the specified range.  
* Can automatically calculate and write the correct DDR3 CRC checksum for the generated binary file.

**Usage:**  

```sh
python utils/spd_csv_to_bin.py micron_data.csv --out spd.bin --fix-crc
```

## **Extending the Tool**

To add support for a new memory type (e.g., DDR4), you would:

1. Create a new ddr4\_decoder.py file, mirroring the structure of ddr3\_decoder.py.  
2. Implement the specific decoding logic for the DDR4 standard within the new file.  
3. Update the \_get\_decoder factory function in spd\_library.py to recognize the DDR4 memory type byte and return an instance of your new DDR4Decoder.

## **License**

This project is licensed under the MIT License.