# **SPD Tool for DDR Memory**

A modular command-line tool in Python for inspecting, comparing, patching, and organizing Serial Presence Detect (SPD) data from DDR2, DDR3, and DDR4 memory modules. This tool is intended for hardware enthusiasts, hackers, and system builders who need to verify, troubleshoot, or modify memory module firmware.

It provides detailed decoding of JEDEC standards, high-performance XMP profiles, and module-specific data for Unbuffered, Registered, and Load-Reduced DIMMs. Its modular architecture is designed for extension to support other memory standards like DDR5.

---

## **Features**

* **SPD Decoding (DDR2, DDR3, DDR4):**
  * **JEDEC Standards:** Decodes standard timing parameters, capacity, and organization.
  * **Intel XMP 1.3:** Decodes high-performance overclocking profiles, including voltage, timings, and command rate.
  * **Module Types:** Parses specific data for **UDIMM**, **SO-DIMM**, **RDIMM**, and **LRDIMM** modules.
  * **Manufacturer Identification:** Decodes JEDEC JEP-106 codes to show manufacturer names (e.g., SK hynix, Corsair, Kingston).

* **Analysis & Verification:**
  * **Timing Analysis:** Displays timings in both nanoseconds (ns) and clock cycles, with sanity checks for inconsistencies.
  * **Down-clock Profiles:** Calculates and displays standard JEDEC timings for lower clock speeds.
  * **CRC Validation:** Performs a CRC-16 check and automatically tests alternate coverage rules to validate data integrity.
  * **HP SmartMemory Detection:** Identifies and decodes the HPT block found on HP server memory.

* **Command-Line Interface:**
  * **`dump`:** Provides a detailed, human-readable view of a single SPD file.
  * **`diff`:** Shows a byte-level comparison of two SPD files.
  * **`patch`:** A validated method for copying data between SPD files.
  * **Programmer Mode:** An optional `--programmer` flag for the dump command shows byte/bit offsets and raw hex values.
  * **JSON Export:** Exports all decoded data to a structured JSON file.

* **SPD Organization and Cataloging:**
  * Scans directories for DDR2, DDR3, and DDR4 SPD dumps.
  * Organizes SPD files into a clean directory structure based on memory type, vendor, and part number.
  * Creates and maintains a SQLite database of all scanned SPDs for easy querying and management.
  * Generates an interactive HTML index of all cataloged SPDs, with a detailed modal view for each entry.

* **HP SmartMemory Tools:**
  * Identifies HP SmartMemory part numbers from serial and HPT codes using a learnable registry.
  * Can compute the HPT code from a serial number and part number.

* **Modular Design & Safety:**
  * **Patching Safeguards:** The `patch` command includes warnings and checks to prevent errors like module type mismatches or creating a file with an invalid CRC.
  * **Extensible Architecture:** The core decoding logic is separated from the UI, allowing for the addition of new memory type decoders (e.g., `ddr4_decoder.py`).

---

## **File Structure**

The tool is organized into a modular structure:

* **`spd_tool.py`**: The main entry point and command-line interface.
* **`spd_library.py`**: The core library that handles file loading and orchestrates the decoding process.
* **`ddr3_decoder.py`**: A dedicated module containing all logic for decoding DDR3 SPD files.
* **`sort_spd.py`**: A utility for organizing and cataloging SPD files.
* **`hp_smartmemory_ident.py`**: A tool for identifying and working with HP SmartMemory.
* **`utils/`**: A directory for helper and utility scripts.

---

## **Requirements**

* Python 3.x

---

## **Usage**

### **`spd_tool.py` (Inspect, Compare, Patch)**

#### **Dump (Inspect a single SPD file)**

The `dump` command provides a summary of an SPD file.

**Standard View:**

```sh
python spd_tool.py dump --spd my_module.bin
````

**Programmer View (with offsets and hex values):**

```sh
python spd_tool.py dump --spd my_module.bin --programmer
```

**JSON Export:**

```sh
python spd_tool.py dump --spd my_module.bin --json output.json
```

#### **Diff (Compare two SPD files)**

The `diff` command shows a byte-for-byte comparison of two files.

```sh
python spd_tool.py diff --file-a original.bin --file-b modified.bin
```

#### **Patch (Modify an SPD file)**

The `patch` command copies data from a source file to a target file and writes the result to a new file. The CRC is automatically recalculated and validated.

**Example: Copying an HP SmartMemory block:**

```sh
python spd_tool.py patch --source hp_module.bin --target generic_module.bin --out patched_module.bin --copy-hpt --force
```

### **Utility Scripts**

#### **`sort_spd.py` (Organize and Catalog)**

This script scans a directory for SPD files, organizes them into a structured output directory, and creates a SQLite database and HTML index.

```sh
python sort_spd.py /path/to/your/spds --out-root /path/to/organized_spds --db spd_catalog.sqlite3 --html index.html --recursive
```

#### **`hp_smartmemory_ident.py` (HP SmartMemory Identification)**

This script can identify, learn, and compute HP SmartMemory HPT codes.

**Identify an existing module:**

```sh
python hp_smartmemory_ident.py identify --serial 0x4132E061 --hpt 0xFCD7E032
```

**Learn a new memory family (requires two samples):**

```sh
python hp_smartmemory_ident.py learn --serial1 <s1> --hpt1 <h1> --serial2 <s2> --hpt2 <h2> --part-number "712383-081"
```

**Compute HPT from serial and part number:**

```sh
python hp_smartmemory_ident.py hpt --serial 0x4132E061 --part-number "712383-081"
```

#### **`utils/spd_csv_to_bin.py` (CSV to Binary Converter)**

This utility converts SPD data from a CSV format, like those provided by manufacturers such as Micron, into a raw binary `.bin` file that can be used with this tool.

**Features:**

* Parses CSV files with decimal indices and value columns.
* Supports ranges in the index column (e.g., "60 - 76").
* Validates that the length of the provided value (hex run or string) matches the length of the specified range.
* Can automatically calculate and write the correct DDR3 CRC checksum for the generated binary file.

**Usage:**

```sh
python utils/spd_csv_to_bin.py micron_data.csv --out spd.bin --fix-crc
```

## **Extending the Tool**

To add support for a new memory type (e.g., DDR4), you would:

1. Create a new `ddr4_decoder.py` file, mirroring the structure of `ddr3_decoder.py`.
2. Implement the specific decoding logic for the DDR4 standard within the new file.
3. Update the `_get_decoder` factory function in `spd_library.py` to recognize the DDR4 memory type byte and return an instance of your new `DDR4Decoder`.

## **License**

This project is licensed under the MIT License.
