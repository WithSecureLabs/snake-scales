# Snake Scales

The official snake scales repository.

## Installation

Scale can be installed in one of three ways, using snake, pip or by cloning the respository and pointing Snake to it.

Once installed Snake and the Celery workers must be restarted.

> Note: Any missing dependencies or configuration settings will be reported in Snake's log!

### Snake Based

The Snake command line utility can be used to install a scale.

```bash
snake install SCALE_NAME
```

The Snake command line utility can also be used to check the loadable state of a scale.
This is very useful when a scale has multiple dependencies.

```bash
snake check SCALE_NAME
```

### Pip Based

A scale can be installed using pip as follows:

```bash
# 1. Install the scale with pip
pip install git+https://github.com/countercept/snake-scales/<SCALE>

# 2. (Optional) Copy scales conf file if present to /etc/snake/scales
export SCALE=<SCALE>
export SCALE_DIR=`python -c "import imp; print(imp.find_module('snake_${SCALE}')[1])"`
if [ -f "${SCALE_DIR}/${SCALE}.conf" ]; then cp "${SCALE_DIR}/${SCALE}.conf" "/etc/snake/scales/${SCALE}.conf.example"; fi

# 3. Install system dependencies
# If any, these will be reported in the Snake log, or usually listed in the `check` functions within components
```

### Clone Based

All the scales from a repository can easily be added to Snake, just by cloning and pointing.

```bash
# 1. Clone the repository to the desired location
git clone https://github.com/countercept/snake-scales.git <SCALE_DIR>

# 2. Add directory to snake.conf
[snip]
snake_scale_dirs: [
  '<SCALE_DIR>'
]
[snip]

# 3. (Optional) Copy scales conf files if present to /etc/snake/scales
# Check through the scales folders and copy their .conf files if present to /etc/snake/scales

# 4. Install python requirements
# If any, either look through the setup.py files or look at the Snake log.

# 5. Install system dependencies
# If any, these will be reported in the Snake log, or usually listed in the `check` functions within components
```

## Scales

### Binwalk

Runs `binwalk` on a sample.

#### Dependencies

- (Required) Binwalk

### ClamAV

Scans a sample using ClamAV.

#### Dependencies

- (Required) ClamAV

### Cuckoo

Allows Snake to interact with Cuckoo, such as submitting samples to Cuckoo.

#### Dependencies

- (Required) Cuckoo

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| cuckoo\_api | null | URL for Cuckoo API |
| cuckoo\_url | null | URL to Cuckoo Web UI |
| verify | True | Verify SSL connection if using HTTPS |

### ELF

Analyse ELF files using `elftools`.

### Exiftool

Runs `exiftool` on a sample.

#### Dependencies

- (Required) Exiftool

### Floss

Runs FireEye's `floss` on a binary.

#### Dependencies

- (Required) Floss

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| floss\_path | null | Path to floss binary |
| home | null | Path to HOME directory, required if user does not have a HOME |

### NIST NSRL

Search for sample in NIST's NSRL hashes.

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| nsrl\_path | null | Path to NSRL hashes text file |

### Office

Analyse a sample using `olefile`, `oletools`, and `oledump`.

#### Dependencies

- (Optional) Oledump

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| oledump\_path | null | Path to oledump.py |

### PDF

Analyse a sample using `pdf-parser`, `pdfid` and `peepdf`.

#### Dependencies

- (Optional) pdf-parser
- (Optional) pdfid
- (Optional) peepdf

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| pdf_parser\_path | null | Path to pdf-parser.py |
| pdfid\_path | null | Path to pdfid.py |
| peepdf\_path | null | Path to peepdf.py |

### PEFile

Analyse a sample using `pefile`.

### Radare2

Runs `radare2` on a sample.

#### Dependencies

- (Required) Radare2

### Radare2 Scripts

Runs `radare2` based scripts on a sample.

#### Dependencies

- (Required) Radare2

### Rekall

Runs `rekall` on a sample.

#### Dependencies

- (Required) Rekall

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| cache\_dir | null | Location of the profiles cache directory |
| repository\_path | null | Path to search for profiles in, useful for no internet access |

### RetDec

Runs the Retargetable Decompiler on parts of a sample.

#### Dependencies

- (Required) Rardare2

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| online | true | Toggle between using the online instance or a local one |
| api\_key | null | API key required for interaction with RetDec's online instance (online) |
| retdec\_dir | null | Directory that retdec is installed to (local) |

### TRiD

Runs `trid` on a sample.

#### Dependencies

- (Required) TRiD

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| trid\_path | null | Path to trid |
| tridupdate\_path | null | Path to tridupdate.py |
| triddefs\_path | null | Path to triddefs.trd |

### VirusTotal

Allows Snake to interact with VirusTotal, such as querying VT for information about a sample.

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| api\_key | null | VirusTotal API key |
| api\_private | false | Enable private features when using private VirusTotal API key |

### Volatility

Run `vol.py` on a sample

#### Dependencies

- (Required) Volatility

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| vol\_path | null | Path to vol.py |

### Yara

Scan a sample with `yara`.

#### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| rules\_key | null | Path to directory containing yara rules |
| blacklisted\_rules | [] | A list of rules to ignore |
