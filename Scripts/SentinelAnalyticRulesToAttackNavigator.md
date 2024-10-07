# README: Converting Azure Sentinel Analytic Rules to ATT&CK Navigator Layer

## Overview

This Python script converts Azure Sentinel analytic rule JSON files into an ATT&CK Navigator layer. It processes the analytic rules to assign scores to corresponding MITRE ATT&CK techniques and sub-techniques based on the count of **enabled** analytic rules associated with them. If a sub-technique is specified in an analytic rule, the score is assigned to the sub-technique; otherwise, it is assigned to the parent technique.

The output is an updated ATT&CK Navigator layer JSON file that visualizes your detection coverage across the MITRE ATT&CK framework.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Directory Structure](#directory-structure)
- [Setup Instructions](#setup-instructions)
- [Usage](#usage)
- [Output](#output)
- [Notes](#notes)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- **Python 3.6 or higher**
- **Required Python Libraries**:
  - `pandas`
  - `json` (standard library)
  - `glob` (standard library)
  - `os` (standard library)

## Directory Structure

Ensure your project directory is organized as follows:

```
project_directory/
├── Attack/
│   └── content/
│       ├── Azure_Sentinel_analytics_rules1.json
│       ├── Azure_Sentinel_analytics_rules2.json
│       ├── DEFAULTLAYER.json
│       └── (other Azure Sentinel analytic rule JSON files)
├── script.py
└── README.md
```

- **`Attack/content/`**: Contains all your Azure Sentinel analytic rule JSON files and the `DEFAULTLAYER.json` file.
- **`script.py`**: The Python script provided.
- **`README.md`**: This readme file.

## Setup Instructions

### 1. Install Python 3

If you haven't already installed Python 3, download and install it from the [official website](https://www.python.org/downloads/).

### 2. Install Required Python Libraries

Open a command prompt or terminal and install the required libraries using `pip`:

```bash
pip install pandas
```

### 3. Prepare Your Analytic Rule JSON Files

- Collect all your Azure Sentinel analytic rule JSON files.
- Ensure they are named using the following pattern:

  ```
  Azure_Sentinel_analytics_rules*.json
  ```

  For example:

  ```
  Azure_Sentinel_analytics_rules1.json
  Azure_Sentinel_analytics_rules2.json
  ```

- Place all these files into the `Attack/content/` directory.

### 4. Obtain the DEFAULTLAYER.json File

- Download the default ATT&CK Navigator layer file (`DEFAULTLAYER.json`).
- Place it into the `Attack/content/` directory.

### 5. Verify Directory Structure

Ensure that your directory structure matches the one described in the [Directory Structure](#directory-structure) section.

## Usage

### 1. Navigate to the Project Directory

Open a command prompt or terminal and navigate to the project directory:

```bash
cd path/to/project_directory
```

### 2. Run the Script

Execute the script using Python:

```bash
python script.py
```

### 3. Script Execution Details

- The script will:

  - Print the current working directory.
  - Display the path to the JSON files and list them.
  - Process each analytic rule JSON file.
  - Extract techniques and sub-techniques from enabled analytic rules.
  - Count the number of times each technique or sub-technique appears.
  - Update the `DEFAULTLAYER.json` with the scores based on these counts.
  - Save the updated ATT&CK Navigator layer as `updated_layer.json` in the `Attack/content/` directory.

- You will see output in the console showing intermediate DataFrames and confirmation messages.

### 4. View the Output

After the script finishes executing, you can find the updated ATT&CK Navigator layer file at:

```
Attack/content/updated_layer.json
```

## Output

- **`updated_layer.json`**: An ATT&CK Navigator layer file where each technique or sub-technique's score represents the count of enabled analytic rules associated with it.

## Notes

- **Technique and Sub-Technique IDs**: Ensure that the IDs used in your analytic rule JSON files match the IDs in the ATT&CK framework (e.g., `T1037` for techniques and `T1037.001` for sub-techniques).

- **Enabled Analytic Rules**: The script only considers analytic rules where `"enabled": true`. Disabled rules are ignored in the scoring.

- **Sub-Techniques Priority**: If an analytic rule specifies sub-techniques, the score is assigned to those sub-techniques. If no sub-techniques are specified, the parent techniques are used.

- **ATT&CK Navigator Compatibility**: The output file is compatible with ATT&CK Navigator version 4.5 and above.

## Troubleshooting

### Common Issues

1. **No Analytic Rule Files Found**:

   - **Problem**: The script outputs an empty file list or cannot find the analytic rule JSON files.
   - **Solution**: Ensure that your analytic rule files are correctly named (`Azure_Sentinel_analytics_rules*.json`) and placed in the `Attack/content/` directory.

2. **Incorrect File Paths**:

   - **Problem**: The script cannot find `DEFAULTLAYER.json` or outputs an error related to file paths.
   - **Solution**: Verify that the `DEFAULTLAYER.json` file is in the `Attack/content/` directory and that the directory structure matches the expected layout.

3. **Missing Python Libraries**:

   - **Problem**: Import errors when running the script.
   - **Solution**: Install the required Python libraries using `pip install pandas`.

4. **Data Format Issues**:

   - **Problem**: Errors during JSON parsing or data extraction.
   - **Solution**: Ensure that your analytic rule JSON files conform to the expected schema. The script expects certain fields like `displayName`, `enabled`, `tactics`, `techniques`, and `subTechniques`.

### Debugging Steps

- **Print Statements**: The script includes `print` statements that display the current working directory, file paths, and intermediate DataFrames. Use these outputs to verify that the data is being processed correctly.

- **Verify DataFrames**: Check the printed `expanded_df` and `final` DataFrames to ensure that they contain the expected data.

- **Check Scores**: After running the script, open the `updated_layer.json` file and verify that the scores are correctly assigned to the techniques and sub-techniques.

## Example

### Sample Analytic Rule JSON

```json
{
  "resources": [
    {
      "properties": {
        "displayName": "Suspicious PowerShell Activity",
        "enabled": true,
        "tactics": ["Execution"],
        "techniques": ["T1059"],
        "subTechniques": ["T1059.001", "T1059.003"]
      }
    },
    {
      "properties": {
        "displayName": "Brute Force Attack Detected",
        "enabled": true,
        "tactics": ["Credential Access"],
        "techniques": ["T1110"],
        "subTechniques": []
      }
    }
  ]
}
```

### Expected Outcome

- **Techniques and Sub-Techniques Processed**:
  - `T1059.001` and `T1059.003` (from the first rule's sub-techniques)
  - `T1110` (from the second rule's techniques)

- **Scores Assigned**:
  - `T1059.001`: 1
  - `T1059.003`: 1
  - `T1110`: 1

- **Navigator Layer Update**: The `updated_layer.json` will reflect these scores on the corresponding techniques and sub-techniques.

## Additional Resources

- **MITRE ATT&CK Navigator**:
  - [GitHub Repository](https://github.com/mitre-attack/attack-navigator)
  - [Live Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/)

- **Azure Sentinel Documentation**:
  - [Create Custom Analytics Rules](https://docs.microsoft.com/en-us/azure/sentinel/create-custom-detection-rules)
  - [Export and Import Analytics Rules](https://docs.microsoft.com/en-us/azure/sentinel/export-import-analytics-rules)

## Contact

If you encounter any issues or have questions, please feel free to reach out to the script maintainer or consult the Azure Sentinel and ATT&CK Navigator documentation for further guidance.