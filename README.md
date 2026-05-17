# SOC Cryptographic Hashing Framework

An automated, real-time benchmarking framework designed to evaluate the performance and efficacy of inline cryptographic hashing for log integrity in Security Operations Centres (SOCs). 

This framework ingests telemetry from live threat intelligence feeds (or simulated data), computes hashes using five distinct cryptographic algorithms (MD5, SHA-256, SHA3-256, BLAKE2b, and BLAKE3), performs tamper simulation to calculate detection accuracy (confusion matrix), and automatically generates comprehensive visualisations and a formatted Word document report.

## Prerequisites

- **Python 3.10** or higher
- Standard Python environment (Windows, macOS, or Linux)

## Installation

1. Clone or download this repository.
2. Navigate into the `soc_hashing_framework` directory:
   ```bash
   cd soc_hashing_framework
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *Note: Dependencies include `certstream`, `psutil`, `matplotlib`, `tabulate`, and `blake3`.*

## How to Run (Command Line)

The framework is operated via the `main.py` entry point. It can be run interactively or fully automated via command-line flags.

### 1. Interactive Mode
If you run the script with just the mode flag, it will prompt you interactively for the dataset and experimental parameters:

**Simulated Data (Demo):**
```bash
python main.py --demo
```

**Live Threat Intelligence Feeds:**
```bash
python main.py --live
```
*When running in `--live` mode, an interactive menu will ask you to select a data source (e.g., Certstream, URLhaus, OTX, or CISA AIS).*

### 2. Fully Automated (Scriptable) Mode
You can bypass all interactive prompts by providing the parameters as command-line flags. This is ideal for automated, repeatable benchmarking.

**Example Command:**
```bash
python main.py --demo --entries 5000 --iterations 10 --tamper-rate 25
```

**Available Flags:**
- `--live`: Use real-time data ingestion.
- `--demo`: Use simulated offline data.
- `--entries <int>`: Number of log entries to process per batch (e.g., 5000).
- `--iterations <int>`: Number of benchmark cycles to run for statistical accuracy (e.g., 10).
- `--tamper-rate <int>`: Percentage of entries to mutate during the tamper detection phase (0-100).

## How to Run (Visual Studio Code)

If you are using Visual Studio Code, a `.vscode/launch.json` profile is included for easy execution and debugging.

1. Open the project folder in VS Code.
2. Go to the **Run and Debug** view (`Ctrl+Shift+D` or `Cmd+Shift+D`).
3. Select one of the pre-configured profiles from the dropdown (e.g., `Python: Run Demo Benchmark`).
4. Click the green **Play** button (or press `F5`). 
5. Follow any interactive prompts in the integrated terminal.

## Outputs

All benchmarking results are automatically saved in the `output/` directory. After a successful run, you will find:
- **`summary_report.txt`**: A plain-text console summary of the run.
- **`csv/`**: Raw statistical data files (`benchmark_results.csv`, `tamper_results.csv`, `ingestion_impact.csv`).
- **`charts/`**: Eight PNG visualisations (Throughput, Latency, CPU Usage, Memory, Tamper Detection Accuracy, Ingestion Overhead, etc.).
- **`Automated_Benchmark_Report.docx`**: A professionally formatted Word document containing all generated tables, charts, and summary statistics, ready for academic or professional review.
