# NS-3 Simulation: Robust HECC-based AKA for UAV-enabled SAR Networks

This repository contains the **NS-3 (Network Simulator 3)** implementation source codes for the paper: **"A Robust HECC-based Authentication and Key Agreement for UAV-enabled SAR Networks"**.

The repository includes the simulation code for our proposed **HECC-based scheme** and **six state-of-the-art baseline schemes** for performance comparison in a MANET (Mobile Ad-hoc Network) environment.

## 📋 Table of Contents

- [Overview](#overview)
- [Implemented Schemes](#implemented-schemes)
- [Prerequisites & Environment](#prerequisites--environment)
- [Installation Guide (NS-3.26)](#installation-guide-ns-326)
- [Directory Structure](#directory-structure)
- [How to Run](#how-to-run)
- [Simulation Parameters](#simulation-parameters)
- [Results & Output](#results--output)
- [License](#license)

## 📖 Overview

Unmanned Aerial Vehicles (UAVs) in Search and Rescue (SAR) missions require secure and efficient communication. This project simulates a UAV ad-hoc network using the **OLSR** routing protocol and **802.11b** WiFi standards to evaluate the performance of various Authentication and Key Agreement (AKA) protocols.

We compare the computation cost, communication cost, and network performance (end-to-end delay, packet loss rate, throughput) of our proposed scheme against existing protocols.

## 🛡️ Implemented Schemes

The following schemes are implemented as standalone C++ simulation files:

| File Name | Scheme Description | Reference Paper |
| :--- | :--- | :--- |
| **`OurScheme.cc`** | **Proposed Scheme** | *A Robust HECC-based Authentication and Key Agreement for UAV-enabled SAR Networks* |
| `Khan.cc` | Baseline 1 | Khan et al. (2021) - *An Efficient and Secure Certificate-Based Access Control...* |
| `Gope.cc` | Baseline 2 | Gope et al. (2020) - *A provably secure authentication scheme for RFID-enabled UAV...* |
| `Yahuza.cc` | Baseline 3 | Yahuza et al. (2021) - *SLPAKA: An Edge Assisted Secure Lightweight Authentication...* |
| `Bera.cc` | Baseline 4 | Bera et al. (2020) - *ACSUD-IoD: Private blockchain-based access control...* |
| `Huang-1.cc` | Baseline 5 | Huang et al. (2024) - *BAKAS-UAV* (UAV-to-GCS scenario) |
| `Huang-2.cc` | Baseline 6 | Huang et al. (2024) - *BAKAS-UAV* (UAV-to-UAV scenario) |

## ⚙️ Prerequisites & Environment

These simulations are specifically designed for **NS-3.26**. Using newer versions of NS-3 (e.g., 3.3x or 3.4x) may require significant code refactoring due to API changes.

*   **Operating System:** Linux (Ubuntu 16.04 or 18.04 recommended for NS-3.26 compatibility).
*   **Compiler:** GCC/G++ (Version 5.x or 6.x recommended).
*   **Simulator:** NS-3.26.

## 📥 Installation Guide (NS-3.26)

If you do not have NS-3.26 installed, follow these steps:

1.  **Install dependencies** (Ubuntu example):
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential python-dev python-setuptools git qt5-default mercurial
    ```

2.  **Download NS-3.26**:
    ```bash
    wget https://www.nsnam.org/release/ns-allinone-3.26.tar.bz2
    tar xjf ns-allinone-3.26.tar.bz2
    cd ns-allinone-3.26/ns-3.26
    ```

3.  **Configure and Build**:
    ```bash
    ./waf configure --enable-examples --enable-tests
    ./waf
    ```

## 📂 Directory Structure

Place the simulation files (`.cc`) from this repository into the `scratch/` directory of your NS-3 installation.

```text
ns-allinone-3.26/
└── ns-3.26/
    ├── scratch/
    │   ├── OurScheme.cc       <-- Place file here
    │   ├── Khan.cc            <-- Place file here
    │   ├── Gope.cc            <-- Place file here
    │   ├── Yahuza.cc          <-- Place file here
    │   ├── Bera.cc            <-- Place file here
    │   ├── Huang-1.cc         <-- Place file here
    │   └── Huang-2.cc         <-- Place file here
    ├── src/
    └── waf
```

## 🚀 How to Run

To run a simulation, use the `./waf` command inside the `ns-3.26` directory.

**Run the Proposed Scheme:**
```bash
./waf --run scratch/OurScheme
```

**Run Baseline Schemes:**
```bash
./waf --run scratch/Khan
./waf --run scratch/Gope
./waf --run scratch/Yahuza
./waf --run scratch/Bera
./waf --run scratch/Huang-1
./waf --run scratch/Huang-2
```

### Optional Arguments
The scripts support command-line arguments to adjust the WiFi physical mode or enable tracing (if configured in code):
```bash
./waf --run "scratch/OurScheme --phyMode=DsssRate11Mbps"
```

## 📊 Simulation Parameters

All schemes are simulated under an identical network environment to ensure a fair comparison.

| Parameter | Value |
| :--- | :--- |
| **Simulator** | NS-3.26 |
| **Simulation Time** | 1500 seconds |
| **Simulation Area** | 2000m x 2000m |
| **Number of UAVs** | 20 (Adjustable via `NUAV` macro) |
| **Routing Protocol** | OLSR (Optimized Link State Routing) |
| **MAC Layer** | IEEE 802.11b (Ad-hoc mode) |
| **Wifi Rate** | DsssRate2Mbps |
| **Propagation Loss** | LogDistancePropagationLossModel |
| **Propagation Delay** | ConstantSpeedPropagationDelayModel |
| **Mobility Model** | RandomWalk2dMobilityModel |
| **Speed** | Constant (10 m/s) |
| **Computational Delays** | Simulates crypto operations (Hash, HECC, scalar mult) |

*Note: Please check and edit the `NUAV` define in the code before collecting final data.*

## 📈 Results & Output

After the simulation finishes, the console will output the statistical results, including:

1.  **Application Layer Performance:**
    *   Total Authentication Attempts
    *   Authentication Success Rate (%)
    *   **Average Authentication Delay (ms)**

2.  **Network Layer Performance:**
    *   Packet Loss Rate (%)
    *   **Average Communication Delay (ms)**
    *   **Average Throughput (kbps/Mbps)**

**Example Output:**
```text
----------------------------------------------------
---           Simulation Final Results           ---
----------------------------------------------------

--- Application Layer Performance ---
Total Authentication Attempts: 145
Total Successful Authentications: 145
Authentication Success Rate: 100.00000%
Average Authentication Delay (end-to-end): 12.45000 ms

--- Network Layer Performance ---
Total Packets Sent: 435
Total Packets Received: 430
Packet Loss Rate: 1.14943%
Average Communication Delay (per packet): 2.10000 ms

--- Aggregate Network Throughput ---
Average Throughput: 15.34000 kbps
```


## 📄 License

This project is open-source and available under the MIT License.
