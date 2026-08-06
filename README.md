# AKA-Logistics-4.0
# Logistics 4.0 Three-Party Authentication Protocol - Testbed Implementation

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

---

## Overview

This repository contains the complete testbed implementation of the **Three-Party Mutual Authentication Scheme for Logistics 4.0** as described in the manuscript:

> **"A Mutual Authentication Scheme for Logistics 4.0 with Provable Security"**
> *(Under Review at Elsevier)*

The implementation demonstrates a lightweight, provably secure authentication protocol for Logistics 4.0 environments, supporting mutual authentication between three entities: **User (Operator Device)**, **Cloud Server**, and **E-Tag** in a single session.


---

## Key Features

| Feature | Description |
|---------|-------------|
| **Three-Party Authentication** | User-Cloud Server-E-Tag mutual authentication |
| **Lightweight Design** | Only 3 ECC operations per session |
| **Dynamic Key Management** | Key update and revocation without re-registration |
| **Provable Security** | RoR, ProVerif, Scyther, BAN Logic verification |
| **Performance Optimized** | 16.87 ms computation, 2432 bits communication |
| **Energy Efficient** | 183.55 mJ per session |

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup Instructions

```bash
# Clone the repository
git clone https://github.com/yourusername/logistics40-authentication.git
cd logistics40-authentication

# Create and activate virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

numpy>=1.21.0
matplotlib>=3.4.0
pandas>=1.3.0


╔═══════════════════════════════════════════════════════════════════╗
║     Logistics 4.0 Three-Party Authentication Protocol Testbed      ║
║                        Version 1.0                                 ║
╚═══════════════════════════════════════════════════════════════════╝

PHASE 1: REGISTRATION
============================================================
[CS-MAIN] Initialized with ECC keys
[ET-ET_001] Registration successful
[OD-OP_001] Registration successful

PHASE 2: AUTHENTICATION (100 sessions)
============================================================
  Progress: 20/100 sessions
  Progress: 40/100 sessions
  Progress: 60/100 sessions
  Progress: 80/100 sessions
  Progress: 100/100 sessions

PHASE 3: KEY UPDATE AND RE-AUTHENTICATION
============================================================
[OD-OP_001] Key updated successfully
[ET-ET_001] Key updated successfully

PERFORMANCE REPORT
============================================================
┌─────────────────────────────────────────────────────────────────┐
│                    PROTOCOL PERFORMANCE SUMMARY                  │
├─────────────────────────────────────────────────────────────────┤
│ Total Sessions:           100                                  │
│ Successful Sessions:      99                                   │
│ Success Rate:             99.00%                               │
│ Average Auth Time:        16.87 ms                             │
│ Communication Overhead:   2432 bits                            │
│ Energy per Session:       183.55 mJ                            │
└─────────────────────────────────────────────────────────────────┘

proverif ProVerif_Code.pv

Query not attacker(SKTE[]) is true.
Query not attacker(SKCS[]) is true.
Query not attacker(SKO[]) is true.
Query inj-event(ODEnd(id)) ==> inj-event(ODStart(id)) is true.
Query inj-event(CSEnd(id)) ==> inj-event(CSStart(id)) is true.
Query inj-event(TEnd(id)) ==> inj-event(TStart(id)) is true.

Step 1: User → Cloud Server
   O3 = C7 ⊕ h(IDO || r5)
   O4 = IDO ⊕ h(O3 || C7 || r5)

Step 2: Cloud Server → E-Tag
   C11 = h(C8 || C9 || r5 || r6) ⊕ C7
   C12 = h(C10 || C11 || r5 || r6) ⊕ C2

Step 3: E-Tag → Cloud Server
   SKT = h(A3 || A4 || r1)
   A5 = h(SKT || A2 || A3)

Step 4: Cloud Server → User
   SKC = h(C13 || C14 || r1)
   C15 = h(SKC || C2 || C13)

Step 5: User
   SKO = h(O5 || O6 || r1)

class ETag:          # E-Tag entity
class OperatorDevice # Operator Device entity  
class CloudServer    # Cloud Server entity

sha256_hash()        # SHA-256 hash function
xor_operation()      # XOR operation on hex strings
generate_random_nonce() # Random nonce generation
generate_ecc_keypair()  # ECC key pair simulation

PerformanceMetrics   # Collects timing and overhead data
generate_report()    # Generates performance report
plot_comparison()    # Visualizes comparison results

Logistics40Testbed   # Complete testbed class
  - run_registration_phase()
  - run_authentication_batch()
  - run_key_update_phase()
  - run_full_testbed()

@article{assiri2026logistics,
  title={A Mutual Authentication Scheme for Logistics 4.0 with Provable Security},
  author={Assiri, Adel Saad and, Elaf Ali},
  journal={Elsevier},
  year={2026},
  note={Under Review}
}
