#!/usr/bin/env python3
"""
Main execution script for Logistics 4.0 testbed
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.testbed import Logistics40Testbed
from src.metrics import generate_performance_report, plot_performance_comparison, plot_latency_throughput
import json
import numpy as np


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     Logistics 4.0 Three-Party Authentication Protocol Testbed      ║
    ║                        Version 1.0                                 ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║  This testbed implements the proposed authentication scheme for    ║
    ║  secure three-party mutual authentication in Logistics 4.0.        ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize testbed with 100 authentication sessions
    testbed = Logistics40Testbed(num_sessions=100)
    
    # Run full testbed evaluation
    results = testbed.run_full_testbed()
    
    if 'error' in results:
        print(f"ERROR: {results['error']}")
        return 1
    
    # Generate reports
    generate_performance_report(results)
    plot_performance_comparison(results)
    plot_latency_throughput(results)
    
    # Save results
    os.makedirs('results', exist_ok=True)
    
    def convert(obj):
        if isinstance(obj, np.float32) or isinstance(obj, np.float64):
            return float(obj)
        return obj
    
    serializable = {k: convert(v) for k, v in results.items()}
    
    with open('results/testbed_results.json', 'w') as f:
        json.dump(serializable, f, indent=2, default=str)
    
    print("\n✓ Results saved to 'results/testbed_results.json'")
    print("✓ Performance plots saved to 'results/'")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())