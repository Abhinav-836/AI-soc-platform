#!/usr/bin/env python3
# \"\"\"Benchmark platform performance.\"\"\"
import sys
import time
import json
from pathlib import Path
from datetime import datetime
import statistics

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingestion.parsers.json_parser import JSONParser
from src.detection.rules.custom_rules import BruteForceRule
from src.ml.anomaly.isolation_forest import AnomalyDetector

def benchmark_parsing(iterations=10000):
   # \"\"\"Benchmark log parsing performance.\"\"\"
    parser = JSONParser()
    
    sample_log = json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "event_type": "connection"
    })
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        parser.parse(sample_log)
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
    
    return {
        "operation": "Log Parsing",
        "iterations": iterations,
        "avg_time_ms": statistics.mean(times),
        "median_time_ms": statistics.median(times),
        "min_time_ms": min(times),
        "max_time_ms": max(times),
        "throughput_per_sec": 1000 / statistics.mean(times)
    }

def benchmark_detection(iterations=10000):
    
    rule = BruteForceRule(threshold=5)
    
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": "192.168.1.100",
        "event_type": "failed_login"
    }
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        rule.matches(event)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return {
        "operation": "Rule Detection",
        "iterations": iterations,
        "avg_time_ms": statistics.mean(times),
        "median_time_ms": statistics.median(times),
        "min_time_ms": min(times),
        "max_time_ms": max(times),
        "throughput_per_sec": 1000 / statistics.mean(times)
    }

def benchmark_ml_inference(iterations=1000):
   # \"\"\"Benchmark ML inference performance.\"\"\"
    detector = AnomalyDetector()
    
    # Quick training with small dataset
    training_data = [
        {
            "source_ip": f"192.168.1.{i}",
            "dest_ip": "10.0.0.1",
            "source_port": 5000 + i,
            "dest_port": 80,
            "bytes_transferred": 1000 + i * 10,
            "packet_count": 10 + i,
            "duration": 60,
            "protocol": "tcp"
        }
        for i in range(100)
    ]
    detector.train(training_data)
    
    event = training_data[0]
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        detector.predict(event)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return {
        "operation": "ML Inference",
        "iterations": iterations,
        "avg_time_ms": statistics.mean(times),
        "median_time_ms": statistics.median(times),
        "min_time_ms": min(times),
        "max_time_ms": max(times),
        "throughput_per_sec": 1000 / statistics.mean(times)
    }

def main():
   # \"\"\"Run all benchmarks.\"\"\"
    print("AI SOC Platform - Performance Benchmark")
    print("=" * 70)
    print()
    
    benchmarks = [
        ("Parsing", benchmark_parsing, 10000),
        ("Detection", benchmark_detection, 10000),
        ("ML Inference", benchmark_ml_inference, 1000)
    ]
    
    results = []
    
    for name, func, iterations in benchmarks:
        print(f"Running {name} benchmark ({iterations} iterations)...")
        result = func(iterations)
        results.append(result)
        print(f"  ✓ Completed")
    
    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    
    for result in results:
        print(f"\\n{result['operation']}:")
        print(f"  Iterations:       {result['iterations']:,}")
        print(f"  Avg Time:         {result['avg_time_ms']:.4f} ms")
        print(f"  Median Time:      {result['median_time_ms']:.4f} ms")
        print(f"  Min Time:         {result['min_time_ms']:.4f} ms")
        print(f"  Max Time:         {result['max_time_ms']:.4f} ms")
        print(f"  Throughput:       {result['throughput_per_sec']:,.0f} ops/sec")
    
    print()
    print("=" * 70)

if __name__ == "__main__":
    main()
