#!/usr/bin/env python3
"""
Train ML models for the AI SOC platform.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from src.utils.config_loader import ConfigLoader
from src.ml.training import ModelTrainer
from src.storage.local_store import LocalStorage


async def train_models(config_path: str = "./config", force_retrain: bool = False):
    """Train ML models for anomaly detection."""
    print("Starting ML model training...")
    
    try:
        # Load configuration
        config_loader = ConfigLoader(config_path)
        await config_loader.load_all()
        
        # Create model trainer
        trainer = ModelTrainer(config_loader)
        
        # Check if training data exists
        storage = LocalStorage(config_loader)
        
        # Load some events for training
        events = storage.load_events(
            event_type="processed",
            limit=10000
        )
        
        if not events:
            print("Warning: No training data found. Generating sample data...")
            await generate_sample_data(storage)
            events = storage.load_events(
                event_type="processed",
                limit=10000
            )
        
        if not events:
            print("Error: Could not generate or load training data.")
            return False
        
        print(f"Loaded {len(events)} events for training")
        
        # Train models
        await trainer.train_all_models(force_retrain=force_retrain)
        
        # Evaluate models
        evaluation_results = await trainer.evaluate_models()
        
        print("\nModel Evaluation Results:")
        for model_name, results in evaluation_results.items():
            if "error" in results:
                print(f"  {model_name}: Error - {results['error']}")
            else:
                print(f"  {model_name}:")
                print(f"    Anomaly rate: {results.get('anomaly_rate', 0):.2%}")
                print(f"    Mean score: {results.get('mean_score', 0):.4f}")
                print(f"    Sample size: {results.get('sample_size', 0)}")
        
        # Cross-validation (optional)
        if len(events) >= 100:
            print("\nRunning cross-validation...")
            cv_results = await trainer.cross_validate(n_folds=3)
            
            print("Cross-validation Results:")
            for model_name, results in cv_results.items():
                if "error" not in results:
                    print(f"  {model_name}:")
                    print(f"    Mean anomaly rate: {results.get('mean_anomaly_rate', 0):.2%}")
                    print(f"    Std anomaly rate: {results.get('std_anomaly_rate', 0):.2%}")
        
        # Save training stats
        training_stats = trainer.get_training_stats()
        stats_file = Path("data/models/training_stats.json")
        stats_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(stats_file, "w") as f:
            json.dump(training_stats, f, indent=2)
        
        print(f"\nTraining stats saved to: {stats_file}")
        print("\nModel training completed successfully!")
        
        return True
        
    except Exception as e:
        print(f"Error training models: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


async def generate_sample_data(storage):
    """Generate sample training data."""
    print("Generating sample training data...")
    
    from scripts.generate_logs import LogGenerator
    
    generator = LogGenerator(seed=42)
    
    # Generate normal events
    normal_events = []
    for i in range(5000):
        event = generator.generate_event(malicious_probability=0.05)  # 5% malicious
        normal_events.append(event)
    
    # Generate attack sequences
    attack_events = []
    
    # Brute force attack
    brute_force = generator.generate_brute_force_attack(count=20)
    attack_events.extend(brute_force)
    
    # Port scan
    port_scan = generator.generate_port_scan(count=30)
    attack_events.extend(port_scan)
    
    # Combine and save
    all_events = normal_events + attack_events
    
    # Shuffle
    import random
    random.shuffle(all_events)
    
    # Save to storage
    for event in all_events:
        storage.save_event(event, event_type="processed")
    
    print(f"Generated {len(all_events)} sample events")
    print(f"  Normal events: {len(normal_events)}")
    print(f"  Attack events: {len(attack_events)}")


async def model_diagnostics(config_path: str = "./config"):
    """Run model diagnostics and health checks."""
    print("Running model diagnostics...")
    
    try:
        # Load configuration
        config_loader = ConfigLoader(config_path)
        await config_loader.load_all()
        
        from src.ml.inference import MLInferenceEngine
        from src.ml.drift_monitor import DriftMonitor
        
        # Initialize inference engine
        ml_engine = MLInferenceEngine(config_loader)
        await ml_engine.initialize()
        
        # Initialize drift monitor
        drift_monitor = DriftMonitor(config_loader)
        
        # Get model stats
        model_stats = ml_engine.get_model_stats()
        print("\nModel Statistics:")
        print(f"  Total models: {model_stats.get('total_models', 0)}")
        print(f"  Inferences: {model_stats.get('inferences', 0)}")
        print(f"  Anomalies detected: {model_stats.get('anomalies_detected', 0)}")
        
        for model_name, stats in model_stats.get("models", {}).items():
            print(f"\n  {model_name}:")
            print(f"    Trained: {stats.get('is_trained', False)}")
            print(f"    Features: {stats.get('feature_count', 0)}")
            if 'train_error_mean' in stats:
                print(f"    Train error mean: {stats.get('train_error_mean', 0):.4f}")
        
        # Health check
        print("\nModel Health Check:")
        health_results = await ml_engine.health_check()
        
        for check in health_results.get("checks", []):
            status_icon = "✅" if check["status"] == "healthy" else "❌"
            print(f"  {status_icon} {check['model']}: {check['status']} - {check.get('message', '')}")
        
        # Check for drift
        print("\nChecking for model drift...")
        drift_results = await drift_monitor.check_drift()
        
        overall_drift = drift_results.get("overall_drift", {})
        if overall_drift.get("drift_detected", False):
            print(f"  ⚠️  Drift detected! Severity: {overall_drift.get('severity')}")
            print(f"  Recommendation: {overall_drift.get('recommendation')}")
        else:
            print("  ✅ No significant drift detected")
        
        # Generate drift report
        drift_report = await drift_monitor.generate_report()
        report_file = Path("data/models/drift_report.json")
        report_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_file, "w") as f:
            json.dump(drift_report, f, indent=2)
        
        print(f"\nDrift report saved to: {report_file}")
        
        return True
        
    except Exception as e:
        print(f"Error in model diagnostics: {e}", file=sys.stderr)
        return False


async def test_inference(config_path: str = "./config", sample_count: int = 100):
    """Test model inference with sample data."""
    print(f"Testing model inference with {sample_count} samples...")
    
    try:
        # Load configuration
        config_loader = ConfigLoader(config_path)
        await config_loader.load_all()
        
        from src.ml.inference import MLInferenceEngine
        from scripts.generate_logs import LogGenerator
        
        # Initialize inference engine
        ml_engine = MLInferenceEngine(config_loader)
        await ml_engine.initialize()
        
        # Generate test events
        generator = LogGenerator(seed=123)
        test_events = []
        
        for i in range(sample_count):
            event = generator.generate_event(malicious_probability=0.2)  # 20% malicious
            test_events.append(event)
        
        # Run inference
        start_time = asyncio.get_event_loop().time()
        results = await ml_engine.batch_detect(test_events)
        inference_time = asyncio.get_event_loop().time() - start_time
        
        # Analyze results
        anomalies = [r for r in results.get("results", []) if r.get("is_anomaly", False)]
        
        print(f"\nInference Results:")
        print(f"  Total events: {results.get('total_events', 0)}")
        print(f"  Anomalies detected: {results.get('anomalies_detected', 0)}")
        print(f"  Anomaly rate: {results.get('anomaly_rate', 0):.2%}")
        print(f"  Processing time: {results.get('processing_time_seconds', 0):.2f} seconds")
        print(f"  Events per second: {results.get('events_per_second', 0):.2f}")
        
        # Show some example anomalies
        if anomalies:
            print(f"\nExample anomalies detected:")
            for i, anomaly in enumerate(anomalies[:3]):  # Show first 3
                print(f"  {i+1}. Event ID: {anomaly.get('event_id', 'unknown')}")
                print(f"     Score: {anomaly.get('score', 0):.4f}")
                print(f"     Confidence: {anomaly.get('confidence', 0):.2f}")
                if anomaly.get("models"):
                    models = ", ".join(m["model"] for m in anomaly["models"])
                    print(f"     Models: {models}")
        
        # Save results
        results_file = Path("data/models/inference_test_results.json")
        results_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\nInference results saved to: {results_file}")
        
        return True
        
    except Exception as e:
        print(f"Error testing inference: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


def main():
    parser = argparse.ArgumentParser(description="Train and manage ML models for AI SOC platform")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Train ML models")
    train_parser.add_argument(
        "--config",
        "-c",
        default="./config",
        help="Configuration directory path"
    )
    train_parser.add_argument(
        "--force",
        action="store_true",
        help="Force retraining even if models are up to date"
    )
    
    # Diagnostics command
    diag_parser = subparsers.add_parser("diagnostics", help="Run model diagnostics")
    diag_parser.add_argument(
        "--config",
        "-c",
        default="./config",
        help="Configuration directory path"
    )
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Test model inference")
    test_parser.add_argument(
        "--config",
        "-c",
        default="./config",
        help="Configuration directory path"
    )
    test_parser.add_argument(
        "--samples",
        type=int,
        default=100,
        help="Number of samples to test"
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == "train":
        success = asyncio.run(train_models(args.config, args.force))
        sys.exit(0 if success else 1)
    
    elif args.command == "diagnostics":
        success = asyncio.run(model_diagnostics(args.config))
        sys.exit(0 if success else 1)
    
    elif args.command == "test":
        success = asyncio.run(test_inference(args.config, args.samples))
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()