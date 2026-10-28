from src.ml.features import FeatureExtractor
from src.ml.training import ModelTrainer


def test_baseline_model_catches_behavioural_attacks_with_few_false_positives(config):
    trainer = ModelTrainer(config)
    detector = trainer.train(trainer.load_events(n_normal=8000), save=False)
    report = trainer.evaluate(detector, n_normal=3000, n_attacks=25, seed=3)
    for scenario in ("brute_force", "port_scan", "dns_tunneling"):
        if scenario in report["by_scenario"]:
            hit, total = map(int, report["by_scenario"][scenario].split("/"))
            assert hit == total, f"{scenario}: {report['by_scenario'][scenario]}"
    assert report["false_positive_sources"] <= 2


def test_model_explains_itself(config):
    trainer = ModelTrainer(config)
    detector = trainer.train(trainer.load_events(n_normal=5000), save=False)
    fx = FeatureExtractor()
    vec = None
    for i in range(30):
        vec = fx.transform({"event_type": "ssh_failed", "src_ip": "198.51.100.3", "user": f"u{i}",
                            "@timestamp": f"2026-01-01T00:00:{i:02d}Z"})
    assert detector.score([vec], ["external"])[0] > detector.margin
    names = [r["feature"] for r in detector.explain(vec, "external")]
    assert "src_distinct_users_5m_log" in names or "src_failures_5m_log" in names
