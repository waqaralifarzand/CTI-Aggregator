"""CLI script to trigger ML model training on current database data."""

import sys
import os
import argparse
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db, SessionLocal
from backend.models.indicator import Indicator
from backend.ml.training import train_model


def main():
    parser = argparse.ArgumentParser(description="Train the CTI severity classifier")
    parser.add_argument("--version", default="v1", help="Model version string")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()

    try:
        indicators = db.query(Indicator).all()
        if len(indicators) < 10:
            print(f"Not enough data: {len(indicators)} indicators. Need at least 10.")
            sys.exit(1)

        print(f"Training on {len(indicators)} indicators...")

        records = []
        for ind in indicators:
            records.append({
                "ioc_value": ind.ioc_value,
                "ioc_type": ind.ioc_type,
                "source_feed": ind.source_feed,
                "first_seen": ind.first_seen,
                "last_seen": ind.last_seen,
                "severity": ind.severity,
                "confidence": ind.confidence,
                "tags": ind.tags,
                "malware_family": ind.malware_family,
                "tlp": ind.tlp,
            })

        metrics = train_model(records, model_version=args.version)

        print(f"\nTraining complete!")
        print(f"Version: {metrics['version']}")
        print(f"Train size: {metrics['train_size']}, Test size: {metrics['test_size']}")
        print(f"Cross-val F1 (weighted): {metrics['cv_f1_mean']:.3f} +/- {metrics['cv_f1_std']:.3f}")
        print(f"\nTop 10 features by importance:")
        sorted_features = sorted(metrics["feature_importances"].items(), key=lambda x: x[1], reverse=True)
        for name, importance in sorted_features[:10]:
            print(f"  {name:30s} {importance:.4f}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
