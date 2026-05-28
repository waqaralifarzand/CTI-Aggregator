import json
import os
from datetime import datetime

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

from ml.features import extract_features, FEATURE_NAMES

ML_DIR = os.path.join(os.path.dirname(__file__))
MODEL_PATH = os.path.join(ML_DIR, "model.pkl")
METRICS_PATH = os.path.join(ML_DIR, "metrics.json")

SEVERITY_LABEL_MAP = {
    "clean": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
LABEL_SEVERITY_MAP = {v: k for k, v in SEVERITY_LABEL_MAP.items()}
MIN_SAMPLES = 50


def train_model(db_session) -> dict:
    """Train a RandomForest classifier on historical scan results.

    Requires at least MIN_SAMPLES records in the database.
    Saves model.pkl and metrics.json to the ml/ directory.
    Returns a metrics dict.
    """
    from models.scan_result import ScanResult
    from models.ioc import IoC
    from models.feed_result import FeedResult
    import json as _json

    # ---- Build dataset ----
    scan_results = (
        db_session.query(ScanResult)
        .join(IoC, ScanResult.ioc_id == IoC.id)
        .all()
    )

    if len(scan_results) < MIN_SAMPLES:
        raise ValueError(
            f"Insufficient training data: {len(scan_results)} samples found, "
            f"minimum {MIN_SAMPLES} required."
        )

    X = []
    y = []

    for sr in scan_results:
        label = SEVERITY_LABEL_MAP.get(sr.overall_severity)
        if label is None:
            continue  # skip unknown severity values

        # Reconstruct feed data from raw_summary
        try:
            raw = _json.loads(sr.raw_summary)
        except (ValueError, TypeError):
            raw = {}

        scan_data = {
            "ioc_type": sr.ioc.type if sr.ioc else "",
            "threat_score": sr.threat_score or 0,
            "feeds": raw.get("feeds", {}),
        }

        features = extract_features(scan_data)
        X.append(features)
        y.append(label)

    if len(X) < MIN_SAMPLES:
        raise ValueError(
            f"After filtering, only {len(X)} valid samples remain. "
            f"Minimum {MIN_SAMPLES} required."
        )

    # ---- Train / test split ----
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
    )

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    # ---- Evaluate ----
    y_pred = clf.predict(X_test)
    class_labels_present = sorted(set(y))
    label_names = [LABEL_SEVERITY_MAP[l] for l in class_labels_present]

    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(
        precision_score(y_test, y_pred, average="weighted", zero_division=0)
    )
    recall = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    # Feature importance
    feature_importances = [
        {"feature": FEATURE_NAMES[i], "importance": float(imp)}
        for i, imp in enumerate(clf.feature_importances_)
    ]
    feature_importances.sort(key=lambda x: x["importance"], reverse=True)

    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "num_samples": len(X),
        "num_classes": len(class_labels_present),
        "class_labels": label_names,
        "trained_at": datetime.utcnow().isoformat(),
        "feature_importances": feature_importances,
    }

    # ---- Persist ----
    joblib.dump(clf, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    return metrics
