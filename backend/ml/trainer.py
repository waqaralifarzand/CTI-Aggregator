import json
import os
from datetime import datetime

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
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
ENCODER_PATH = os.path.join(ML_DIR, "label_encoder.pkl")
META_PATH = os.path.join(ML_DIR, "model_meta.json")
MIN_SAMPLES = 50

_ALL_CLASSES = ["clean", "critical", "high", "low", "medium"]


def load_model():
    """Load (model, label_encoder) from disk. Returns None if files are missing."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(ENCODER_PATH):
        return None
    try:
        model = joblib.load(MODEL_PATH)
        encoder = joblib.load(ENCODER_PATH)
        return (model, encoder)
    except Exception:
        return None


def train_model(db_session) -> dict:
    """Train a RandomForest classifier on historical scan results.

    Requires at least MIN_SAMPLES records in the database.
    Saves model.pkl, label_encoder.pkl, and model_meta.json to the ml/ directory.
    Returns a metadata dict.
    """
    from models.scan_result import ScanResult
    from models.ioc import IoC
    import json as _json

    # ---- Build dataset ----
    scan_results = (
        db_session.query(ScanResult)
        .join(IoC, ScanResult.ioc_id == IoC.id)
        .all()
    )

    if len(scan_results) < MIN_SAMPLES:
        raise ValueError(
            f"Insufficient training data. Need at least {MIN_SAMPLES} scans."
        )

    X = []
    y_labels = []

    for sr in scan_results:
        if not sr.overall_severity:
            continue

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
        y_labels.append(sr.overall_severity)

    if len(X) < MIN_SAMPLES:
        raise ValueError(
            f"Insufficient training data. Need at least {MIN_SAMPLES} scans."
        )

    # ---- Encode labels ----
    le = LabelEncoder()
    le.fit(_ALL_CLASSES)
    y = le.transform(y_labels)

    # ---- Train / test split ----
    n_classes = len(set(y))
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42,
        stratify=y if n_classes > 1 else None,
    )

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    # ---- Evaluate ----
    y_pred = clf.predict(X_test)

    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    recall = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    # ---- Feature importance ----
    feature_importances = [
        {"feature": FEATURE_NAMES[i], "importance": float(imp)}
        for i, imp in enumerate(clf.feature_importances_)
    ]
    feature_importances.sort(key=lambda x: x["importance"], reverse=True)

    meta = {
        "model_trained": True,
        "last_trained": datetime.utcnow().isoformat(),
        "training_samples": len(X),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "feature_importances": feature_importances,
    }

    # ---- Persist ----
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    return meta
