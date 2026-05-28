import json
import os

import joblib

ML_DIR = os.path.join(os.path.dirname(__file__), "..", "ml")
MODEL_PATH = os.path.join(ML_DIR, "model.pkl")
METRICS_PATH = os.path.join(ML_DIR, "metrics.json")

LABEL_SEVERITY_MAP = {
    0: "clean",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

_model_cache = None


def _load_model():
    """Load and cache the trained model from disk."""
    global _model_cache
    if _model_cache is not None:
        return _model_cache
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        _model_cache = joblib.load(MODEL_PATH)
        return _model_cache
    except Exception:
        return None


def predict_severity(scan_data: dict) -> dict:
    """Predict severity using the trained ML model.

    Returns dict with ml_severity and ml_confidence.
    If the model is not loaded, returns None values.
    """
    from ml.features import extract_features

    model = _load_model()
    if model is None:
        return {"ml_severity": None, "ml_confidence": None}

    try:
        features = extract_features(scan_data)
        features_2d = [features]  # shape (1, n_features)

        prediction = model.predict(features_2d)[0]
        proba = model.predict_proba(features_2d)[0]
        confidence = float(max(proba))

        severity = LABEL_SEVERITY_MAP.get(int(prediction), "unknown")
        return {"ml_severity": severity, "ml_confidence": round(confidence, 4)}

    except Exception:
        return {"ml_severity": None, "ml_confidence": None}


def get_metrics() -> dict | None:
    """Load and return training metrics from metrics.json."""
    if not os.path.exists(METRICS_PATH):
        return None
    try:
        with open(METRICS_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return None


def get_feature_importance() -> list:
    """Return feature importances from the loaded model."""
    from ml.features import FEATURE_NAMES

    model = _load_model()
    if model is None:
        return []

    try:
        importances = model.feature_importances_
        result = [
            {"feature": FEATURE_NAMES[i], "importance": float(imp)}
            for i, imp in enumerate(importances)
        ]
        result.sort(key=lambda x: x["importance"], reverse=True)
        return result
    except Exception:
        return []
