import json
import os

import joblib

ML_DIR = os.path.join(os.path.dirname(__file__), "..", "ml")
MODEL_PATH = os.path.join(ML_DIR, "model.pkl")
ENCODER_PATH = os.path.join(ML_DIR, "label_encoder.pkl")
META_PATH = os.path.join(ML_DIR, "model_meta.json")

# Cache: (model, label_encoder) tuple or None
_cache = None


def _load_model():
    """Load and cache (model, label_encoder) from disk. Returns None if unavailable."""
    global _cache
    if _cache is not None:
        return _cache
    if not os.path.exists(MODEL_PATH) or not os.path.exists(ENCODER_PATH):
        return None
    try:
        model = joblib.load(MODEL_PATH)
        encoder = joblib.load(ENCODER_PATH)
        _cache = (model, encoder)
        return _cache
    except Exception:
        return None


def _bust_cache():
    """Invalidate the in-process model cache after retraining."""
    global _cache
    _cache = None


def predict_severity(scan_data: dict) -> dict:
    """Predict severity using the trained Random Forest model.

    Returns dict with ml_severity (str) and ml_confidence (float).
    Returns None values if the model is not yet trained.
    """
    from ml.features import extract_features

    loaded = _load_model()
    if loaded is None:
        return {"ml_severity": None, "ml_confidence": None}

    model, encoder = loaded
    try:
        features = extract_features(scan_data)
        proba = model.predict_proba([features])[0]
        predicted_idx = int(model.predict([features])[0])
        confidence = float(max(proba))
        severity = encoder.inverse_transform([predicted_idx])[0]
        return {"ml_severity": str(severity), "ml_confidence": round(confidence, 4)}
    except Exception:
        return {"ml_severity": None, "ml_confidence": None}


def get_metrics() -> dict:
    """Return training metadata. Always includes model_trained bool."""
    if not os.path.exists(META_PATH):
        return {"model_trained": False}
    try:
        with open(META_PATH, "r") as f:
            data = json.load(f)
        data.setdefault("model_trained", True)
        return data
    except Exception:
        return {"model_trained": False}


def get_feature_importance() -> list:
    """Return feature importances sorted descending. Empty list if no model."""
    from ml.features import FEATURE_NAMES

    loaded = _load_model()
    if loaded is None:
        return []

    model, _ = loaded
    try:
        result = [
            {"feature": FEATURE_NAMES[i], "importance": float(imp)}
            for i, imp in enumerate(model.feature_importances_)
        ]
        result.sort(key=lambda x: x["importance"], reverse=True)
        return result
    except Exception:
        return []
