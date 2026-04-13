from typing import Dict, Any, List, Optional

import pandas as pd

from backend.ml.features import extract_features, FEATURE_COLUMNS
from backend.utils.logging import logger

LABEL_MAP_INV = {0: "low", 1: "medium", 2: "high", 3: "critical"}


class Predictor:
    """Serves ML predictions using a loaded model."""

    def __init__(self, model_data: Optional[Dict[str, Any]] = None):
        self.model_data = model_data

    @property
    def is_ready(self) -> bool:
        return self.model_data is not None and "model" in self.model_data

    def predict_single(self, indicator_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Predict severity for a single indicator."""
        if not self.is_ready:
            return {"severity": "medium", "confidence": 0.0}

        df = pd.DataFrame([indicator_dict])
        features = extract_features(df)

        clf = self.model_data["model"]
        feature_cols = self.model_data.get("feature_columns", FEATURE_COLUMNS)

        # Ensure all required columns exist
        for col in feature_cols:
            if col not in features.columns:
                features[col] = 0
        features = features[feature_cols]

        prediction = clf.predict(features)[0]
        probabilities = clf.predict_proba(features)[0]
        confidence = float(probabilities.max()) * 100

        return {
            "severity": LABEL_MAP_INV.get(prediction, "medium"),
            "confidence": round(confidence, 2),
        }

    def predict_batch(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict severity for a batch of indicators."""
        if not records:
            return []

        if not self.is_ready:
            return [
                {"ioc_value": r.get("ioc_value", ""), "severity": "medium", "confidence": 0.0}
                for r in records
            ]

        df = pd.DataFrame(records)
        features = extract_features(df)

        clf = self.model_data["model"]
        feature_cols = self.model_data.get("feature_columns", FEATURE_COLUMNS)

        for col in feature_cols:
            if col not in features.columns:
                features[col] = 0
        features = features[feature_cols]

        predictions = clf.predict(features)
        probabilities = clf.predict_proba(features)

        results = []
        for i, record in enumerate(records):
            results.append({
                "ioc_value": record.get("ioc_value", ""),
                "ioc_type": record.get("ioc_type", ""),
                "severity": LABEL_MAP_INV.get(predictions[i], "medium"),
                "confidence": round(float(probabilities[i].max()) * 100, 2),
            })

        logger.info(f"Batch prediction: {len(results)} indicators classified.")
        return results
