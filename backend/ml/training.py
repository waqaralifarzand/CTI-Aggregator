from typing import Dict, Any, List

import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report

from backend.ml.features import extract_features, FEATURE_COLUMNS
from backend.config import settings
from backend.utils.logging import logger

LABEL_MAP = {"low": 0, "medium": 1, "high": 2, "critical": 3}
LABEL_MAP_INV = {v: k for k, v in LABEL_MAP.items()}


def bootstrap_labels(df: pd.DataFrame) -> pd.Series:
    """Generate labels from rule-based severity for initial training.

    Uses the existing 'severity' column as pseudo ground truth.
    """
    return df["severity"].map(LABEL_MAP).fillna(1).astype(int)


def train_model(records: List[Dict[str, Any]], model_version: str = "v1") -> Dict[str, Any]:
    """Full training pipeline.

    Args:
        records: List of indicator dicts (must have ioc_value, ioc_type,
                 source_feed, severity, confidence, first_seen, last_seen,
                 tags, malware_family, tlp)
        model_version: Version string for the saved model.

    Returns:
        Dict with training metrics.
    """
    df = pd.DataFrame(records)
    logger.info(f"Training: Starting with {len(df)} records.")

    # Extract features
    features = extract_features(df)
    labels = bootstrap_labels(df)

    # Need at least 2 classes
    unique_labels = labels.unique()
    if len(unique_labels) < 2:
        logger.warning("Training: Only one class present. Adding synthetic minority class.")
        # Ensure at least 2 classes for stratified split
        min_class = (set(LABEL_MAP.values()) - set(unique_labels)).pop()
        labels.iloc[0] = min_class

    # Train/test split
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels,
        )
    except ValueError:
        # Fall back to non-stratified split if class too small
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42,
        )

    # Train Random Forest
    clf = RandomForestClassifier(
        n_estimators=settings.RF_N_ESTIMATORS,
        max_depth=settings.RF_MAX_DEPTH,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    present_labels = sorted(set(y_test.unique()) | set(y_pred))
    target_names = [LABEL_MAP_INV.get(l, str(l)) for l in present_labels]

    report = classification_report(
        y_test, y_pred,
        labels=present_labels,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )

    # Cross-validation
    try:
        cv_scores = cross_val_score(clf, features, labels, cv=min(5, len(features)), scoring="f1_weighted")
        cv_f1_mean = float(cv_scores.mean())
        cv_f1_std = float(cv_scores.std())
    except ValueError:
        cv_f1_mean = 0.0
        cv_f1_std = 0.0

    # Feature importance
    importances = dict(zip(FEATURE_COLUMNS, [float(x) for x in clf.feature_importances_]))

    # Persist model
    model_data = {
        "model": clf,
        "feature_columns": FEATURE_COLUMNS,
        "version": model_version,
        "feature_importances": importances,
        "classification_report": report,
    }
    model_path = f"backend/ml/models/rf_severity_{model_version}.joblib"
    joblib.dump(model_data, model_path)
    joblib.dump(model_data, settings.MODEL_PATH)

    logger.info(f"Training complete: version={model_version}, cv_f1={cv_f1_mean:.3f}")

    return {
        "version": model_version,
        "classification_report": report,
        "cv_f1_mean": cv_f1_mean,
        "cv_f1_std": cv_f1_std,
        "feature_importances": importances,
        "train_size": len(X_train),
        "test_size": len(X_test),
    }
