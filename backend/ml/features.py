import json

import pandas as pd
import numpy as np

from backend.utils.logging import logger

# Canonical feature column order used by the model
FEATURE_COLUMNS = [
    "num_sources", "mean_feed_score", "max_feed_score", "min_feed_score",
    "ioc_type_ip", "ioc_type_domain", "ioc_type_url", "ioc_type_hash", "ioc_type_email", "ioc_type_other",
    "age_days", "last_seen_recency_days", "active_duration_days", "reporting_frequency",
    "num_tags", "has_malware_family", "num_malware_families",
    "feed_agreement", "tlp_numeric", "is_active_ratio",
    "has_payload", "anomaly_score",
    "flag_duplicate", "flag_frequency_spike", "flag_temporal_corr",
    "flag_conflict", "flag_stale", "flag_reactivation",
    "blacklist_count", "hour_of_day",
]


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract 30 ML features from a normalized indicator DataFrame.

    Expects columns: ioc_value, ioc_type, source_feed, first_seen, last_seen,
    confidence, tags, malware_family, tlp, and optionally anomaly_flags / anomaly_score.

    Returns a DataFrame with FEATURE_COLUMNS columns.
    """
    features = pd.DataFrame(index=df.index)

    # --- Cross-feed aggregated features ---
    source_counts = df.groupby("ioc_value")["source_feed"].transform("nunique")
    features["num_sources"] = source_counts

    conf = df["confidence"].astype(float)
    features["mean_feed_score"] = df.groupby("ioc_value")["confidence"].transform("mean")
    features["max_feed_score"] = df.groupby("ioc_value")["confidence"].transform("max")
    features["min_feed_score"] = df.groupby("ioc_value")["confidence"].transform("min")

    # --- IoC type one-hot ---
    ioc_type = df["ioc_type"].fillna("")
    features["ioc_type_ip"] = ioc_type.isin(["ip"]).astype(int)
    features["ioc_type_domain"] = ioc_type.isin(["domain", "hostname"]).astype(int)
    features["ioc_type_url"] = ioc_type.isin(["url"]).astype(int)
    features["ioc_type_hash"] = ioc_type.str.startswith("hash_").astype(int)
    features["ioc_type_email"] = ioc_type.isin(["email"]).astype(int)
    type_cols = ["ioc_type_ip", "ioc_type_domain", "ioc_type_url", "ioc_type_hash", "ioc_type_email"]
    features["ioc_type_other"] = (features[type_cols].sum(axis=1) == 0).astype(int)

    # --- Temporal features ---
    now = pd.Timestamp.now(tz="UTC")
    first_seen = pd.to_datetime(df["first_seen"], errors="coerce", utc=True)
    last_seen = pd.to_datetime(df["last_seen"], errors="coerce", utc=True)

    features["age_days"] = (now - first_seen).dt.total_seconds().fillna(0) / 86400
    features["last_seen_recency_days"] = (now - last_seen).dt.total_seconds().fillna(0) / 86400
    features["active_duration_days"] = (
        features["age_days"] - features["last_seen_recency_days"]
    ).clip(lower=0)
    features["reporting_frequency"] = features["num_sources"] / features["age_days"].clip(lower=1)

    # --- Tag & malware features ---
    def count_tags(val):
        if isinstance(val, list):
            return len(val)
        if isinstance(val, str):
            try:
                return len(json.loads(val))
            except (json.JSONDecodeError, TypeError):
                return 0
        return 0

    features["num_tags"] = df["tags"].apply(count_tags)
    features["has_malware_family"] = df["malware_family"].notna().astype(int) & (df["malware_family"] != "").astype(int)
    features["num_malware_families"] = df.groupby("ioc_value")["malware_family"].transform("nunique")

    # --- Feed agreement ---
    # Fraction of feeds reporting the most common severity for this IoC
    def _agreement(group):
        if len(group) <= 1:
            return 1.0
        mode_count = group["severity"].value_counts().iloc[0]
        return mode_count / len(group)

    agreement_map = df.groupby("ioc_value").apply(_agreement)
    features["feed_agreement"] = df["ioc_value"].map(agreement_map)

    # --- TLP numeric ---
    tlp_map = {"white": 0, "green": 1, "amber": 2, "red": 3}
    features["tlp_numeric"] = df["tlp"].map(tlp_map).fillna(0).astype(int)

    # --- Placeholder features (enriched data may not always be available) ---
    features["is_active_ratio"] = 1.0  # Default: assume active
    features["has_payload"] = 0  # Can be enriched from URLhaus data

    # Anomaly score from detection engine (if available)
    features["anomaly_score"] = df.get("anomaly_score", pd.Series(0.0, index=df.index))

    # Detection flags (if anomaly_flags column exists)
    flag_cols = {
        "flag_duplicate": "duplicate_cross_feed",
        "flag_frequency_spike": "frequency_spike",
        "flag_temporal_corr": "temporal_correlation",
        "flag_conflict": "cross_feed_conflict",
        "flag_stale": "stale_recency_decay",
        "flag_reactivation": "reactivation_detected",
    }
    for col, flag_name in flag_cols.items():
        if "anomaly_flags" in df.columns:
            features[col] = df["anomaly_flags"].apply(
                lambda flags: int(flag_name in flags) if isinstance(flags, list) else 0
            )
        else:
            features[col] = 0

    features["blacklist_count"] = 0  # Can be enriched from URLhaus blacklist data
    features["hour_of_day"] = first_seen.dt.hour.fillna(12).astype(int)

    # Ensure column order and fill NaN
    for col in FEATURE_COLUMNS:
        if col not in features.columns:
            features[col] = 0
    features = features[FEATURE_COLUMNS].fillna(0)

    logger.info(f"Feature extraction: {len(features)} rows, {len(FEATURE_COLUMNS)} features.")
    return features
