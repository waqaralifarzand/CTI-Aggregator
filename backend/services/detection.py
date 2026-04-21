from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List

try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False
    pd = None  # type: ignore

from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.models.indicator import Indicator
from backend.models.anomaly_flag import AnomalyFlag
from backend.utils.logging import logger


class DetectionEngine:
    """Rule-based anomaly detection engine operating on indicator data."""

    def __init__(self, db: Session):
        self.db = db

    def run_and_store(self) -> int:
        """Run all detection rules and persist flags to the database.

        Returns the number of new flags generated.
        """
        if not _PANDAS_AVAILABLE:
            logger.warning("pandas not installed; anomaly detection engine skipped.")
            return 0

        indicators = self.db.query(Indicator).all()
        if not indicators:
            return 0

        # Build DataFrame
        records = []
        for ind in indicators:
            records.append({
                "id": ind.id,
                "ioc_value": ind.ioc_value,
                "ioc_type": ind.ioc_type,
                "source_feed": ind.source_feed,
                "first_seen": ind.first_seen,
                "last_seen": ind.last_seen,
                "severity": ind.severity,
                "confidence": ind.confidence,
                "malware_family": ind.malware_family,
                "tags": ind.tags,
            })
        df = pd.DataFrame(records)

        # Clear previous flags
        self.db.query(AnomalyFlag).delete()
        self.db.commit()

        # Run each rule
        all_flags: List[AnomalyFlag] = []
        all_flags.extend(self._detect_duplicates(df))
        all_flags.extend(self._detect_frequency_spike(df))
        all_flags.extend(self._detect_temporal_correlation(df))
        all_flags.extend(self._detect_cross_feed_conflict(df))
        all_flags.extend(self._apply_recency_decay(df))

        # Store flags
        for flag in all_flags:
            self.db.add(flag)
        self.db.commit()

        logger.info(f"Detection engine: Generated {len(all_flags)} anomaly flags.")
        return len(all_flags)

    def _detect_duplicates(self, df: pd.DataFrame) -> List[AnomalyFlag]:
        """Rule 1: Flag IoCs appearing in more than one source feed."""
        flags = []
        source_counts = df.groupby("ioc_value")["source_feed"].nunique()
        duplicates = source_counts[source_counts > 1]

        for ioc_value, num_sources in duplicates.items():
            indicator_ids = df[df["ioc_value"] == ioc_value]["id"].tolist()
            for ind_id in indicator_ids:
                flags.append(AnomalyFlag(
                    indicator_id=ind_id,
                    flag_type="duplicate_cross_feed",
                    description=f"IoC reported by {num_sources} different feeds",
                    anomaly_score=20.0 * num_sources,
                    metadata_json=json.dumps({"num_sources": int(num_sources)}),
                ))

        logger.info(f"Duplicate detection: {len(flags)} flags.")
        return flags

    def _detect_frequency_spike(self, df: pd.DataFrame, threshold: float = 3.0) -> List[AnomalyFlag]:
        """Rule 2: Flag IoC types with report counts exceeding threshold * historical median."""
        flags = []

        df_copy = df.copy()
        df_copy["report_date"] = pd.to_datetime(df_copy["first_seen"], errors="coerce")
        df_copy = df_copy.dropna(subset=["report_date"])
        if df_copy.empty:
            return flags

        df_copy["report_date"] = df_copy["report_date"].dt.normalize()
        today = pd.Timestamp.now(tz=timezone.utc).normalize()

        daily_counts = df_copy.groupby(["ioc_type", "report_date"]).size().reset_index(name="count")

        for ioc_type in daily_counts["ioc_type"].unique():
            type_counts = daily_counts[daily_counts["ioc_type"] == ioc_type]
            historical_median = type_counts["count"].median()
            if historical_median <= 0:
                continue

            today_row = type_counts[type_counts["report_date"] == today]
            if today_row.empty:
                continue
            today_count = today_row["count"].iloc[0]

            if today_count / historical_median > threshold:
                mask = (df_copy["ioc_type"] == ioc_type) & (df_copy["report_date"] == today)
                for ind_id in df_copy[mask]["id"].tolist():
                    flags.append(AnomalyFlag(
                        indicator_id=ind_id,
                        flag_type="frequency_spike",
                        description=f"Spike: {today_count} reports today vs {historical_median:.1f} median for {ioc_type}",
                        anomaly_score=30.0,
                        metadata_json=json.dumps({
                            "today_count": int(today_count),
                            "historical_median": float(historical_median),
                            "ratio": float(today_count / historical_median),
                        }),
                    ))

        logger.info(f"Frequency spike: {len(flags)} flags.")
        return flags

    def _detect_temporal_correlation(self, df: pd.DataFrame, window_hours: int = 2) -> List[AnomalyFlag]:
        """Rule 3: Flag IoCs first reported within a 2-hour window sharing a malware family."""
        flags = []

        has_family = df[df["malware_family"].notna() & (df["malware_family"] != "")].copy()
        if has_family.empty:
            return flags

        has_family["first_seen_ts"] = pd.to_datetime(has_family["first_seen"], errors="coerce")
        has_family = has_family.dropna(subset=["first_seen_ts"])

        for family in has_family["malware_family"].unique():
            family_df = has_family[has_family["malware_family"] == family].sort_values("first_seen_ts")
            if len(family_df) < 3:
                continue

            start_time = family_df["first_seen_ts"].iloc[0]
            window_delta = pd.Timedelta(hours=window_hours)

            current_group = []
            current_start = start_time

            for _, row in family_df.iterrows():
                if row["first_seen_ts"] - current_start <= window_delta:
                    current_group.append(row["id"])
                else:
                    if len(current_group) >= 3:
                        for ind_id in current_group:
                            flags.append(AnomalyFlag(
                                indicator_id=ind_id,
                                flag_type="temporal_correlation",
                                description=f"{len(current_group)} IoCs for '{family}' in {window_hours}h window",
                                anomaly_score=25.0,
                                metadata_json=json.dumps({
                                    "malware_family": family,
                                    "cluster_size": len(current_group),
                                }),
                            ))
                    current_group = [row["id"]]
                    current_start = row["first_seen_ts"]

            if len(current_group) >= 3:
                for ind_id in current_group:
                    flags.append(AnomalyFlag(
                        indicator_id=ind_id,
                        flag_type="temporal_correlation",
                        description=f"{len(current_group)} IoCs for '{family}' in {window_hours}h window",
                        anomaly_score=25.0,
                        metadata_json=json.dumps({
                            "malware_family": family,
                            "cluster_size": len(current_group),
                        }),
                    ))

        logger.info(f"Temporal correlation: {len(flags)} flags.")
        return flags

    def _detect_cross_feed_conflict(self, df: pd.DataFrame) -> List[AnomalyFlag]:
        """Rule 4: Flag IoCs where >20% of reporting feeds assign 'low' severity."""
        flags = []

        multi_source = df.groupby("ioc_value").filter(lambda x: x["source_feed"].nunique() > 1)
        if multi_source.empty:
            return flags

        severity_agg = multi_source.groupby("ioc_value").agg(
            total_feeds=("source_feed", "nunique"),
            low_count=("severity", lambda x: (x == "low").sum()),
        ).reset_index()

        severity_agg["low_ratio"] = severity_agg["low_count"] / severity_agg["total_feeds"]
        conflicts = severity_agg[severity_agg["low_ratio"] > 0.2]["ioc_value"]

        for ioc_value in conflicts:
            indicator_ids = df[df["ioc_value"] == ioc_value]["id"].tolist()
            for ind_id in indicator_ids:
                flags.append(AnomalyFlag(
                    indicator_id=ind_id,
                    flag_type="cross_feed_conflict",
                    description=f"Conflicting severity assessments across feeds for {ioc_value}",
                    anomaly_score=-15.0,
                    metadata_json=json.dumps({"ioc_value": str(ioc_value)}),
                ))

        logger.info(f"Cross-feed conflict: {len(flags)} flags.")
        return flags

    def _apply_recency_decay(self, df: pd.DataFrame, decay_days: int = 180) -> List[AnomalyFlag]:
        """Rule 5: Flag stale IoCs and detect reactivations."""
        flags = []
        now = pd.Timestamp.now(tz=timezone.utc)

        df_copy = df.copy()
        df_copy["last_seen_ts"] = pd.to_datetime(df_copy["last_seen"], errors="coerce")
        df_copy["first_seen_ts"] = pd.to_datetime(df_copy["first_seen"], errors="coerce")

        has_last_seen = df_copy.dropna(subset=["last_seen_ts"])
        if has_last_seen.empty:
            return flags

        has_last_seen["days_since_seen"] = (now - has_last_seen["last_seen_ts"]).dt.days

        stale = has_last_seen[has_last_seen["days_since_seen"] > decay_days]
        for _, row in stale.iterrows():
            flags.append(AnomalyFlag(
                indicator_id=row["id"],
                flag_type="stale_recency_decay",
                description=f"IoC not seen in {int(row['days_since_seen'])} days",
                anomaly_score=-20.0,
                metadata_json=json.dumps({"days_since_seen": int(row["days_since_seen"])}),
            ))

        if not stale.empty:
            stale_with_first = stale.dropna(subset=["first_seen_ts"])
            if not stale_with_first.empty:
                days_since_first = (now - stale_with_first["first_seen_ts"]).dt.days
                reactivated = stale_with_first[days_since_first <= 7]
                for _, row in reactivated.iterrows():
                    flags.append(AnomalyFlag(
                        indicator_id=row["id"],
                        flag_type="reactivation_detected",
                        description=f"Previously stale IoC reactivated (first_seen within 7 days)",
                        anomaly_score=40.0,
                    ))

        logger.info(f"Recency decay: {len(flags)} flags.")
        return flags
