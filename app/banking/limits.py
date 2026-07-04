from __future__ import annotations

from decimal import Decimal


PAYUP_DAILY_LIMIT_MIN = Decimal("100.00")
PAYUP_DAILY_LIMIT_MAX = Decimal("10000.00")
PAYUP_DAILY_LIMIT_DEFAULT = Decimal("500.00")
PAYUP_DAILY_LIMIT_PRECISION = Decimal("0.01")
PAYUP_DAILY_LIMIT_PRESETS = ("100", "500", "1000", "3000", "5000", "10000")
PAYUP_DAILY_LIMIT_CHOICES = [
    (value, f"SGD {value}") for value in PAYUP_DAILY_LIMIT_PRESETS
] + [("custom", "Custom amount")]
