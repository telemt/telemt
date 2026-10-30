use serde::{Deserialize, Serialize};

/// Calendar used for recurring quota resets; all boundaries are UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserQuotaPeriod {
    /// Each UTC midnight.
    Daily,
    /// Monday at UTC midnight.
    Weekly,
    /// The first day of each UTC month.
    Monthly,
}

impl UserQuotaPeriod {
    /// Returns the UTC boundary at or before the supplied Unix timestamp.
    pub(crate) fn start(self, epoch: u64) -> std::io::Result<u64> {
        use chrono::Datelike;
        let timestamp = i64::try_from(epoch).map_err(|_| invalid_time())?;
        let date = chrono::DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(invalid_time)?
            .date_naive();
        let start = match self {
            Self::Daily => Some(date),
            Self::Weekly => date.checked_sub_days(chrono::Days::new(u64::from(
                date.weekday().num_days_from_monday(),
            ))),
            Self::Monthly => date.with_day(1),
        }
        .ok_or_else(invalid_time)?;
        u64::try_from(
            start
                .and_hms_opt(0, 0, 0)
                .ok_or_else(invalid_time)?
                .and_utc()
                .timestamp(),
        )
        .map_err(|_| invalid_time())
    }

    /// Returns the first UTC calendar boundary strictly after the cursor.
    pub(crate) fn next(self, cursor: u64) -> std::io::Result<u64> {
        let start = self.start(cursor)?;
        let date = chrono::DateTime::from_timestamp(start as i64, 0)
            .ok_or_else(invalid_time)?
            .date_naive();
        let next = match self {
            Self::Daily => date.checked_add_days(chrono::Days::new(1)),
            Self::Weekly => date.checked_add_days(chrono::Days::new(7)),
            Self::Monthly => date.checked_add_months(chrono::Months::new(1)),
        }
        .ok_or_else(invalid_time)?;
        u64::try_from(
            next.and_hms_opt(0, 0, 0)
                .ok_or_else(invalid_time)?
                .and_utc()
                .timestamp(),
        )
        .map_err(|_| invalid_time())
    }
}

fn invalid_time() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "quota calendar timestamp is outside the supported UTC range",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(value: &str) -> u64 {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .timestamp() as u64
    }

    #[test]
    fn quota_calendar_boundaries_are_strict_and_handle_leap_years() {
        for (period, now, start, next) in [
            (
                UserQuotaPeriod::Daily,
                "2024-02-29T23:59:59Z",
                "2024-02-29T00:00:00Z",
                "2024-03-01T00:00:00Z",
            ),
            (
                UserQuotaPeriod::Weekly,
                "2024-12-31T12:00:00Z",
                "2024-12-30T00:00:00Z",
                "2025-01-06T00:00:00Z",
            ),
            (
                UserQuotaPeriod::Monthly,
                "2024-02-15T12:00:00Z",
                "2024-02-01T00:00:00Z",
                "2024-03-01T00:00:00Z",
            ),
            (
                UserQuotaPeriod::Monthly,
                "2023-12-31T23:59:59Z",
                "2023-12-01T00:00:00Z",
                "2024-01-01T00:00:00Z",
            ),
        ] {
            assert_eq!(period.start(epoch(now)).unwrap(), epoch(start));
            assert_eq!(period.next(epoch(now)).unwrap(), epoch(next));
            assert_eq!(period.next(epoch(start)).unwrap(), epoch(next));
        }
        assert!(UserQuotaPeriod::Daily.next(u64::MAX).is_err());
    }
}
