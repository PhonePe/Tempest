// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use jiff::{Timestamp, tz::Offset};
use serde::{Deserialize, Deserializer, Serializer};

fn precision(timestamp: Timestamp) -> usize {
    match timestamp.subsec_nanosecond() {
        0 => 0,
        nanos if nanos % 1_000_000 == 0 => 3,
        nanos if nanos % 1_000 == 0 => 6,
        _ => 9,
    }
}

pub(crate) fn to_rfc3339(timestamp: Timestamp) -> String {
    format!(
        "{:.precision$}",
        timestamp.display_with_offset(Offset::UTC),
        precision = precision(timestamp)
    )
}

pub(crate) fn serialize<S: Serializer>(
    timestamp: &Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!(
        "{timestamp:.precision$}",
        precision = precision(*timestamp)
    ))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Timestamp, D::Error> {
    Timestamp::deserialize(deserializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Record {
        #[serde(with = "super")]
        timestamp: Timestamp,
    }

    #[test]
    fn preserves_legacy_signed_and_json_timestamp_bytes() {
        for (input, expected) in [
            ("2026-11-17T12:34:56Z", "2026-11-17T12:34:56Z"),
            ("2026-11-17T12:34:56.123Z", "2026-11-17T12:34:56.123Z"),
            ("2026-11-17T12:34:56.123450Z", "2026-11-17T12:34:56.123450Z"),
            (
                "2026-11-17T12:34:56.123456780Z",
                "2026-11-17T12:34:56.123456780Z",
            ),
            (
                "1969-12-31T23:59:59.123456780Z",
                "1969-12-31T23:59:59.123456780Z",
            ),
            (
                "2026-11-17T18:04:56.123450+05:30",
                "2026-11-17T12:34:56.123450Z",
            ),
        ] {
            let timestamp: Timestamp = input.parse().unwrap();
            assert_eq!(
                to_rfc3339(timestamp),
                format!("{}+00:00", expected.strip_suffix('Z').unwrap())
            );
            let encoded = serde_json::to_string(&Record { timestamp }).unwrap();
            assert_eq!(
                encoded,
                serde_json::json!({"timestamp": expected}).to_string()
            );
            assert_eq!(
                serde_json::from_str::<Record>(&encoded).unwrap().timestamp,
                timestamp
            );
            let legacy_offset = serde_json::json!({"timestamp": to_rfc3339(timestamp)});
            assert_eq!(
                serde_json::from_value::<Record>(legacy_offset)
                    .unwrap()
                    .timestamp,
                timestamp
            );
        }
    }
}
