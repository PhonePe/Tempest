// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Prometheus text from STANDARD OpenTelemetry SDK data. Unlike the protobuf
//! model in prometheus's encoder, this path never casts u64 counters to f64.

use std::fmt::{Display, Write};

use bytes::Bytes;

use super::render::Definition;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};

pub(super) fn render(metrics: &ResourceMetrics, definitions: &[Definition]) -> Bytes {
    let mut output = String::with_capacity(8192);
    for &(name, help, kind) in definitions {
        let _ = writeln!(output, "# HELP {name} {help}\n# TYPE {name} {kind}");
        for metric in metrics
            .scope_metrics()
            .flat_map(|scope| scope.metrics())
            .filter(|m| m.name() == name)
        {
            match metric.data() {
                AggregatedMetrics::U64(data) => write_data(&mut output, name, data),
                AggregatedMetrics::F64(data) => write_data(&mut output, name, data),
                AggregatedMetrics::I64(data) => write_data(&mut output, name, data),
            }
        }
        output.push('\n');
    }
    Bytes::from(output)
}

fn write_data<T: Copy + Display>(output: &mut String, name: &str, data: &MetricData<T>) {
    match data {
        MetricData::Gauge(gauge) => {
            for point in gauge.data_points() {
                write_sample(
                    output,
                    name,
                    "",
                    point.attributes().collect(),
                    None,
                    point.value(),
                );
            }
        }
        MetricData::Sum(sum) => {
            for point in sum.data_points() {
                write_sample(
                    output,
                    name,
                    "",
                    point.attributes().collect(),
                    None,
                    point.value(),
                );
            }
        }
        MetricData::Histogram(histogram) => {
            for point in histogram.data_points() {
                let mut cumulative = 0u64;
                for (bound, count) in point.bounds().zip(point.bucket_counts()) {
                    cumulative = cumulative.saturating_add(count);
                    write_sample(
                        output,
                        name,
                        "_bucket",
                        point.attributes().collect(),
                        Some(&bound.to_string()),
                        cumulative,
                    );
                }
                write_sample(
                    output,
                    name,
                    "_bucket",
                    point.attributes().collect(),
                    Some("+Inf"),
                    point.count(),
                );
                write_sample(
                    output,
                    name,
                    "_sum",
                    point.attributes().collect(),
                    None,
                    point.sum(),
                );
                write_sample(
                    output,
                    name,
                    "_count",
                    point.attributes().collect(),
                    None,
                    point.count(),
                );
            }
        }
        MetricData::ExponentialHistogram(_) => {
            unreachable!("local histograms use explicit buckets")
        }
    }
}

fn write_sample(
    output: &mut String,
    name: &str,
    suffix: &str,
    mut labels: Vec<&KeyValue>,
    bound: Option<&str>,
    value: impl Display,
) {
    // Preserve the established compound-label order regardless of SDK storage.
    labels.sort_by_key(|kv| match kv.key.as_str() {
        "boot_profile" => (0, kv.key.as_str()),
        "transport" | "contract" => (1, kv.key.as_str()),
        _ => (2, kv.key.as_str()),
    });
    let _ = write!(output, "{name}{suffix}");
    if !labels.is_empty() || bound.is_some() {
        output.push('{');
        for (index, label) in labels.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let _ = write!(output, "{}=\"", label.key.as_str().replace('.', "_"));
            for character in label.value.to_string().chars() {
                match character {
                    '\\' => output.push_str("\\\\"),
                    '"' => output.push_str("\\\""),
                    '\n' => output.push_str("\\n"),
                    other => output.push(other),
                }
            }
            output.push('"');
        }
        if let Some(bound) = bound {
            if !labels.is_empty() {
                output.push(',');
            }
            let _ = write!(output, "le=\"{bound}\"");
        }
        output.push('}');
    }
    let _ = writeln!(output, " {value}");
}
