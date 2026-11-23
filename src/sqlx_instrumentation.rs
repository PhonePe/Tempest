// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use futures_core::{future::BoxFuture, stream::BoxStream};
use sqlx::{
    Any, AnyConnection, AnyPool, Database, Describe, Either, Error, Execute, Executor, Transaction,
    any::{AnyQueryResult, AnyRow},
    pool::PoolConnection,
};
use tracing::{Instrument, Span};

#[derive(Clone, Debug)]
pub(crate) struct TracedPool {
    inner: AnyPool,
    system: &'static str,
}

impl TracedPool {
    #[cfg(test)]
    pub(crate) async fn close(&self) {
        self.inner.close().await;
    }

    pub(crate) fn new(inner: AnyPool, system: &'static str) -> Self {
        Self { inner, system }
    }

    pub(crate) async fn begin(&self) -> Result<TracedTransaction<'static>, Error> {
        let span = transaction_span("BEGIN", self.system);
        let result = self.inner.begin().instrument(span.clone()).await;
        if let Err(error) = &result {
            record_error(&span, error);
        }
        let inner = result?;
        Ok(TracedTransaction {
            inner,
            system: self.system,
        })
    }

    pub(crate) async fn acquire(&self) -> Result<TracedPoolConnection, Error> {
        Ok(TracedPoolConnection {
            inner: self.inner.acquire().await?,
            system: self.system,
        })
    }
}

impl<'pool> Executor<'pool> for &'pool TracedPool {
    type Database = Any;

    fn fetch_many<'execute, 'query: 'execute, Query>(
        self,
        query: Query,
    ) -> BoxStream<'execute, Result<Either<AnyQueryResult, AnyRow>, Error>>
    where
        'pool: 'execute,
        Query: 'query + Execute<'query, Any>,
    {
        traced_fetch_many(&self.inner, query, self.system)
    }

    fn fetch_optional<'execute, 'query: 'execute, Query>(
        self,
        query: Query,
    ) -> BoxFuture<'execute, Result<Option<AnyRow>, Error>>
    where
        'pool: 'execute,
        Query: 'query + Execute<'query, Any>,
    {
        traced_fetch_optional(&self.inner, query, self.system)
    }

    fn fetch_one<'execute, 'query: 'execute, Query>(
        self,
        query: Query,
    ) -> BoxFuture<'execute, Result<AnyRow, Error>>
    where
        'pool: 'execute,
        Query: 'query + Execute<'query, Any>,
    {
        traced_fetch_one(&self.inner, query, self.system)
    }

    fn prepare_with<'execute, 'query: 'execute>(
        self,
        sql: &'query str,
        parameters: &'execute [<Any as Database>::TypeInfo],
    ) -> BoxFuture<'execute, Result<<Any as Database>::Statement<'query>, Error>>
    where
        'pool: 'execute,
    {
        (&self.inner).prepare_with(sql, parameters)
    }

    fn describe<'execute, 'query: 'execute>(
        self,
        sql: &'query str,
    ) -> BoxFuture<'execute, Result<Describe<Any>, Error>>
    where
        'pool: 'execute,
    {
        (&self.inner).describe(sql)
    }
}

pub(crate) struct TracedTransaction<'connection> {
    inner: Transaction<'connection, Any>,
    system: &'static str,
}

impl TracedTransaction<'_> {
    pub(crate) fn executor(&mut self) -> TracedConnection<'_> {
        TracedConnection {
            inner: &mut self.inner,
            system: self.system,
        }
    }

    pub(crate) async fn commit(self) -> Result<(), Error> {
        let span = transaction_span("COMMIT", self.system);
        let result = self.inner.commit().instrument(span.clone()).await;
        if let Err(error) = &result {
            record_error(&span, error);
        }
        result
    }

    #[cfg(test)]
    pub(crate) async fn rollback(self) -> Result<(), Error> {
        self.inner.rollback().await
    }
}

pub(crate) struct TracedPoolConnection {
    inner: PoolConnection<Any>,
    system: &'static str,
}

impl TracedPoolConnection {
    pub(crate) fn executor(&mut self) -> TracedConnection<'_> {
        TracedConnection {
            inner: &mut self.inner,
            system: self.system,
        }
    }
}

#[derive(Debug)]
pub(crate) struct TracedConnection<'connection> {
    inner: &'connection mut AnyConnection,
    system: &'static str,
}

impl<'connection> Executor<'connection> for TracedConnection<'connection> {
    type Database = Any;

    fn fetch_many<'execute, 'query: 'execute, Query>(
        self,
        query: Query,
    ) -> BoxStream<'execute, Result<Either<AnyQueryResult, AnyRow>, Error>>
    where
        'connection: 'execute,
        Query: 'query + Execute<'query, Any>,
    {
        traced_fetch_many(self.inner, query, self.system)
    }

    fn fetch_optional<'execute, 'query: 'execute, Query>(
        self,
        query: Query,
    ) -> BoxFuture<'execute, Result<Option<AnyRow>, Error>>
    where
        'connection: 'execute,
        Query: 'query + Execute<'query, Any>,
    {
        traced_fetch_optional(self.inner, query, self.system)
    }

    fn fetch_one<'execute, 'query: 'execute, Query>(
        self,
        query: Query,
    ) -> BoxFuture<'execute, Result<AnyRow, Error>>
    where
        'connection: 'execute,
        Query: 'query + Execute<'query, Any>,
    {
        traced_fetch_one(self.inner, query, self.system)
    }

    fn prepare_with<'execute, 'query: 'execute>(
        self,
        sql: &'query str,
        parameters: &'execute [<Any as Database>::TypeInfo],
    ) -> BoxFuture<'execute, Result<<Any as Database>::Statement<'query>, Error>>
    where
        'connection: 'execute,
    {
        self.inner.prepare_with(sql, parameters)
    }

    fn describe<'execute, 'query: 'execute>(
        self,
        sql: &'query str,
    ) -> BoxFuture<'execute, Result<Describe<Any>, Error>>
    where
        'connection: 'execute,
    {
        self.inner.describe(sql)
    }
}

fn traced_fetch_many<'executor, 'query: 'executor, Query, E>(
    executor: E,
    query: Query,
    system: &'static str,
) -> BoxStream<'executor, Result<Either<AnyQueryResult, AnyRow>, Error>>
where
    E: Executor<'executor, Database = Any> + 'executor,
    Query: 'query + Execute<'query, Any>,
{
    let span = query_span(query.sql(), system);
    let mut affected_rows = 0_u64;
    let mut returned_rows = 0_u64;
    let mut stream = executor.fetch_many(query);
    Box::pin(futures_util::stream::poll_fn(move |cx| {
        // Enter only for this poll; never retain an entered guard across Pending.
        let _entered = span.enter();
        stream.as_mut().poll_next(cx).map(|item| {
            if let Some(result) = &item {
                match result {
                    Ok(Either::Left(query_result)) => {
                        affected_rows = affected_rows.saturating_add(query_result.rows_affected());
                        span.record("db.response.affected_rows", affected_rows);
                    }
                    Ok(Either::Right(_)) => {
                        returned_rows = returned_rows.saturating_add(1);
                        span.record("db.response.returned_rows", returned_rows);
                    }
                    Err(error) => record_error(&span, error),
                }
            }
            item
        })
    }))
}

fn traced_fetch_optional<'executor, 'query: 'executor, Query, E>(
    executor: E,
    query: Query,
    system: &'static str,
) -> BoxFuture<'executor, Result<Option<AnyRow>, Error>>
where
    E: Executor<'executor, Database = Any> + 'executor,
    Query: 'query + Execute<'query, Any>,
{
    let span = query_span(query.sql(), system);
    let result_span = span.clone();
    Box::pin(
        async move {
            let result = executor.fetch_optional(query).await;
            match &result {
                Ok(row) => {
                    result_span.record("db.response.returned_rows", u64::from(row.is_some()));
                }
                Err(error) => record_error(&result_span, error),
            }
            result
        }
        .instrument(span),
    )
}

fn traced_fetch_one<'executor, 'query: 'executor, Query, E>(
    executor: E,
    query: Query,
    system: &'static str,
) -> BoxFuture<'executor, Result<AnyRow, Error>>
where
    E: Executor<'executor, Database = Any> + 'executor,
    Query: 'query + Execute<'query, Any>,
{
    let span = query_span(query.sql(), system);
    let result_span = span.clone();
    Box::pin(
        async move {
            let result = executor.fetch_one(query).await;
            match &result {
                Ok(_) => {
                    result_span.record("db.response.returned_rows", 1_u64);
                }
                Err(error) => record_error(&result_span, error),
            }
            result
        }
        .instrument(span),
    )
}

fn query_span(statement: &str, system: &'static str) -> Span {
    let operation = operation_name(statement);
    tracing::info_span!(
        "db.query",
        otel.name = %format_args!("{operation} {system}"),
        otel.kind = "client",
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
        db.system.name = system,
        db.operation.name = operation,
        db.query.text = statement,
        db.response.affected_rows = tracing::field::Empty,
        db.response.returned_rows = tracing::field::Empty,
        error.type = tracing::field::Empty,
    )
}

fn transaction_span(operation: &'static str, system: &'static str) -> Span {
    tracing::info_span!(
        "db.query",
        otel.name = %format_args!("{operation} {system}"),
        otel.kind = "client",
        db.system.name = system,
        db.operation.name = operation,
        db.query.text = "",
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
        error.type = tracing::field::Empty,
    )
}

fn record_error(span: &Span, error: &Error) {
    span.record("otel.status_code", "error");
    span.record("otel.status_description", "Database operation failed");
    span.record("error.type", error_type(error));
}

fn error_type(error: &Error) -> &'static str {
    match error {
        Error::Configuration(_) => "configuration",
        Error::Database(_) => "database",
        Error::Io(_) | Error::Tls(_) => "transport",
        Error::Protocol(_) => "protocol",
        Error::RowNotFound => "row_not_found",
        Error::TypeNotFound { .. } => "type_not_found",
        Error::ColumnIndexOutOfBounds { .. }
        | Error::ColumnNotFound(_)
        | Error::ColumnDecode { .. } => "column",
        Error::Encode(_) => "encode",
        Error::Decode(_) => "decode",
        Error::PoolTimedOut | Error::PoolClosed => "pool",
        Error::WorkerCrashed => "worker",
        _ => "unknown",
    }
}

fn operation_name(statement: &str) -> &'static str {
    const OPERATIONS: &[&str] = &[
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "REPLACE",
        "CREATE",
        "ALTER",
        "DROP",
        "TRUNCATE",
        "EXPLAIN",
        "PRAGMA",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
    ];
    let token = statement
        .split_ascii_whitespace()
        .next()
        .unwrap_or_default();
    OPERATIONS
        .iter()
        .copied()
        .find(|operation| token.eq_ignore_ascii_case(operation))
        .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

    #[derive(Clone, Default)]
    struct Capture(
        Arc<Mutex<BTreeMap<String, String>>>,
        Arc<std::sync::atomic::AtomicUsize>,
    );
    impl Visit for Capture {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .lock()
                .unwrap()
                .insert(field.name().into(), format!("{value:?}"));
        }
    }
    impl<S> Layer<S> for Capture
    where
        S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    {
        fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
            if ctx.span(id).is_some_and(|span| span.name() == "db.query") {
                self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        fn on_record(
            &self,
            _: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _: Context<'_, S>,
        ) {
            values.record(&mut self.clone());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bulk_queries_enter_span_and_record_errors() {
        use std::sync::atomic::Ordering;
        let capture = Capture::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        pool.close().await;
        let pool = TracedPool::new(pool, "postgresql");
        assert!(sqlx::query("SELECT 1").fetch_all(&pool).await.is_err());
        assert!(capture.1.swap(0, Ordering::Relaxed) > 0);
        assert!(Span::current().is_none(), "query span leaked after polling");
        assert!(sqlx::query("SELECT 1").execute(&pool).await.is_err());
        assert!(capture.1.load(Ordering::Relaxed) > 0);
        assert!(Span::current().is_none(), "query span leaked after polling");
        assert_eq!(
            capture.0.lock().unwrap().get("otel.status_code").unwrap(),
            "\"error\""
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bulk_queries_record_successful_results() {
        let Some(url) = crate::persistence::test_database_url() else {
            return;
        };
        let _database_slot = crate::persistence::test_database_slot().await;
        let capture = Capture::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
        sqlx::any::install_default_drivers();
        let pool = TracedPool::new(AnyPool::connect(&url).await.unwrap(), "test");
        let rows = sqlx::query("SELECT 1 UNION ALL SELECT 2")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            capture
                .0
                .lock()
                .unwrap()
                .get("db.response.returned_rows")
                .unwrap(),
            "2"
        );
        capture.0.lock().unwrap().clear();
        sqlx::query("SELECT 1").execute(&pool).await.unwrap();
        let fields = capture.0.lock().unwrap();
        assert!(fields.contains_key("db.response.affected_rows"));
        assert!(!fields.contains_key("otel.status_code"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_one_missing_row_records_error_status() {
        let Some(url) = crate::persistence::test_database_url() else {
            return;
        };
        let _database_slot = crate::persistence::test_database_slot().await;
        let capture = Capture::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
        sqlx::any::install_default_drivers();
        let pool = TracedPool::new(AnyPool::connect(&url).await.unwrap(), "test");

        let result = sqlx::query("SELECT 1 WHERE 1 = 0").fetch_one(&pool).await;
        assert!(matches!(result, Err(Error::RowNotFound)));
        let fields = capture.0.lock().unwrap();
        assert_eq!(fields.get("otel.status_code").unwrap(), "\"error\"");
        assert_eq!(fields.get("error.type").unwrap(), "\"row_not_found\"");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn begin_failure_records_error_status() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        pool.close().await;
        assert!(TracedPool::new(pool, "postgresql").begin().await.is_err());
        assert_eq!(
            capture.0.lock().unwrap().get("otel.status_code").unwrap(),
            "\"error\""
        );
        assert_eq!(
            capture.0.lock().unwrap().get("error.type").unwrap(),
            "\"pool\""
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn commit_failure_records_error_status() {
        let Some(url) = crate::persistence::test_database_url() else {
            return;
        };
        let _database_slot = crate::persistence::test_database_slot().await;
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        sqlx::any::install_default_drivers();
        let pool = AnyPool::connect(&url).await.unwrap();
        let traced = TracedPool::new(pool.clone(), "test");
        let mut tx = traced.begin().await.unwrap();
        let id_sql = if url.starts_with("mysql:") {
            "SELECT CONNECTION_ID()"
        } else {
            "SELECT pg_backend_pid()"
        };
        use sqlx::Row;
        let id: i64 = sqlx::query(id_sql)
            .fetch_one(tx.executor())
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        let kill = if url.starts_with("mysql:") {
            format!("KILL CONNECTION {id}")
        } else {
            format!("SELECT pg_terminate_backend({id})")
        };
        sqlx::query(&kill).execute(&pool).await.unwrap();
        capture.0.lock().unwrap().clear();
        assert!(tx.commit().await.is_err());
        assert_eq!(
            capture.0.lock().unwrap().get("otel.status_code").unwrap(),
            "\"error\""
        );
        assert!(capture.0.lock().unwrap().contains_key("error.type"));
    }
}
