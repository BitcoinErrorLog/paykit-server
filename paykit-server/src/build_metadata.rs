include!(concat!(env!("OUT_DIR"), "/build_metadata.rs"));

/// Returns the source revision embedded into this binary at build time.
pub const fn source_sha() -> &'static str {
    SOURCE_SHA
}

/// Returns whether a value is a full hexadecimal Git object ID.
pub fn is_valid_source_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Emits the secret-free startup identity after initialization and before bind.
pub fn emit_startup_metadata(network: &str, role: &str, stack_id: &str) {
    tracing::info!(
        source_sha = source_sha(),
        version = env!("CARGO_PKG_VERSION"),
        network,
        role,
        stack_id,
    );
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    use serde_json::Value;
    use tracing_subscriber::fmt::MakeWriter;

    use super::{emit_startup_metadata, is_valid_source_sha, source_sha};

    #[derive(Clone)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().flush()
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn source_sha_is_build_exposed() {
        assert!(!source_sha().is_empty());
    }

    #[test]
    fn source_sha_parser_rejects_invalid_values() {
        assert!(is_valid_source_sha(
            "0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(!is_valid_source_sha("not-a-commit"));
        assert!(!is_valid_source_sha(
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        ));
        assert!(!is_valid_source_sha(
            "0123456789abcdef0123456789abcdef012345678"
        ));
        assert!(!is_valid_source_sha(
            "0123456789abcdef0123456789abcdef0123456g"
        ));
    }

    #[test]
    fn startup_metadata_is_structured_and_secret_free() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .with_writer(BufferWriter(output.clone()))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            emit_startup_metadata("mainnet", "production", "production:stack-1");
        });

        let rendered = output.lock().unwrap().clone();
        let event: Value = serde_json::from_slice(&rendered).unwrap();
        let fields = event.get("fields").unwrap().as_object().unwrap();
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["network", "role", "source_sha", "stack_id", "version"]
        );
        assert_eq!(fields["network"], "mainnet");
        assert_eq!(fields["role"], "production");
        assert_eq!(fields["source_sha"], source_sha());
        assert_eq!(fields["stack_id"], "production:stack-1");
        assert_eq!(fields["version"], env!("CARGO_PKG_VERSION"));
        assert!(
            !rendered
                .windows("database".len())
                .any(|window| window == b"database")
        );
        assert!(
            !rendered
                .windows("master".len())
                .any(|window| window == b"master")
        );
        assert!(!rendered.windows("key".len()).any(|window| window == b"key"));
        assert!(
            !rendered
                .windows("endpoint".len())
                .any(|window| window == b"endpoint")
        );
    }
}
