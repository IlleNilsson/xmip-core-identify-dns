//! The resolver the node supplies, and the static one the tests do.
//!
//! `std` can look a name up and cannot look an address up, so the reverse
//! half is the one a node has to bring — from its own stub resolver, from a
//! DNS transport, from a hosts table. The forward half has a default over
//! `ToSocketAddrs` that any implementation may keep.

use std::net::{IpAddr, ToSocketAddrs};

use identify::IdentifyError;

/// Answers the two questions forward-confirmed reverse DNS asks.
pub trait Resolver: Send + Sync {
    /// The `PTR` name behind an address, or `None` where there is none.
    ///
    /// # Errors
    ///
    /// Where the resolver could not be asked. Not the same as no record.
    fn reverse(&self, address: IpAddr) -> Result<Option<String>, IdentifyError>;

    /// The addresses a name resolves to. Empty where it resolves to none.
    ///
    /// The default asks the operating system through `ToSocketAddrs`.
    ///
    /// # Errors
    ///
    /// Where the resolver could not be asked.
    fn forward(&self, name: &str) -> Result<Vec<IpAddr>, IdentifyError> {
        forward_by_system(name)
    }
}

/// The operating system's forward lookup. A name that does not exist is an
/// empty answer rather than an error, as it is for a reverse record.
///
/// # Errors
///
/// Where the lookup itself failed for a reason other than the name not
/// existing — the system reports both as one `io::Error`, so a name it
/// cannot resolve is read as no answer and only a name that is not even
/// askable is an error.
pub fn forward_by_system(name: &str) -> Result<Vec<IpAddr>, IdentifyError> {
    if name.is_empty() || name.contains(|character: char| character.is_whitespace()) {
        return Err(IdentifyError::new(format!(
            "{name:?} is not a host name the system can resolve"
        )));
    }

    Ok((name, 0u16)
        .to_socket_addrs()
        .map(|addresses| addresses.map(|socket| socket.ip()).collect())
        .unwrap_or_default())
}

/// A resolver that answers from a table. What the tests use, and what a
/// node with a hosts file can use.
#[derive(Clone, Debug, Default)]
pub struct StaticResolver {
    reverse: Vec<(IpAddr, String)>,
    forward: Vec<(String, IpAddr)>,
}

impl StaticResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This address reverses to this name.
    #[must_use]
    pub fn reverse(mut self, address: IpAddr, name: impl Into<String>) -> Self {
        self.reverse.push((address, name.into()));
        self
    }

    /// This name resolves to this address, among whatever else it resolves to.
    #[must_use]
    pub fn forward(mut self, name: impl Into<String>, address: IpAddr) -> Self {
        self.forward.push((crate::canonical(&name.into()), address));
        self
    }
}

impl Resolver for StaticResolver {
    fn reverse(&self, address: IpAddr) -> Result<Option<String>, IdentifyError> {
        Ok(self
            .reverse
            .iter()
            .find(|(candidate, _)| *candidate == address)
            .map(|(_, name)| name.clone()))
    }

    fn forward(&self, name: &str) -> Result<Vec<IpAddr>, IdentifyError> {
        let name = crate::canonical(name);

        Ok(self
            .forward
            .iter()
            .filter(|(candidate, _)| *candidate == name)
            .map(|(_, address)| *address)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_static_table_answers_both_directions_and_nothing_it_was_not_told() {
        let loopback: IpAddr = "127.0.0.1".parse().expect("an address");
        let table = StaticResolver::new()
            .reverse(loopback, "localhost.")
            .forward("LOCALHOST", loopback);

        assert_eq!(
            Resolver::reverse(&table, loopback).expect("asked"),
            Some("localhost.".to_string())
        );
        assert_eq!(
            Resolver::forward(&table, "localhost.").expect("asked"),
            vec![loopback]
        );
        assert!(
            Resolver::forward(&table, "elsewhere")
                .expect("asked")
                .is_empty()
        );
    }

    #[test]
    fn the_system_forward_lookup_finds_localhost_and_nothing_for_nonsense() {
        let answers = forward_by_system("localhost").expect("asked");

        assert!(
            answers.iter().all(IpAddr::is_loopback),
            "localhost is loopback"
        );
        assert!(forward_by_system("no such host").is_err());
    }
}
