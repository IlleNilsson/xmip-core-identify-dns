#![forbid(unsafe_code)]

//! Identify by dns: the peer's reverse name is the claim.
//!
//! Nothing on the wire says a name. The transport reports the socket peer as
//! `peer.address`, and this asks the [`Resolver`] the node is given for the
//! `PTR` record behind it — which is why the claim is *detected*, read out
//! of what is there, and never passed ([`xcore::mechanism::dns`]).
//!
//! A reverse record is written by whoever holds the reverse zone for the
//! address, which for most of the internet is not the peer's owner, and for
//! anyone who does hold it is a free-text field. So the name is
//! forward-confirmed before it is presented: the resolver looks the name up
//! and the peer address has to be among its answers. A name that does not
//! confirm is not a claim at all and the identifier presents nothing, on
//! the same footing as a peer with no reverse record. Where the resolver
//! itself fails, that is an error: the node was asked to read something and
//! could not.
//!
//! The node supplies the resolver. `std` has forward lookup and no reverse,
//! so [`Resolver::forward`] has a default over `ToSocketAddrs` and
//! [`Resolver::reverse`] is the one method an implementation must bring; a
//! [`StaticResolver`] answers both from a table and is what the tests use.
//!
//! Only a pushed Stream has a peer; a detected or scheduled arrival presents
//! nothing here.
//!
//! Property name this technology reads: `peer.address` (defined by
//! `context::property::PEER_ADDRESS`). Evidence it writes: `peer.address` and
//! `dns.forward-confirmed`, always `true` on a claim it presents.

pub mod resolver;

use context::property::PEER_ADDRESS;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
pub use resolver::{Resolver, StaticResolver};
use xcore::{Arriving, Mechanism};

/// Reads the peer's reverse name through the node's resolver.
pub struct DnsIdentifier {
    resolver: Box<dyn Resolver>,
}

impl DnsIdentifier {
    /// Resolve through this.
    #[must_use]
    pub fn new(resolver: impl Resolver + 'static) -> Self {
        Self {
            resolver: Box::new(resolver),
        }
    }
}

impl TransportIdentifier for DnsIdentifier {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::dns()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(peer) = arrival.property(PEER_ADDRESS) else {
            return Ok(None);
        };
        let peer = net::address::parse(peer)?;

        let Some(name) = self.resolver.reverse(peer)? else {
            return Ok(None);
        };
        let name = canonical(&name);

        if !self.resolver.forward(&name)?.contains(&peer) {
            return Ok(None);
        }

        Ok(Some(
            Presented::detected(self.mechanism(), name)
                .with_evidence(PEER_ADDRESS, peer.to_string())
                .with_evidence("dns.forward-confirmed", "true"),
        ))
    }
}

/// A host name as it is compared: lowercase, no trailing dot.
#[must_use]
pub fn canonical(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use stream::Stream;
    use xcore::StreamId;

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn facts(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// One partner whose reverse and forward agree, one whose reverse zone
    /// claims a name the name does not claim back.
    fn resolver() -> StaticResolver {
        StaticResolver::new()
            .reverse(address("192.0.2.10"), "mail.partner-x.example.")
            .forward("mail.partner-x.example", address("192.0.2.10"))
            .reverse(address("203.0.113.9"), "mail.partner-x.example")
    }

    fn identifier() -> DnsIdentifier {
        DnsIdentifier::new(resolver())
    }

    #[test]
    fn a_forward_confirmed_reverse_name_is_detected() {
        let stream = stream();
        let facts = facts(&[("peer.address", "192.0.2.10:44123")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "smtp://xmip/in", &facts);

        let claim = identifier()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "mail.partner-x.example");
        assert_eq!(claim.established, xcore::Established::Detected);
        assert_eq!(
            claim.evidence,
            vec![
                ("peer.address".to_string(), "192.0.2.10".to_string()),
                ("dns.forward-confirmed".to_string(), "true".to_string()),
            ]
        );
    }

    #[test]
    fn a_reverse_name_the_forward_zone_does_not_claim_back_is_no_claim() {
        // Whoever holds 203.0.113.9's reverse zone wrote partner-x's name in
        // it. The name's own zone does not point back, so nothing is claimed.
        let stream = stream();
        let facts = facts(&[("peer.address", "203.0.113.9")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "smtp://xmip/in", &facts);

        assert!(identifier().identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn a_peer_with_no_reverse_record_presents_nothing() {
        let stream = stream();
        let facts = facts(&[("peer.address", "198.51.100.17")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "smtp://xmip/in", &facts);

        assert!(identifier().identify(&arrival).expect("read").is_none());

        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "smtp://xmip/in", &[]);

        assert!(identifier().identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn a_peer_that_is_not_an_address_is_an_error() {
        let stream = stream();
        let facts = facts(&[("peer.address", "not-an-address")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "smtp://xmip/in", &facts);

        let failure = identifier().identify(&arrival).expect_err("not an address");

        assert_eq!(
            failure.to_string(),
            "the peer address \"not-an-address\" is not an IP address"
        );
    }

    #[test]
    fn a_scheduled_pickup_has_no_peer_to_name() {
        let stream = stream();
        let facts = facts(&[("peer.address", "192.0.2.10")]);
        let arrival = StreamArrival::new(&stream, Arriving::Scheduled, "imap://mail/inbox", &facts);

        assert!(identifier().identify(&arrival).expect("read").is_none());
    }
}
