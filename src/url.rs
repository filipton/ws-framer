/// Parsed `ws://` / `wss://` url, borrowing the input.
///
/// `ws://localhost:321/dsa?x=1` gives host `localhost:321`, hostname `localhost`, port `321`,
/// path `/dsa?x=1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsUrl<'a> {
    /// `hostname[:port]` as written (the HTTP `Host` header value)
    pub host: &'a str,
    /// Host name or IP address without the port
    pub hostname: &'a str,
    /// Explicit port, or 80 (`ws`) / 443 (`wss`)
    pub port: u16,
    /// Path including the query, `/` if empty
    pub path: &'a str,
    /// `wss://` (TLS)
    pub secure: bool,
}

impl WsUrl<'_> {
    /// Parses a `ws://` or `wss://` url; `None` if it is malformed.
    pub fn parse(ws_url: &str) -> Option<WsUrl<'_>> {
        let (secure, rest) = if let Some(rest) = ws_url.strip_prefix("ws://") {
            (false, rest)
        } else {
            (true, ws_url.strip_prefix("wss://")?)
        };

        let (host, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, "/"),
        };
        let (hostname, port) = match host.split_once(':') {
            Some((hostname, port)) => (hostname, port.parse().ok()?),
            None => (host, if secure { 443 } else { 80 }),
        };
        if hostname.is_empty() || hostname.contains(['?', '#']) {
            return None;
        }

        Some(WsUrl {
            host,
            hostname,
            port,
            path,
            secure,
        })
    }
}

/// Owned version of [`WsUrl`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsUrlOwned {
    pub host: alloc::string::String,
    pub hostname: alloc::string::String,
    pub port: u16,

    pub path: alloc::string::String,
    pub secure: bool,
}

#[cfg(feature = "alloc")]
impl WsUrlOwned {
    /// Copies a borrowed url.
    pub fn new(ws_url: &WsUrl<'_>) -> Self {
        use crate::alloc::string::ToString;

        Self {
            host: ws_url.host.to_string(),
            hostname: ws_url.hostname.to_string(),
            port: ws_url.port,
            path: ws_url.path.to_string(),
            secure: ws_url.secure,
        }
    }

    /// Borrows this url as a [`WsUrl`].
    pub fn as_url(&self) -> WsUrl<'_> {
        WsUrl {
            host: &self.host,
            hostname: &self.hostname,
            port: self.port,
            path: &self.path,
            secure: self.secure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ws_url_parse() {
        assert_eq!(
            WsUrl::parse("ws://127.0.0.1"),
            Some(WsUrl {
                host: "127.0.0.1",
                hostname: "127.0.0.1",
                port: 80,
                path: "/",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::parse("wss://127.0.0.1"),
            Some(WsUrl {
                host: "127.0.0.1",
                hostname: "127.0.0.1",
                port: 443,
                path: "/",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::parse("ws://127.0.0.1:4321"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                hostname: "127.0.0.1",
                port: 4321,
                path: "/",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::parse("wss://127.0.0.1:4321"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                hostname: "127.0.0.1",
                port: 4321,
                path: "/",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::parse("ws://127.0.0.1:4321/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                hostname: "127.0.0.1",
                port: 4321,
                path: "/cxz/ewq",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::parse("wss://127.0.0.1:4321/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                hostname: "127.0.0.1",
                port: 4321,
                path: "/cxz/ewq",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::parse("ws://127.0.0.1/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1",
                hostname: "127.0.0.1",
                port: 80,
                path: "/cxz/ewq",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::parse("wss://127.0.0.1/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1",
                hostname: "127.0.0.1",
                port: 443,
                path: "/cxz/ewq",
                secure: true
            })
        );

        assert_eq!(WsUrl::parse("ws://127.0.0.1:d123"), None);
        assert_eq!(WsUrl::parse("ws://127.0.0.1:123d"), None);

        assert_eq!(WsUrl::parse("wsc://127.0.0.1/cxz/ewq"), None);
        assert_eq!(WsUrl::parse("ws://"), None);
        assert_eq!(WsUrl::parse("ws://:80/x"), None);
        assert_eq!(WsUrl::parse("ws://h?x=1"), None);
        assert_eq!(WsUrl::parse("ws://h:99999"), None);
        assert_eq!(WsUrl::parse("ws://127.0.0.1:4321:123/cxz/ewq"), None);
    }
}
