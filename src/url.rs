#[derive(Debug, PartialEq)]
/// Struct that stores parsed websocket url result
///
/// Example input:
/// ws://localhost:321/dsa
pub struct WsUrl<'a> {
    pub host: &'a str,
    pub ip: &'a str,
    pub port: u16,

    pub path: &'a str,
    pub secure: bool,
}

impl WsUrl<'_> {
    /// Parse ws url string
    pub fn from_str<'a>(ws_url: &'a str) -> Option<WsUrl<'a>> {
        let (secure, host_start_offset) = if ws_url.starts_with("ws://") {
            (false, 5)
        } else if ws_url.starts_with("wss://") {
            (true, 6)
        } else {
            return None;
        };

        let mut host_end = None;
        if let Some(ws_url) = ws_url.get(host_start_offset..) {
            let chars = ws_url.char_indices();
            for c in chars {
                if c.1 == '/' {
                    host_end = Some(c.0 + host_start_offset);
                    break;
                }
            }
        }

        let host = ws_url.get(host_start_offset..host_end.unwrap_or(ws_url.len()))?;
        let path = ws_url.get(host_end.unwrap_or(ws_url.len())..ws_url.len())?;
        let path = if path.len() == 0 { "/" } else { path };

        let mut host_split = host.split(':');
        let ip = host_split.next()?;
        let port = host_split
            .next()
            .and_then(|p_str| u16::from_str_radix(p_str, 10).ok())
            .unwrap_or(if secure { 443 } else { 80 });

        if host_split.count() > 0 {
            return None;
        }

        Some(WsUrl {
            host,
            ip,
            port,
            path,
            secure,
        })
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, PartialEq)]
pub struct WsUrlOwned {
    pub host: alloc::string::String,
    pub ip: alloc::string::String,
    pub port: u16,

    pub path: alloc::string::String,
    pub secure: bool,
}

#[cfg(feature = "alloc")]
impl WsUrlOwned {
    pub fn new(ws_url: &WsUrl<'_>) -> Self {
        use crate::alloc::string::ToString;

        Self {
            host: ws_url.host.to_string(),
            ip: ws_url.ip.to_string(),
            port: ws_url.port,
            path: ws_url.path.to_string(),
            secure: ws_url.secure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ws_url_parse() {
        assert_eq!(
            WsUrl::from_str("ws://127.0.0.1"),
            Some(WsUrl {
                host: "127.0.0.1",
                ip: "127.0.0.1",
                port: 80,
                path: "/",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::from_str("wss://127.0.0.1"),
            Some(WsUrl {
                host: "127.0.0.1",
                ip: "127.0.0.1",
                port: 443,
                path: "/",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::from_str("ws://127.0.0.1:4321"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                ip: "127.0.0.1",
                port: 4321,
                path: "/",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::from_str("wss://127.0.0.1:4321"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                ip: "127.0.0.1",
                port: 4321,
                path: "/",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::from_str("ws://127.0.0.1:4321/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                ip: "127.0.0.1",
                port: 4321,
                path: "/cxz/ewq",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::from_str("wss://127.0.0.1:4321/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1:4321",
                ip: "127.0.0.1",
                port: 4321,
                path: "/cxz/ewq",
                secure: true
            })
        );

        assert_eq!(
            WsUrl::from_str("ws://127.0.0.1/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1",
                ip: "127.0.0.1",
                port: 80,
                path: "/cxz/ewq",
                secure: false
            })
        );

        assert_eq!(
            WsUrl::from_str("wss://127.0.0.1/cxz/ewq"),
            Some(WsUrl {
                host: "127.0.0.1",
                ip: "127.0.0.1",
                port: 443,
                path: "/cxz/ewq",
                secure: true
            })
        );

        assert_eq!(WsUrl::from_str("wsc://127.0.0.1/cxz/ewq"), None);
        assert_eq!(WsUrl::from_str("ws://127.0.0.1:4321:123/cxz/ewq"), None);
    }
}
