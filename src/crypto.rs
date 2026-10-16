use crate::consts::{PROCESSED_WS_KEY_B64_LEN, WS_KEY_B64_LEN, WS_KEY_GUID};

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Padded base64 length of `n` bytes.
pub const fn base64_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Padded base64 of `input` into `out` (`out.len()` must be `base64_len(N)`).
fn base64<const N: usize, const M: usize>(input: &[u8; N]) -> [u8; M] {
    let mut out = [b'='; M];
    for (chunk, o) in input.chunks(3).zip(out.chunks_mut(4)) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, c) in o.iter_mut().enumerate().take(chunk.len() + 1) {
            *c = BASE64[((n >> (18 - 6 * i)) & 0x3F) as usize];
        }
    }
    out
}

/// SHA-1 of `input`.
fn sha1(input: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (input.len() as u64).wrapping_mul(8);

    // message, 0x80, zero padding, 64-bit length; processed in 64 byte blocks
    let total = (input.len() + 9).div_ceil(64) * 64;
    let byte = |i: usize| -> u8 {
        if let Some(b) = input.get(i) {
            *b
        } else if i == input.len() {
            0x80
        } else if i >= total - 8 {
            bit_len.to_be_bytes()[i - (total - 8)]
        } else {
            0
        }
    };

    let mut w = [0u32; 80];
    for block in (0..total).step_by(64) {
        for (t, word) in w.iter_mut().take(16).enumerate() {
            let i = block + t * 4;
            *word = u32::from_be_bytes([byte(i), byte(i + 1), byte(i + 2), byte(i + 3)]);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (t, wt) in w.iter().enumerate() {
            let (f, k) = match t {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(*wt)
                .wrapping_add(k);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for (hv, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *hv = hv.wrapping_add(v);
        }
    }

    let mut out = [0; 20];
    for (o, v) in out.chunks_mut(4).zip(h) {
        o.copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Sec-WebSocket-Accept value for a 24 char Sec-WebSocket-Key.
pub(crate) fn accept_key(key: &[u8; WS_KEY_B64_LEN]) -> [u8; PROCESSED_WS_KEY_B64_LEN] {
    let mut input = [0; WS_KEY_B64_LEN + WS_KEY_GUID.len()];
    input[..WS_KEY_B64_LEN].copy_from_slice(key);
    input[WS_KEY_B64_LEN..].copy_from_slice(WS_KEY_GUID.as_bytes());
    base64(&sha1(&input))
}

/// Base64 random key for the Sec-WebSocket-Key header.
#[cfg(feature = "http")]
pub(crate) fn random_key() -> [u8; WS_KEY_B64_LEN] {
    let mut key = [0; 16];
    crate::rng_fill(&mut key);
    base64(&key)
}

/// Computes the Sec-WebSocket-Accept header value (sent by the server) for the client's
/// Sec-WebSocket-Key. Returns `None` if the key isn't 24 base64 chars (16 bytes), as RFC 6455
/// requires.
pub fn process_sec_websocket_key(key: &str) -> Option<[u8; PROCESSED_WS_KEY_B64_LEN]> {
    key.as_bytes().try_into().ok().map(accept_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_sec_ws_key() {
        assert_eq!(
            process_sec_websocket_key("dGhlIHNhbXBsZSBub25jZQ==").as_ref(),
            Some(b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );
        assert_eq!(process_sec_websocket_key("short"), None);
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        // 56 bytes: padding spills into a second block
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            [
                0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
                0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
            ]
        );
    }

    #[test]
    fn base64_padding() {
        assert_eq!(&base64::<1, 4>(b"f"), b"Zg==");
        assert_eq!(&base64::<2, 4>(b"fo"), b"Zm8=");
        assert_eq!(&base64::<3, 4>(b"foo"), b"Zm9v");
    }
}
