use ws_framer_macros::base64_impl;

base64_impl!(
    Base64Pad,
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    true,
    false
);

macro_rules! left_rotate {
    ($x:expr,$c:expr) => {
        ($x << $c) | ($x >> (32 - $c))
    };
}

#[inline(always)]
fn f(t: u32, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => (b & c) | (!b & d),
        20..=39 | 60..=79 => b ^ c ^ d,
        40..=59 => (b & c) | (b & d) | (c & d),
        _ => 0,
    }
}

#[inline(always)]
fn k(t: u32) -> u32 {
    match t {
        0..=19 => 0x5A827999,
        20..=39 => 0x6ED9EBA1,
        40..=59 => 0x8F1BBCDC,
        60..=79 => 0xCA62C1D6,
        _ => 0,
    }
}

pub const fn sha1_blocks_len(len: usize) -> usize {
    (((len + 8) / 64) + 1) * 64
}

/// Calculate sha1 hash for given input
///
/// WARN: input buffer should be padded to length,
/// so len and input.len() are different
pub fn sha1(input: &mut [u8], len: usize) -> [u8; 20] {
    let blocks_len = sha1_blocks_len(len);
    input[len] = 0x80;
    input[blocks_len - 8..blocks_len].copy_from_slice(&((len * 8) as u64).to_be_bytes());
    let blocks =
        unsafe { core::slice::from_raw_parts(input.as_ptr() as *const u32, blocks_len / 4) };

    let mut w = [0u32; 80];
    let mut h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for chunk in blocks.chunks(16) {
        for t in 0..16 {
            w[t] = u32::from_be(chunk[t]);
        }

        for t in 16..80 {
            w[t] = left_rotate!(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        for t in 0..80usize {
            let temp = (left_rotate!(a, 5) as u32)
                .wrapping_add(f(t as u32, b, c, d))
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(k(t as u32));

            e = d;
            d = c;
            c = left_rotate!(b, 30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let tmp = [
        h[0].to_be(),
        h[1].to_be(),
        h[2].to_be(),
        h[3].to_be(),
        h[4].to_be(),
    ];

    let digest = unsafe { core::slice::from_raw_parts(tmp.as_ptr() as *const u8, 20) };
    digest.try_into().unwrap()
}

/// Changes key (input) that is retreived by server from Sec-WebSocket-Key
/// into another string that is then sent by server as Sec-WebSocket-Accept header
///
/// Can be also used by client to verify accept header
pub fn process_sec_websocket_key(key: &str) -> [u8; crate::consts::PROCESSED_WS_KEY_B64_LEN] {
    let mut blocks = [0; crate::consts::SHA1_BLOCKS_LEN];
    blocks[..key.len()].copy_from_slice(key.as_bytes());
    blocks[key.len()..key.len() + crate::consts::WS_KEY_GUID.len()]
        .copy_from_slice(crate::consts::WS_KEY_GUID.as_bytes());

    let mut tmp = [0; crate::consts::PROCESSED_WS_KEY_B64_LEN];
    let hash = crate::crypto::sha1(&mut blocks, crate::consts::WS_HASH_LEN);
    crate::crypto::Base64Pad::encode_slice(&hash, &mut tmp);

    tmp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_sec_ws_key() {
        assert_eq!(
            process_sec_websocket_key("dGhlIHNhbXBsZSBub25jZQ=="),
            b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".as_ref()
        );
    }
}
