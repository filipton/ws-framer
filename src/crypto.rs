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

pub fn sha1(input: &[u8]) -> [u32; 5] {
    let blocks_len = ((input.len() / 64) + 1) * 64;
    let mut blocks_tmp = vec![0u8; blocks_len];
    blocks_tmp[0..input.len()].copy_from_slice(input);
    blocks_tmp[input.len()] = 0x80;
    blocks_tmp[blocks_len - 8..blocks_len].copy_from_slice(&(input.len() * 8).to_be_bytes());
    let blocks =
        unsafe { core::slice::from_raw_parts(blocks_tmp.as_ptr() as *const u32, blocks_len / 4) };

    let mut w = [0u32; 80];
    let mut h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    for b in (0..blocks_len / 4).step_by(16) {
        for t in 0..16 {
            w[t] = blocks[b + t].to_be();
        }

        for t in 16..80 {
            w[t] = left_rotate!(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }

        let mut a = h.clone();
        for t in 0..80usize {
            let tmp = (left_rotate!(a[0], 5) as u32)
                .wrapping_add(f(t as u32, a[1], a[2], a[3]))
                .wrapping_add(a[4])
                .wrapping_add(w[t])
                .wrapping_add(k(t as u32));

            a[4] = a[3];
            a[3] = a[2];
            a[2] = left_rotate!(a[1], 30);
            a[1] = a[0];
            a[0] = tmp;
        }

        h[0] = h[0].wrapping_add(a[0]);
        h[1] = h[1].wrapping_add(a[1]);
        h[2] = h[2].wrapping_add(a[2]);
        h[3] = h[3].wrapping_add(a[3]);
        h[4] = h[4].wrapping_add(a[4]);
    }

    [h[0].to_be(), h[1].to_be(), h[2].to_be(), h[3].to_be(), h[4].to_be()]
}

pub fn hash_to_str(input: [u32; 5]) -> String {
    let digest = unsafe { core::slice::from_raw_parts(input.as_ptr() as *const u8, 20) };
    let hash_str = digest
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect::<String>();

    hash_str
}