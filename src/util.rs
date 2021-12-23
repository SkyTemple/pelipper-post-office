use bytes::{Buf, BufMut};
use log::debug;
use rand::distributions::uniform::{SampleRange, SampleUniform};
use rand::Rng;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn md5sum(input: &str) -> String {
    format!("{:x}", md5::compute(input))
}

pub(crate) fn random_string<T, R, const N: usize>(char_range: R) -> [T; N]
where
    T: SampleUniform + Default + Copy,
    R: SampleRange<T> + Clone
{
    let mut rng = rand::thread_rng();
    let mut c: [T; N] = [T::default(); N];
    for item in c.iter_mut() {
        *item = rng.gen_range(char_range.clone())
    }
    c
}

/// Returns the content up to the next null byte.
/// Advances the cursor after that byte.
/// Stops at end of buffer.
/// Returns None if the end was reached or content is empty.
pub(crate) fn advance_nul<B>(mut buf: B) -> Option<Vec<u8>> where B: Buf {
    let mut content = Vec::with_capacity(buf.remaining());
    let mut finished = false;
    while buf.has_remaining() {
        let v = buf.get_u8();
        if v == 0 {
            finished = true;
            break;
        } else {
            content.push(v);
        }
    }
    if finished && !content.is_empty() {
        Some(content)
    } else {
        debug!("Reached EOF in advance_nul: {:?}", content);
        None
    }
}

/// Decodes a challenge response
/// See: http://aluigi.altervista.org/papers/gsmsalg.h for source.
//  Original license:
//     Copyright 2004,2005,2006,2007,2008 Luigi Auriemma
//
//     This program is free software; you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation; either version 2 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program; if not, write to the Free Software
//     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
//
//     http://www.gnu.org/licenses/gpl.txt
pub fn decode_cr(src: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let mut dst = Vec::with_capacity(89);
    let size = src.len();
    if !(1..=65).contains(&size) {
        return None
    }
    let keysz = key.len();
    let mut enctmp = (0..=255).into_iter().collect::<Vec<u8>>();

    let mut a: usize = 0;
    for i in 0..256 {
        a += (enctmp[i] + key[i % keysz]) as usize;
        enctmp.swap(a, i);
    }

    let mut a: u8 = 0;
    let mut b: u8 = 0;
    let mut tmp = [0; 66];
    let mut i = 0;
    for val in src {
        a += val + 1;
        let x = enctmp[a as usize];
        b += x;
        let y = enctmp[b as usize];
        enctmp[b as usize] = x;
        enctmp[a as usize] = y;
        tmp[i] = src[i] ^ enctmp[((x as u16 + y as u16) & 0xff) as usize];
        i += 1;
    }
    let mut size = i;
    while size % 3 != 0 {
        tmp[size] = 0;
        size += 1;
    }

    for i in (0..size).step_by(3) {
        let x = tmp[i];
        let y = tmp[i + 1];
        let z = tmp[i + 2];
        dst.put_u8(gsvalfunc(x >> 2));
        dst.put_u8(gsvalfunc(((x & 3) << 4) | (y >> 4)));
        dst.put_u8(gsvalfunc(((y & 15) << 2) | (z >> 6)));
        dst.put_u8(gsvalfunc(z & 63));
    }
    Some(dst)
}

fn gsvalfunc(reg: u8) -> u8 {
     if reg < 26 {
         return reg + b'A';
     }
     if reg < 52 {
         return reg + b'G';
     }
     if reg < 62 {
         return reg - 4;
     }
     if reg == 62 {
         return b'+';
     }
     if reg == 63 {
         return b'/';
     }
     0
}

pub(crate) fn userid_base32(input: u64) -> String {
    const TABLE: [char; 32] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        'u', 'v'
    ];
    let mut str = ['0'; 9];
    let mut rest = input;
    for i in (0..9).rev() {
        let ev = 32_u64.pow(i);
        str[(8 - i) as usize] = TABLE[(rest / ev) as usize];
        rest -= ev * (rest / ev)
    }
    str.into_iter().collect()
}

#[test]
fn test_userid_base32() {
    println!("{:?}: {:?}", 0_u64, userid_base32(0_u64));
    println!("{:?}: {:?}", 1_u64, userid_base32(1_u64));
    println!("{:?}: {:?}", 2_u64, userid_base32(2_u64));
    println!("{:?}: {:?}", 31_u64, userid_base32(31_u64));
    println!("{:?}: {:?}", 32_u64, userid_base32(32_u64));
    println!("{:?}: {:?}", 33_u64, userid_base32(33_u64));
    let enc: String = userid_base32(1582006588001_u64).to_string();
    assert_eq!("1e1bf1kj1", &enc);
}
