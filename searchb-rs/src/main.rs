// 2018, Georg Sauthoff <mail@gms.tf>
// 2023, Marco 'Capypara' Köpcke <hello@capypara.de>
// SPDX-License-Identifier: GPL-3.0-or-later

extern crate memchr;

use memchr::memmem::find_iter;

fn mmap(filename: &str) -> Result<memmap::Mmap, std::io::Error> {
    let file = std::fs::File::open(filename)?;
    let p = unsafe { memmap::Mmap::map(&file)? };
    Ok(p)
}

fn real_main(args: &mut std::env::Args) -> Result<Vec<usize>, String> {
    args.next();
    let qfilename = args.next().ok_or("query filename missing")?;
    let filename = args.next().ok_or("target filename missing")?;
    let q = match mmap(&qfilename) {
        Ok(x) => x,
        Err(ref e) if e.kind() == std::io::ErrorKind::InvalidInput => return Ok(vec![0]),
        Err(e) => return Err(e.to_string()),
    };
    let t = match mmap(&filename) {
        Ok(x) => x,
        Err(ref e) if e.kind() == std::io::ErrorKind::InvalidInput => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    Ok(find_iter(&t, &q).collect())
}

fn main() {
    std::process::exit(match real_main(&mut std::env::args()) {
        Ok(t) => match t.is_empty() {
            false => {
                for x in t {
                    println!("{}", x);
                }
                0
            }
            true => 1,
        },
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    })
}
