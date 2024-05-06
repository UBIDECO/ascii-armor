use std::{env, fs};

use armor::AsciiArmor;

fn main() {
    let mut args = env::args();
    let args = args.by_ref();
    let out_name = args.next_back().expect("use: armor [-r] <INPUT-FILE> <OUTPUT-FILE>");
    let in_name = args.next_back().expect("use: armor [-r] <INPUT-FILE> <OUTPUT-FILE>");
    let rev = args.next_back();

    let rev = match rev.as_deref() {
        Some("-r") | Some("--rev") => true,
        None => false,
        _ if args.count() > 0 => panic!("use: armor [-r] <INPUT-FILE> <OUTPUT-FILE>"),
        _ => false,
    };

    if rev {
        let armor = fs::read_to_string(in_name).expect("input file does not contain armored data");
        let data = Vec::<u8>::from_ascii_armored_str(&armor)
            .expect("invalid ASCII armored data in the input file");
        fs::write(out_name, data).expect("unable to write data to the output file");
    } else {
        let data = fs::read(in_name).expect("unable to read data from the input file");
        let armor = data.to_ascii_armored_string();
        fs::write(out_name, armor).expect("unable to write ASCII armored data to the output file");
    }
}
