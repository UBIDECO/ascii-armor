// ASCII Armor: binary to text encoding library and command-line utility.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2024 by
//     Dr. Maxim Orlovsky <orlovsky@ubideco.org>
//
// Copyright 2024 UBIDECO Institute, Switzerland
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate amplify;

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;
use std::fmt::Debug;

use amplify::num::u24;
use amplify::{hex, Bytes32};
use sha2::{Digest, Sha256};

pub const ASCII_ARMOR_MAX_LEN: usize = u24::MAX.to_usize();

pub struct DisplayAsciiArmored<'a, A: AsciiArmor>(&'a A);

impl<'a, A: AsciiArmor> DisplayAsciiArmored<'a, A> {
    fn data_digest(&self) -> (Vec<u8>, Bytes32) {
        let data = self.0.to_ascii_armored_data();
        let digest = Sha256::digest(&data);
        (data, Bytes32::from_byte_array(digest))
    }
}

impl<'a, A: AsciiArmor> Display for DisplayAsciiArmored<'a, A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "-----BEGIN {}-----", A::ASCII_ARMOR_PLATE_TITLE)?;
        if let Some(id) = self.0.ascii_armored_id() {
            writeln!(f, "Id: {}", id)?;
        }

        let (data, digest) = self.data_digest();
        writeln!(f, "Checksum-SHA256: {digest}")?;

        for header in self.0.ascii_armored_headers() {
            writeln!(f, "{header}")?;
        }
        writeln!(f)?;

        let data = base85::encode(&data);
        let mut data = data.as_str();
        while data.len() >= 64 {
            let (line, rest) = data.split_at(64);
            writeln!(f, "{}", line)?;
            data = rest;
        }
        writeln!(f, "{}", data)?;

        writeln!(f, "\n-----END {}-----", A::ASCII_ARMOR_PLATE_TITLE)?;

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct ArmorHeader {
    pub title: String,
    pub value: String,
    pub params: Vec<(String, String)>,
}

impl Display for ArmorHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.title, self.value)?;
        if self.params.is_empty() {
            writeln!(f)?;
        }
        for (name, val) in &self.params {
            write!(f, ";\n{name}={val}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ArmorParseError {
    /// armored header has invalid format ("{0}").
    InvalidHeaderFormat(String),

    /// armored header '{0}' has invalid parameter '{1}'.
    InvalidHeaderParam(String, String),

    /// the provided text doesn't represent a recognizable ASCII-armored RGB
    /// bindle encoding.
    WrongStructure,

    /// bindle data has invalid Base85 encoding (ASCII armoring).
    #[from(base85::Error)]
    Base85,

    /// header providing id for the armored data must not contain additional
    /// parameters.
    NonEmptyIdParams,

    /// header providing checksum for the armored data must not contain additional
    /// parameters.
    NonEmptyChecksumParams,

    /// ASCII armor contains unparsable checksum. Details: {0}
    #[from]
    UnparsableChecksum(hex::Error),

    /// ASCII armor contains which does not match the id generated from the parsed data.
    MismatchedId,

    /// ASCII armor checksum doesn't match the actual data.
    MismatchedChecksum,

    /// unrecognized header '{0}' in ASCII armor.
    UnrecognizedHeader(String),
}

impl FromStr for ArmorHeader {
    type Err = ArmorParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (title, rest) =
            s.split_once(':').ok_or_else(|| ArmorParseError::InvalidHeaderFormat(s.to_owned()))?;
        let rest = rest.trim();
        let mut split = rest.split(';');
        let value =
            split.next().ok_or_else(|| ArmorParseError::InvalidHeaderFormat(s.to_owned()))?.trim();
        let mut params = vec![];
        for param in split {
            let (name, val) = s.split_once('=').ok_or_else(|| {
                ArmorParseError::InvalidHeaderParam(title.to_owned(), param.to_owned())
            })?;
            params.push((name.trim().to_owned(), val.trim().to_owned()));
        }
        Ok(ArmorHeader {
            title: title.to_owned(),
            value: value.to_owned(),
            params,
        })
    }
}

pub trait AsciiArmor: Sized {
    type Id: Display;
    type Err: Debug + From<ArmorParseError>;

    const ASCII_ARMOR_PLATE_TITLE: &'static str;

    fn display_ascii_armored(&self) -> DisplayAsciiArmored<Self> { DisplayAsciiArmored(self) }
    fn ascii_armored_id(&self) -> Option<Self::Id> { None }
    fn ascii_armored_headers(&self) -> Vec<ArmorHeader>;
    fn ascii_armored_digest(&self) -> Bytes32 { DisplayAsciiArmored(self).data_digest().1 }
    fn to_ascii_armored_data(&self) -> Vec<u8>;

    fn from_ascii_armored_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.lines();
        let first = format!("-----BEGIN {}-----", Self::ASCII_ARMOR_PLATE_TITLE);
        let last = format!("-----END {}-----", Self::ASCII_ARMOR_PLATE_TITLE);
        if (lines.next(), lines.next_back()) != (Some(&first), Some(&last)) {
            return Err(ArmorParseError::WrongStructure.into());
        }
        let mut header_id = None;
        let mut checksum = None;
        let mut headers = vec![];
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            let header = ArmorHeader::from_str(&line)?;
            if header.title == "Id" {
                if !header.params.is_empty() {
                    return Err(ArmorParseError::NonEmptyIdParams.into());
                }
                header_id = Some(header.title);
            } else if header.title == "Checksum-SHA256" {
                if !header.params.is_empty() {
                    return Err(ArmorParseError::NonEmptyChecksumParams.into());
                }
                checksum = Some(header.value);
            } else {
                headers.push(header);
            }
        }
        let armor = lines.collect::<String>();
        let data = base85::decode(&armor).map_err(ArmorParseError::from)?;
        if let Some(checksum) = checksum {
            let checksum = Bytes32::from_str(&checksum)
                .map_err(|err| ArmorParseError::UnparsableChecksum(err))?;
            let expected = Bytes32::from_byte_array(Sha256::digest(&data));
            if checksum != expected {
                return Err(ArmorParseError::MismatchedChecksum.into());
            }
        }
        let me = Self::with_ascii_armored_data(header_id, headers, data)?;
        Ok(me)
    }

    fn with_ascii_armored_data(
        id: Option<String>,
        headers: Vec<ArmorHeader>,
        data: Vec<u8>,
    ) -> Result<Self, Self::Err>;
}

#[cfg(test)]
mod test {
    use super::*;

    impl AsciiArmor for Vec<u8> {
        type Id = Bytes32;
        type Err = ArmorParseError;
        const ASCII_ARMOR_PLATE_TITLE: &'static str = "";

        fn ascii_armored_headers(&self) -> Vec<ArmorHeader> { none!() }

        fn to_ascii_armored_data(&self) -> Vec<u8> { self.clone() }

        fn with_ascii_armored_data(
            id: Option<String>,
            headers: Vec<ArmorHeader>,
            data: Vec<u8>,
        ) -> Result<Self, Self::Err> {
            assert_eq!(id, None);
            assert!(headers.is_empty());
            Ok(data)
        }
    }

    #[test]
    fn roundtrip() {
        let noise = Sha256::digest("some test data");
        let data = noise.as_slice().repeat(100).iter().cloned().collect::<Vec<u8>>();
        let armor = format!("{}", data.display_ascii_armored());
        let data2 = Vec::<u8>::from_ascii_armored_str(&armor).unwrap();
        let armor2 = format!("{}", data2.display_ascii_armored());
        assert_eq!(data, data2);
        assert_eq!(armor, armor2);
    }
}
