// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use routing::NameType;
use routing::sendable::Sendable;
use sodiumoxide::crypto;
use std::fmt;
use TypeTag;

/// TypeTag for ImmutableData
#[derive(Clone)]
pub struct ImmutableDataTypeTag;
/// TypeTag for ImmutableDataBackup
#[derive(Clone)]
pub struct ImmutableDataBackupTypeTag;
/// TypeTag for ImmutableDataSacrificial
#[derive(Clone)]
pub struct ImmutableDataSacrificialTypeTag;

impl TypeTag for ImmutableDataTypeTag {
    fn type_tag(&self) -> u64 {
        return 101;
    }
}

impl TypeTag for ImmutableDataBackupTypeTag {
    fn type_tag(&self) -> u64 {
        return 102;
    }
}

impl TypeTag for ImmutableDataSacrificialTypeTag {
    fn type_tag(&self) -> u64 {
        return 103;
    }
}

/// ImmutableData
#[derive(Clone)]
pub struct ImmutableData {
    type_tag: ImmutableDataTypeTag,
    value: Vec<u8>,
}

impl Sendable for ImmutableData {
    fn name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.value);
        NameType(digest.0)
    }

    fn type_tag(&self) -> u64 {
        self.type_tag.type_tag().clone()
    }

    fn serialised_contents(&self) -> Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, _: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl PartialEq for ImmutableData {
    fn eq(&self, other: &ImmutableData) -> bool {
        &self.type_tag.type_tag() == &other.type_tag.type_tag() &&
        self.value == other.value
    }
}

impl fmt::Debug for ImmutableData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ImmutableData( type_tag:{}, name: {:?}, value: {:?} )",
               self.type_tag.type_tag(), self.name(), self.value)
    }
}

impl ImmutableData {
    /// Creates a new instance of ImmutableData
    pub fn new(value: Vec<u8>) -> ImmutableData {
        ImmutableData {
            type_tag: ImmutableDataTypeTag,
            value: value,
        }
    }

    /// Returns the value
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }
}

impl Encodable for ImmutableData {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.value)).encode(e)
    }
}

impl Decodable for ImmutableData {
    fn decode<D: Decoder>(d: &mut D)->Result<ImmutableData, D::Error> {
        try!(d.read_u64());
        let value = try!(Decodable::decode(d));
        Ok(ImmutableData::new(value))
    }
}


/// ImmutableDataBackup
#[derive(Clone)]
pub struct ImmutableDataBackup {
    type_tag: ImmutableDataBackupTypeTag,
    value: Vec<u8>,
}

impl Sendable for ImmutableDataBackup {
    fn name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&crypto::hash::sha512::hash(&self.value).0);
        NameType(digest.0)
    }

    fn type_tag(&self) -> u64 {
        self.type_tag.type_tag().clone()
    }

    fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, _: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl PartialEq for ImmutableDataBackup {
    fn eq(&self, other: &ImmutableDataBackup) -> bool {
        &self.type_tag.type_tag() == &other.type_tag.type_tag() &&
        self.value == other.value
    }
}

impl fmt::Debug for ImmutableDataBackup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ImmutableDataBackup( type_tag:{}, name: {:?}, value: {:?} )",
               self.type_tag.type_tag(), self.name(), self.value)
    }
}

impl ImmutableDataBackup {
    /// Creates a new instance of ImmutableDataBackup
    pub fn new(immutable_data: ImmutableData) -> ImmutableDataBackup {
        ImmutableDataBackup {
            type_tag: ImmutableDataBackupTypeTag,
            value: immutable_data.value().clone(),
        }
    }

    /// Returns the value
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }
}

impl Encodable for ImmutableDataBackup {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.value)).encode(e)
    }
}

impl Decodable for ImmutableDataBackup {
    fn decode<D: Decoder>(d: &mut D)->Result<ImmutableDataBackup, D::Error> {
        try!(d.read_u64());
        let value = try!(Decodable::decode(d));
        Ok(ImmutableDataBackup::new(ImmutableData::new(value)))
    }
}


/// ImmutableDataSacrificial
#[derive(Clone)]
pub struct ImmutableDataSacrificial {
    type_tag: ImmutableDataSacrificialTypeTag,
    value: Vec<u8>,
}

impl Sendable for ImmutableDataSacrificial {
    fn name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(
                &crypto::hash::sha512::hash(&crypto::hash::sha512::hash(&self.value).0).0);
        NameType(digest.0)
    }

    fn type_tag(&self) -> u64 {
        self.type_tag.type_tag().clone()
    }

    fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, _: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl PartialEq for ImmutableDataSacrificial {
    fn eq(&self, other: &ImmutableDataSacrificial) -> bool {
        &self.type_tag.type_tag() == &other.type_tag.type_tag() &&
        self.value == other.value
    }
}

impl fmt::Debug for ImmutableDataSacrificial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ImmutableDataSacrificial( type_tag:{}, name: {:?}, value: {:?} )",
               self.type_tag.type_tag(), self.name(), self.value)
    }
}

impl ImmutableDataSacrificial {
    /// Creates a new instance of ImmutableDataSacrificial from ImmutableData type
    pub fn new(immutable_data: ImmutableData) -> ImmutableDataSacrificial {
        ImmutableDataSacrificial {
            type_tag: ImmutableDataSacrificialTypeTag,
            value: immutable_data.value().clone(),
        }
    }

    /// Returns the value
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }
}

impl Encodable for ImmutableDataSacrificial {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.value)).encode(e)
    }
}

impl Decodable for ImmutableDataSacrificial {
    fn decode<D: Decoder>(d: &mut D)->Result<ImmutableDataSacrificial, D::Error> {
        try!(d.read_u64());
        let value = try!(Decodable::decode(d));
        Ok(ImmutableDataSacrificial::new(ImmutableData::new(value)))
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use cbor::{ Encoder, Decoder};
    use rustc_serialize::{Decodable, Encodable};
    use Random;
    use rand;
    use routing::sendable::Sendable;

    #[allow(unused_variables)]
    impl Random for ImmutableData {
        fn generate_random() -> ImmutableData {
            use rand::Rng;
            let size = 64;
            let mut data = Vec::with_capacity(size);
            let mut rng = rand::thread_rng();
            for i in 0..size {
                data.push(rng.gen());
            }
            ImmutableData::new(data)
        }
    }

    #[test]
    fn creation() {
        use rustc_serialize::hex::ToHex;

        let value = "immutable data value".to_string().into_bytes();

        let immutable_data = ImmutableData::new(value);
        let immutable_data_name = immutable_data.name().0.as_ref().to_hex();
        let expected_immutable_data_name =
                "9f1c9e526f47e36d782de464ea9df0a31a5c19c321f2a5d9c8faacdda4d59abc\
                 713445c8c853e1842d7c2c2311650df1ee24107371935b6be88a10cbf4cd2f8f";
        assert_eq!(&expected_immutable_data_name, &immutable_data_name);

        let immutable_data_backup = ImmutableDataBackup::new(immutable_data.clone());
        let immutable_data_backup_name = immutable_data_backup.name().0.as_ref().to_hex();
        let expected_immutable_data_backup_name =
                "8c6377c848321dd3c6886a53b1a2bc28a5bc8ce35ac85d10d75467a5df9434ab\
                 aee19ce2c710507533d306302b165b4387458b752579fc15e520daaf984a2e38";       
        assert_eq!(&expected_immutable_data_backup_name, &immutable_data_backup_name);

        let immutable_data_sacrificial = ImmutableDataSacrificial::new(immutable_data);
        let immutable_data_sacrificial_name = immutable_data_sacrificial.name().0.as_ref().to_hex();
        let expected_immutable_data_sacrificial_name =
                "ecb6c761c35d4da33b25057fbf6161e68711f9e0c11122732e62661340e630d3\
                 c59f7c165f4862d51db5254a38ab9b15a9b8af431e8500a4eb558b9136bd4135";
        assert_eq!(&expected_immutable_data_sacrificial_name, &immutable_data_sacrificial_name);
    }

    #[test]
    fn serialisation() {
        let immutable_data = ImmutableData::generate_random();
        let immutable_data_backup = ImmutableDataBackup::new(immutable_data.clone());
        let immutable_data_sacrificial = ImmutableDataSacrificial::new(immutable_data.clone());

        // ImmutableData
        let mut immutable_data_encoder = Encoder::from_memory();
        immutable_data_encoder.encode(&[&immutable_data]).unwrap();
        let mut immutable_data_decoder =
                Decoder::from_bytes(immutable_data_encoder.as_bytes());
        let decoded_immutable_data: ImmutableData =
                immutable_data_decoder.decode().next().unwrap().unwrap();
        // ImmutableDataBackup
        let mut immutable_data_backup_encoder = Encoder::from_memory();
        immutable_data_backup_encoder.encode(&[&immutable_data_backup]).unwrap();
        let mut immutable_data_backup_decoder =
                Decoder::from_bytes(immutable_data_backup_encoder.as_bytes());
        let decoded_immutable_data_backup: ImmutableDataBackup =
                immutable_data_backup_decoder.decode().next().unwrap().unwrap();
        // ImmutableDataSacrificial
        let mut immutable_data_sacrificial_encoder = Encoder::from_memory();
        immutable_data_sacrificial_encoder.encode(&[&immutable_data_sacrificial]).unwrap();
        let mut immutable_data_sacrificial_decoder =
                Decoder::from_bytes(immutable_data_sacrificial_encoder.as_bytes());
        let decoded_immutable_data_sacrificial: ImmutableDataSacrificial =
                immutable_data_sacrificial_decoder.decode().next().unwrap().unwrap();

        assert_eq!(immutable_data, decoded_immutable_data);
        assert_eq!(immutable_data_backup, decoded_immutable_data_backup);
        assert_eq!(immutable_data_sacrificial, decoded_immutable_data_sacrificial);
    }

    #[test]
    fn equality() {
        let immutable_data_first = ImmutableData::generate_random();
        let immutable_data_second = ImmutableData::generate_random();
        let immutable_data_second_clone = immutable_data_second.clone();

        assert!(immutable_data_first != immutable_data_second);
        assert!(immutable_data_second_clone == immutable_data_second);

        let immutable_data_backup_first = ImmutableDataBackup::new(immutable_data_first.clone());
        let immutable_data_backup_second = ImmutableDataBackup::new(immutable_data_second.clone());
        let immutable_data_backup_second_clone = immutable_data_backup_second.clone();

        assert!(immutable_data_backup_first != immutable_data_backup_second);
        assert!(immutable_data_backup_second_clone == immutable_data_backup_second);

        let immutable_data_sacrificial_first = ImmutableDataSacrificial::new(immutable_data_first.clone());
        let immutable_data_sacrificial_second = ImmutableDataSacrificial::new(immutable_data_second.clone());
        let immutable_data_sacrificial_second_clone = immutable_data_sacrificial_second.clone();

        assert!(immutable_data_sacrificial_first != immutable_data_sacrificial_second);
        assert!(immutable_data_sacrificial_second_clone == immutable_data_sacrificial_second);
    }
}
