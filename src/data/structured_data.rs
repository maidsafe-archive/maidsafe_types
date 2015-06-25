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

use std::cmp;

use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use routing::NameType;
use routing::sendable::Sendable;
use TypeTag;

/// TypeTag for StructuredData
#[derive(Clone, PartialEq, Debug)]
pub struct StructuredDataTypeTag;

impl TypeTag for StructuredDataTypeTag {
    fn type_tag(&self) -> u64 {
        ::data_tags::STRUCTURED_DATA_TAG
    }
}

/// StructuredData
#[derive(Clone, PartialEq, Debug)]
pub struct StructuredData {
    type_tag: StructuredDataTypeTag,
    name: NameType,
    owner: NameType,
    value: Vec<NameType>,
}

impl Sendable for StructuredData {
    fn name(&self) -> NameType {
        self.name.clone()
    }

    fn type_tag(&self) -> u64 {
        self.type_tag.type_tag().clone()
    }

    fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn owner(&self) -> Option<NameType> {
        Some(self.owner.clone())
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, sdvs: Vec<Box<Sendable>>) -> Option<Box<Sendable>> {
        let mut merged_value = self.value.clone();
        for itr in sdvs {
            let mut d_sdv = cbor::Decoder::from_bytes(&itr.serialised_contents()[..]);
            let sdv: StructuredData = d_sdv.decode().next().unwrap().unwrap();
            if sdv.name() == self.name() {
                let mut merging = Vec::new();
                let incoming_value = sdv.value();
                for i in 0..cmp::min(merged_value.len(), incoming_value.len()) {
                    if merged_value[i] == incoming_value[i] {
                        merging.push(merged_value[i].clone());
                    } else {
                        break;
                    }
                }
                merged_value = merging;
            }
        }
        if merged_value.len() == 0 {
            None
        } else {
            Some(Box::new(StructuredData::new(self.name.clone(), self.owner.clone(), merged_value)))
        }
    }
}

impl StructuredData {
    /// An instance of the StructuredData can be created by invoking the new()
    pub fn new(name: NameType, owner: NameType, value: Vec<NameType>) -> StructuredData {
        StructuredData {type_tag: StructuredDataTypeTag, name: name, owner: owner, value: value}
    }

    /// Returns the value
    pub fn value(&self) -> Vec<NameType> {
        self.value.clone()
    }

    /// Sets the value
    pub fn set_value(&mut self, data: Vec<NameType>) {
        self.value = data;
    }
}

impl Encodable for StructuredData {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        CborTagEncode::new(::data_tags::STRUCTURED_DATA_TAG, &(&self.name, &self.owner, &self.value)).encode(e)
    }
}

impl Decodable for StructuredData {
    fn decode<D: Decoder>(d: &mut D) -> Result<StructuredData, D::Error> {
        let (name, owner, value) = try!(Decodable::decode(d));
        let structured = StructuredData {
            type_tag: StructuredDataTypeTag,
            name: name,
            owner: owner,
            value: value
        };
        Ok(structured)
    }
}
#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use cbor::{ Encoder, Decoder };
    use rustc_serialize::{Decodable, Encodable};
    use routing;
    use routing::NameType;
    use routing::sendable::Sendable;
    use Random;

    impl Random for StructuredData {
        fn generate_random() -> StructuredData {
            let size = rand::random::<usize>() % 100 + 1;
            let mut value = Vec::<NameType>::with_capacity(size);
            for _ in 0..size {
                value.push(routing::test_utils::Random::generate_random());
            }
            StructuredData {
                type_tag: StructuredDataTypeTag,
                name: routing::test_utils::Random::generate_random(),
                owner: routing::test_utils::Random::generate_random(),
                value: value,
            }
        }
    }

#[test]
    fn creation() {
        let structured_data = StructuredData::generate_random();
        let data = StructuredData::new(structured_data.name(), structured_data.owner().unwrap(), structured_data.value());
        assert_eq!(data, structured_data);
        assert_eq!(structured_data.type_tag(), ::data_tags::STRUCTURED_DATA_TAG);
    }

#[test]
    fn serialisation_structured_data() {
        let obj_before = StructuredData::generate_random();
        let obj_before_clone = obj_before.clone();
        let obj_before1 = StructuredData::generate_random();

        let mut e = Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = Decoder::from_bytes(e.as_bytes());
        match d.decode().next().unwrap().unwrap() {
            ::test_utils::Parser::StructData(obj_after) => {
                assert_eq!(obj_before, obj_after);
                assert!(!(obj_before != obj_before_clone));
                assert!(obj_before != obj_before1);
            },
            _ => panic!("Unexpected!"),
        }
    }
}
