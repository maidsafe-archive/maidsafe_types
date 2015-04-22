// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License, version
// 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which licence you
// accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at
// http://maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to use
// of the MaidSafe Software.

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use routing::name_type::NameType;
use routing::message_interface::MessageInterface;



/// StructuredData
#[derive(Clone, PartialEq, Debug)]
pub struct StructuredData {
    name: NameType,
    owner: NameType,
    value: Vec<Vec<NameType>>,
}


impl MessageInterface for StructuredData {
    fn get_name(&self) -> NameType {
        self.name.clone()
    }

    fn get_owner(&self) -> Option<Vec<u8>> {
        Some(self.owner.0.as_ref().to_vec())
    }
}

impl StructuredData {
    /// An instance of the StructuredData can be created by invoking the new()
    pub fn new(name: NameType, owner: NameType) -> StructuredData {
        StructuredData {
            name: name,
            owner: owner,
            value: Vec::<Vec<NameType>>::new(),
        }
    }
    /// Returns the value
    pub fn get_value(&self) -> &Vec<Vec<NameType>> {
        &self.value
    }
}

impl Encodable for StructuredData {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        CborTagEncode::new(5483_002, &(&self.name, &self.owner, &self.value)).encode(e)
    }
}

impl Decodable for StructuredData {
    fn decode<D: Decoder>(d: &mut D) -> Result<StructuredData, D::Error> {
        try!(d.read_u64());
        let (name, owner, value) = try!(Decodable::decode(d));
        let structured = StructuredData {
            name: name,
            owner: owner,
            value: value
        };
        Ok(structured)
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use cbor::{ Encoder, Decoder };
    use rustc_serialize::{Decodable, Encodable};
    use routing::name_type::NameType;
    use routing::message_interface::MessageInterface;
    use Random;
    use rand;

    impl Random for StructuredData {
        fn generate_random() -> StructuredData {
            let outer_limit = rand::random::<u8>() as usize;
            let mut outer = Vec::<Vec<NameType>>::with_capacity(outer_limit);
            for _ in 0..rand::random::<u8>() {
                let inner_limit = rand::random::<u8>() as usize;
                let mut inner = Vec::<NameType>::with_capacity(inner_limit);
                for _ in 0..inner_limit {
                    inner.push(NameType::generate_random());
                }
                outer.push(inner);
            }
            StructuredData {
                name: NameType::generate_random(),
                owner: NameType::generate_random(),
                value: outer,
            }
        }
    }

#[test]
    fn creation() {
        let name = NameType::generate_random();
        let owner = NameType::generate_random();
        let structured_data = StructuredData::new(name.clone(), owner.clone());
        assert_eq!(&name, &structured_data.get_name());
        assert_eq!(&owner.0.as_ref().to_vec(), structured_data.get_owner().as_ref().unwrap());
        let expected_value = Vec::<Vec<NameType>>::new();
        assert_eq!(&expected_value, structured_data.get_value());
    }

#[test]
    fn serialisation_structured_data() {
        let obj_before = StructuredData::generate_random();
        let obj_before_clone = obj_before.clone();
        let obj_before1 = StructuredData::generate_random();

        let mut e = Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = Decoder::from_bytes(e.as_bytes());
        let obj_after: StructuredData = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
        assert!(!(obj_before != obj_before_clone));
        assert!(obj_before != obj_before1);
    }  
}
