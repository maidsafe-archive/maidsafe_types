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

/// StructuredData
#[derive(Clone, PartialEq, Debug)]
pub struct StructuredData {
    name: NameType,
    owner: NameType,
    value: Vec<Vec<NameType>>,
}

impl Sendable for StructuredData {
    fn name(&self) -> NameType {
             self.name.clone()
    }

    fn type_tag(&self)->u64 {
        102
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

    fn merge<'a, I>(_: I) -> Option<Self> where I: Iterator<Item=&'a Self> {
        None
    }
}

impl StructuredData {
    /// An instance of the StructuredData can be created by invoking the new()
    pub fn new(name: NameType, owner: NameType, value: Vec<Vec<NameType>>) -> StructuredData {
        StructuredData {
            name: name,
            owner: owner,
            value: value,
        }
    }

    /// Returns the value
    pub fn get_value(&self) -> Vec<Vec<NameType>> {
        self.value.clone()
    }

    /// Sets the value
    pub fn set_value(&mut self, data: Vec<Vec<NameType>>) {
        self.value = data;
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
    use routing;
    use routing::NameType;    
    use routing::sendable::Sendable;
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
                    inner.push(routing::test_utils::Random::generate_random());
                }
                outer.push(inner);
            }
            StructuredData {
                name: routing::test_utils::Random::generate_random(),
                owner: routing::test_utils::Random::generate_random(),
                value: outer,
            }
        }
    }

#[test]
    fn creation() {
        let structured_data = StructuredData::generate_random();        
        let data = StructuredData::new(structured_data.name(), structured_data.owner().unwrap(), structured_data.get_value());        
        assert_eq!(data, structured_data);
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
