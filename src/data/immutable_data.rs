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
use sodiumoxide::crypto;
use std::fmt;

/// ImmutableData
#[derive(Clone)]
pub struct ImmutableData {
    value: Vec<u8>,
}

impl MessageInterface for ImmutableData {
    fn get_name(&self) -> NameType {
        self.calculate_name()
    }
}

impl PartialEq for ImmutableData {
    fn eq(&self, other: &ImmutableData) -> bool {
        self.value == other.value
    }
}

impl fmt::Debug for ImmutableData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ImmutableData( name: {:?}, value: {:?} )", self.calculate_name(), self.value)
    }
}

impl ImmutableData {
    /// New instance of ImmutableData can be created using the new()
    pub fn new(value: Vec<u8>) -> ImmutableData {
        ImmutableData {
            value: value,
        }
    }

    // debug cannot call RoutingTrait due to current visibility
    /// Calculates the name for the Data based on the SHA512 Hash of the Value
    fn calculate_name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.value);
        NameType(digest.0)
    }
    /// Returns the vaue
    pub fn get_value(&self) -> &Vec<u8> {
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

#[cfg(test)]
mod test {
    use super::*;
    use cbor::{ Encoder, Decoder};
    use rustc_serialize::{Decodable, Encodable};
    use Random;
    use routing::message_interface::MessageInterface;
    use rand;

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
        let data = "this is a known string".to_string().into_bytes();
        let expected_name = "8758b09d420bdb901d68fdd6888b38ce9ede06aad7f\
                             e1e0ea81feffc76260554b9d46fb6ea3b169ff8bb02\
                             ef14a03a122da52f3063bcb1bfb22cffc614def522".to_string();
        let chunk = ImmutableData::new(data);
        let actual_name = chunk.calculate_name().0.as_ref().to_hex();
        assert_eq!(&expected_name, &actual_name);
        assert_eq!(&chunk.calculate_name(), &chunk.get_name());
    }

    #[test]
    fn serialisation_immutable_data() {
        let obj_before = ImmutableData::generate_random();
        let mut e = Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = Decoder::from_bytes(e.as_bytes());
        let obj_after: ImmutableData = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn equality_assertion_immutable_data() {
        let first_obj = ImmutableData::generate_random();
        let second_obj = ImmutableData::generate_random();
        let cloned_obj = second_obj.clone();

        assert!(first_obj != second_obj);
        assert!(second_obj == cloned_obj);
    }
}
