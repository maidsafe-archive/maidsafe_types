/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate cbor;
extern crate core;

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use common::NameType;
use traits::RoutingTrait;
use sodiumoxide::crypto;
use std::fmt;
use rand;
use Random;

/// ImmutableData
///
/// #Examples
///
/// ```
/// // Create an ImmutableData using the new function.
/// let immutable_data = maidsafe_types::ImmutableData::new(maidsafe_types::NameType([0u8; 64]),  vec![99u8; 10]);
/// // Retrieving values
/// let ref name_type = immutable_data.get_name();
/// let ref value = immutable_data.get_value();
/// ```
///
#[derive(Clone)]
pub struct ImmutableData {
    value: Vec<u8>,
}

impl RoutingTrait for ImmutableData {
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
    pub fn new(value: Vec<u8>) -> ImmutableData {
        ImmutableData {
            value: value,
        }
    }

    // debug cannot call RoutingTrait due to current visibility
    fn calculate_name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.value);
        NameType(digest.0)
    }

    pub fn get_value(&self) -> &Vec<u8> {
        &self.value
    }
}

#[allow(unused_variables)]
impl Random for ImmutableData {
    fn generate_random() -> ImmutableData {
        let mut data = Vec::with_capacity(64);
        for i in 0..data.len() {
            data.push(rand::random::<u8>());
        }
        ImmutableData {
            value: data,
        }
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
    use common::NameType;

    #[test]
    fn creation() {
        let ascii = "012456789ABCDEF".to_string().into_bytes();
        let data = "this is a known string".to_string().into_bytes();
        let expected_name = "c937425f55ed0096a97eea1ccb5585d0242c517afe\
                             eb9a18f8f5a209adc852213fa6b210694f1b86f55b\
                             8cfc35b8d9c577af61e0304e79c10bfc1e4661d9ae15".to_string();
        let chunk = ImmutableData::new(data);
        let actual_name =
            chunk.calculate_name().0.iter()
                                    .fold(Vec::<u8>::new(), |mut value, byte| {
                                        value.push(*ascii.iter().skip((byte & 0x0F) as usize).take(1).next().unwrap());
                                        value.push(*ascii.iter().skip((byte >> 4) as usize).take(1).next().unwrap());
                                        value
                                     });
        assert_eq!(&expected_name, String::from_utf8(actual_name).as_ref().unwrap());
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
