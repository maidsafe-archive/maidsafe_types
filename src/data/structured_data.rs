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
extern crate rand;

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use common::NameType;
use traits::RoutingTrait;
use helper::*;
use Random;

/// StructuredData
///
/// #Examples
///
/// ```
/// let mut value = Vec::new();
/// value.push(Vec::new());
/// match value.last_mut() {
///   Some(v) => v.push(maidsafe_types::NameType([7u8; 64])),
///   None => ()
/// }
/// // Create a StructuredData
/// let structured_data = maidsafe_types::StructuredData::new((maidsafe_types::NameType([3u8; 64]), maidsafe_types::NameType([5u8; 64])), value);
/// // Retrieving the values
/// let (maidsafe_types::NameType(name), maidsafe_types::NameType(owner)) = *structured_data.get_name();
/// let ref value = structured_data.get_value();
/// ```
///
#[derive(Clone, PartialEq, Debug)]
pub struct StructuredData {
	name: (NameType, NameType),  /// name + owner of this StructuredData
	value: Vec<Vec<NameType>>,
}

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
            name: (NameType::generate_random(), NameType::generate_random()),
            value: outer,
        }
    }
}

impl RoutingTrait for StructuredData {
    fn get_name(&self) -> NameType {
        self.name.0.clone()
    }

    fn get_owner(&self) -> Option<Vec<u8>> {
        Some(array_as_vector(&(&self.name.1).0))
    }
}

impl StructuredData {
	pub fn new(name: (NameType, NameType), value: Vec<Vec<NameType>>) -> StructuredData {
		StructuredData {
			name: name,
			value: value,
		}
	}
	pub fn get_name(&self) -> &(NameType, NameType) {
		&self.name
	}
	pub fn get_value(&self) -> &Vec<Vec<NameType>> {
		&self.value
	}
}

impl Encodable for StructuredData {
	fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
		CborTagEncode::new(5483_002, &(&self.name, &self.value)).encode(e)
	}
}

impl Decodable for StructuredData {
	fn decode<D: Decoder>(d: &mut D) -> Result<StructuredData, D::Error> {
		try!(d.read_u64());
		let (name, value) = try!(Decodable::decode(d));
		Ok(StructuredData::new(name, value))
	}
}

#[test]
fn serialisation_structured_data() {
	let obj_before = StructuredData::generate_random();
    let obj_before_clone = obj_before.clone();
	let obj_before1 = StructuredData::generate_random();

	let mut e = cbor::Encoder::from_memory();
	e.encode(&[&obj_before]).unwrap();

	let mut d = cbor::Decoder::from_bytes(e.as_bytes());
	let obj_after: StructuredData = d.decode().next().unwrap().unwrap();

	assert_eq!(obj_before, obj_after);
	assert!(!(obj_before != obj_before_clone));
	assert!(obj_before != obj_before1);
}
