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

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use common::NameType;
use traits::RoutingTrait;
use sodiumoxide::crypto;

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
pub struct ImmutableData {
	name: NameType,
	value: Vec<u8>,
}

impl RoutingTrait for ImmutableData {
	fn get_name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.name.0);
        NameType(digest.0)
	}
}

impl ImmutableData {
	#[allow(dead_code)]
	pub fn new(name: NameType, value: Vec<u8>) -> ImmutableData {
		ImmutableData {
		name: name,
		value: value,
		}
	}

	pub fn get_name(&self) -> &NameType {
		&self.name
	}

	pub fn get_value(&self) -> &Vec<u8> {
		&self.value
	}

}

impl Encodable for ImmutableData {
	fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
				CborTagEncode::new(5483_001, &(&self.name, &self.value)).encode(e)
	}
}

impl Decodable for ImmutableData {
	fn decode<D: Decoder>(d: &mut D)->Result<ImmutableData, D::Error> {
		try!(d.read_u64());
		let (name, value) = try!(Decodable::decode(d));
		Ok(ImmutableData::new(name, value))
	}
}
#[cfg(test)]
mod test {
use helper::*;
use super::*;
use cbor::{ Encoder, Decoder};
use rustc_serialize::{Decodable, Encodable};
use common::NameType;

#[test]
fn serialisation_immutable_data() {
	let obj_before = ImmutableData::new(NameType([3u8; 64]), vec![99u8; 10]);
	let mut e = Encoder::from_memory();
	e.encode(&[&obj_before]).unwrap();

	let mut d = Decoder::from_bytes(e.as_bytes());
	let obj_after: ImmutableData = d.decode().next().unwrap().unwrap();
	let id_before = obj_before.get_name().get_id();
	let id_after = obj_after.get_name().get_id();
	assert!(compare_u8_array(&id_before, &id_after));
	assert_eq!(obj_before.get_value(), obj_after.get_value());
}
}
