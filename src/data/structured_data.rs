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
extern crate "rustc-serialize" as rustc_serialize;
extern crate sodiumoxide;
extern crate cbor;

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use common::NameType;

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
pub struct StructuredData {
	name: (NameType, NameType),  /// name + owner of this StructuredData
	value: Vec<Vec<NameType>>,
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
	let mut value = Vec::new();
	value.push(Vec::new());
	match value.last_mut() {
		Some(v) => v.push(NameType([7u8; 64])),
		None => ()
	}
	let obj_before = StructuredData::new((NameType([3u8; 64]), NameType([5u8; 64])), value);
	let mut e = cbor::Encoder::from_memory();
	e.encode(&[&obj_before]).unwrap();

	let mut d = cbor::Decoder::from_bytes(e.as_bytes());
	let obj_after: StructuredData = d.decode().next().unwrap().unwrap();

  let name_before = obj_before.get_name();
  let name_after = obj_after.get_name();
  	
	assert!(name_before.0 == name_after.0);
	assert!(name_before.1 == name_after.1);
}
