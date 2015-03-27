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
use helper::*;
use std::cmp::*;

/// NameType struct
///
/// #Examples
///
/// ```
/// // NameType Struct can be created using the new function by passing, id as its parameter.
/// let name_type = maidsafe_types::NameType::new([7u8; 64]);
/// let id: [u8; 64] = name_type.get_id();
/// //
/// let name_type = maidsafe_types::NameType([0u8; 64]);
///
/// // de-reference id value from the NameType
/// let maidsafe_types::NameType(id) = name_type;
/// ```
#[derive(Eq)]
pub struct NameType(pub [u8; 64]);

impl PartialEq for NameType {
  fn eq(&self, other: &NameType) -> bool {
  	self.0.iter().zip(other.0.iter()).all(|(a,b)| a == b) 
  }
  fn ne(&self, other: &NameType) -> bool {
    !self.0.iter().zip(other.0.iter()).all(|(a,b)| a == b)
  }
}
    

impl NameType {

  pub fn new(id: [u8;64]) -> NameType {
    NameType(id)
  }

  pub fn get_id(&self) -> [u8;64] {
    self.0
  }
  
  pub fn is_valid(&self) -> bool {
  	for it in self.0.iter() {
    if *it != 0 {
      return true;
    }
   }
   false
  }
}


impl Clone for NameType {
  fn clone(&self) -> Self {
    let mut arr_cloned = [0u8; 64];
    let &NameType(arr_self) = self;

    for i in 0..arr_self.len() {
      arr_cloned[i] = arr_self[i];
    }

    NameType(arr_cloned)
  }
}


impl Encodable for NameType {
  fn encode<E: Encoder>(& self, e: &mut E)->Result<(), E::Error> {
    let NameType(id) = * self;
    CborTagEncode::new(5483_000, &(array_as_vector(&id))).encode(e)
  }
}

impl Decodable for NameType {
  fn decode<D: Decoder>(d: &mut D)->Result<NameType, D::Error> {
    try!(d.read_u64());
    let id = try!(Decodable::decode(d));
    Ok(NameType(vector_as_u8_64_array(id)))
  }
}

#[test]
fn serialisation_name_type() {
  let obj_before = NameType([99u8; 64]);
  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: NameType = d.decode().next().unwrap().unwrap();
  assert!(obj_before == obj_after);
}

#[test]
fn name_type_equal_assertion() {
	let type1 = NameType([1u8;64]);
	let type2 = NameType([1u8;64]);
	let type3 = NameType([2u8;64]);
	assert!(type1 == type2);
	assert!(type1 != type3);
}

#[test]
fn name_type_validity_assertion() {
	assert!(NameType([1u8;64]).is_valid());
}
