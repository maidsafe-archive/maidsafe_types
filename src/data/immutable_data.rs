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
	name: NameType,
	value: Vec<u8>,
}

impl RoutingTrait for ImmutableData {
	fn get_name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.name.0);
        NameType(digest.0)
	}

    fn get_type_id(&self) -> Option<u64> {
        Some(0)
    }
}

impl PartialEq for ImmutableData {
    fn eq(&self, other: &ImmutableData) -> bool {
        self.name == other.name && self.value == other.value
    }
}

impl fmt::Debug for ImmutableData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ImmutableData( name: {:?}, value: {:?}", self.name, self.value)
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

#[allow(unused_variables)]
impl Random for ImmutableData {
    fn generate_random() -> ImmutableData {     
        let mut data = Vec::with_capacity(64);         
        for i in 0..data.len() {
            data.push(rand::random::<u8>());
        }
        ImmutableData {            
            name: NameType::generate_random(),
            value: data,
        }
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
    use super::*;
    use cbor::{ Encoder, Decoder};
    use rustc_serialize::{Decodable, Encodable};
    use Random;
    
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
