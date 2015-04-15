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

extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate cbor;

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;
use helper::*;
use common::NameType;
use traits::RoutingTrait;
use Random;
use rand;
use std::mem;
use std::fmt;

/// PublicAnMaid
///
/// #Examples
/// ```
/// extern crate sodiumoxide;
/// extern crate maidsafe_types;
/// // Generating publick and secret keys using sodiumoxide
/// let (pub_sign_key, _) = sodiumoxide::crypto::sign::gen_keypair();
/// let (pub_asym_key, _) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
/// // Create PublicAnMaid
/// let pub_an_maid = maidsafe_types::PublicAnMaid::new((pub_sign_key, pub_asym_key), sodiumoxide::crypto::sign::Signature([5u8; 64]), maidsafe_types::NameType([99u8; 64]));
/// // Retrieving the values
/// let ref publicKeys = pub_an_maid.get_public_keys();
/// let ref signature = pub_an_maid.get_signature();
/// let ref name = pub_an_maid.get_name();
/// ```
///
#[derive(Clone)]
pub struct PublicAnMaid {
	public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
	signature: crypto::sign::Signature,
	name: NameType,
}

impl PartialEq for PublicAnMaid {
    fn eq(&self, other: &PublicAnMaid) -> bool {
        self.public_keys.0 .0.iter().chain(self.public_keys.1 .0.iter().chain(self.signature.0.iter())).zip(
            other.public_keys.0 .0.iter().chain(other.public_keys.1 .0.iter().chain(other.signature.0.iter())))
            .all(|a| a.0 == a.1) && self.name == other.name
    }
}

impl Random for PublicAnMaid {
    fn generate_random() -> PublicAnMaid {
        let (pub_sign_key, _) = crypto::sign::gen_keypair();
        let (pub_asym_key, _) = crypto::asymmetricbox::gen_keypair();
        let mut arr: [u8; 64] = unsafe { mem::uninitialized() };
        for i in 0..64 {
            arr[i] = rand::random::<u8>();
        }
        PublicAnMaid {
            public_keys: (pub_sign_key, pub_asym_key),
            signature: crypto::sign::Signature(arr),
            name: NameType::generate_random()
        }
    }
}

impl fmt::Debug for PublicAnMaid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (crypto::sign::PublicKey(public_key), crypto::asymmetricbox::PublicKey(assym_public_key)) = self.public_keys;
        let crypto::sign::Signature(signature) = self.signature;
        write!(f, "PublicAnMaid( public_keys: ({:?}, {:?}), signature: {:?}, name: {:?} )",
             public_key, assym_public_key, signature.to_vec(), self.name)
    }
}

impl RoutingTrait for PublicAnMaid {
    fn get_name(&self) -> NameType {
        let sign_arr = &(&self.public_keys.0).0;
        let asym_arr = &(&self.public_keys.1).0;

        let mut arr_combined = [0u8; 64 * 2];

        for i in 0..sign_arr.len() {
            arr_combined[i] = sign_arr[i];
        }
        for i in 0..asym_arr.len() {
            arr_combined[64 + i] = asym_arr[i];
        }

        let digest = crypto::hash::sha512::hash(&arr_combined);

        NameType(digest.0)
    }

    fn get_owner(&self) -> Option<Vec<u8>> {
        Some(array_as_vector(&self.name.0))
    }
}

impl PublicAnMaid {
	pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
						 signature: crypto::sign::Signature,
						 name: NameType) -> PublicAnMaid {
		PublicAnMaid {
    		public_keys: public_keys,
    		signature: signature,
    		name: name
		}
	}
	pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
		&self.public_keys
	}
	pub fn get_signature(&self) -> &crypto::sign::Signature {
		&self.signature
	}
	pub fn get_name(&self) -> &NameType {
		&self.name
	}
}

impl Encodable for PublicAnMaid {
	fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
		let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
		let crypto::sign::Signature(signature_arr) = self.signature;

            CborTagEncode::new(5483_001, &(
            array_as_vector(&pub_sign_vec),
            array_as_vector(&pub_asym_vec),
            array_as_vector(&signature_arr),
            &self.name)).encode(e)
	}
}

impl Decodable for PublicAnMaid {
	fn decode<D: Decoder>(d: &mut D)-> Result<PublicAnMaid, D::Error> {
		try!(d.read_u64());

		let(pub_sign_vec, pub_asym_vec, signature_vec, name) = try!(Decodable::decode(d));
		let pub_keys = (crypto::sign::PublicKey(vector_as_u8_32_array(pub_sign_vec)),
				crypto::asymmetricbox::PublicKey(vector_as_u8_32_array(pub_asym_vec)));
		let signature = crypto::sign::Signature(vector_as_u8_64_array(signature_vec));

		Ok(PublicAnMaid::new(pub_keys, signature, name))
	}
}


#[test]
fn serialisation_public_anmaid() {
	let obj_before = PublicAnMaid::generate_random();
	let mut e = cbor::Encoder::from_memory();
	e.encode(&[&obj_before]).unwrap();

	let mut d = cbor::Decoder::from_bytes(e.as_bytes());
	let obj_after: PublicAnMaid = d.decode().next().unwrap().unwrap();

	assert_eq!(obj_before, obj_after);
}

#[test]
fn equality_assertion_public_anmaid() {
    let first_obj = PublicAnMaid::generate_random();
    let second_obj = PublicAnMaid::generate_random();
    let cloned_obj = second_obj.clone();

    assert!(first_obj != second_obj);
    assert!(second_obj == cloned_obj);
}
