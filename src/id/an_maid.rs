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
use std::fmt;

/// The following key types use the internal cbor tag to identify them and this
/// should be carried through to any json representation if stored on disk
///
/// AnMaid
///
/// #Examples
/// ```
/// extern crate sodiumoxide;
/// extern crate maidsafe_types;
/// // Generating publick and secret keys using sodiumoxide
/// let (pub_sign_key, sec_sign_key) = sodiumoxide::crypto::sign::gen_keypair();
/// let (pub_asym_key, sec_asym_key) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
/// // Create AnMaid
/// let an_maid = maidsafe_types::AnMaid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), maidsafe_types::NameType([3u8; 64]));
/// // Retrieving the values
/// let ref publicKeys = an_maid.get_public_keys();
/// let ref secretKeys = an_maid.get_secret_keys();
/// let ref name = an_maid.get_name();
/// ```
///
#[derive(Clone)]
pub struct AnMaid {
	public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
	secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
	name: NameType,
}

impl PartialEq for AnMaid {
    fn eq(&self, other: &AnMaid) -> bool {
        self.public_keys.0 .0.iter().chain(self.public_keys.1 .0.iter().chain(self.secret_keys.0 .0.iter().chain(self.secret_keys.1 .0.iter()))).zip(
            other.public_keys.0 .0.iter().chain(other.public_keys.1 .0.iter().chain(other.secret_keys.0 .0.iter().chain(other.secret_keys.1 .0.iter())))).all(|a| a.0 == a.1) &&
            self.name == other.name
    }
}

impl Random for AnMaid {
    fn generate_random() -> AnMaid {
        let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
        let (pub_asym_key, sec_asym_key) = crypto::asymmetricbox::gen_keypair();

        AnMaid {
            public_keys: (pub_sign_key, pub_asym_key),
            secret_keys: (sec_sign_key, sec_asym_key),
            name: NameType::generate_random()
        }
    }
}


impl fmt::Debug for AnMaid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (crypto::sign::PublicKey(public_key), crypto::asymmetricbox::PublicKey(assym_public_key)) = self.public_keys;
        let (crypto::sign::SecretKey(secret_key), crypto::asymmetricbox::SecretKey(assym_secret_key)) = self.secret_keys;
        write!(f, "AnMaid( public_keys: ({:?}, {:?}), secret_keys: ({:?}, {:?}), name: {:?} )",
             public_key, assym_public_key, secret_key.to_vec(), assym_secret_key, self.name)
    }
}

impl RoutingTrait for AnMaid {
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

impl AnMaid {
	pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
						 secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
						 name_type: NameType) -> AnMaid {
		AnMaid {
			public_keys: public_keys,
			secret_keys: secret_keys,
			name: name_type
		}
	}
	pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
		&self.public_keys
	}
	pub fn get_secret_keys(&self) -> &(crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey) {
		&self.secret_keys
	}
	pub fn get_name(&self) -> &NameType {
		&self.name
	}
}

impl Encodable for AnMaid {
	fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
		let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
		let (crypto::sign::SecretKey(sec_sign_vec), crypto::asymmetricbox::SecretKey(sec_asym_vec)) = self.secret_keys;

		CborTagEncode::new(5483_001, &(
            array_as_vector(&pub_sign_vec),
            array_as_vector(&pub_asym_vec),
            array_as_vector(&sec_sign_vec),
            array_as_vector(&sec_asym_vec),
            &self.name)).encode(e)
	}
}

impl Decodable for AnMaid {
	fn decode<D: Decoder>(d: &mut D)-> Result<AnMaid, D::Error> {
		try!(d.read_u64());
		let(pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec, name) = try!(Decodable::decode(d));
		let pub_keys = (crypto::sign::PublicKey(vector_as_u8_32_array(pub_sign_vec)),
				crypto::asymmetricbox::PublicKey(vector_as_u8_32_array(pub_asym_vec)));
		let sec_keys = (crypto::sign::SecretKey(vector_as_u8_64_array(sec_sign_vec)),
				crypto::asymmetricbox::SecretKey(vector_as_u8_32_array(sec_asym_vec)));
		Ok(AnMaid::new(pub_keys, sec_keys, name))
	}
}

#[test]
fn serialisation_an_maid() {
    let obj_before = AnMaid::generate_random();
	let mut e = cbor::Encoder::from_memory();
	e.encode(&[&obj_before]).unwrap();

	let mut d = cbor::Decoder::from_bytes(e.as_bytes());
	let obj_after: AnMaid = d.decode().next().unwrap().unwrap();

	assert_eq!(obj_before, obj_after);
}

#[test]
fn equality_assertion_an_maid() {
    let first_obj = AnMaid::generate_random();
    let second_obj = AnMaid::generate_random();
    let cloned_obj = second_obj.clone();

    assert!(first_obj != second_obj);
    assert!(second_obj == cloned_obj);
}
