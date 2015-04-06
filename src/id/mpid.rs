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
use sodiumoxide::crypto;
use helper::*;
use common::NameType;
use traits::RoutingTrait;
use std::fmt;
use Random;

/// Mpid
///
/// #Examples
/// ```
/// extern crate sodiumoxide;
/// extern crate maidsafe_types;
///
/// // Generating sign and asymmetricbox keypairs,
/// let (pub_sign_key, sec_sign_key) = sodiumoxide::crypto::sign::gen_keypair(); // returns (PublicKey, SecretKey)
/// let (pub_asym_key, sec_asym_key) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
///
/// // Creating new Mpid
/// let mpid  = maidsafe_types::id::mpid::Mpid::new((pub_sign_key, pub_asym_key),
///                     (sec_sign_key, sec_asym_key),
///                     maidsafe_types::NameType([6u8; 64]));
///
/// // getting Mpid::public_keys
/// let &(pub_sign, pub_asym) = mpid.get_public_keys();
///
/// // getting Mpid::secret_keys
/// let &(sec_sign, sec_asym) = mpid.get_public_keys();
///
/// // getting Mpid::name
/// let name: &maidsafe_types::NameType = mpid.get_name();
/// ```
#[derive(Clone)]
pub struct Mpid {
	public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
	secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
	name: NameType
}

impl PartialEq for Mpid {
	fn eq(&self, other: &Mpid) -> bool {
        self.public_keys.0 .0.iter().chain(self.public_keys.1 .0.iter().chain(self.secret_keys.0 .0.iter().chain(self.secret_keys.1 .0.iter()))).zip(
            other.public_keys.0 .0.iter().chain(other.public_keys.1 .0.iter().chain(other.secret_keys.0 .0.iter().chain(other.secret_keys.1 .0.iter())))).all(|a| a.0 == a.1) &&
            self.name == other.name
    }
}

impl fmt::Debug for Mpid {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Mpid {{ public_keys:({:?}, {:?}), secret_keys:({:?}, {:?}), name: {:?} }}", self.public_keys.0 .0.to_vec(), self.public_keys.1 .0.to_vec(), 
        	self.secret_keys.0 .0.to_vec(), self.secret_keys.1 .0.to_vec(), self.name)
    }
}

impl Random for Mpid {
	fn generate_random() -> Mpid {
        let (sign_pub_key, sign_sec_key) = crypto::sign::gen_keypair();
        let (asym_pub_key, asym_sec_key) = crypto::asymmetricbox::gen_keypair();        
		Mpid {
			public_keys: (sign_pub_key, asym_pub_key),
			secret_keys: (sign_sec_key, asym_sec_key),
			name: NameType::generate_random()
		}
	}
}

impl RoutingTrait for Mpid {
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
}

impl Mpid {
pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
					 secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
					 name_type: NameType) -> Mpid {
	Mpid {
	public_keys: public_keys,
	secret_keys: secret_keys,
	name: name_type
	}
}
pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey){
	&self.public_keys
}

pub fn get_secret_keys(&self) -> &(crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey) {
	&self.secret_keys
}

pub fn get_name(&self) -> &NameType {
	&self.name
}
}

impl Encodable for Mpid {
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

impl Decodable for Mpid {
fn decode<D: Decoder>(d: &mut D)-> Result<Mpid, D::Error> {
	try!(d.read_u64());
	let(pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec, name) = try!(Decodable::decode(d));
	let pub_keys = (crypto::sign::PublicKey(vector_as_u8_32_array(pub_sign_vec)),
			crypto::asymmetricbox::PublicKey(vector_as_u8_32_array(pub_asym_vec)));
	let sec_keys = (crypto::sign::SecretKey(vector_as_u8_64_array(sec_sign_vec)),
			crypto::asymmetricbox::SecretKey(vector_as_u8_32_array(sec_asym_vec)));
	Ok(Mpid::new(pub_keys, sec_keys, name))
}
}

#[test]
fn serialisation_mpid() {
	let obj_before = Mpid::generate_random();

	let mut e = cbor::Encoder::from_memory();
	e.encode(&[&obj_before]).unwrap();

	let mut d = cbor::Decoder::from_bytes(e.as_bytes());
	let obj_after: Mpid = d.decode().next().unwrap().unwrap();

	assert_eq!(obj_before, obj_after);
}

#[test]
fn equality_assertion_mpid() {
	let mpid_first = Mpid::generate_random();
	let mpid_second = mpid_first.clone();
	let mpid_third = Mpid::generate_random();
	assert_eq!(mpid_first, mpid_second);
	assert!(mpid_first != mpid_third);
}