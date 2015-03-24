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
use sodiumoxide::crypto;
use helper::*;
use common::NameType;

/// Maid
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
/// // Creating new Maid
/// let maid  = maidsafe_types::Maid::new((pub_sign_key, pub_asym_key),
///                     (sec_sign_key, sec_asym_key),
///                     maidsafe_types::NameType([6u8; 64]));
///
/// // getting Maid::public_keys
/// let &(pub_sign, pub_asym) = maid.get_public_keys();
///
/// // getting Maid::secret_keys
/// let &(sec_sign, sec_asym) = maid.get_public_keys();
///
/// // getting Maid::name
/// let name: &maidsafe_types::NameType = maid.get_name();
/// ```
pub struct Maid {
	public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
	secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
	name: NameType,
}

impl Maid {
	pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
						 secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
						 name_type: NameType) -> Maid {
		Maid {
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

impl Encodable for Maid {
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

impl Decodable for Maid {
	fn decode<D: Decoder>(d: &mut D)-> Result<Maid, D::Error> {
		try!(d.read_u64());
		let(pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec, name) = try!(Decodable::decode(d));
		let pub_keys = (crypto::sign::PublicKey(vector_as_u8_32_array(pub_sign_vec)),
				crypto::asymmetricbox::PublicKey(vector_as_u8_32_array(pub_asym_vec)));
		let sec_keys = (crypto::sign::SecretKey(vector_as_u8_64_array(sec_sign_vec)),
				crypto::asymmetricbox::SecretKey(vector_as_u8_32_array(sec_asym_vec)));
		Ok(Maid::new(pub_keys, sec_keys, name))
	}
}

#[test]
fn serialisation_maid() {
	let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
	let (pub_asym_key, sec_asym_key) = crypto::asymmetricbox::gen_keypair();

	let obj_before = Maid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType([3u8; 64]));

	let mut e = cbor::Encoder::from_memory();
	e.encode(&[&obj_before]).unwrap();

	let mut d = cbor::Decoder::from_bytes(e.as_bytes());
	let obj_after: Maid = d.decode().next().unwrap().unwrap();

	let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = obj_before.get_public_keys();
	let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = obj_after.get_public_keys();
	let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = obj_before.get_secret_keys();
	let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = obj_after.get_secret_keys();
	let (&NameType(name_before), &NameType(name_after)) = (obj_before.get_name(), obj_after.get_name());

	assert!(compare_u8_array(&name_before, &name_after));
	assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
	assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
	assert!(compare_u8_array(&sec_sign_arr_before, &sec_sign_arr_after));
	assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
}

