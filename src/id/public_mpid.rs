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

/// PublicMpid
///
/// #Examples
///
/// ```
/// extern crate sodiumoxide;
/// extern crate maidsafe_types;
///
/// // Generating sign and asymmetricbox keypairs,
/// let (pub_sign_key, _) = sodiumoxide::crypto::sign::gen_keypair(); // returns (PublicKey, SecretKey)
/// let (pub_asym_key, _) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
///
/// // Creating new PublicMpid
/// let public_mpid  = maidsafe_types::PublicMpid::new((pub_sign_key, pub_asym_key),
///                     sodiumoxide::crypto::sign::Signature([2u8; 64]),
///                     maidsafe_types::NameType([8u8; 64]),
///                     sodiumoxide::crypto::sign::Signature([5u8; 64]),
///                     maidsafe_types::NameType([6u8; 64]));
///
/// // getting PublicMpid::public_keys
/// let &(pub_sign, pub_asym) = public_mpid.get_public_keys();
///
/// // getting PublicMpid::mpid_signature
/// let mpid_signature: &sodiumoxide::crypto::sign::Signature = public_mpid.get_mpid_signature();
///
/// // getting PublicMpid::owner
/// let owner: &maidsafe_types::NameType = public_mpid.get_owner();
///
/// // getting PublicMpid::signature
/// let signature: &sodiumoxide::crypto::sign::Signature = public_mpid.get_signature();
///
/// // getting PublicMpid::name
/// let name: &maidsafe_types::NameType = public_mpid.get_name();
/// ```
pub struct PublicMpid {
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
mpid_signature: crypto::sign::Signature,
owner: NameType,
signature: crypto::sign::Signature,
name: NameType
}

impl PublicMpid {
pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
					 mpid_signature: crypto::sign::Signature,
					 owner: NameType,
					 signature: crypto::sign::Signature,
					 name: NameType) -> PublicMpid {
	PublicMpid {
	public_keys: public_keys,
	mpid_signature: mpid_signature,
	owner: owner,
	signature: signature,
	name: name,
	}
}
#[warn(dead_code)]
pub fn get_public_keys(& self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
	&self.public_keys
}
#[warn(dead_code)]
pub fn get_mpid_signature(& self) -> &crypto::sign::Signature {
	&self.mpid_signature
}
#[warn(dead_code)]
pub fn get_owner(& self) -> &NameType {
	&self.owner
}
#[warn(dead_code)]
pub fn get_signature(& self) -> &crypto::sign::Signature {
	&self.signature
}
#[warn(dead_code)]
pub fn get_name(& self) -> &NameType {
	&self.name
}
}

impl Encodable for PublicMpid {
fn encode<E: Encoder>(& self, e: &mut E)->Result<(), E::Error> {
	let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
	let crypto::sign::Signature(mpid_signature) = self.mpid_signature;
	let crypto::sign::Signature(signature) = self.signature;
	CborTagEncode::new(5483_001, &(
			array_as_vector(&pub_sign_vec),
				array_as_vector(&pub_asym_vec),
				array_as_vector(&mpid_signature),
			&self.owner,
				array_as_vector(&signature),
			&self.name)).encode(e)
}
}

impl Decodable for PublicMpid {
	fn decode<D: Decoder>(d: &mut D)-> Result<PublicMpid, D::Error> {
		try!(d.read_u64());
		let (pub_sign_vec, pub_asym_vec, mpid_signature, owner, signature, name) = try!(Decodable::decode(d));
		let pub_keys = (crypto::sign::PublicKey(vector_as_u8_32_array(pub_sign_vec)),
				crypto::asymmetricbox::PublicKey(vector_as_u8_32_array(pub_asym_vec)));
		let parsed_mpid_signature = crypto::sign::Signature(vector_as_u8_64_array(mpid_signature));
		let parsed_signature = crypto::sign::Signature(vector_as_u8_64_array(signature));

		Ok(PublicMpid::new(pub_keys, parsed_mpid_signature, owner, parsed_signature, name))
	}
}

#[test]
fn serialisation_public_mpid() {
	let (pub_sign_key, _) = crypto::sign::gen_keypair();
	let (pub_asym_key, _) = crypto::asymmetricbox::gen_keypair();

	let obj_before = PublicMpid::new((pub_sign_key, pub_asym_key), crypto::sign::Signature([5u8; 64]),
	NameType([5u8; 64]), crypto::sign::Signature([5u8; 64]), NameType([3u8; 64]))                                                                                        ;

	let mut e = cbor::Encoder::from_memory();
	e.encode(&[&obj_before]).unwrap();

	let mut d = cbor::Decoder::from_bytes(e.as_bytes());
	let obj_after: PublicMpid = d.decode()                                                                                                                               .next().unwrap().unwrap();

	let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = obj_before.get_public_keys()                            ;
	let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = obj_after.get_public_keys();
	let (&crypto::sign::Signature(mpid_signature_before), &crypto::sign::Signature(mpid_signature_after)) = (obj_before.get_mpid_signature(), obj_after.get_mpid_signature());
	let (&crypto::sign::Signature(signature_before), &crypto::sign::Signature(signature_after))                                                                          = (obj_before.get_signature(), obj_after.get_signature());
	let (&NameType(name_before), &NameType(name_after)) = (obj_before.get_name(), obj_after.get_name());
	let (&NameType(owner_before), &NameType(owner_after)) = (obj_after.get_owner(), obj_after.get_owner())                                                               ;

	assert!(compare_u8_array(&name_before, &name_after));
	assert!(compare_u8_array(&owner_before, &owner_after));
	assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
	assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
	assert!(compare_u8_array(&mpid_signature_before, &mpid_signature_after))                                                                                    ;
	assert!(compare_u8_array(&signature_before, &signature_after));
}
