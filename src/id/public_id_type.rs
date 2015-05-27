// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;
use helper::*;
use routing::NameType;
use routing::sendable::Sendable;
use std::fmt;
use IdTypeTags;
use super::revocation_type::*;
use super::id_type::*;

/// PublicIdType
///
/// #Examples
///
/// ```
/// extern crate sodiumoxide;
/// extern crate maidsafe_types;
/// extern crate routing;
///
///  let an_maid = maidsafe_types::AnMaid::new();
///  let maid = maidsafe_types::Maid::new(&an_maid);
///  let public_maid  = maidsafe_types::PublicIdType::new(&maid, &an_maid);
/// ```

#[derive(Clone)]
pub struct PublicIdType {
    type_tag: u64,
    public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
    revocation_public_key: crypto::sign::PublicKey,
    signature: crypto::sign::Signature
}

impl Sendable for PublicIdType {
    fn name(&self) -> NameType {
        name(&self.public_keys, self.type_tag.clone(), Some(self.signature.clone()))
    }

    fn type_tag(&self)->u64 {
        self.type_tag.clone()
    }

    fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, _: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl PartialEq for PublicIdType {
    fn eq(&self, other: &PublicIdType) -> bool {
        &self.type_tag == &other.type_tag &&
        slice_equal(&self.public_keys.0 .0, &other.public_keys.0 .0) &&
        slice_equal(&self.public_keys.1 .0, &other.public_keys.1 .0) &&
        slice_equal(&self.revocation_public_key.0, &other.revocation_public_key.0) &&
        slice_equal(&self.signature.0, &other.signature.0)
    }
}

impl fmt::Debug for PublicIdType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicIdType {{ type_tag:{}, public_keys:({:?}, {:?}), revocation_public_key:{:?}, signature:{:?}}}",
            self.type_tag, self.public_keys.0 .0.to_vec(), self.public_keys.1 .0.to_vec(), self.revocation_public_key.0.to_vec(),
            self.signature.0.to_vec())
    }
}

impl PublicIdType {
    /// An instanstance of the PublicIdType can be created using the new()
    pub fn new(id_type: &IdType, revocation_id: &Revocation) -> PublicIdType {
        let type_tag = revocation_id.type_tags().2;
        let public_keys = id_type.public_keys().clone();
        let revocation_public_key = revocation_id.public_key();
        let combined_iter = (public_keys.0).0.into_iter().chain((public_keys.1).0.into_iter().chain(revocation_public_key.0.into_iter()));
        let mut combined: Vec<u8> = Vec::new();
        for iter in combined_iter {
            combined.push(*iter);
        }
        for i in type_tag.to_string().into_bytes().into_iter() {
            combined.push(i);
        }
        let message_length = combined.len();
        let signature = revocation_id.sign(&combined).into_iter().skip(message_length).collect::<Vec<_>>();
        let signature_arr = convert_to_array!(signature, crypto::sign::SIGNATUREBYTES);
        PublicIdType { type_tag: type_tag, public_keys: public_keys,
             revocation_public_key: revocation_id.public_key().clone(),
             signature: crypto::sign::Signature(signature_arr.unwrap()) }
    }
    /// Returns the PublicKeys
    pub fn public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
        &self.public_keys
    }
    /// Returns revocation public key
    pub fn revocation_public_key(&self) -> &crypto::sign::PublicKey {
        &self.revocation_public_key
    }
    /// Returns the Signature of PublicIdType
    pub fn signature(&self) -> &crypto::sign::Signature {
        &self.signature
    }
}

impl Encodable for PublicIdType {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let (crypto::sign::PublicKey(ref pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
        let crypto::sign::PublicKey(ref revocation_public_key_vec) = self.revocation_public_key;
        let crypto::sign::Signature(ref signature) = self.signature;
        let type_vec = self.type_tag.to_string().into_bytes();
        CborTagEncode::new(5483_001, &(
            type_vec,
            pub_sign_vec.as_ref(),
            pub_asym_vec.as_ref(),
            revocation_public_key_vec.as_ref(),
            signature.as_ref())).encode(e)
    }
}

impl Decodable for PublicIdType {
    fn decode<D: Decoder>(d: &mut D)-> Result<PublicIdType, D::Error> {
    try!(d.read_u64());
    let (tag_type_vec, pub_sign_vec, pub_asym_vec, revocation_public_key_vec, signature_vec): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = try!(Decodable::decode(d));
    let pub_sign_arr = convert_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
    let pub_asym_arr = convert_to_array!(pub_asym_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
    let revocation_public_key_arr = convert_to_array!(revocation_public_key_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
    let signature_arr = convert_to_array!(signature_vec, crypto::sign::SIGNATUREBYTES);

    if pub_sign_arr.is_none() || pub_asym_arr.is_none() || revocation_public_key_arr.is_none()
        || signature_arr.is_none() {
             return Err(d.error("Bad PublicIdType size"));
    }

    let type_tag: u64 = match String::from_utf8(tag_type_vec) {
        Ok(string) =>  {
            match string.parse::<u64>() {
                Ok(type_tag) => type_tag,
                Err(_) => return Err(d.error("Bad Tag Type"))
            }
        },
        Err(_) => return Err(d.error("Bad Tag Type"))
    };

    Ok(PublicIdType{ type_tag: type_tag,
        public_keys: (crypto::sign::PublicKey(pub_sign_arr.unwrap()), crypto::asymmetricbox::PublicKey(pub_asym_arr.unwrap())),
        revocation_public_key: crypto::sign::PublicKey(revocation_public_key_arr.unwrap()),
        signature: crypto::sign::Signature(signature_arr.unwrap())})
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor;
    use Random;
    use super::super::{AnMaid, Maid, AnMpid, Mpid};
    use sodiumoxide::crypto;

    impl Random for PublicIdType {
        fn generate_random() -> PublicIdType {
            let an_maid = AnMaid::new();
            let maid = Maid::new(&an_maid);
            PublicIdType::new(&maid, &an_maid)
        }
    }

#[test]
    fn create_public_mpid() {
        let (sign_pub_key, sign_sec_key) = crypto::sign::gen_keypair();
        let (asym_pub_key, asym_sec_key) = crypto::asymmetricbox::gen_keypair();
        let mpid = Mpid::new((sign_pub_key.clone(), asym_pub_key.clone()),(sign_sec_key.clone(), asym_sec_key.clone()));
        let an_mpid = AnMpid::new((sign_pub_key, asym_pub_key),(sign_sec_key, asym_sec_key));
        PublicIdType::new(&mpid, &an_mpid);
    }


#[test]
    fn serialisation_public_maid() {
        let obj_before = PublicIdType::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: PublicIdType = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

#[test]
    fn equality_assertion_public_maid() {
        let public_maid_first = PublicIdType::generate_random();
        let public_maid_second = public_maid_first.clone();
        let public_maid_third = PublicIdType::generate_random();
        assert_eq!(public_maid_first, public_maid_second);
        assert!(public_maid_first != public_maid_third);
    }
}
