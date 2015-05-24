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

/// PublicMpid
///
/// #Examples
///
/// ```
/// extern crate sodiumoxide;
/// extern crate maidsafe_types;
/// extern crate routing;
///
/// // Generating sign and asymmetricbox keypairs,
/// let (pub_sign_key, _) = sodiumoxide::crypto::sign::gen_keypair(); // returns (PublicKey, SecretKey)
/// let (pub_asym_key, _) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
/// let (revocation_public_key, _) = sodiumoxide::crypto::sign::gen_keypair();
///
/// // Creating new PublicMpid
/// let public_mpid  = maidsafe_types::PublicMpid::new((pub_sign_key, pub_asym_key),
///                     revocation_public_key,
///                     sodiumoxide::crypto::sign::Signature([2u8; 64]),
///                     routing::NameType([8u8; 64]),
///                     sodiumoxide::crypto::sign::Signature([5u8; 64]));
///
/// // getting PublicMpid::public_keys
/// let &(pub_sign, pub_asym) = public_mpid.public_keys();
///
/// // getting PublicMpid::revocation public key
/// let revocation_public_key: &sodiumoxide::crypto::sign::PublicKey = public_mpid.revocation_public_key();
///
/// // getting PublicMpid::mpid_signature
/// let mpid_signature: &sodiumoxide::crypto::sign::Signature = public_mpid.mpid_signature();
///
/// // getting PublicMpid::owner
/// let owner: &routing::NameType = public_mpid.owner();
///
/// // getting PublicMpid::signature
/// let signature: &sodiumoxide::crypto::sign::Signature = public_mpid.signature();
///
/// ```

#[derive(Clone)]
pub struct PublicMpid {
    type_tag: u64,
    public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
    revocation_public_key: crypto::sign::PublicKey,
    mpid_signature: crypto::sign::Signature,
    owner: NameType,
    signature: crypto::sign::Signature
}

impl Sendable for PublicMpid {
    fn name(&self) -> NameType {
        name(&self.public_keys)
    }

    fn type_tag(&self)->u64 {
        self.type_tag.clone()
    }

    fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }


    fn owner(&self) -> Option<NameType> {
        Some(self.owner.clone())
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, _: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl PartialEq for PublicMpid {
    fn eq(&self, other: &PublicMpid) -> bool {
        &self.type_tag == &other.type_tag &&
        slice_equal(&self.public_keys.0 .0, &other.public_keys.0 .0) &&
        slice_equal(&self.public_keys.1 .0, &other.public_keys.1 .0) &&
        slice_equal(&self.revocation_public_key.0, &other.revocation_public_key.0) &&
        slice_equal(&self.mpid_signature.0, &other.mpid_signature.0) &&
        slice_equal(&self.signature.0, &other.signature.0)
    }
}

impl fmt::Debug for PublicMpid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicMpid {{ type_tag:{}, public_keys:({:?}, {:?}), revocation_public_key:{:?}, mpid_signature:{:?}, owner:{:?}, signature:{:?}}}",
            self.type_tag, self.public_keys.0 .0.to_vec(), self.public_keys.1 .0.to_vec(), self.revocation_public_key.0.to_vec(),
            self.mpid_signature.0.to_vec(), self.owner, self.signature.0.to_vec())
    }
}

impl PublicMpid {
    /// An instance of the PublicMaid can be created by invoking the new function
    ///
    /// #Examples
    ///
    /// // Creating new PublicMpid
    /// let public_mpid  = maidsafe_types::PublicMpid::new((pub_sign_key, pub_asym_key),
    ///                     sodiumoxide::crypto::sign::Signature([2u8; 64]),
    ///                     routing::NameType([8u8; 64]),
    ///                     sodiumoxide::crypto::sign::Signature([5u8; 64]));
    ///
    pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
                        revocation_public_key: crypto::sign::PublicKey,
                        mpid_signature: crypto::sign::Signature,
                        owner: NameType,
                        signature: crypto::sign::Signature) -> PublicMpid {
        PublicMpid { type_tag: 106u64, public_keys: public_keys, revocation_public_key: revocation_public_key,
             mpid_signature: mpid_signature, owner: owner,  signature: signature }
    }

    /// Returns the Symetric and Assymetric Publick keys
    #[warn(dead_code)]
    pub fn public_keys(& self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
        &self.public_keys
    }
    /// Returns revocation public key
    pub fn revocation_public_key(&self) -> &crypto::sign::PublicKey {
        &self.revocation_public_key
    }
    /// Returns the Signature for the Mpid
    #[warn(dead_code)]
    pub fn mpid_signature(& self) -> &crypto::sign::Signature {
        &self.mpid_signature
    }
    /// Returns the owner
    #[warn(dead_code)]
    pub fn owner(& self) -> &NameType {
        &self.owner
    }
    /// Returns the PublicMpid Signature
    #[warn(dead_code)]
    pub fn signature(& self) -> &crypto::sign::Signature {
        &self.signature
    }
}

impl Encodable for PublicMpid {
    fn encode<E: Encoder>(& self, e: &mut E)->Result<(), E::Error> {
        let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
        let crypto::sign::PublicKey(ref revocation_public_key_vec) = self.revocation_public_key;
        let crypto::sign::Signature(mpid_signature) = self.mpid_signature;
        let crypto::sign::Signature(signature) = self.signature;
        CborTagEncode::new(5483_001, &(
                pub_sign_vec.as_ref(),
                pub_asym_vec.as_ref(),
                revocation_public_key_vec.as_ref(),
                mpid_signature.as_ref(),
                &self.owner,
                signature.as_ref())).encode(e)
    }
}

impl Decodable for PublicMpid {
    fn decode<D: Decoder>(d: &mut D)-> Result<PublicMpid, D::Error> {
    try!(d.read_u64());

    let (pub_sign_vec, pub_asym_vec, revocation_public_key_vec, mpid_signature_vec, owner, signature_vec) : (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, NameType, Vec<u8>) = try!(Decodable::decode(d));
        let pub_sign_arr = convert_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
        let pub_asym_arr = convert_to_array!(pub_asym_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
        let revocation_public_key_arr = convert_to_array!(revocation_public_key_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
        let mpid_signature_arr = convert_to_array!(mpid_signature_vec, crypto::sign::SIGNATUREBYTES);
        let signature_arr = convert_to_array!(signature_vec, crypto::sign::SIGNATUREBYTES);

        if pub_sign_arr.is_none() || pub_asym_arr.is_none() || mpid_signature_arr.is_none() ||
            revocation_public_key_arr.is_none() || signature_arr.is_none() {
                return Err(d.error("Bad PublicMaid size"));
        }

    Ok(PublicMpid::new((crypto::sign::PublicKey(pub_sign_arr.unwrap()), crypto::asymmetricbox::PublicKey(pub_asym_arr.unwrap())),
        crypto::sign::PublicKey(revocation_public_key_arr.unwrap()), crypto::sign::Signature(mpid_signature_arr.unwrap()), owner,
        crypto::sign::Signature(signature_arr.unwrap())))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor;
    use sodiumoxide::crypto;
    use routing;
    use Random;
    use rand;
    use std::mem;

    impl Random for PublicMpid {
        fn generate_random() -> PublicMpid {
            let (sign_pub_key, _) = crypto::sign::gen_keypair();
            let (asym_pub_key, _) = crypto::asymmetricbox::gen_keypair();
            let (revocation_public_key, _) = crypto::sign::gen_keypair();
            let mut mpid_signature_arr: [u8; 64] = unsafe { mem::uninitialized() };
            let mut signature_arr: [u8; 64] = unsafe { mem::uninitialized() };
            for i in 0..64 {
                mpid_signature_arr[i] = rand::random::<u8>();
                signature_arr[i] = rand::random::<u8>();
            }

            PublicMpid {
                type_tag: 106u64,
                public_keys: (sign_pub_key, asym_pub_key),
                revocation_public_key: revocation_public_key,
                mpid_signature: crypto::sign::Signature(mpid_signature_arr),
                owner: routing::test_utils::Random::generate_random(),
                signature: crypto::sign::Signature(signature_arr)
            }
        }
    }


#[test]
    fn serialisation_public_mpid() {
        let obj_before = PublicMpid::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: PublicMpid = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

#[test]
    fn equality_assertion_public_mpid() {
        let public_mpid_first = PublicMpid::generate_random();
        let public_mpid_second = public_mpid_first.clone();
        let public_mpid_third = PublicMpid::generate_random();
        assert_eq!(public_mpid_first, public_mpid_second);
        assert!(public_mpid_first != public_mpid_third);
    }

}
