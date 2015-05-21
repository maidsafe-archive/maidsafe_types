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

/// PublicMaid
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
///
/// // Creating new PublicMaid
/// let public_maid  = maidsafe_types::PublicMaid::new((pub_sign_key, pub_asym_key),
///                     sodiumoxide::crypto::sign::Signature([2u8; 64]),
///                     routing::NameType([8u8; 64]),
///                     sodiumoxide::crypto::sign::Signature([5u8; 64]));
///
/// // getting PublicMaid::public_keys
/// let &(pub_sign, pub_asym) = public_maid.get_public_keys();
///
/// // getting PublicMaid::mpid_signature
/// let maid_signature: &sodiumoxide::crypto::sign::Signature = public_maid.get_maid_signature();
///
/// // getting PublicMaid::owner
/// let owner: &routing::NameType = public_maid.get_owner();
///
/// // getting PublicMaid::signature
/// let signature: &sodiumoxide::crypto::sign::Signature = public_maid.get_signature();
///
/// // getting PublicMaid::name
/// let name: routing::NameType = public_maid.get_name();
/// ```

#[derive(Clone)]
pub struct PublicMaid {
    public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
    maid_signature: crypto::sign::Signature,
    owner: NameType,
    signature: crypto::sign::Signature
}

impl Sendable for PublicMaid {
    fn name(&self) -> NameType {
        self.get_name()
    }

    fn type_tag(&self)->u64 {
        106
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

impl PartialEq for PublicMaid {
    fn eq(&self, other: &PublicMaid) -> bool {
        let pub1_equal = slice_equal(&self.public_keys.0 .0, &other.public_keys.0 .0);
        let pub2_equal = slice_equal(&self.public_keys.1 .0, &other.public_keys.1 .0);
        let sig1_equal = slice_equal(&self.maid_signature.0, &other.maid_signature.0);
        let sig2_equal = slice_equal(&self.signature.0, &other.signature.0);
        return pub1_equal && pub2_equal && sig1_equal && sig2_equal;
    }
}

impl fmt::Debug for PublicMaid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicMaid {{ public_keys:({:?}, {:?}), maid_signature:{:?}, owner:{:?}, signature:{:?}}}", self.public_keys.0 .0.to_vec(), self.public_keys.1 .0.to_vec(),
            self.maid_signature.0.to_vec(), self.owner, self.signature.0.to_vec())
    }
}

impl PublicMaid {
    /// An instanstance of the PublicMaid can be created using the new()
    pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
                         maid_signature: crypto::sign::Signature,
                         owner: NameType,
                         signature: crypto::sign::Signature) -> PublicMaid {
        PublicMaid {public_keys: public_keys, maid_signature: maid_signature, owner: owner,
                    signature: signature}
    }
    /// Returns the PublicKeys
    pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
        &self.public_keys
    }
    /// Returns the Maid Signature
    pub fn get_maid_signature(&self) -> &crypto::sign::Signature {
        &self.maid_signature
    }
    /// Returns the Owner
    pub fn get_owner(&self) -> &NameType {
        &self.owner
    }
    /// Returns the Signature of PublicMaid
    pub fn get_signature(&self) -> &crypto::sign::Signature {
        &self.signature
    }
    /// Returns the name
    pub fn get_name(&self) -> NameType {
        let combined_iter = (self.public_keys.0).0.into_iter().chain((self.public_keys.1).0.into_iter()).collect::<Vec<_>>();
        let mut combined: Vec<u8> = Vec::new();
        for iter in combined_iter {
            combined.push(*iter);
        }
        NameType(crypto::hash::sha512::hash(&combined).0)
    }

}

impl Encodable for PublicMaid {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let (crypto::sign::PublicKey(ref pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
        let crypto::sign::Signature(ref maid_signature) = self.maid_signature;
        let crypto::sign::Signature(ref signature) = self.signature;
        CborTagEncode::new(5483_001, &(
            pub_sign_vec.as_ref(),
            pub_asym_vec.as_ref(),
            maid_signature.as_ref(),
            &self.owner,
            signature.as_ref())).encode(e)
    }
}

impl Decodable for PublicMaid {
    fn decode<D: Decoder>(d: &mut D)-> Result<PublicMaid, D::Error> {
    try!(d.read_u64());
    let (pub_sign_vec, pub_asym_vec, maid_signature_vec, owner, signature_vec) : (Vec<u8>, Vec<u8>, Vec<u8>, NameType, Vec<u8>) = try!(Decodable::decode(d));

        let pub_sign_arr = convert_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
        let pub_asym_arr = convert_to_array!(pub_asym_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
        let maid_signature_arr = convert_to_array!(maid_signature_vec, crypto::sign::SIGNATUREBYTES);
        let signature_arr = convert_to_array!(signature_vec, crypto::sign::SIGNATUREBYTES);

        if pub_sign_arr.is_none() || pub_asym_arr.is_none() || maid_signature_arr.is_none() || signature_arr.is_none() {
            return Err(d.error("Bad PublicMaid size"));
        }

    let pub_keys = (crypto::sign::PublicKey(pub_sign_arr.unwrap()),
            crypto::asymmetricbox::PublicKey(pub_asym_arr.unwrap()));
    let parsed_maid_signature = crypto::sign::Signature(maid_signature_arr.unwrap());
    let parsed_signature = crypto::sign::Signature(signature_arr.unwrap());

    Ok(PublicMaid::new(pub_keys, parsed_maid_signature, owner, parsed_signature))
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

    impl Random for PublicMaid {
        fn generate_random() -> PublicMaid {
            let (sign_pub_key, _) = crypto::sign::gen_keypair();
            let (asym_pub_key, _) = crypto::asymmetricbox::gen_keypair();
            let mut maid_signature_arr: [u8; 64] = unsafe { mem::uninitialized() };
            let mut signature_arr: [u8; 64] = unsafe { mem::uninitialized() };
            for i in 0..64 {
                maid_signature_arr[i] = rand::random::<u8>();
                signature_arr[i] = rand::random::<u8>();
            }

            PublicMaid {
                public_keys: (sign_pub_key, asym_pub_key),
                maid_signature: crypto::sign::Signature(maid_signature_arr),
                owner: routing::test_utils::Random::generate_random(),
                signature: crypto::sign::Signature(signature_arr)
            }
        }
    }

#[test]
    fn serialisation_public_maid() {
        let obj_before = PublicMaid::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: PublicMaid = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

#[test]
    fn equality_assertion_public_maid() {
        let public_maid_first = PublicMaid::generate_random();
        let public_maid_second = public_maid_first.clone();
        let public_maid_third = PublicMaid::generate_random();
        assert_eq!(public_maid_first, public_maid_second);
        assert!(public_maid_first != public_maid_third);
    }

}
