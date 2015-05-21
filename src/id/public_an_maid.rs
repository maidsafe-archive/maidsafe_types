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

/// PublicAnMaid
///
/// #Examples
/// ```
/// extern crate sodiumoxide;
/// extern crate routing;
/// extern crate maidsafe_types;
///
/// // Generating public and secret keys using sodiumoxide
/// let (pub_sign_key, _) = sodiumoxide::crypto::sign::gen_keypair();
/// let (pub_asym_key, _) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
/// // Create PublicAnMaid
/// let pub_an_maid = maidsafe_types::PublicAnMaid::new((pub_sign_key, pub_asym_key), sodiumoxide::crypto::sign::Signature([5u8; 64]));
/// // Retrieving the values
/// let ref publicKeys = pub_an_maid.get_public_keys();
/// let ref signature = pub_an_maid.get_signature();
/// ```
///

#[derive(Clone)]
pub struct PublicAnMaid {
        public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
        signature: crypto::sign::Signature
}

impl PartialEq for PublicAnMaid {
    fn eq(&self, other: &PublicAnMaid) -> bool {
        // Private keys are mathematically linked, so just check public keys
        let public0_equal = slice_equal(&self.public_keys.0 .0, &other.public_keys.0 .0);
        let public1_equal = slice_equal(&self.public_keys.1 .0, &other.public_keys.1 .0);
        let signature = slice_equal(&self.signature.0, &other.signature.0);
        return public0_equal && public1_equal && signature;
    }
}

impl fmt::Debug for PublicAnMaid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (crypto::sign::PublicKey(public_key), crypto::asymmetricbox::PublicKey(assym_public_key)) = self.public_keys;
        let crypto::sign::Signature(signature) = self.signature;
        write!(f, "PublicAnMaid( public_keys: ({:?}, {:?}), signature: {:?}, name: {:?} )",
             public_key, assym_public_key, signature.to_vec(), self.name())
    }
}

impl Sendable for PublicAnMaid {
    fn name(&self) -> NameType {
        name(&self.public_keys)
    }

    fn type_tag(&self)->u64 {
        105
    }

    fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn owner(&self) -> Option<NameType> {
        Some(name(&self.public_keys))
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, _: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl PublicAnMaid {
        /// new() is invoked to create an instance of the PublicAnMaid
        pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
                                                 signature: crypto::sign::Signature) -> PublicAnMaid {
            PublicAnMaid {public_keys: public_keys, signature: signature }
        }
        /// Returns the PublicKeys
        pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
            &self.public_keys
        }
        /// Returns the Signature
        pub fn get_signature(&self) -> &crypto::sign::Signature {
            &self.signature
        }
}

impl Encodable for PublicAnMaid {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
       CborTagEncode::new(5483_001,
                          &(self.public_keys.0 .0.as_ref(),
                            self.public_keys.1 .0.as_ref(),
                            self.signature.0.as_ref())).encode(e)
    }
}

impl Decodable for PublicAnMaid {
    fn decode<D: Decoder>(d: &mut D)-> Result<PublicAnMaid, D::Error> {
        try!(d.read_u64());
        let (pub_sign_vec, pub_asym_vec, signature_vec) : (Vec<u8>, Vec<u8>, Vec<u8>) = try!(Decodable::decode(d));

        let pub_sign_arr = convert_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
        let pub_asym_arr = convert_to_array!(pub_asym_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
        let signature_arr = convert_to_array!(signature_vec, crypto::sign::SIGNATUREBYTES);

        if pub_sign_arr.is_none() || pub_asym_arr.is_none() || signature_arr.is_none() {
            return Err(d.error("PubAnMaid bad size"));
        }

        let pub_keys = (crypto::sign::PublicKey(pub_sign_arr.unwrap()),
                        crypto::asymmetricbox::PublicKey(pub_asym_arr.unwrap()));
        let signature = crypto::sign::Signature(signature_arr.unwrap());

        Ok(PublicAnMaid::new(pub_keys, signature))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor;
    use sodiumoxide::crypto;
    use Random;
    use rand;
    use std::mem;

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
                signature: crypto::sign::Signature(arr)
            }
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

}
