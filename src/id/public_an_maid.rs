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

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;
use helper::*;
use routing::name_type::NameType;
use routing::message_interface::MessageInterface;
use std::fmt;
use id::an_maid::*;

/// PublicAnMaid
///
/// #Examples
/// ```
/// use maidsafe_types::Random;
///
/// let an_maid = maidsafe_types::id::AnMaid::generate_random();
/// let pub_an_maid = maidsafe_types::id::PublicAnMaid::new(&an_maid);
///
/// assert!(&pub_an_maid.verify_owner(&an_maid));
/// ```
///

#[derive(Clone)]
pub struct PublicAnMaid {
    owner: crypto::sign::PublicKey,
    signature: crypto::sign::Signature
}

impl PartialEq for PublicAnMaid {
    fn eq(&self, other: &PublicAnMaid) -> bool {
        // Private keys are mathematically linked, so just check public keys
        let owner = slice_equal(&self.owner.0, &other.owner.0);
        return owner && slice_equal(&self.signature.0, &other.signature.0);
    }
}

impl fmt::Debug for PublicAnMaid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let crypto::sign::PublicKey(ref owner) = self.owner;
        let crypto::sign::Signature(ref signature) = self.signature;
        write!(f, "PublicAnMaid( owner: {:?}, signature: {:?}, name: {:?} )",
             owner, signature.to_vec(), self.get_name())
    }
}

impl MessageInterface for PublicAnMaid {
    fn get_name(&self) -> NameType {
        // the signature should not be in the NAE, otherwise it couldn't be found for verification
        NameType(crypto::hash::sha512::hash(&self.owner.0).0)
    }

    fn get_owner(&self) -> Option<Vec<u8>> {
        Some(self.owner.0.as_ref().to_vec())
    }
}

impl PublicAnMaid {
    pub fn new(an_maid: &AnMaid) -> PublicAnMaid {
        PublicAnMaid {
            owner: an_maid.get_public_key().clone(),
            signature: detach_signature(an_maid.sign(&an_maid.get_public_key().0))
        }
    }

    ///
    /// PublicAnMaid is self signed. Verifies the AnMaid is associated
    /// with this PublicAnMaid, and verifies the self-signature.
    ///
    pub fn verify_owner(&self, an_maid: &AnMaid) -> bool {
        if slice_equal(&self.owner.0, &an_maid.get_public_key().0) {
            let verification_block = attach_signature(&self.signature, &self.owner.0);
            return crypto::sign::verify(&verification_block, &self.owner).is_some();
        }
        return false;
    }
}

impl Encodable for PublicAnMaid {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
       CborTagEncode::new(5483_001, &(self.owner.0.as_ref(), self.signature.0.as_ref())).encode(e)
    }
}

impl Decodable for PublicAnMaid {
    fn decode<D: Decoder>(d: &mut D)-> Result<PublicAnMaid, D::Error> {
        try!(d.read_u64());

        let (owner_vec, signature_vec) : (Vec<u8>, Vec<u8>) = try!(Decodable::decode(d));
        let owner_arr = convert_to_array!(owner_vec, crypto::sign::PUBLICKEYBYTES);
        let signature_arr = convert_to_array!(signature_vec, crypto::sign::SIGNATUREBYTES);

        if owner_arr.is_none() || signature_arr.is_none() {
            return Err(d.error("PubAnMaid bad size"));
        }

        let owner = crypto::sign::PublicKey(owner_arr.unwrap());
        let signature = crypto::sign::Signature(signature_arr.unwrap());

        if crypto::sign::verify(&attach_signature(&signature, &owner.0), &owner).is_none() {
            return Err(d.error("PubAnMaid bad self signature"));
        }

        Ok(PublicAnMaid{ owner: owner, signature: signature })
    }
}

#[cfg(test)]
mod test {
    use cbor;
    use cbor::CborTagEncode;
    use id::an_maid::*;
    use Random;
    use routing::name_type::NameType;
    use rustc_serialize::Encodable;
    use sodiumoxide::crypto;
    use super::*;

    #[test]
    fn get_name_public_anmaid() {
        use routing::message_interface::MessageInterface;

        let maid = AnMaid::generate_random();
        let pub_an_maid = PublicAnMaid::new(&maid);
        let hashed_pub = crypto::hash::sha512::hash(&maid.get_public_key().0);
        assert_eq!(NameType(hashed_pub.0), pub_an_maid.get_name());
    }

    #[test]
    fn get_owner_public_anmaid() {
        use routing::message_interface::MessageInterface;

        let maid = AnMaid::generate_random();
        let pub_an_maid = PublicAnMaid::new(&maid);
        assert_eq!(maid.get_public_key().0.to_vec(), pub_an_maid.get_owner().unwrap());
    }

    #[test]
    fn serialisation_public_anmaid() {
        let maid = AnMaid::generate_random();
        let obj_before = PublicAnMaid::new(&maid);
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: PublicAnMaid = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn bad_deserialisation_public_anmaid() {
        let mut array1 = Vec::<u8>::new();
        let mut array2 = Vec::<u8>::new();

        let verify = |a : &Vec<u8>, b : &Vec<u8>| {
            let mut e = cbor::Encoder::from_memory();
            CborTagEncode::new(65, &(a, b)).encode(&mut e).unwrap();
            let mut d = cbor::Decoder::from_bytes(e.as_bytes());
            d.decode::<PublicAnMaid>().next().unwrap()
        };

        assert!(verify(&array1, &array2).is_err());

        array1.extend((0..crypto::sign::PUBLICKEYBYTES).map(|_| 0));
        assert!(verify(&array1, &array2).is_err());

        array2.extend((0..crypto::sign::SIGNATUREBYTES).map(|_| 0));
        match verify(&array1, &array2).unwrap_err() {
            cbor::CborError::Decode(decode_error) => match decode_error {
                cbor::ReadError::Other(error_msg) => assert_eq!("PubAnMaid bad self signature".to_string(), error_msg),
                _ => assert!(false)
            },
            _ => assert!(false)
        }
    }

    #[test]
    fn equality_assertion_public_anmaid() {
        let maid1 = AnMaid::generate_random();
        let maid2 = AnMaid::generate_random();
        let first_obj = PublicAnMaid::new(&maid1);
        let second_obj = PublicAnMaid::new(&maid2);
        let cloned_obj = second_obj.clone();

        assert!(first_obj != second_obj);
        assert!(second_obj == cloned_obj);
    }

    #[test]
    fn owner_verification_public_anmaid() {
        let maid1 = AnMaid::generate_random();
        let maid2 = AnMaid::generate_random();
        let first_obj = PublicAnMaid::new(&maid1);
        let second_obj = PublicAnMaid::new(&maid2);
        let cloned_obj = second_obj.clone();

        assert!(first_obj.verify_owner(&maid1));
        assert!(second_obj.verify_owner(&maid2));
        assert!(cloned_obj.verify_owner(&maid2));

        assert!(!first_obj.verify_owner(&maid2));
        assert!(!second_obj.verify_owner(&maid1));
        assert!(!cloned_obj.verify_owner(&maid1));
    }
}
