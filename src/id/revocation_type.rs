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

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;
use helper::*;
use std::fmt;
use IdTypeTags;
use std::mem;

/// The following key types use the internal cbor tag to identify them and this
/// should be carried through to any json representation if stored on disk
///
/// RevocationType
///
/// #Examples
/// ```
/// extern crate sodiumoxide;
/// extern crate maidsafe_types;
/// // Generating public and secret keys using sodiumoxide
/// // Create RevocationType
/// let an_maid : maidsafe_types::RevocationType = maidsafe_types::RevocationType::new::<maidsafe_types::MaidTypeTags>();
/// ```
///
#[derive(Clone)]
pub struct RevocationType {
    type_tags: (u64, u64, u64),
    public_key: crypto::sign::PublicKey,
    secret_key: crypto::sign::SecretKey
}

impl PartialEq for RevocationType {
    fn eq(&self, other: &RevocationType) -> bool {
        // Private key is mathematically linked, so just check public key
        &self.type_tags == &other.type_tags &&
        slice_equal(&self.public_key.0, &other.public_key.0)
    }
}


impl fmt::Debug for RevocationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let crypto::sign::PublicKey(ref public_key) = self.public_key;
        write!(f, "RevocationType( type_tags:{:?}, public_key: {:?} )", self.type_tags, public_key)
    }
}

impl RevocationType {
    /// An instance of RevocationType can be created by invoking the new()
    /// Default contructed RevocationType instance is returned
    pub fn new<TypeTags>() -> RevocationType where TypeTags: IdTypeTags {
        let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
        let type_tags: TypeTags = unsafe { mem::uninitialized() };
        RevocationType {
            type_tags: type_tags.type_tags(),
            public_key: pub_sign_key,
            secret_key: sec_sign_key
        }
    }

    /// Returns type tag
    pub fn type_tags(&self) -> &(u64, u64, u64) {
        &self.type_tags
    }
    /// Returns the SecretKey of the RevocationType
    pub fn secret_key(&self) -> &crypto::sign::SecretKey {
        &self.secret_key
    }
    /// Returns the PublicKey of the AnMaid
    pub fn public_key(&self) -> &crypto::sign::PublicKey {
        &self.public_key
    }
    /// Signs the data with the SecretKey of the AnMaid and recturns the Signed Data
    pub fn sign(&self, data : &[u8]) -> Vec<u8> {
        return crypto::sign::sign(&data, &self.secret_key)
    }
}

fn convert_to_u64(num_vec: Vec<u8>) -> u64 {
    match String::from_utf8(num_vec) {
         Ok(string) =>  {
             match string.parse::<u64>() {
                 Ok(type_tag) => type_tag,
                 Err(_) => 0u64
             }
         },
         Err(_) => 0u64
     }
}

impl Encodable for RevocationType {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let revocation_type_tag_vec = self.type_tags.0.to_string().into_bytes();
        let id_type_tag_vec = self.type_tags.1.to_string().into_bytes();
        let public_id_type_tag_vec = self.type_tags.2.to_string().into_bytes();
        CborTagEncode::new(5483_001,
             &(revocation_type_tag_vec,
               id_type_tag_vec,
               public_id_type_tag_vec,
               self.public_key.0.as_ref(), self.secret_key.0.as_ref())).encode(e)
    }
}

impl Decodable for RevocationType {
    fn decode<D: Decoder>(d: &mut D)-> Result<RevocationType, D::Error> {
        try!(d.read_u64());
        let(revocation_type_tag_vec, id_type_tag_vec, public_id_type_tag_vec , pub_sign_vec, sec_sign_vec) : (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = try!(Decodable::decode(d));
        let pub_sign_arr = convert_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
        let sec_sign_arr = convert_to_array!(sec_sign_vec, crypto::sign::SECRETKEYBYTES);

        if pub_sign_arr.is_none() || sec_sign_arr.is_none() {
            return Err(d.error("Bad RevocationType size"));
        }

        let pub_key = crypto::sign::PublicKey(pub_sign_arr.unwrap());
        let sec_key = crypto::sign::SecretKey(sec_sign_arr.unwrap());
        Ok(RevocationType{ type_tags: (convert_to_u64(revocation_type_tag_vec),
             convert_to_u64(id_type_tag_vec), convert_to_u64(public_id_type_tag_vec)),
             public_key: pub_key, secret_key: sec_key })
    }
}

#[cfg(test)]
mod test {
    use cbor;
    use rand;
    use rand::Rng;
    use Random;
    use sodiumoxide::crypto;
    use super::RevocationType;
    use MaidTypeTags;
    use MpidTypeTags;

    impl Random for RevocationType {
        fn generate_random() -> RevocationType {
            RevocationType::new::<MaidTypeTags>()
        }
    }

#[test]
    fn create_an_mpid() {
        let _ = RevocationType::new::<MpidTypeTags>();
    }

#[test]
    fn serialisation_an_maid() {
        let obj_before = RevocationType::generate_random();
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: RevocationType = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }

#[test]
    fn equality_assertion_an_maid() {
        let first_obj = RevocationType::generate_random();
        let second_obj = RevocationType::generate_random();
        let cloned_obj = second_obj.clone();

        assert!(first_obj != second_obj);
        assert!(second_obj == cloned_obj);
    }

#[test]
    fn generation() {
        let maid1 = RevocationType::generate_random();
        let maid2 = RevocationType::generate_random();
        let maid2_clone = maid2.clone();

        assert_eq!(maid2, maid2_clone);
        assert!(!(maid2 != maid2_clone));
        assert!(maid1 != maid2);

        let random_bytes = rand::thread_rng().gen_iter::<u8>().take(100).collect::<Vec<u8>>();
        {
            let sign1 = maid1.sign(&random_bytes);
            let sign2 = maid2.sign(&random_bytes);
            assert!(sign1 != sign2);

            assert!(crypto::sign::verify(&sign1, &maid1.public_key()).is_some());
            assert!(crypto::sign::verify(&sign2, &maid1.public_key()).is_none());

            assert!(crypto::sign::verify(&sign2, &maid2.public_key()).is_some());
            assert!(crypto::sign::verify(&sign2, &maid1.public_key()).is_none());
        }
    }
}
