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
/// // Create AnMaid
/// let an_maid : maidsafe_types::AnMaid = maidsafe_types::Random::generate_random();
/// // Retrieving the values
/// let ref publicKeys = an_maid.get_public_key();
/// ```
///
#[derive(Clone)]
pub struct AnMaid {
    public_key: crypto::sign::PublicKey,
    secret_key: crypto::sign::SecretKey
}

impl PartialEq for AnMaid {
    fn eq(&self, other: &AnMaid) -> bool {
        // Private key is mathematically linked, so just check public key
        slice_equal(&self.public_key.0, &other.public_key.0)
    }
}

impl Random for AnMaid {
    fn generate_random() -> AnMaid {
        let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();

        AnMaid {
            public_key: pub_sign_key,
            secret_key: sec_sign_key
        }
    }
}

impl fmt::Debug for AnMaid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let crypto::sign::PublicKey(ref public_key) = self.public_key;
        write!(f, "AnMaid( public_key: {:?} )", public_key)
    }
}

impl AnMaid {
    pub fn get_public_key(&self) -> &crypto::sign::PublicKey {
        &self.public_key
    }

    pub fn sign(&self, data : &[u8]) -> Vec<u8> {
        return crypto::sign::sign(&data, &self.secret_key)
    }
}

impl Encodable for AnMaid {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(self.public_key.0.as_ref(), self.secret_key.0.as_ref())).encode(e)
    }
}

impl Decodable for AnMaid {
    fn decode<D: Decoder>(d: &mut D)-> Result<AnMaid, D::Error> {
        try!(d.read_u64());
        let(pub_sign_vec, sec_sign_vec) : (Vec<u8>, Vec<u8>) = try!(Decodable::decode(d));
        let pub_sign_arr = convert_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
        let sec_sign_arr = convert_to_array!(sec_sign_vec, crypto::sign::SECRETKEYBYTES);

        if pub_sign_arr.is_none() || sec_sign_arr.is_none() {
            return Err(d.error("Bad AnMaid size"));
        }

        let pub_key = crypto::sign::PublicKey(pub_sign_arr.unwrap());
        let sec_key = crypto::sign::SecretKey(sec_sign_arr.unwrap());
        Ok(AnMaid{ public_key: pub_key, secret_key: sec_key })
    }
}

#[cfg(test)]
mod test {
    use cbor;
    use cbor::CborTagEncode;
    use helper::*;
    use rand;
    use rand::Rng;
    use Random;
    use rustc_serialize::Encodable;
    use sodiumoxide::crypto;
    use super::AnMaid;

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
    fn bad_deserialisation_anmaid() {
        let mut array1 = Vec::<u8>::new();
        let mut array2 = Vec::<u8>::new();

        let verify = |a : &Vec<u8>, b : &Vec<u8>| {
            let mut e = cbor::Encoder::from_memory();
            CborTagEncode::new(65, &(a, b)).encode(&mut e).unwrap();
            let mut d = cbor::Decoder::from_bytes(e.as_bytes());
            d.decode::<AnMaid>().next().unwrap().is_ok()
        };

        assert!(!verify(&array1, &array2));

        array1.extend((0..crypto::sign::PUBLICKEYBYTES).map(|_| 0));
        assert!(!verify(&array1, &array2));

        array2.extend((0..crypto::sign::SIGNATUREBYTES).map(|_| 0));
        assert!(verify(&array1, &array2));
    }

    #[test]
    fn equality_assertion_an_maid() {
        let first_obj = AnMaid::generate_random();
        let second_obj = AnMaid::generate_random();
        let cloned_obj = second_obj.clone();

        assert!(first_obj != second_obj);
        assert!(second_obj == cloned_obj);
    }

    #[test]
    fn generation() {
        let maid1 = AnMaid::generate_random();
        let maid2 = AnMaid::generate_random();
        let maid2_clone = maid2.clone();

        assert_eq!(maid2, maid2_clone);
        assert!(!(maid2 != maid2_clone));
        assert!(maid1 != maid2);

        let random_bytes = rand::thread_rng().gen_iter::<u8>().take(100).collect::<Vec<u8>>();
        {
            let sign1 = maid1.sign(&random_bytes);
            let sign2 = maid2.sign(&random_bytes);
            assert!(sign1 != sign2);

            assert!(crypto::sign::verify(&sign1, &maid1.get_public_key()).is_some());
            assert!(crypto::sign::verify(&sign2, &maid1.get_public_key()).is_none());

            assert!(crypto::sign::verify(&sign2, &maid2.get_public_key()).is_some());
            assert!(crypto::sign::verify(&sign2, &maid1.get_public_key()).is_none());
        }
    }
}
