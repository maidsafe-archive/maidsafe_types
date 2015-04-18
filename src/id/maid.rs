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

extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate cbor;
extern crate rand;

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;
use helper::*;
use Random;
use std::cmp;
use std::fmt;

/// Maid
///
/// #Examples
/// ```
/// use maidsafe_types::Random;
///
/// // Creating new Maid
/// let maid  = maidsafe_types::id::maid::Maid::generate_random();
///
/// // getting Maid::public_keys
/// let &(pub_sign, pub_asym) = maid.get_public_keys();
///
/// ```
#[derive(Clone)]
pub struct Maid {
    public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
    secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey)
}

impl Maid {
    pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey){
        &self.public_keys
    }

    pub fn sign(&self, data : &[u8]) -> Vec<u8> {
        return crypto::sign::sign(&data, &self.secret_keys.0)
    }

    pub fn seal(&self, data : &[u8], to : &crypto::asymmetricbox::PublicKey) -> (Vec<u8>, crypto::asymmetricbox::Nonce) {
        let nonce = crypto::asymmetricbox::gen_nonce();
        let sealed = crypto::asymmetricbox::seal(data, &nonce, &to, &self.secret_keys.1);
        return (sealed, nonce);
    }

    pub fn open(
        &self,
        data : &[u8],
        nonce : &crypto::asymmetricbox::Nonce,
        from : &crypto::asymmetricbox::PublicKey) -> Result<Vec<u8>, ::CryptoError> {
        return crypto::asymmetricbox::open(&data, &nonce, &from, &self.secret_keys.1).ok_or(::CryptoError::Unknown);
    }
}

impl Random for Maid {
    fn generate_random() -> Maid {
        let sign_keys = crypto::sign::gen_keypair();
        let asym_keys = crypto::asymmetricbox::gen_keypair();

        Maid {
            public_keys: (sign_keys.0, asym_keys.0),
            secret_keys: (sign_keys.1, asym_keys.1)
        }
    }
}

impl cmp::PartialEq for Maid {
    fn eq(&self, other: &Maid) -> bool {
        // Private keys are mathematically linked, so just check public keys
        let public0_equal =  slice_equal(&self.public_keys.0 .0, &other.public_keys.0 .0);
        let public1_equal = slice_equal(&self.public_keys.1 .0, &other.public_keys.1 .0);
        return public0_equal && public1_equal;
    }
}

impl fmt::Debug for Maid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Maid {{ public_keys: ({:?}, {:?}) }}", self.public_keys.0 .0.to_vec(), self.public_keys.1 .0.to_vec())
    }
}

impl Encodable for Maid {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
        let (crypto::sign::SecretKey(sec_sign_vec), crypto::asymmetricbox::SecretKey(sec_asym_vec)) = self.secret_keys;

        CborTagEncode::new(5483_001, &(
            pub_sign_vec.as_ref(),
            pub_asym_vec.as_ref(),
            sec_sign_vec.as_ref(),
            sec_asym_vec.as_ref())).encode(e)
    }
}

impl Decodable for Maid {
    fn decode<D: Decoder>(d: &mut D)-> Result<Maid, D::Error> {
        try!(d.read_u64());
        let (pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec) : (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = try!(Decodable::decode(d));

        let pub_sign_arr = convert_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
        let pub_asym_arr = convert_to_array!(pub_asym_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
        let sec_sign_arr = convert_to_array!(sec_sign_vec, crypto::sign::SECRETKEYBYTES);
        let sec_asym_arr = convert_to_array!(sec_asym_vec, crypto::asymmetricbox::SECRETKEYBYTES);

        if pub_sign_arr.is_none() || pub_asym_arr.is_none() || sec_sign_arr.is_none() || sec_asym_arr.is_none() {
            return Err(d.error("Bad Maid size"));
        }

        let pub_keys = (crypto::sign::PublicKey(pub_sign_arr.unwrap()),
                        crypto::asymmetricbox::PublicKey(pub_asym_arr.unwrap()));
        let sec_keys = (crypto::sign::SecretKey(sec_sign_arr.unwrap()),
                        crypto::asymmetricbox::SecretKey(sec_asym_arr.unwrap()));
        Ok(Maid{ public_keys: pub_keys, secret_keys: sec_keys })
    }
}

#[cfg(test)]
use self::rand::Rng;

#[test]
fn serialisation_maid() {
    use helper::*;
    let obj_before = Maid::generate_random();

    let mut e = cbor::Encoder::from_memory();
    e.encode(&[&obj_before]).unwrap();

    let mut d = cbor::Decoder::from_bytes(e.as_bytes());
    let obj_after: Maid = d.decode().next().unwrap().unwrap();

    let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = obj_before.get_public_keys();
    let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = obj_after.get_public_keys();
    let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
    let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;

    assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
    assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
    assert!(slice_equal(&sec_sign_arr_before, &sec_sign_arr_after));
    assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
}

#[test]
fn generation() {
    let maid1 = Maid::generate_random();
    let maid2 = Maid::generate_random();
    let maid2_clone = maid2.clone();

    assert_eq!(maid2, maid2_clone);
    assert!(!(maid2 != maid2_clone));
    assert!(maid1 != maid2);

    let random_bytes = rand::thread_rng().gen_iter::<u8>().take(100).collect::<Vec<u8>>();
    {
        let sign1 = maid1.sign(&random_bytes);
        let sign2 = maid2.sign(&random_bytes);
        assert!(sign1 != sign2);

        assert!(crypto::sign::verify(&sign1, &maid1.get_public_keys().0).is_some());
        assert!(crypto::sign::verify(&sign2, &maid1.get_public_keys().0).is_none());

        assert!(crypto::sign::verify(&sign2, &maid2.get_public_keys().0).is_some());
        assert!(crypto::sign::verify(&sign2, &maid1.get_public_keys().0).is_none());
    }
    {
        let maid3 = Maid::generate_random();

        let encrypt1 = maid1.seal(&random_bytes, &maid3.get_public_keys().1);
        let encrypt2 = maid2.seal(&random_bytes, &maid3.get_public_keys().1);
        assert!(encrypt1.0 != encrypt2.0);

        assert!(maid3.open(&encrypt1.0, &encrypt1.1, &maid1.get_public_keys().1).is_ok());
        assert!(maid3.open(&encrypt1.0, &encrypt1.1, &maid2.get_public_keys().1).is_err());

        assert!(maid3.open(&encrypt2.0, &encrypt2.1, &maid2.get_public_keys().1).is_ok());
        assert!(maid3.open(&encrypt2.0, &encrypt2.1, &maid1.get_public_keys().1).is_err());
    }
}
