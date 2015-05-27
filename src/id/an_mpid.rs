// // Copyright 2015 MaidSafe.net limited.
// //
// // This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// // version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// // licence you accepted on initial access to the Software (the "Licences").
// //
// // By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// // bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// // Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
// //
// // Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// // under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// // KIND, either express or implied.
// //
// // Please review the Licences for the specific language governing permissions and limitations
// // relating to use of the SAFE Network Software.
//
// use cbor::CborTagEncode;
// use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
// use sodiumoxide::crypto;
// use helper::*;
// use routing::NameType;
// use routing::sendable::Sendable;
// use std::fmt;
// use cbor;
// use RevocationIdTypeTag;
//
// /// AnMpid
// ///
// /// #Examples
// /// ```
// /// extern crate sodiumoxide;
// /// extern crate maidsafe_types;
// /// extern crate routing;
// ///
// /// // Generating publick and secret keys using sodiumoxide
// /// let (pub_sign_key, sec_sign_key) = sodiumoxide::crypto::sign::gen_keypair();
// /// let (pub_asym_key, sec_asym_key) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
// /// // Create AnMpid
// /// let an_mpid = maidsafe_types::AnMpid::new((pub_sign_key, pub_asym_key),
// ///                                           (sec_sign_key, sec_asym_key));
// /// // Retrieving the values
// /// let ref publicKeys = an_mpid.public_keys();
// /// let ref secret_keys = an_mpid.secret_keys();
// /// ```
// ///
// #[derive(Clone)]
// pub struct AnMpid {
//     type_tag: u64,
//     public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
//     secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey)
// }
//
// impl Sendable for AnMpid {
//     fn name(&self) -> NameType {
//         name(&self.public_keys, self.type_tag.clone(), None)
//     }
//
//     fn type_tag(&self)->u64 {
//         self.type_tag.clone()
//     }
//
//     fn serialised_contents(&self)->Vec<u8> {
//         let mut e = cbor::Encoder::from_memory();
//         e.encode(&[&self]).unwrap();
//         e.into_bytes()
//     }
//
//     fn owner(&self) -> Option<NameType> {
//         Some(self.name().clone())
//     }
//
//     fn refresh(&self)->bool {
//         false
//     }
//
//     fn merge(&self, _: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
// }
//
// impl Revokable for AnMpid {
//     /// Returns the PublicKey of the AnMaid
//     fn public_key(&self) -> &crypto::sign::PublicKey {
//         &self.public_keys.0
//     }
//     /// Signs the data with the SecretKey of the AnMpid and recturns the Signed Data
//     fn sign(&self, data : &[u8]) -> Vec<u8> {
//         return crypto::sign::sign(&data, &self.secret_keys.0)
//     }
// }
//
// impl fmt::Debug for AnMpid {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "AnMpid {{ type_tag:{}, public_keys:({:?}, {:?}), secret_keys:({:?}, {:?}) }}",
//             self.type_tag, self.public_keys.0 .0.to_vec(), self.public_keys.1 .0.to_vec(),
//             self.secret_keys.0 .0.to_vec(), self.secret_keys.1 .0.to_vec())
//     }
// }
// impl PartialEq for AnMpid {
//     fn eq(&self, other: &AnMpid) -> bool {
//         // secret keys are mathematically linked, just check public ones
//         &self.type_tag == &other.type_tag &&
//         slice_equal(&self.public_keys.0 .0, &other.public_keys.0 .0) &&
//         slice_equal(&self.public_keys.1 .0, &other.public_keys.1 .0)
//     }
// }
//
// impl AnMpid {
//     /// Invoked to create an instance of AnMpid
//     pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
//                          secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey)) -> AnMpid {
//         AnMpid { type_tag: 102u64, public_keys: public_keys, secret_keys: secret_keys }
//     }    /// Returns the PublicKeys
//     pub fn public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
//         &self.public_keys
//     }
//     /// Returns the SecretKeys
//     pub fn secret_keys(&self) -> &(crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey) {
//         &self.secret_keys
//     }
// }
//
// impl Encodable for AnMpid {
//     fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
//     let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
//     let (crypto::sign::SecretKey(sec_sign_vec), crypto::asymmetricbox::SecretKey(sec_asym_vec)) = self.secret_keys;
//     let type_vec = self.type_tag.to_string().into_bytes();
//     CborTagEncode::new(5483_001, &(
//         type_vec,
//         pub_sign_vec.as_ref(),
//         pub_asym_vec.as_ref(),
//         sec_sign_vec.as_ref(),
//         sec_asym_vec.as_ref())).encode(e)
//     }
// }
//
// impl Decodable for AnMpid {
//     fn decode<D: Decoder>(d: &mut D)-> Result<AnMpid, D::Error> {
//         try!(d.read_u64());
//         let (tag_type_vec, pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec) : (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = try!(Decodable::decode(d));
//
//         let pub_sign_arr = convert_to_array!(pub_sign_vec, crypto::sign::PUBLICKEYBYTES);
//         let pub_asym_arr = convert_to_array!(pub_asym_vec, crypto::asymmetricbox::PUBLICKEYBYTES);
//         let sec_sign_arr = convert_to_array!(sec_sign_vec, crypto::sign::SECRETKEYBYTES);
//         let sec_asym_arr = convert_to_array!(sec_asym_vec, crypto::asymmetricbox::SECRETKEYBYTES);
//
//         if pub_sign_arr.is_none() || pub_asym_arr.is_none() || sec_sign_arr.is_none() || sec_asym_arr.is_none() {
//             return Err(d.error("Bad AnMpid size"));
//         }
//
//         let type_tag: u64 = match String::from_utf8(tag_type_vec) {
//             Ok(string) =>  {
//                 match string.parse::<u64>() {
//                     Ok(type_tag) => type_tag,
//                     Err(_) => return Err(d.error("Bad Tag Type"))
//                 }
//             },
//             Err(_) => return Err(d.error("Bad Tag Type"))
//         };
//
//         Ok(AnMpid { type_tag: type_tag,
//                     public_keys: (crypto::sign::PublicKey(pub_sign_arr.unwrap()), crypto::asymmetricbox::PublicKey(pub_asym_arr.unwrap())),
//                     secret_keys: (crypto::sign::SecretKey(sec_sign_arr.unwrap()), crypto::asymmetricbox::SecretKey(sec_asym_arr.unwrap())) })
//     }
// }
//
// #[cfg(test)]
// mod test {
//     use super::*;
//     use cbor::{ Encoder, Decoder };
//     use Random;
//     use sodiumoxide::crypto;
//
//     impl Random for AnMpid {
//         fn generate_random() -> AnMpid {
//             let (sign_pub_key, sign_sec_key) = crypto::sign::gen_keypair();
//             let (asym_pub_key, asym_sec_key) = crypto::asymmetricbox::gen_keypair();
//             AnMpid {
//                 type_tag: 102u64,
//                 public_keys: (sign_pub_key, asym_pub_key),
//                 secret_keys: (sign_sec_key, asym_sec_key)
//             }
//         }
//     }
//
// #[test]
//     fn serialisation_an_mpid() {
//         let obj_before = AnMpid::generate_random();
//         let mut e = Encoder::from_memory();
//         e.encode(&[&obj_before]).unwrap();
//
//         let mut d = Decoder::from_bytes(e.as_bytes());
//         let obj_after: AnMpid = d.decode().next().unwrap().unwrap();
//
//         assert_eq!(obj_before, obj_after);
//     }
//
// #[test]
//     fn equality_assertion_an_mpid() {
//         let an_mpid_first = AnMpid::generate_random();
//         let an_mpid_second = an_mpid_first.clone();
//         let an_mpid_third = AnMpid::generate_random();
//         assert_eq!(an_mpid_first, an_mpid_second);
//         assert!(an_mpid_first != an_mpid_third);
//     }
//
// }
