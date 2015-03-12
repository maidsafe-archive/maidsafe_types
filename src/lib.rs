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
    
#![crate_name = "maidsafe_types"]
#![crate_type = "lib"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://dirvine.github.io/dirvine/maidsafe_types/")]
//! Placeholder DO NOT USE ! until version 0.1 - all code is a test and useless
//! Types of data functors and messages for MaidSafe secure Autonomous networks.
//! This crate is of no use to anyone as a stand alone crate. It is a module that is 
//! specialised, but it is a crate to make version handling and distribution easier. 

extern crate "rustc-serialize" as rustc_serialize;
extern crate sodiumoxide;
use sodiumoxide::crypto;


struct NameType ( [u8; 64] );

enum Data {
ImmutableData(NameType, Vec<u8>),
StructuredData((NameType, NameType), Vec<Vec<NameType>>),
AnMaid(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey, crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
PublicAnMaid(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey, crypto::sign::Signature),
AnMpid(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey, crypto::sign::Signature),
PublicAnMpid(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey, crypto::sign::Signature),
Maid(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey, crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
PublicMaid(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey, crypto::sign::Signature, crypto::sign::Signature),
Mpid(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey, crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
PublicMpid(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey, crypto::sign::Signature, crypto::sign::Signature),
}

// TODO(dirvine) Only specialisation is StructuredData :12/03/2015
trait DataTraits {
  fn get_name(&self)->crypto::hash::sha512::Digest {
    crypto::hash::sha512::hash("Unimplemented".as_bytes())
  }
}

impl DataTraits for Data::Struc {
  fn get_name(&self)->NameType {
    &self.name
  }
}

/* #[derive(PartialEq, Eq, PartialOrd, Ord, RustcEncodable, RustcDecodable)]  */
struct ImmutableData {
name: NameType,
value: Vec<u8>,
}

/* #[derive(PartialEq, Eq, PartialOrd, Ord, RustcEncodable, RustcDecodable)]  */
struct StructuredData {
name: (NameType, NameType),  /// name + owner of this StructuredData
value: Vec<Vec<NameType>>,
}

/* #[derive(PartialEq, Eq, PartialOrd, Ord, RustcEncodable, RustcDecodable)]  */
struct DataWrapper {
  data_type : Data,
  serialised_data : Vec<u8>,
}

fn parse_serialised_data_type(wrapped_data: DataWrapper) -> Data {
  unimplemented!();
  }



























/// Placeholder doc test
pub fn always_true() -> bool { true }

#[test]
fn it_works() {
 assert_eq!(always_true(), true);
}
