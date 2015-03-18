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
extern crate cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;


struct NameType {
  id: Vec<u8>,
}

// temporary code to test passing a trait to routing to query and possible decode types or
// at least soem info routing needs which is access to these functions on data types
// These traits will be defined in routing and require to be avauilable for any type 
// passed to routing, refresh / account transfer is optional 
// The name will let routing know its an NaeManager and the owner will allow routing to hash
// the requsters id with this name (by hashing the requesters id) for put and post messages 
trait RoutingTrait {
  fn get_name(&self)->NameType;
  fn get_owner(&self)->NameType;
  fn refresh(&self)->bool { false } // is this an account transfer type
  fn merge(&self)->bool { false } // how do we merge these 
}

trait RoutingTraitNew {
  fn get_name(&self)->&NameType;
  fn get_owner(&self)->&Vec<u8>;
  fn refresh(&self)->bool { false } // is this an account transfer type
  fn merge(&self)->bool { false } // how do we merge these
}

// ################## Immutable Data ##############################################
// [TODO]: Implement validate() for all types, possibly get_name() should always check invariants - 2015-03-14 09:03pm

struct ImmutableData {
  name: NameType,
  value: Vec<u8>,
}

impl RoutingTraitNew for ImmutableData {
  fn get_name(&self)->&NameType {
    &self.name
  }

  fn get_owner(&self)->&Vec<u8> {
    &self.value
  }
}

impl Encodable for NameType {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_000, &self.id).encode(e)
  }
}

impl Decodable for NameType {
  fn decode<D: Decoder>(d: &mut D)->Result<NameType, D::Error> {
    try!(d.read_u64());
    let id = try!(Decodable::decode(d));
    Ok(NameType{ id: id })
  }
}

impl Encodable for ImmutableData {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.name, &self.value)).encode(e)
  }
}

impl Decodable for ImmutableData {
  fn decode<D: Decoder>(d: &mut D)->Result<ImmutableData, D::Error> {
    try!(d.read_u64());
    let (name, value) = try!(Decodable::decode(d));
    Ok(ImmutableData { name: name, value: value })
  }
}

#[test]
#[allow(non_snake_case)]
fn Serialisation_ImmutableData() {
  let obj_before = ImmutableData {
    name: NameType{ id: vec![3u8; 10] },
    value: vec![99u8; 10],
  };

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: ImmutableData = d.decode().next().unwrap().unwrap();

  assert_eq!(obj_before.name.id, obj_after.name.id);
  assert_eq!(obj_before.value, obj_after.value);
}

//###################### Structured Data ##########################################


struct StructuredData {
name: (NameType, NameType),  /// name + owner of this StructuredData
value: Vec<Vec<NameType>>,
}

impl Encodable for StructuredData {
  fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
    CborTagEncode::new(5483_002, &(&self.name, &self.value)).encode(e)
  }
}

/// The following key types use the internal cbor tag to identify them and this 
/// should be carried through to any json representation if stored on disk

//###################### AnMaid ##########################################
struct AnMaid {
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
name: NameType,
}

//######################  PublicAnMaid ##########################################
struct PublicAnMaid {
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey), 
signature: crypto::sign::Signature,
name: NameType,
}

//###################### AnMpid ##########################################
struct AnMpid {
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
name: NameType,
}
//######################  ##########################################
struct PublicAnMpid { 
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey), 
signature: crypto::sign::Signature,
name: NameType,
}
//######################  ##########################################
struct Maid { 
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
name: NameType,
}
//######################  ##########################################
struct PublicMaid {
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey), 
maid_signature: crypto::sign::Signature,
owner: NameType,
signature: crypto::sign::Signature,
name: NameType
}
//######################  ##########################################
struct Mpid { 
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
name: NameType
}
//######################  ##########################################
struct PublicMpid {
public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey), 
mpid_signature: crypto::sign::Signature,
owner: NameType,
signature: crypto::sign::Signature,
name: NameType
}
























/// Placeholder doc test
pub fn always_true() -> bool { true }

#[test]
fn it_works() {
 assert_eq!(always_true(), true);
}
