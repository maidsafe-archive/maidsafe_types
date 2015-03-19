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
mod helper;

extern crate "rustc-serialize" as rustc_serialize;
extern crate sodiumoxide;
extern crate cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;
use sodiumoxide::randombytes;

pub struct NameType {
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
fn serialisation_immutable_data() {
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


pub struct StructuredData {
  name: (NameType, NameType),  /// name + owner of this StructuredData
  value: Vec<Vec<NameType>>,
}

impl StructuredData {
  pub fn new(name: (NameType, NameType), value: Vec<Vec<NameType>>) -> StructuredData {
    StructuredData {
      name: name,
      value: value,
    }
  }
}

impl Encodable for StructuredData {
  fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
    CborTagEncode::new(5483_002, &(&self.name, &self.value)).encode(e)
  }
}

impl Decodable for StructuredData {
  fn decode<D: Decoder>(d: &mut D)->Result<StructuredData, D::Error> {
    try!(d.read_u64());
    let (name, value) = try!(Decodable::decode(d));
    Ok(StructuredData { name: name, value: value })
  }
}

#[test]
fn serialisation_structured_data() {
  let mut value = Vec::new();
  value.push(Vec::new());
  match value.last_mut() {
      Some(v) => v.push(NameType{ id: vec![7u8; 10] }),
      None => ()
  }
  let obj_before = StructuredData::new((NameType{ id: vec![3u8; 10] }, NameType{ id: vec![5u8; 10] }), value);

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: StructuredData = d.decode().next().unwrap().unwrap();

  assert_eq!((obj_before.name.0.id, obj_before.name.1.id), (obj_after.name.0.id, obj_after.name.1.id));
  assert_eq!(obj_before.value[0][0].id, obj_after.value[0][0].id);
}

/// The following key types use the internal cbor tag to identify them and this 
/// should be carried through to any json representation if stored on disk

//###################### AnMaid ##########################################
//#[derive(Debug, Eq, PartialEq)]
pub struct AnMaid {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
  name: NameType,
}

impl AnMaid {
pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
  nameType: NameType) -> AnMaid {
    AnMaid {
      public_keys: public_keys,
      secret_keys: secret_keys,
      name: nameType
    }
  }
}

impl Encodable for AnMaid {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
    let (crypto::sign::SecretKey(sec_sign_vec), crypto::asymmetricbox::SecretKey(sec_asym_vec)) = self.secret_keys;

    CborTagEncode::new(5483_001, &(
      helper::array_as_vector(&pub_sign_vec),
      helper::array_as_vector(&pub_asym_vec),
      helper::array_as_vector(&sec_sign_vec),
      helper::array_as_vector(&sec_asym_vec),
      &self.name)).encode(e)
  }
}

impl Decodable for AnMaid {
  fn decode<D: Decoder>(d: &mut D)-> Result<AnMaid, D::Error> {
    try!(d.read_u64());
    let(pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec, name) = try!(Decodable::decode(d));
    let pub_keys = (crypto::sign::PublicKey(helper::vector_as_u8_32_array(pub_sign_vec)),
      crypto::asymmetricbox::PublicKey(helper::vector_as_u8_32_array(pub_asym_vec)));
    let sec_keys = (crypto::sign::SecretKey(helper::vector_as_u8_64_array(sec_sign_vec)),
      crypto::asymmetricbox::SecretKey(helper::vector_as_u8_32_array(sec_asym_vec)));
    Ok(AnMaid::new(pub_keys, sec_keys, name))
  }
}

#[test]
fn serialisation_an_maid() {
  let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
  let (pub_asym_key, sec_asym_key) = crypto::asymmetricbox::gen_keypair();

  let obj_before = AnMaid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType{ id: vec![3u8; 10] });

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: AnMaid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;

  assert_eq!(obj_before.name.id, obj_after.name.id);
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
}

//######################  PublicAnMaid ##########################################
pub struct PublicAnMaid {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey), 
  signature: crypto::sign::Signature,
  name: NameType,
}

impl PublicAnMaid {
  pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey), 
    signature: crypto::sign::Signature, name: NameType) -> PublicAnMaid {
      PublicAnMaid {
        public_keys: public_keys,
        signature: signature,
        name: name
      }
  }
}

impl Encodable for PublicAnMaid {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
    let crypto::sign::Signature(signature_arr) = self.signature;

    CborTagEncode::new(5483_001, &(
        helper::array_as_vector(&pub_sign_vec),
        helper::array_as_vector(&pub_asym_vec),
        helper::array_as_vector(&signature_arr),
        &self.name)).encode(e)
  }
}

impl Decodable for PublicAnMaid {
  fn decode<D: Decoder>(d: &mut D)-> Result<PublicAnMaid, D::Error> {
    try!(d.read_u64());

    let(pub_sign_vec, pub_asym_vec, signature_vec, name) = try!(Decodable::decode(d));
    let pub_keys = (crypto::sign::PublicKey(helper::vector_as_u8_32_array(pub_sign_vec)),
      crypto::asymmetricbox::PublicKey(helper::vector_as_u8_32_array(pub_asym_vec)));
    let signature = crypto::sign::Signature(helper::vector_as_u8_64_array(signature_vec));

    Ok(PublicAnMaid::new(pub_keys, signature, name))
  }
}


#[test]
fn serialisation_public_anmaid() {
  let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
  let (pub_asym_key, sec_asym_key) = crypto::asymmetricbox::gen_keypair();

  let obj_before = PublicAnMaid::new((pub_sign_key, pub_asym_key), 
  crypto::sign::Signature([5u8; 64]), NameType { id: vec![99u8; 10] });

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: PublicAnMaid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &crypto::sign::Signature(signature_arr_before) = &obj_before.signature;
  let &crypto::sign::Signature(signature_arr_after) = &obj_after.signature;

  assert_eq!(obj_before.name.id, obj_after.name.id);
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert!(helper::compare_arr_u8_64(&signature_arr_before, &signature_arr_after));
}
//###################### AnMpid ##########################################
pub struct AnMpid {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
  name: NameType,
}

impl AnMpid {
pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
  nameType: NameType) -> AnMpid {
    AnMpid {
      public_keys: public_keys,
      secret_keys: secret_keys,
      name: nameType
    }
  }
}

impl Encodable for AnMpid {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
    let (crypto::sign::SecretKey(sec_sign_vec), crypto::asymmetricbox::SecretKey(sec_asym_vec)) = self.secret_keys;

    CborTagEncode::new(5483_001, &(
      helper::array_as_vector(&pub_sign_vec),
      helper::array_as_vector(&pub_asym_vec),
      helper::array_as_vector(&sec_sign_vec),
      helper::array_as_vector(&sec_asym_vec),
      &self.name)).encode(e)
  }
}

impl Decodable for AnMpid {
  fn decode<D: Decoder>(d: &mut D)-> Result<AnMpid, D::Error> {
    try!(d.read_u64());
    let(pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec, name) = try!(Decodable::decode(d));
    let pub_keys = (crypto::sign::PublicKey(helper::vector_as_u8_32_array(pub_sign_vec)),
      crypto::asymmetricbox::PublicKey(helper::vector_as_u8_32_array(pub_asym_vec)));
    let sec_keys = (crypto::sign::SecretKey(helper::vector_as_u8_64_array(sec_sign_vec)),
      crypto::asymmetricbox::SecretKey(helper::vector_as_u8_32_array(sec_asym_vec)));
    Ok(AnMpid::new(pub_keys, sec_keys, name))
  }
}

#[test]
fn serialisation_an_mpid() {
  let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
  let (pub_asym_key, sec_asym_key) = crypto::asymmetricbox::gen_keypair();

  let obj_before = AnMpid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType{ id: vec![3u8; 10] });

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: AnMpid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;

  assert_eq!(obj_before.name.id, obj_after.name.id);
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
}
//######################  ##########################################
pub struct Maid {
    public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
    secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
    name: NameType,
}

impl Maid {
  pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
      secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
      nameType: NameType) -> Maid {
    Maid {
      public_keys: public_keys,
      secret_keys: secret_keys,
      name: nameType
    }
  }
}

impl Encodable for Maid {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
    let (crypto::sign::SecretKey(sec_sign_vec), crypto::asymmetricbox::SecretKey(sec_asym_vec)) = self.secret_keys;

    CborTagEncode::new(5483_001, &(
      helper::array_as_vector(&pub_sign_vec),
      helper::array_as_vector(&pub_asym_vec),
      helper::array_as_vector(&sec_sign_vec),
      helper::array_as_vector(&sec_asym_vec),
      &self.name)).encode(e)
  }
}

impl Decodable for Maid {
  fn decode<D: Decoder>(d: &mut D)-> Result<Maid, D::Error> {
    try!(d.read_u64());
    let(pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec, name) = try!(Decodable::decode(d));
    let pub_keys = (crypto::sign::PublicKey(helper::vector_as_u8_32_array(pub_sign_vec)),
            crypto::asymmetricbox::PublicKey(helper::vector_as_u8_32_array(pub_asym_vec)));
    let sec_keys = (crypto::sign::SecretKey(helper::vector_as_u8_64_array(sec_sign_vec)),
            crypto::asymmetricbox::SecretKey(helper::vector_as_u8_32_array(sec_asym_vec)));
    Ok(Maid::new(pub_keys, sec_keys, name))
  }
}

#[test]
fn serialisation_maid() {
  let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
  let (pub_asym_key, sec_asym_key) = crypto::asymmetricbox::gen_keypair();

  let obj_before = Maid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType{ id: vec![3u8; 10] });

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: Maid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;

  assert_eq!(obj_before.name.id, obj_after.name.id);
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
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
pub struct Mpid { 
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
  name: NameType
}

impl Mpid {
  pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
             secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
             nameType: NameType) -> Mpid {
    Mpid {
      public_keys: public_keys,
      secret_keys: secret_keys,
      name: nameType
    }
  }
}

impl Encodable for Mpid {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
    let (crypto::sign::SecretKey(sec_sign_vec), crypto::asymmetricbox::SecretKey(sec_asym_vec)) = self.secret_keys;

    CborTagEncode::new(5483_001, &(
        helper::array_as_vector(&pub_sign_vec),
          helper::array_as_vector(&pub_asym_vec),
          helper::array_as_vector(&sec_sign_vec),
          helper::array_as_vector(&sec_asym_vec),
        &self.name)).encode(e)
  }
}

impl Decodable for Mpid {
  fn decode<D: Decoder>(d: &mut D)-> Result<Mpid, D::Error> {
    try!(d.read_u64());
    let(pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec, name) = try!(Decodable::decode(d));
    let pub_keys = (crypto::sign::PublicKey(helper::vector_as_u8_32_array(pub_sign_vec)),
        crypto::asymmetricbox::PublicKey(helper::vector_as_u8_32_array(pub_asym_vec)));
    let sec_keys = (crypto::sign::SecretKey(helper::vector_as_u8_64_array(sec_sign_vec)),
        crypto::asymmetricbox::SecretKey(helper::vector_as_u8_32_array(sec_asym_vec)));
    Ok(Mpid::new(pub_keys, sec_keys, name))
  }
}

#[test]
fn serialisation_mpid() {
  let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
  let (pub_asym_key, sec_asym_key) = crypto::asymmetricbox::gen_keypair();

  let obj_before = Mpid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType{ id: vec![3u8; 10] });

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: Maid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;

  assert_eq!(obj_before.name.id, obj_after.name.id);
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
}
//######################  ##########################################
pub struct PublicMpid {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  mpid_signature: crypto::sign::Signature,
  owner: NameType,
  signature: crypto::sign::Signature,
  name: NameType
}

impl PublicMpid {
  pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
             mpid_signature: crypto::sign::Signature,
             owner: NameType,
             signature: crypto::sign::Signature,
             name: NameType) -> PublicMpid {
    PublicMpid {
      public_keys: public_keys,
      mpid_signature: mpid_signature,
      owner: owner,
      signature: signature,
      name: name,
    }
  }
}

impl Encodable for PublicMpid {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
    let crypto::sign::Signature(mpid_signature) = self.mpid_signature;
    let crypto::sign::Signature(signature) = self.signature;
    CborTagEncode::new(5483_001, &(
        helper::array_as_vector(&pub_sign_vec),
        helper::array_as_vector(&pub_asym_vec),
        helper::array_as_vector(&mpid_signature),
        &self.owner,
        helper::array_as_vector(&signature),
        &self.name)).encode(e)
  }
}

impl Decodable for PublicMpid {
  fn decode<D: Decoder>(d: &mut D)-> Result<PublicMpid, D::Error> {
    try!(d.read_u64());
    let(pub_sign_vec, pub_asym_vec, mpid_signature, owner, signature, name) = try!(Decodable::decode(d));
    let pub_keys = (crypto::sign::PublicKey(helper::vector_as_u8_32_array(pub_sign_vec)),
        crypto::asymmetricbox::PublicKey(helper::vector_as_u8_32_array(pub_asym_vec)));
    let parsed_mpid_signature = crypto::sign::Signature(helper::vector_as_u8_64_array(mpid_signature));
    let parsed_signature = crypto::sign::Signature(helper::vector_as_u8_64_array(signature));

    Ok(PublicMpid::new(pub_keys, parsed_mpid_signature, owner, parsed_signature, name))
  }
}

#[test]
fn serialisation_public_mpid() {
  let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
  let (pub_asym_key, _) = crypto::asymmetricbox::gen_keypair();

  let obj_before = PublicMpid::new((pub_sign_key, pub_asym_key), crypto::sign::Signature([5u8; 64]), 
    NameType{ id: vec![5u8; 10] }, crypto::sign::Signature([5u8; 64]), NameType{ id: vec![3u8; 10] });

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: PublicMpid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::Signature(mpid_signature_before), crypto::sign::Signature(mpid_signature_after)) = &(obj_before.mpid_signature, obj_after.mpid_signature);
  let &(crypto::sign::Signature(signature_before), crypto::sign::Signature(signature_after)) = &(obj_before.signature, obj_after.signature);

  assert_eq!(obj_before.name.id, obj_after.name.id);
  assert_eq!(obj_before.owner.id, obj_after.owner.id);
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert!(helper::compare_arr_u8_64(&mpid_signature_before, &mpid_signature_after));
  assert!(helper::compare_arr_u8_64(&signature_before, &signature_after));
}

/// Placeholder doc test
pub fn always_true() -> bool { true }
