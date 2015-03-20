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

/// NameType struct
///
/// #Examples
///
/// ```
/// // NameType Struct can be created using the new function by passing, id as its parameter.
/// let name_type = maidsafe_types::NameType::new([7u8; 64]);
/// let id: [u8; 64] = name_type.get_id();
/// //
/// let name_type = maidsafe_types::NameType([0u8; 64]);
///
/// // de-reference id value from the NameType
/// let maidsafe_types::NameType(id) = name_type;
/// ```
pub struct NameType(pub [u8; 64] );

impl NameType {

  pub fn new(id: [u8;64]) -> NameType {
    NameType(id)
  }

  pub fn get_id(&self) -> [u8;64] {
    let NameType(id) = *self;
    id
  }
}

impl Encodable for NameType {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let NameType(id) = *self;
    CborTagEncode::new(5483_000, &(helper::array_as_vector(&id))).encode(e)
  }
}

impl Decodable for NameType {
  fn decode<D: Decoder>(d: &mut D)->Result<NameType, D::Error> {
    try!(d.read_u64());
    let id = try!(Decodable::decode(d));
    Ok(NameType(helper::vector_as_u8_64_array(id)))
  }
}
#[test]
fn serialisation_name_type() {
  let obj_before = NameType([99u8; 64]);
  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: NameType = d.decode().next().unwrap().unwrap();
  assert!(helper::compare_arr_u8_64(&obj_before.get_id(), &obj_after.get_id()));
}

/// temporary code to test passing a trait to routing to query and possible decode types or
/// at least soem info routing needs which is access to these functions on data types
/// These traits will be defined in routing and require to be avauilable for any type
/// passed to routing, refresh / account transfer is optional
/// The name will let routing know its an NaeManager and the owner will allow routing to hash
/// the requsters id with this name (by hashing the requesters id) for put and post messages

pub trait RoutingTrait {
  fn get_name(&self)->&NameType;
  fn get_owner(&self)->&Vec<u8>;
  fn refresh(&self)->bool { false } // is this an account transfer type
  fn merge(&self)->bool { false } // how do we merge these
}

// ################## Immutable Data ##############################################
// [TODO]: Implement validate() for all types, possibly get_name() should always check invariants - 2015-03-14 09:03pm
/// ImmutableData
///
/// #Examples
///
/// ```
/// // Create an ImmutableData using the new function.
/// let immutable_data = maidsafe_types::ImmutableData::new(maidsafe_types::NameType([0u8; 64]),  vec![99u8; 10]);
/// // Retrieving values
/// let ref name_type = immutable_data.get_name();
/// let ref value = immutable_data.get_value();
/// ```
///
pub struct ImmutableData {
  name: NameType,
  value: Vec<u8>,
}

impl RoutingTrait for ImmutableData {
  fn get_name(&self)->&NameType {
    &self.name
  }

  fn get_owner(&self)->&Vec<u8> {
    &self.value
  }
}

impl ImmutableData {
  #[allow(dead_code)]
  pub fn new(name: NameType, value: Vec<u8>) -> ImmutableData {
    ImmutableData {
      name: name,
      value: value,
    }
  }

  pub fn get_name(&self) -> &NameType {
    &self.name
  }

  pub fn get_value(&self) -> &Vec<u8> {
    &self.value
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
    Ok(ImmutableData::new(name, value))
  }
}

#[test]
fn serialisation_immutable_data() {
  let obj_before = ImmutableData::new(NameType([3u8; 64]), vec![99u8; 10]);
  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: ImmutableData = d.decode().next().unwrap().unwrap();
  let id_before = obj_before.get_name().get_id();
  let id_after = obj_after.get_name().get_id();
  assert!(helper::compare_arr_u8_64(&id_before, &id_after));
  assert_eq!(obj_before.get_value(), obj_after.get_value());
}

//###################### Structured Data ##########################################
/// StructuredData
///
/// #Examples
///
/// ```
/// let mut value = Vec::new();
/// value.push(Vec::new());
/// match value.last_mut() {
///   Some(v) => v.push(maidsafe_types::NameType([7u8; 64])),
///   None => ()
/// }
/// // Create a StructuredData
/// let structured_data = maidsafe_types::StructuredData::new((maidsafe_types::NameType([3u8; 64]), maidsafe_types::NameType([5u8; 64])), value);
/// // Retrieving the values
/// let (maidsafe_types::NameType(name), maidsafe_types::NameType(owner)) = *structured_data.get_name();
/// let ref value = structured_data.get_value();
/// ```
///
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
  pub fn get_name(&self) -> &(NameType, NameType) {
    &self.name
  }
  pub fn get_value(&self) -> &Vec<Vec<NameType>> {
    &self.value
  }
}

impl Encodable for StructuredData {
  fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
    CborTagEncode::new(5483_002, &(&self.name, &self.value)).encode(e)
  }
}

impl Decodable for StructuredData {
  fn decode<D: Decoder>(d: &mut D) -> Result<StructuredData, D::Error> {
    try!(d.read_u64());
    let (name, value) = try!(Decodable::decode(d));
    Ok(StructuredData::new(name, value))
  }
}

#[test]
fn serialisation_structured_data() {
  let mut value = Vec::new();
  value.push(Vec::new());
  match value.last_mut() {
    Some(v) => v.push(NameType([7u8; 64])),
    None => ()
  }
  let obj_before = StructuredData::new((NameType([3u8; 64]), NameType([5u8; 64])), value);
  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: StructuredData = d.decode().next().unwrap().unwrap();

  let (NameType(name_before_0), NameType(name_before_1)) = *obj_before.get_name();
  let (NameType(name_after_0), NameType(name_after_1)) = *obj_after.get_name();
  let NameType(value_before) = obj_before.get_value()[0][0];
  let NameType(value_after) = obj_after.get_value()[0][0];
  assert!(helper::compare_arr_u8_64(&name_before_0, &name_after_0));
  assert!(helper::compare_arr_u8_64(&name_before_1, &name_after_1));
  assert!(helper::compare_arr_u8_64(&value_before, &value_after));
}

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
/// let (pub_sign_key, sec_sign_key) = sodiumoxide::crypto::sign::gen_keypair();
/// let (pub_asym_key, sec_asym_key) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
/// // Create AnMaid
/// let an_maid = maidsafe_types::AnMaid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), maidsafe_types::NameType([3u8; 64]));
/// // Retrieving the values
/// let ref publicKeys = an_maid.get_public_keys();
/// let ref secretKeys = an_maid.get_secret_keys();
/// let ref name = an_maid.get_name();
/// ```
///
pub struct AnMaid {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
  name: NameType,
}

impl AnMaid {
  pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
             secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
             name_type: NameType) -> AnMaid {
    AnMaid {
      public_keys: public_keys,
      secret_keys: secret_keys,
      name: name_type
    }
  }
  pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
    &self.public_keys
  }
  pub fn get_secret_keys(&self) -> &(crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey) {
    &self.secret_keys
  }
  pub fn get_name(&self) -> &NameType {
    &self.name
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
  let obj_before = AnMaid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType([3u8; 64]));
  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: AnMaid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = obj_before.get_public_keys();
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = obj_after.get_public_keys();
  let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = obj_before.get_secret_keys();
  let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = obj_after.get_secret_keys();
  let NameType(name_before) = *obj_before.get_name();
  let NameType(name_after) = *obj_after.get_name();
  assert!(helper::compare_arr_u8_64(&name_before, &name_after));
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert!(helper::compare_arr_u8_64(&sec_sign_arr_before, &sec_sign_arr_after));
  assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
}

//######################  PublicAnMaid ##########################################
/// PublicAnMaid
///
/// #Examples
/// ```
/// extern crate sodiumoxide;
/// extern crate maidsafe_types;
/// // Generating publick and secret keys using sodiumoxide
/// let (pub_sign_key, _) = sodiumoxide::crypto::sign::gen_keypair();
/// let (pub_asym_key, _) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
/// // Create AnMaid
/// let pub_an_maid = maidsafe_types::PublicAnMaid::new((pub_sign_key, pub_asym_key), sodiumoxide::crypto::sign::Signature([5u8; 64]), maidsafe_types::NameType([99u8; 64]));
/// // Retrieving the values
/// let ref publicKeys = pub_an_maid.get_public_keys();
/// let ref signature = pub_an_maid.get_signature();
/// let ref name = pub_an_maid.get_name();
/// ```
///
pub struct PublicAnMaid {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  signature: crypto::sign::Signature,
  name: NameType,
}

impl PublicAnMaid {
  pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
             signature: crypto::sign::Signature,
             name: NameType) -> PublicAnMaid {
      PublicAnMaid {
        public_keys: public_keys,
        signature: signature,
        name: name
      }
  }
  pub fn get_public_keys(&self) -> &(crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey) {
    &self.public_keys
  }
  pub fn get_signature(&self) -> &crypto::sign::Signature {
    &self.signature
  }
  pub fn get_name(&self) -> &NameType {
    &self.name
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
  let (pub_sign_key, _) = crypto::sign::gen_keypair();
  let (pub_asym_key, _) = crypto::asymmetricbox::gen_keypair();

  let obj_before = PublicAnMaid::new((pub_sign_key, pub_asym_key),
  crypto::sign::Signature([5u8; 64]), NameType([99u8; 64]));

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: PublicAnMaid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = obj_before.get_public_keys();
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = obj_after.get_public_keys();
  let &crypto::sign::Signature(signature_arr_before) = obj_before.get_signature();
  let &crypto::sign::Signature(signature_arr_after) = obj_after.get_signature();
  let NameType(name_before) = *obj_before.get_name();
  let NameType(name_after) = *obj_after.get_name();
  assert!(helper::compare_arr_u8_64(&name_before, &name_after));
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
             name_type: NameType) -> AnMpid {
    AnMpid {
      public_keys: public_keys,
      secret_keys: secret_keys,
      name: name_type
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

  let obj_before = AnMpid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType([3u8; 64]));

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: AnMpid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;
  let NameType(name_before) = obj_before.name;
  let NameType(name_after) = obj_after.name;

  assert!(helper::compare_arr_u8_64(&name_before, &name_after));
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert!(helper::compare_arr_u8_64(&sec_sign_arr_before, &sec_sign_arr_after));
  assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
}

//###################### MAID ##########################################
pub struct Maid {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
  name: NameType,
}

impl Maid {
  pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
             secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
             name_type: NameType) -> Maid {
    Maid {
      public_keys: public_keys,
      secret_keys: secret_keys,
      name: name_type
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

  let obj_before = Maid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType([3u8; 64]));

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: Maid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;
  let NameType(name_before) = obj_before.name;
  let NameType(name_after) = obj_after.name;

  assert!(helper::compare_arr_u8_64(&name_before, &name_after));
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert!(helper::compare_arr_u8_64(&sec_sign_arr_before, &sec_sign_arr_after));
  assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
}

//###################### PublicMaid ##########################################
pub struct PublicMaid {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  maid_signature: crypto::sign::Signature,
  owner: NameType,
  signature: crypto::sign::Signature,
  name: NameType
}

impl PublicMaid {
  pub fn new(public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
             maid_signature: crypto::sign::Signature,
             owner: NameType,
             signature: crypto::sign::Signature,
             name: NameType) -> PublicMaid {
    PublicMaid {
      public_keys: public_keys,
      maid_signature: maid_signature,
      owner: owner,
      signature: signature,
      name: name,
    }
  }
}

impl Encodable for PublicMaid {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let (crypto::sign::PublicKey(pub_sign_vec), crypto::asymmetricbox::PublicKey(pub_asym_vec)) = self.public_keys;
    let crypto::sign::Signature(maid_signature) = self.maid_signature;
    let crypto::sign::Signature(signature) = self.signature;
    CborTagEncode::new(5483_001, &(
        helper::array_as_vector(&pub_sign_vec),
        helper::array_as_vector(&pub_asym_vec),
        helper::array_as_vector(&maid_signature),
        &self.owner,
        helper::array_as_vector(&signature),
        &self.name)).encode(e)
  }
}

impl Decodable for PublicMaid {
  fn decode<D: Decoder>(d: &mut D)-> Result<PublicMaid, D::Error> {
    try!(d.read_u64());
    let(pub_sign_vec, pub_asym_vec, maid_signature, owner, signature, name) = try!(Decodable::decode(d));
    let pub_keys = (crypto::sign::PublicKey(helper::vector_as_u8_32_array(pub_sign_vec)),
        crypto::asymmetricbox::PublicKey(helper::vector_as_u8_32_array(pub_asym_vec)));
    let parsed_maid_signature = crypto::sign::Signature(helper::vector_as_u8_64_array(maid_signature));
    let parsed_signature = crypto::sign::Signature(helper::vector_as_u8_64_array(signature));

    Ok(PublicMaid::new(pub_keys, parsed_maid_signature, owner, parsed_signature, name))
  }
}

#[test]
fn serialisation_public_maid() {
  let (pub_sign_key, _) = crypto::sign::gen_keypair();
  let (pub_asym_key, _) = crypto::asymmetricbox::gen_keypair();

  let obj_before = PublicMaid::new((pub_sign_key, pub_asym_key), crypto::sign::Signature([5u8; 64]),
    NameType([5u8; 64]), crypto::sign::Signature([5u8; 64]), NameType([3u8; 64]));

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: PublicMaid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::Signature(maid_signature_before), crypto::sign::Signature(maid_signature_after)) = &(obj_before.maid_signature, obj_after.maid_signature);
  let &(crypto::sign::Signature(signature_before), crypto::sign::Signature(signature_after)) = &(obj_before.signature, obj_after.signature);
  let NameType(name_before) = obj_before.name;
  let NameType(name_after) = obj_after.name;
  let NameType(owner_before) = obj_after.owner;
  let NameType(owner_after) = obj_after.owner;

  assert!(helper::compare_arr_u8_64(&name_before, &name_after));
  assert!(helper::compare_arr_u8_64(&owner_before, &owner_after));
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert!(helper::compare_arr_u8_64(&maid_signature_before, &maid_signature_after));
  assert!(helper::compare_arr_u8_64(&signature_before, &signature_after));
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
             name_type: NameType) -> Mpid {
    Mpid {
      public_keys: public_keys,
      secret_keys: secret_keys,
      name: name_type
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

  let obj_before = Mpid::new((pub_sign_key, pub_asym_key), (sec_sign_key, sec_asym_key), NameType([3u8; 64]));

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: Maid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_before), crypto::asymmetricbox::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
  let &(crypto::sign::SecretKey(sec_sign_arr_after), crypto::asymmetricbox::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;
  let NameType(name_before) = obj_before.name;
  let NameType(name_after) = obj_after.name;

  assert!(helper::compare_arr_u8_64(&name_before, &name_after));
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert!(helper::compare_arr_u8_64(&sec_sign_arr_before, &sec_sign_arr_after));
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
  let (pub_sign_key, _) = crypto::sign::gen_keypair();
  let (pub_asym_key, _) = crypto::asymmetricbox::gen_keypair();

  let obj_before = PublicMpid::new((pub_sign_key, pub_asym_key), crypto::sign::Signature([5u8; 64]), 
    NameType([5u8; 64]), crypto::sign::Signature([5u8; 64]), NameType([3u8; 64]));

  let mut e = cbor::Encoder::from_memory();
  e.encode(&[&obj_before]).unwrap();

  let mut d = cbor::Decoder::from_bytes(e.as_bytes());
  let obj_after: PublicMpid = d.decode().next().unwrap().unwrap();

  let &(crypto::sign::PublicKey(pub_sign_arr_before), crypto::asymmetricbox::PublicKey(pub_asym_arr_before)) = &obj_before.public_keys;
  let &(crypto::sign::PublicKey(pub_sign_arr_after), crypto::asymmetricbox::PublicKey(pub_asym_arr_after)) = &obj_after.public_keys;
  let &(crypto::sign::Signature(mpid_signature_before), crypto::sign::Signature(mpid_signature_after)) = &(obj_before.mpid_signature, obj_after.mpid_signature);
  let &(crypto::sign::Signature(signature_before), crypto::sign::Signature(signature_after)) = &(obj_before.signature, obj_after.signature);
  let NameType(name_before) = obj_before.name;
  let NameType(name_after) = obj_after.name;
  let NameType(owner_before) = obj_after.owner;
  let NameType(owner_after) = obj_after.owner;

  assert!(helper::compare_arr_u8_64(&name_before, &name_after));
  assert!(helper::compare_arr_u8_64(&owner_before, &owner_after));
  assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
  assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
  assert!(helper::compare_arr_u8_64(&mpid_signature_before, &mpid_signature_after));
  assert!(helper::compare_arr_u8_64(&signature_before, &signature_after));
}
