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

extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate cbor;

mod id;
mod common;
mod data;

pub mod traits;
pub mod helper;
pub use common::*;
pub use id::*;
pub use data::*;

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

fn array_as_vector(arr: &[u8]) -> Vec<u8> {
  let mut vector = Vec::new();
  for i in arr.iter() {
    vector.push(*i);
  }
  vector
}

#[derive(PartialEq, Eq, Clone, Debug)]
/// Types of payload that will be exchange among vaults
///     MaidManager : PublicMaid, PublicAnMaid
///     All : Datatype -- ImmutableData, StructuredData
pub enum PayloadTypeTag {
  PublicMaid,
  PublicAnMaid,
  ImmutableData,
  StructuredData,
  Unknown
}

impl Encodable for PayloadTypeTag {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let mut type_tag : &str;
    match *self {
      PayloadTypeTag::PublicMaid => type_tag = "PublicMaid",
      PayloadTypeTag::PublicAnMaid => type_tag = "PublicAnMaid",
      PayloadTypeTag::ImmutableData => type_tag = "ImmutableData",
      PayloadTypeTag::StructuredData => type_tag = "StructuredData",     
      PayloadTypeTag::Unknown => type_tag = "Unknown",
    };
    CborTagEncode::new(5483_100, &(&type_tag)).encode(e)
  }
}

impl Decodable for PayloadTypeTag {
  fn decode<D: Decoder>(d: &mut D)->Result<PayloadTypeTag, D::Error> {
    try!(d.read_u64());
    let mut type_tag : String;
    type_tag = try!(Decodable::decode(d));
    match &type_tag[..] {
      "PublicMaid" => Ok(PayloadTypeTag::PublicMaid),
      "PublicAnMaid" => Ok(PayloadTypeTag::PublicAnMaid),
      "ImmutableData" => Ok(PayloadTypeTag::ImmutableData),
      "StructuredData" => Ok(PayloadTypeTag::StructuredData),
      _ => Ok(PayloadTypeTag::Unknown)
    }
  }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Payload {
  type_tag : PayloadTypeTag,
  payload : Vec<u8>
}

impl Encodable for Payload {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.type_tag, &self.payload)).encode(e)
  }
}

impl Decodable for Payload {
  fn decode<D: Decoder>(d: &mut D)->Result<Payload, D::Error> {
    try!(d.read_u64());
    let (type_tag, payload) = try!(Decodable::decode(d));
    Ok(Payload { type_tag: type_tag, payload: payload })
  }
}

impl Payload {
  pub fn dummy_new(type_tag : PayloadTypeTag) -> Payload {
    Payload { type_tag: type_tag, payload: Vec::<u8>::new() }
  }

  pub fn new<T>(type_tag : PayloadTypeTag, data : &T) -> Payload where T: for<'a> Encodable + Decodable {
    let mut e = cbor::Encoder::from_memory();
    e.encode(&[data]).unwrap();
    Payload { type_tag: type_tag, payload: array_as_vector(e.as_bytes()) }
  }

  pub fn get_data<T>(&self) -> T where T: for<'a> Encodable + Decodable {
    let mut d = cbor::Decoder::from_bytes(&self.payload[..]);
    let obj: T = d.decode().next().unwrap().unwrap();
    obj
  }

  pub fn set_data<T>(&mut self, data: T) where T: for<'a> Encodable + Decodable {
    let mut e = cbor::Encoder::from_memory();
    e.encode(&[&data]).unwrap();
    self.payload = array_as_vector(e.as_bytes())
  }

  pub fn get_type_tag(&self) -> PayloadTypeTag {
    self.type_tag.clone()
  }
}