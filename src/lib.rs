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
//! Types of data functors and messages for MaidSafe secure Autonomous networks.
//! This crate is of no use to anyone as a stand alone crate. It is a module that is 
//! specialised, but it is a crate to make version handling and distribution easier. 

extern crate "rustc-serialize" as rustc_serialize;

struct NameType ( [u8; 64] );

enum DataTypes {
ImmutableData,
MutableData,
  
}

trait DataTraits {
fn get_type_id(&self)->u32;
fn parse(serialised_data: Vec<u8>) -> Self;
fn get_name(&self)->&NameType;
fn validate(&self, public_key: Option<NameType>)->bool;
}

impl DataTraits for ImmutableData {
  fn get_type_id(&self)->u32 {
    DataTypes::ImmutableData as u32
  }
  fn parse(serialised_data: Vec<u8>) -> ImmutableData {
  unimplemented!();
  /*  ImmutableData { name : [u8, ..64], value: vec![1,2,3] }  */
  }
  fn get_name(&self)->&NameType {
    &self.name
  }
  fn validate(&self, public_key: Option<NameType>)->bool {
    true // FIXME Hash value and check name is 
  }  
}

/* #[derive(PartialEq, Eq, PartialOrd, Ord, RustcEncodable, RustcDecodable)]  */
struct ImmutableData {
name: NameType,
value: Vec<u8>,
}

/* #[derive(PartialEq, Eq, PartialOrd, Ord, RustcEncodable, RustcDecodable)]  */
struct MutableData {
name: NameType,
value: Vec<u8>,
validation_token: Option<u8>
}

/* #[derive(PartialEq, Eq, PartialOrd, Ord, RustcEncodable, RustcDecodable)]  */
struct Data {
  data_type : DataTypes,
  serialised_data : Vec<u8>,
}

fn parse_serialised_data_type( serialised_data : Vec<u8>) -> DataTypes {
  unimplemented!();
  }



























/// Placeholder doc test
pub fn always_true() -> bool { true }

#[test]
fn it_works() {
 assert_eq!(always_true(), true);
}
