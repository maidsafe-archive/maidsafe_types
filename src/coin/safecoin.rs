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

use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use helper::*;
use routing::NameType;
use routing::sendable::Sendable;
use routing::types::Signature;
use std::fmt;
// use sodiumoxide::crypto::sign::{SecretKey, sign_detached};
use TypeTag;

/// TypeTag for SafeCoin
#[derive(Clone)]
pub struct SafeCoinTypeTag;

impl TypeTag for SafeCoinTypeTag {
    fn type_tag(&self) -> u64 {
        return 256;
    }
}

/// SafeCoin
#[derive(Clone)]
pub struct SafeCoin {
    type_tag: SafeCoinTypeTag,
    name: NameType,
    owners: Vec<NameType>,
    previous_owners: Vec<NameType>,
    signatures: Vec<Signature>
}

impl SafeCoin {
    /// Construct using new()
    pub fn new(name: NameType, owners: Vec<NameType>, signatures: Vec<Signature>) -> SafeCoin {
        SafeCoin { type_tag: SafeCoinTypeTag,
                   name: name,
                   owners: owners.clone(),
                   previous_owners: owners,
                   signatures: signatures
                 }
    }
}

impl Sendable for SafeCoin {
    fn name(&self) -> NameType {
        self.name.clone()
    }

    fn type_tag(&self) -> u64 {
        self.type_tag.type_tag().clone()
    }

    fn serialised_contents(&self) -> Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, _: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl PartialEq for SafeCoin {
    fn eq(&self, other: &SafeCoin) -> bool {
        &self.type_tag.type_tag() == &other.type_tag.type_tag() &&
        self.name == other.name &&
        self.owners == other.owners &&
        self.previous_owners == other.previous_owners &&
        self.signatures == other.signatures
    }
}

impl fmt::Debug for SafeCoin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SafeCoin {{ type_tag:{:?}, name:{:?}, owners:{:?}, previous_owners:{:?}, signatures:{:?}}}",
            self.type_tag.type_tag(), self.name, self.owners, self.previous_owners, self.signatures)
    }
}

impl Encodable for SafeCoin {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        CborTagEncode::new(5483_003, &(&self.name, &self.owners, &self.previous_owners, &self.signatures)).encode(e)
    }
}

impl Decodable for SafeCoin {
    fn decode<D: Decoder>(d: &mut D) -> Result<SafeCoin, D::Error> {
        try!(d.read_u64());
        let (name, owners, previous_owners, signatures) = try!(Decodable::decode(d));
        let safecoin = SafeCoin { type_tag: SafeCoinTypeTag,
                                  name: name,
                                  owners: owners,
                                  previous_owners: previous_owners,
                                  signatures: signatures
                                };
        Ok(safecoin)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use routing::NameType;
    use routing::types::{vector_as_u8_64_array, generate_random_vec_u8};
    use routing::types::Signature;
    use sodiumoxide::crypto::sign;
    use routing::sendable::Sendable;
    use Random;

    impl Random for SafeCoin {
        fn generate_random() -> SafeCoin {
            let name = NameType::new(vector_as_u8_64_array(generate_random_vec_u8(64)));
            let mut owners = Vec::<NameType>::new();
            owners.push(NameType::new(vector_as_u8_64_array(generate_random_vec_u8(64))));
            let mut previous_owners = Vec::<NameType>::new();
            previous_owners.push(NameType::new(vector_as_u8_64_array(generate_random_vec_u8(64))));
            let mut signatures = Vec::<Signature>::new();
            signatures.push(Signature::new(sign::Signature(vector_as_u8_64_array(generate_random_vec_u8(64)))));

            SafeCoin {
                type_tag: SafeCoinTypeTag,
                name: name,
                owners: owners,
                previous_owners: previous_owners,
                signatures: signatures
            }
        }
    }

    #[test]
    fn create_safecoin() {
        let safecoin = SafeCoin::generate_random();
        assert_eq!(safecoin, safecoin);
        assert_eq!(safecoin.type_tag(), 256u64);
    }
}

