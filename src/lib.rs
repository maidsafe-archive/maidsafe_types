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

#![crate_name = "maidsafe_types"]
#![crate_type = "lib"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/maidsafe/maidsafe_types/")]

#![forbid(bad_style, warnings)]

#![deny(deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints, // unsafe_code,
        unsigned_negation, unused, unused_allocation, unused_attributes, unused_comparisons,
        unused_features, unused_parens, while_true)]

#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, variant_size_differences)]

//! #Safe Network Data Types
//!
//! This library implements the fundimental data types used on the SAFE Network
//! The serialisation mechnism used is ``cbor``` which is an IETF Rfc [7049](http://tools.ietf.org/html/rfc7049)
//! for serialising data and is an attempt to upgrade messagepack and ASN.1
//! On disk serialisation is [JSON](https://www.ietf.org/rfc/rfc4627.txt)
//!
//! [Project github page](https://github.com/maidsafe/maidsafe_types)

extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate cbor;
extern crate routing;

/// Helper provides helper functions for array to vector conversions and vice versa
#[macro_use]
pub mod helper;
/// Holds the structs for Id related Types such as Maid, AnMaid, Mpid, etc
pub mod id;
/// Holds the structs related to data such as ImmutableData/Backup/Sacrificial and StructuredData
pub mod data;
/// SafeCoin related details
pub mod coin;

pub use id::{RevocationIdType, IdType, PublicIdType};
pub use data::{ImmutableData, ImmutableDataBackup, ImmutableDataSacrificial, StructuredData};

/// TypeTag trait
pub trait TypeTag {
    /// returns type tag
    fn type_tag(&self) -> u64;
}

/// Interface to IdTypes
pub trait IdTypeTags {
    /// returns tag type for revocation id type
    fn revocation_id_type_tag(&self) -> u64;
    /// returns tag type for id type
    fn id_type_tag(&self) -> u64;
    /// returns tag type for public id type
    fn public_id_type_tag(&self) -> u64;
}

/// TypeTags for Maid type variants
pub struct MaidTypeTags;

/// TypeTags for Maid type variants
pub struct MpidTypeTags;

impl IdTypeTags for MaidTypeTags {
    /// returns tag type for AnMaid type
    fn revocation_id_type_tag(&self) -> u64 { data_tags::AN_MAID_TAG }
    /// returns tag type for Maid type
    fn id_type_tag(&self) -> u64 { data_tags::MAID_TAG }
    /// returns tag type for PublicMaid type
    fn public_id_type_tag(&self) -> u64 { data_tags::PUBLIC_MAID_TAG }
}

impl IdTypeTags for MpidTypeTags {
    /// returns tag type for AnMpid type
    fn revocation_id_type_tag(&self) -> u64 { data_tags::AN_MPID_TAG }
    /// returns tag type for Mpid type
    fn id_type_tag(&self) -> u64 { data_tags::MPID_TAG }
    /// returns tag type for PublicMpid type
    fn public_id_type_tag(&self) -> u64 { data_tags::PUBLIC_MPID_TAG }
}

/// Random trait is used to generate random instances.
/// Used in the test mod
pub trait Random {
    /// Generates a random instance and returns the created random instance
    fn generate_random() -> Self;
}
/// Crypto Error types
pub enum CryptoError {
    /// Unknown Error Type
    Unknown
}

/// All Maidsafe tagging should offset from this
pub const MAIDSAFE_TAG: u64 = 5483_000;

/// All Maidsafe Data tags
#[allow(missing_docs)]
pub mod data_tags {
    pub const MAIDSAFE_DATA_TAG: u64 = ::MAIDSAFE_TAG + 100;

    pub const IMMUTABLE_DATA_TAG: u64             = MAIDSAFE_DATA_TAG + 1;
    pub const IMMUTABLE_DATA_BACKUP_TAG: u64      = MAIDSAFE_DATA_TAG + 2;
    pub const IMMUTABLE_DATA_SACRIFICIAL_TAG: u64 = MAIDSAFE_DATA_TAG + 3;
    pub const STRUCTURED_DATA_TAG: u64            = MAIDSAFE_DATA_TAG + 4;
    pub const AN_MPID_TAG: u64                    = MAIDSAFE_DATA_TAG + 5;
    pub const AN_MAID_TAG: u64                    = MAIDSAFE_DATA_TAG + 6;
    pub const MAID_TAG: u64                       = MAIDSAFE_DATA_TAG + 7;
    pub const MPID_TAG: u64                       = MAIDSAFE_DATA_TAG + 8;
    pub const PUBLIC_MAID_TAG: u64                = MAIDSAFE_DATA_TAG + 9;
    pub const PUBLIC_MPID_TAG: u64                = MAIDSAFE_DATA_TAG + 10;
}

mod test_utils;
