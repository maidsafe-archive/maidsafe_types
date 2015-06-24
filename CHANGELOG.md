# MaidSafe Types - Change Log

## [0.2.0]

- [#78](https://github.com/maidsafe/maidsafe_types/pull/78) make Payload Sendable -- patch

## [0.1.52]
- Add account type tags for PayLoad.

## [0.1.51]
- Update version in line with routing.

## [0.1.5]
- [MAID-1036](https://maidsafe.atlassian.net/browse/MAID-1036) Add SafeCoin type with entries i) type tag ii) name iii) owners iv) previous owners, and v) signatures. Implement and test Sendable, Encodable, Decodable, PartialEq and fmt::Debug traits for SafeCoin type. Merges [MAID-1044](https://maidsafe.atlassian.net/browse/MAID-1044) to a single unit of work.
- [MAID-1119](https://maidsafe.atlassian.net/browse/MAID-1036) Implement TypeTag for StructuredData type.
- [MAID-1056](https://maidsafe.atlassian.net/browse/MAID-1056) Write tests to confirm invariants of all types

## [0.1.4]
- Remove anonymous public types
  - [MAID-1053](https://maidsafe.atlassian.net/browse/MAID-1053) Anonymous public types to be included as part of the body of the public type
  - [MAID-1058](https://maidsafe.atlassian.net/browse/MAID-1058) Change tests to reflect the above task
- Modifications to Id types
  - [MAID-1029](https://maidsafe.atlassian.net/browse/MAID-1029) Remove name from types to enhance type invariance
  - [MAID-1035](https://maidsafe.atlassian.net/browse/MAID-1035) Add a member of signature type to Id types. The signature in pure keys is sign_using_own_private_key(public keys + type tag). And in dependent keys, is sign_using_owner_private_key(public keys + owner public key + type tag)
  - [MAID-1041](https://maidsafe.atlassian.net/browse/MAID-1041) Remove maid_signature and mpid_signature from PublicMaid and PublicAnMaid
- [MAID-1115](https://maidsafe.atlassian.net/browse/MAID-1115) Update StructuredData
- [MAID-1116](https://maidsafe.atlassian.net/browse/MAID-1116) Create 2 new ImmutableData types

## [0.0.0 -  0.1.3]
- Add all DataTypes for Data Put/Get
- Add Encode/Decode traits for all types (cbor)
- API version 0.0.8
- Write tests to confirm serialising and parsing of all types
