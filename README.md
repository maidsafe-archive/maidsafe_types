# maidsafe_types

**Primary Maintainer:**     Mahmoud Moadeli (mmoadeli@maidsafe.net)

|Crate|Travis|Windows|OSX|Coverage|
|:------:|:-------:|:-------:|:-------:|:-------:|
|[![](http://meritbadge.herokuapp.com/maidsafe_types)](https://crates.io/crates/maidsafe_types)|[![Build Status](https://travis-ci.org/maidsafe/maidsafe_types.svg?branch=master)](https://travis-ci.org/maidsafe/maidsafe_types)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=maidsafe_types_win64_status_badge)](http://ci.maidsafe.net:8080/job/maidsafe_types_win64_status_badge/)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=maidsafe_types_osx_status_badge)](http://ci.maidsafe.net:8080/job/maidsafe_types_osx_status_badge/)|[![Coverage Status](https://coveralls.io/repos/maidsafe/maidsafe_types/badge.svg)](https://coveralls.io/r/maidsafe/maidsafe_types)|

| [ API Documentation](http://maidsafe.github.io/maidsafe_types/) | [MaidSafe System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe web site](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |


###Pre-requisite:
libsodium is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Thus, install sodium by following the instructions [here](http://doc.libsodium.org/installation/README.html).

For windows, download and use the [prebuilt mingw library](https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-mingw.tar.gz).
Extract and place the libsodium.a file in "bin\x86_64-pc-windows-gnu" for 64bit System or "bin\i686-pc-windows-gnu" for a 32bit system.

#Todo Items

## [0.1.4]
- [ ] Remove anonymous public types
  - [ ] [MAID-1053](https://maidsafe.atlassian.net/browse/MAID-1053) Anonymous public types to be included as part of the body of the public type
  - [ ] [MAID-1058](https://maidsafe.atlassian.net/browse/MAID-1058) Change tests to reflect the above task

- [ ] Modifications to Id types
  - [ ] [MAID-1029](https://maidsafe.atlassian.net/browse/MAID-1029) Remove name from types to enhance type invariance
  - [ ] [MAID-1035](https://maidsafe.atlassian.net/browse/MAID-1035) Add a member of signature type to Id types. The signature in pure keys is sign_using_own_private_key(public keys + type tag). And in dependent keys, is sign_using_owner_private_key(public keys + owner public key + type tag)
  - [ ] [MAID-1041](https://maidsafe.atlassian.net/browse/MAID-1041) Remove maid_signature and mpid_signature from PublicMaid and PublicAnMaid
  - [ ] [MAID-1056](https://maidsafe.atlassian.net/browse/MAID-1056) Write tests to confirm invariants of all types

- [ ] SafeCoin type
  - [ ] [MAID-1036](https://maidsafe.atlassian.net/browse/MAID-1036) add SafeCoin entry type which should have i) owners, ii) previous owners and iii) signatures created by            previous owners to verify the transaction approved by them, and iv) Type tag
  - [ ] [MAID-1044](https://maidsafe.atlassian.net/browse/MAID-1044) Implement and test Sendable, Encodable, Decodable, PartialEq and fmt::Debug traits for SafeCoin Type
  
- [ ] Visual presentation
  - [ ] [MAID-1047](https://maidsafe.atlassian.net/browse/MAID-1047) Provide Shona with modifications required in Types representations
  - [ ] [MAID-1073](https://maidsafe.atlassian.net/browse/MAID-1073) Come up with intiuitive representation of types

