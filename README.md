# maidsafe_types

|Crate|Travis|Appveyor|Coverage|
|:------:|:-------:|:-------:|:-------:|
|[![](http://meritbadge.herokuapp.com/maidsafe_types)](https://crates.io/crates/maidsafe_types)|[![Build Status](https://travis-ci.org/maidsafe/maidsafe_types.svg?branch=master)](https://travis-ci.org/maidsafe/maidsafe_types)|[![Build status](https://ci.appveyor.com/api/projects/status/bxjlrqhqdg3dc5y8/branch/master?svg=true)](https://ci.appveyor.com/project/dirvine/maidsafe-types-pgsk8/branch/master)|[![Coverage Status](https://coveralls.io/repos/maidsafe/maidsafe_types/badge.svg)](https://coveralls.io/r/maidsafe/maidsafe_types)|

| [ API Documentation](http://maidsafe.github.io/maidsafe_types/) | [MaidSafe System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe web site](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |


###Pre-requisite:
libsodium is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Thus, install sodium by following the instructions [here](http://doc.libsodium.org/installation/README.html).

For windows, download and use the [prebuilt mingw library](https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-mingw.tar.gz).
Extract and place the libsodium.a file in "bin\x86_64-pc-windows-gnu" for 64bit System or "bin\i686-pc-windows-gnu" for a 32bit system.

#Todo
- [ ] remove name from types if it is possible to obtain it from other fields
- [ ] involve tag in signature creations. tests to be changed to reflect this
- [ ] add public key of the signing key into the dependent id packets to enable in place validation. This should be part of the signature creation
- [ ] add SafeCoin entry type which should have i) owner, ii) previous owner and iii) a signature created by previous owner to verify the transaction approved by him. A tag also is required for indicating type is SafeCoin, which will be part of the SafeCoin the entry associated to.
- [ ] Remove maid_signature and mpid_signature from PublicMaid and PublicAnMaid
- [ ] Confirm all signatures and types conform to the drawn representation of the types
