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

#Todo
- [x] Add all DataTypes for Data Put/Get
- [x] Add Encode/Decode traits for all types (cbor)
- [x] API version 0.0.8
- [ ] Write tests to confirm invariants of all types
- [x] Write tests to confirm serialising and parsing of all types
- [ ] API version 0.1.0
