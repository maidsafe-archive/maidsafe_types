# maidsafe_types

[![](https://img.shields.io/badge/Project%20SAFE-Approved-green.svg)](http://maidsafe.net/applications) [![](https://img.shields.io/badge/License-GPL3-green.svg)](https://github.com/maidsafe/maidsafe_types/blob/master/COPYING)

**Primary Maintainer:**     Brian Smith (brian.smith@maidsafe.net)

|Crate|Linux|Windows|OSX|Coverage|Issues|
|:------:|:-------:|:-------:|:-------:|:-------:|:-------:|
|[![](http://meritbadge.herokuapp.com/maidsafe_types)](https://crates.io/crates/maidsafe_types)|[![Build Status](https://travis-ci.org/maidsafe/maidsafe_types.svg?branch=master)](https://travis-ci.org/maidsafe/maidsafe_types)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=maidsafe_types_win64_status_badge)](http://ci.maidsafe.net:8080/job/maidsafe_types_win64_status_badge/)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=maidsafe_types_osx_status_badge)](http://ci.maidsafe.net:8080/job/maidsafe_types_osx_status_badge/)|[![Coverage Status](https://coveralls.io/repos/maidsafe/maidsafe_types/badge.svg)](https://coveralls.io/r/maidsafe/maidsafe_types)|[![Stories in Ready](https://badge.waffle.io/maidsafe/maidsafe_types.png?label=ready&title=Ready)](https://waffle.io/maidsafe/maidsafe_types)


| [API Documentation - master branch](http://maidsafe.net/maidsafe_types/master) | [SAFE Network System Documention](http://systemdocs.maidsafe.net) | [MaidSafe website](http://maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |
|:------:|:-------:|:-------:|:-------:|

#Overview

The maidsafe_type library defines all types of data stored on maidsafe network. MaidSafe network enables the user of the data to verify the integrity of data, whether it is mutbale or immutable.

## Data

### Immutable Data
On MaidSafe network, most data are represented as Immutable Data. The integrity of the contents of an Immutable Data can be verified by checking the hash of content to be the address on the network where data is stored.

### Structured Data
If data needs to be mutated it is represented as structured data. The structured data can hold a limited history of data updates.

## ID

Id types represent information associated to an identity on the network. The Id types can be secret or public. The secret Id types hold sensitive information and are never stored on network. Each secret Id has a corresponding public Id type which is stored on the network. The secret and public part of the Id are used to offer asymmetric cryptography services.

### Secret Revocation Id Type
Secret revocation Id types are never stored on network. These Id types are used on creation of Public Ids and also they can be used to revoke their corresponding public-private keys if is required.

### Secret Id Type
Similar to revocation Id types, secret Id types are not stored on network. The secret Id types have private and public part of signing and encryption keys associated to an identity.

### Public Id Type
Public Id types represent the public part of the secret Id types and their integrity can be verified by revocation id signed information. Moreover, the address a public id type is located on network is the hash of its contents, which can also be verified.
A public Id type can be revoked by revocation id type, if required. To revoke the public id, the revocation id type sends a signed update request to the public id type. The update is performed to make the hash of the contents not be equal to its address and/or change signature to be not equal to a valid signature. Any further access to the revoked public id type then results in inregrity / validity check.

###Pre-requisite:
libsodium is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Thus, install sodium by following the instructions [here](http://doc.libsodium.org/installation/README.html).

For windows, download and use the [prebuilt mingw library](https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-mingw.tar.gz).
Extract and place the libsodium.a file in "bin\x86_64-pc-windows-gnu" for 64bit System or "bin\i686-pc-windows-gnu" for a 32bit system.

#Todo Items

## [0.2.4]
- [ ] Add MSID type for shared data.
