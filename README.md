# maidsafe_types

Travis build status

[![Build Status](https://travis-ci.org/dirvine/maidsafe_types.svg?branch=master)](https://travis-ci.org/dirvine/maidsafe_types)

Appveyor build status (Windows)

[![Build status](https://ci.appveyor.com/api/projects/status/jsuo65sa631h0kav?svg=true)](https://ci.appveyor.com/project/dirvine/maidsafe-types)


[Documentation](http://dirvine.github.io/maidsafe_types/)

###Pre-requisite:
libsodium is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Thus, install sodium by following the instructions [here](http://doc.libsodium.org/installation/README.html).

For windows, download and use the [prebuilt mingw library](https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-mingw.tar.gz). Extract and place the libsodium.a file in the "third_party_libs" folder in the Project Root.

#Todo
- [x] Add all DataTypes for Data Put/Get 
- [ ] Add Encode/Decode traits for all types (cbor)
- [ ] Write tests to confirm invariants of all types
- [ ] Write tests to confirm serialising and parsing of all types
- [ ] API version 0.1.0
