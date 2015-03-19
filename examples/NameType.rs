extern crate "rustc-serialize" as rustc_serialize;
extern crate maidsafe_types;
extern crate cbor;
use maidsafe_types::NameType;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

// Example show cases how to carete and get value from a NameType
#[allow(unused_variables)]
fn main() {
	// Creating a NameType
	let name_type = NameType([3u8; 64]);
	// De-Referencing id value from NameType
	let NameType(id) = name_type;
	//	Encode data
	let mut enc = cbor::Encoder::from_memory();
	enc.encode(&[&name_type]).unwrap();
	//	Decode
	let mut dec = cbor::Decoder::from_bytes(enc.as_bytes());
	let obj_after: NameType = dec.decode().next().unwrap().unwrap();
}