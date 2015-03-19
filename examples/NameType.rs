extern crate maidsafe_types;
use maidsafe_types::NameType;

fn main() {
	let name_type = NameType([3u8; 64]);
	let NameType(id) = name_type;
	let mut id_vec = Vec::new();
	for i in id.iter() {
		id_vec.push(i);
	}
	println!("{:?}", id_vec);
}