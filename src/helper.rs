pub fn array_as_vector(arr: &[u8]) -> Vec<u8> {
  let mut vector = Vec::new();
  for i in arr.iter() {
    vector.push(*i);
  }
  vector
}

pub fn vector_as_u8_32_array(vector: Vec<u8>) -> [u8;32] {
  let mut arr = [0u8;32];
  for i in (0..32) {
    arr[i] = vector[i];
  }
  arr
}

pub fn vector_as_u8_64_array(vector: Vec<u8>) -> [u8;64] {
  let mut arr = [0u8;64];
  for i in (0..64) {
    arr[i] = vector[i];
  }
  arr
}

#[allow(dead_code)]
pub fn compare_arr_u8_64(lhs: &[u8; 64], rhs: &[u8; 64])->bool {
  for i in 0..64 {
    if lhs[i] != rhs[i] {
      return false;
    }
  }
  return true;
}