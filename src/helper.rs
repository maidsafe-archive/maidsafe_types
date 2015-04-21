// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License, version
// 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which licence you
// accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at
// http://maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to use
// of the MaidSafe Software.

use sodiumoxide::crypto;

///
/// Returns true if both slices are equal in length, and have equal contents
///
pub fn slice_equal<T: PartialEq>(lhs: &[T], rhs: &[T]) -> bool {
    lhs.len() == rhs.len() && lhs.iter().zip(rhs.iter()).all(|(a, b)| a == b)
}

///
/// Convert a container to an array. If the container is not the exact size specified, None is
/// returned. Otherwise, all of the elements are moved into the array.
///
/// ```
/// let mut data = Vec::<usize>::new();
/// data.push(1);
/// data.push(2);
/// assert!(convert_to_array(data, 2).is_some());
/// assert!(convert_to_array(data, 3).is_none());
/// ```
macro_rules! convert_to_array {
    ($container:ident, $size:expr) => {{
        if $container.len() != $size {
            None
        } else {
            let mut arr = [0u8; $size];
            for element in $container.into_iter().enumerate() {
                arr[element.0] = element.1;
            }
            Some(arr)
        }
    }};
}

///
/// SodiumOxide does not allow detached mode of the signature. This detaches the signature
/// from the data. Fails if data isn't at least crypto::sign::SIGNATUREBYTES in length;
/// recommended to be used only with the sodium oxide sign function directly.
///
/// ```
/// extern crate maidsafe_types;
/// extern crate sodiumoxide;
///
/// let keys = sodiumoxide::crypto::sign::gen_keypair();
/// let data = "some data".to_string().into_bytes();
/// let signature : sodiumoxide::crypto::sign::Signature =
///     maidsafe_types::helper::detach_signature(sodiumoxide::crypto::sign::sign(&data, &keys.1)).unwrap();
/// ```
pub fn detach_signature(mut data: Vec<u8>) -> Option<crypto::sign::Signature> {
    data.truncate(crypto::sign::SIGNATUREBYTES);
    convert_to_array!(data, crypto::sign::SIGNATUREBYTES).map(|data| crypto::sign::Signature(data))
}

///
/// SodiumOxide does not allow detached mode of the signature. This re-attaches the signature
/// to the data so that it can be used in the verify function of sodium oxide.
///
pub fn attach_signature(signature: &crypto::sign::Signature, data: &[u8]) -> Vec<u8> {
    let mut attached = Vec::<u8>::with_capacity(signature.0.len() + data.len());
    for byte in signature.0.iter().chain(data.iter()) {
        attached.push(*byte);
    }
    return attached;
}

#[cfg(test)]
mod test {
    use sodiumoxide::crypto;
    use super::*;

    #[test]
    fn compare_u8_equal()  {
        let data = "some data".to_string().into_bytes();
        assert!(slice_equal(&data, &data));

        let data_copy = data.clone();
        assert!(slice_equal(&data, &data_copy));
        assert!(slice_equal(&data_copy, &data));
    }

    #[test]
    fn compare_u8_not_equal()  {
        let data1 = "some data".to_string().into_bytes();
        let data2 = "some daty".to_string().into_bytes();
        assert!(!slice_equal(&data1, &data2));
        assert!(!slice_equal(&data2, &data1));
    }

    #[test]
    fn compare_u8_unequal_length()  {
        let data1 = "some dat".to_string().into_bytes();
        let data2 = "some data".to_string().into_bytes();
        assert!(!slice_equal(&data1, &data2));
        assert!(!slice_equal(&data2, &data1));
    }

    #[test]
    fn compare_string_equal() {
        let one = "some string".to_string();
        let two = "some two".to_string();

        let mut data = Vec::<String>::with_capacity(2);
        data.push(one);
        data.push(two);

        assert!(slice_equal(&data, &data));

        let data2 = data.clone();
        assert!(slice_equal(&data, &data2));
        assert!(slice_equal(&data2, &data));
    }

    #[test]
    fn copy_u8_to_array() {
        let data = "some string".to_string().into_bytes();
        let data2 = data.clone();
        let result = convert_to_array!(data2, 11).unwrap();
        assert!(slice_equal(&data, &result));
    }

    #[test]
    fn copy_u8_to_bad_array() {
        let data = "some string".to_string().into_bytes();
        let data2 = data.clone();
        assert!(convert_to_array!(data2, 10).is_none());
        assert!(convert_to_array!(data, 12).is_none());
    }

    #[test]
    fn detach_signature_failure() {
        let empty = Vec::<u8>::new();
        assert!(detach_signature(empty).is_none());
    }

    #[test]
    fn detached_signature() {
        let mut data = Vec::<u8>::with_capacity(crypto::sign::SIGNATUREBYTES);
        data.extend((0..crypto::sign::SIGNATUREBYTES).map(|_| 4));
        let truncated : Vec<u8> = data.iter().take(crypto::sign::SIGNATUREBYTES).map(|a| a.clone()).collect();
        let detached = detach_signature(data.clone()).unwrap();
        assert!(slice_equal(&truncated, &detached.0));
    }

    #[test]
    fn attached_signature() {
        let signature = crypto::sign::Signature([12u8; crypto::sign::SIGNATUREBYTES]);
        let data = [14u8; 100];
        let attached = attach_signature(&signature, &data);
        assert_eq!(signature.0.len() + data.len(), attached.len());
        assert!(slice_equal(&signature.0, &attached[0..crypto::sign::SIGNATUREBYTES]));
        assert!(slice_equal(&data, &attached[crypto::sign::SIGNATUREBYTES..attached.len()]));
    }

    #[test]
    fn sign_detach_then_attach_and_verify() {
        let mut data = Vec::<u8>::with_capacity(100);
        data.extend((0..100).map(|_| 244));

        let keys = crypto::sign::gen_keypair();
        let detached = detach_signature(crypto::sign::sign(&data, &keys.1)).unwrap();
                     
        assert!(crypto::sign::verify(&attach_signature(&detached, &data), &keys.0).is_some())
    }
}
