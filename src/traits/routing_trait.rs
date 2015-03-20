/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

/// temporary code to test passing a trait to routing to query and possible decode types or
/// at least soem info routing needs which is access to these functions on data types
/// These traits will be defined in routing and require to be avauilable for any type
/// passed to routing, refresh / account transfer is optional
/// The name will let routing know its an NaeManager and the owner will allow routing to hash
/// the requsters id with this name (by hashing the requesters id) for put and post messages
use common::NameType;

pub trait RoutingTrait {
	fn get_name(&self)->&NameType;
	fn get_owner(&self)->&Vec<u8>;
	fn refresh(&self)->bool { false } // is this an account transfer type
	fn merge(&self)->bool { false } // how do we merge these
}
