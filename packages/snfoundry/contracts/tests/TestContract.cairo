// Import libraries
use contracts::IdentityRegistry::{
    IIdentityRegistryDispatcher, IIdentityRegistryDispatcherTrait, IIdentityRegistrySafeDispatcher,
};
use openzeppelin_access::ownable::interface::{IOwnableDispatcher, IOwnableDispatcherTrait};

use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::{ContractAddress};

fn owner() -> ContractAddress {
    'owner'.try_into().unwrap()
}

fn verifier() -> ContractAddress {
    'verifier'.try_into().unwrap()
}

fn user() -> ContractAddress {
    'user'.try_into().unwrap()
}

// Deploy function
fn __deploy__() -> (
    IIdentityRegistryDispatcher, IOwnableDispatcher, IIdentityRegistrySafeDispatcher,
) {
    // declare a contract class
    let contract_class = declare("IdentityRegistry")
        .expect('failed to declare class')
        .contract_class();

    // Serialize the constructor
    let mut calldata: Array<felt252> = array![];
    owner().serialize(ref calldata);

    // Deploy the contract
    let (contract_address, _) = contract_class.deploy(@calldata).expect('failed to deploy');

    // Get a IdentityRegistry  instance
    let IdentityRegistry = IIdentityRegistryDispatcher { contract_address: contract_address };
    let ownable = IOwnableDispatcher { contract_address: contract_address };
    let safe_IdentityRegistry = IIdentityRegistrySafeDispatcher {
        contract_address: contract_address,
    };

    (IdentityRegistry, ownable, safe_IdentityRegistry)
}

#[test]
fn test_identity_registry_deployment() {
    let (_, ownable, _) = __deploy__();
    assert(ownable.owner() == owner(), 'Owner not set');
}

#[test]
fn test_register_identity() {
    let (identity_registry, _, _) = __deploy__();

    // Test identity registration
    let test_hash: felt252 = 0x12345;

    // Mimick a caller
    start_cheat_caller_address(identity_registry.contract_address, user());
    identity_registry.register_identity(test_hash);

    // Verify registration
    let stored_hash = identity_registry.get_identity_hash(user());
    stop_cheat_caller_address(identity_registry.contract_address);
    
    assert(stored_hash == test_hash, 'Identity hash mismatch');
}

#[test]
fn test_update_verification_status() {
    let (identity_registry, _, _) = __deploy__();

    // Test identity registration
    let test_hash: felt252 = 12345;

    // Mimick a caller
    start_cheat_caller_address(identity_registry.contract_address, user());
    identity_registry.register_identity(test_hash);
    stop_cheat_caller_address(identity_registry.contract_address);

    // Mimick the owner (the owner is a verifier by default)
    start_cheat_caller_address(identity_registry.contract_address, owner());
    identity_registry.update_verification_status(user(), true);
    stop_cheat_caller_address(identity_registry.contract_address);

    // Mimick the user again
    start_cheat_caller_address(identity_registry.contract_address, user());
    assert(identity_registry.is_verified(user()) == true,
        'Verification status not correct',
    );
    stop_cheat_caller_address(identity_registry.contract_address);
}

#[test]
fn test_authorize_verifier() {

    let (identity_registry, _, _) = __deploy__();

    let verifier = verifier();

    // Assert that a random address cannot be an authorized verifier
    assert(identity_registry.is_authorized_verifier(verifier) == false, 'Verifier without authorization');

    // Mimick the owner (the owner only can grant verifier status)
    start_cheat_caller_address(identity_registry.contract_address, owner());
    identity_registry.authorize_verifier(verifier);
    stop_cheat_caller_address(identity_registry.contract_address);

    // Assert that a random address cannot be an authorized verifier
    assert(identity_registry.is_authorized_verifier(verifier) == true, 'Verifier should be verified');
}
