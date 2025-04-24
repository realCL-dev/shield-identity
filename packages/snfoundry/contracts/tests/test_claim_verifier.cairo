// Import libraries
use contracts::ClaimVerifier::{IClaimVerifierDispatcher, IClaimVerifierDispatcherTrait};
use contracts::IdentityRegistry::{IIdentityRegistryDispatcher, IIdentityRegistryDispatcherTrait};
//use openzeppelin_access::ownable::interface::{IOwnableDispatcher, IOwnableDispatcherTrait};

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

// Deploy function for IdentityRegistry
fn deploy_identity_registry() -> IIdentityRegistryDispatcher {
    // declare a contract class
    let contract_class = declare("IdentityRegistry")
        .expect('fails declare identity registry')
        .contract_class();

    // Serialize the constructor
    let mut calldata: Array<felt252> = array![];
    owner().serialize(ref calldata);

    // Deploy the contract
    let (contract_address, _) = contract_class.deploy(@calldata).expect('failed to deploy');

    // Get a IdentityRegistry instance
    IIdentityRegistryDispatcher { contract_address }
}

// Deploy function for ClaimVerifier
fn deploy_claim_verifier(identity_registry_address: ContractAddress) -> IClaimVerifierDispatcher {
    // declare a contract class
    let contract_class = declare("ClaimVerifier")
        .expect('fails declare claim verifier')
        .contract_class();

    // Serialize the constructor
    let mut calldata: Array<felt252> = array![];
    identity_registry_address.serialize(ref calldata);
    owner().serialize(ref calldata);

    // Deploy the contract
    let (contract_address, _) = contract_class.deploy(@calldata).expect('failed to deploy');

    // Get a ClaimVerifier instance
    IClaimVerifierDispatcher { contract_address }
}

#[test]
fn test_claim_verifier_deployment() {
    let identity_registry = deploy_identity_registry();
    let claim_verifier = deploy_claim_verifier(identity_registry.contract_address);

    // Verify the identity registry is correctly set
    let registry_address = claim_verifier.get_identity_registry();
    assert(registry_address == identity_registry.contract_address, 'Wrong registry address');

    // Check that age verification is supported by default
    assert(
        claim_verifier.is_verification_type_supported('age_verification'.into()),
        'Age verification not supported',
    );
}

#[test]
fn test_add_verification_type() {
    let identity_registry = deploy_identity_registry();
    let claim_verifier = deploy_claim_verifier(identity_registry.contract_address);

    let new_claim_type: felt252 = 'income_verification'.into();

    // Verify the new claim type is not supported initially
    assert(
        !claim_verifier.is_verification_type_supported(new_claim_type),
        'Should not be supported yet',
    );

    // Add the new verification type as owner
    start_cheat_caller_address(claim_verifier.contract_address, owner());
    claim_verifier.add_verification_type(new_claim_type);
    stop_cheat_caller_address(claim_verifier.contract_address);

    // Verify the new claim type is now supported
    assert(
        claim_verifier.is_verification_type_supported(new_claim_type), 'Should be supported now',
    );
}

#[test]
fn test_verify_age_claim_flow() {
    let identity_registry = deploy_identity_registry();
    let claim_verifier = deploy_claim_verifier(identity_registry.contract_address);

    let test_hash: felt252 = 0x12345;

    // Register user in identity registry
    start_cheat_caller_address(identity_registry.contract_address, user());
    identity_registry.register_identity(test_hash);
    stop_cheat_caller_address(identity_registry.contract_address);

    // Verify the user in identity registry (as owner, who is a verifier)
    start_cheat_caller_address(identity_registry.contract_address, owner());
    identity_registry.update_verification_status(user(), true);
    stop_cheat_caller_address(identity_registry.contract_address);

    // Create a simple proof
    let mut proof: Array<felt252> = array![];
    proof.append(1);
    use contracts::zk::age_verification::AgeVerificationPublicInputs;

    // Construct the public inputs
    // Construct the public inputs
    let public_inputs = AgeVerificationPublicInputs {
        min_age_seconds: 18 * 31536000_u64, // 18 years in seconds
        current_timestamp: 1677777777_u64,   // Example timestamp
        identity_hash: test_hash,
    };
    let min_age_seconds = public_inputs.min_age_seconds;
   
    // Verify age claim (should succeed since the user is verified)
    start_cheat_caller_address(claim_verifier.contract_address, user());
    let result = claim_verifier.verify_age_claim(proof, public_inputs, min_age_seconds);
    stop_cheat_caller_address(claim_verifier.contract_address);

    assert(result, 'Age verification should succeed');
}

#[test]
#[should_panic(expected: ('User not verified',))]
fn test_verify_age_claim_unverified_user() {
    use contracts::zk::age_verification::AgeVerificationPublicInputs;
    let identity_registry = deploy_identity_registry();
    let claim_verifier = deploy_claim_verifier(identity_registry.contract_address);

    let test_hash: felt252 = 0x12345;

    // Construct the public inputs
    let public_inputs = AgeVerificationPublicInputs {
        min_age_seconds: 18 * 31536000_u64, // 18 years in seconds
        current_timestamp: 1677777777_u64,   // Example timestamp
        identity_hash: test_hash,
    };
    let min_age: u64 = 18;
    // Convert years to seconds
    let min_age_seconds = min_age * 31536000_u64; // seconds in a year

    // Register user in identity registry (but don't verify)
    start_cheat_caller_address(identity_registry.contract_address, user());
    identity_registry.register_identity(test_hash);
    stop_cheat_caller_address(identity_registry.contract_address);

    // Create a simple proof
    let mut proof: Array<felt252> = array![];
    proof.append(1);


    // Attempt to verify age claim (should fail since the user is not verified)
    start_cheat_caller_address(claim_verifier.contract_address, user());
    claim_verifier.verify_age_claim(proof, public_inputs, min_age_seconds);
    stop_cheat_caller_address(claim_verifier.contract_address);
}
