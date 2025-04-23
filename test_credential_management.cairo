use snfoundry::CredentialManagement::{
    ICredentialManagerDispatcher, ICredentialManagerDispatcherTrait, CredentialManager
};
use starknet::{ContractAddress, contract_address_const};
use core::option::OptionTrait;
use core::traits::Into;
use starknet::syscalls::get_block_timestamp;

#[test]
fn test_credential_lifecycle() {
    // Setup
    let owner = contract_address_const::<1>();
    let issuer = contract_address_const::<2>();
    let user = contract_address_const::<3>();
    
    let mut state = CredentialManager::contract_state_for_testing();
    CredentialManager::constructor(ref state, owner);

    // Test authorize issuer
    let credential_type = 1234;
    CredentialManager::authorize_issuer(ref state, credential_type, issuer);
    
    let is_authorized = CredentialManager::is_authorized_issuer(@state, credential_type, issuer);
    assert(is_authorized == true, 'Issuer should be authorized');

    // Test issue credential
    let data_hash = 5678;
    let validity_period = 86400; // 1 day
    
    let credential_id = CredentialManager::issue_credential(
        ref state,
        user,
        credential_type,
        data_hash, 
        validity_period
    );
    assert(credential_id == 0, 'First credential should have id 0');

    // Test get credential
    let credential = CredentialManager::get_credential(@state, user, credential_id);
    assert(credential.credential_type == credential_type, 'Wrong credential type');
    assert(credential.data_hash == data_hash, 'Wrong data hash');
    assert(credential.is_revoked == false, 'Should not be revoked');

    // Test credential validity
    let is_valid = CredentialManager::is_valid_credential(@state, user, credential_id);
    assert(is_valid == true, 'Credential should be valid');

    // Test revoke credential
    CredentialManager::revoke_credential(ref state, user, credential_id);
    let revoked_credential = CredentialManager::get_credential(@state, user, credential_id);
    assert(revoked_credential.is_revoked == true, 'Should be revoked');

    // Test credential count
    let count = CredentialManager::get_user_credential_count(@state, user);
    assert(count == 1, 'Should have 1 credential');
}