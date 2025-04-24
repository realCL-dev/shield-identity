use starknet::ContractAddress;

// Define the Credential struct with proper derive traits
#[derive(Drop, Serde, Copy, starknet::Store)]
pub struct Credential {
    credential_type: felt252, // Type of credential (e.g., 'age', 'kyc', 'country')    
    issuer: ContractAddress, // Issuer of the credential   
    data_hash: felt252, // Hash of the credential data    
    issued_at: u64, // Timestamp when the credential was issued    
    expires_at: u64, // Timestamp when the credential expires (0 for no expiration)    
    is_revoked: bool // Whether the credential is revoked
}

#[starknet::interface]
pub trait ICredentialManager<TContractState> {
    fn issue_credential(
        ref self: TContractState,
        user: ContractAddress,
        credential_type: felt252,
        data_hash: felt252,
        validity_period: u64,
    ) -> u64;

    fn revoke_credential(ref self: TContractState, user: ContractAddress, credential_id: u64);

    fn get_credential(
        self: @TContractState, user: ContractAddress, credential_id: u64,
    ) -> Credential;

    fn is_valid_credential(
        self: @TContractState, user: ContractAddress, credential_id: u64,
    ) -> bool;

    fn get_user_credential_count(self: @TContractState, user: ContractAddress) -> u64;

    fn authorize_issuer(
        ref self: TContractState, credential_type: felt252, issuer: ContractAddress,
    );

    fn revoke_issuer(ref self: TContractState, credential_type: felt252, issuer: ContractAddress);

    fn is_authorized_issuer(
        self: @TContractState, credential_type: felt252, issuer: ContractAddress,
    ) -> bool;

    fn get_identity_registry(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod CredentialManager {
    // Import the Identity Registry dispatcher traits
    use contracts::IdentityRegistry::{
        IIdentityRegistryDispatcher, IIdentityRegistryDispatcherTrait,
    };
    use core::traits::{Default, Into};
    use openzeppelin_access::ownable::interface::IOwnableTwoStep;
    use openzeppelin_access::ownable::{OwnableComponent};
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};

    use super::Credential;


    #[generate_trait]
    impl ErrorsImpl of Errors {
        fn not_authorized() -> felt252 {
            'Not authorized'
        }

        fn not_authorized_issuer() -> felt252 {
            'Not authorized issuer'
        }

        fn credential_not_found() -> felt252 {
            'Credential not found'
        }

        fn user_not_verified() -> felt252 {
            'User not verified in registry'
        }

        fn registry_not_set() -> felt252 {
            'Identity registry not set'
        }
    }

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[storage]
    pub struct Storage {
        user_credentials: Map<
            (ContractAddress, u64), Credential,
        >, // Mapping from user address to credential ID to credential        
        user_credential_count: Map<
            ContractAddress, u64,
        >, // Mapping from user address to credential count        
        authorized_issuers: Map<
            (felt252, ContractAddress), bool,
        >, // Mapping of authorized issuers for each credential type        
        identity_registry: ContractAddress, // Identity Registry contract address        
        require_identity_verification: bool, // Whether to enforce identity verification        
        #[substorage(v0)]
        ownable: OwnableComponent::Storage // Contract owner (from Openzeppelin ownable)
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        CredentialIssued: CredentialIssued,
        CredentialRevoked: CredentialRevoked,
        IssuerAuthorized: IssuerAuthorized,
        IssuerRevoked: IssuerRevoked,
        IdentityRegistrySet: IdentityRegistrySet,
        VerificationRequirementUpdated: VerificationRequirementUpdated,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct CredentialIssued {
        user: ContractAddress,
        credential_id: u64,
        credential_type: felt252,
        issuer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct CredentialRevoked {
        user: ContractAddress,
        credential_id: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct IssuerAuthorized {
        credential_type: felt252,
        issuer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct IssuerRevoked {
        credential_type: felt252,
        issuer: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct IdentityRegistrySet {
        registry_address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct VerificationRequirementUpdated {
        require_verification: bool,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        identity_registry_address: ContractAddress,
        require_verification: bool,
    ) {
        // Initialize the ownable component with the provided owner address
        self.ownable.initializer(owner);

        // Set the identity registry address if provided (can be zero)
        self.identity_registry.write(identity_registry_address);

        // Set verification requirement
        self.require_identity_verification.write(require_verification);
        // The owner is automatically authorized to issue all credential types
    // In a production environment, you would set up proper authorities
    }

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl InternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl CredentialManagerImpl of super::ICredentialManager<ContractState> {
        fn issue_credential(
            ref self: ContractState,
            user: ContractAddress,
            credential_type: felt252,
            data_hash: felt252,
            validity_period: u64,
        ) -> u64 {
            // Check if caller is authorized to issue this credential type
            let issuer = get_caller_address();
            assert(
                self.is_authorized_issuer_internal(credential_type, issuer),
                ErrorsImpl::not_authorized_issuer(),
            );

            // Verify user in Identity Registry if required
            if self.require_identity_verification.read() {
                self.verify_user_in_registry(user);
            }

            let issued_at = get_block_timestamp();

            // Calculate expiration time if validity_period is provided
            let expires_at = if validity_period == 0 {
                0
            } else {
                issued_at + validity_period
            };

            // Create new credential
            let credential = Credential {
                credential_type, issuer, data_hash, issued_at, expires_at, is_revoked: false,
            };

            // Get next credential ID for this user
            let credential_id = self.user_credential_count.entry(user).read();

            // Store the credential
            self.user_credentials.entry((user, credential_id)).write(credential);

            // Increment credential count
            self.user_credential_count.entry(user).write(credential_id + 1);

            // Emit event
            self
                .emit(
                    Event::CredentialIssued(
                        CredentialIssued { user, credential_id, credential_type, issuer },
                    ),
                );

            credential_id
        }

        fn revoke_credential(ref self: ContractState, user: ContractAddress, credential_id: u64) {
            // Get the credential
            let mut credential = self.user_credentials.entry((user, credential_id)).read();

            // Check if caller is the issuer or the owner
            let caller = get_caller_address();
            assert(
                credential.issuer == caller || caller == self.ownable.owner(),
                ErrorsImpl::not_authorized(),
            );

            // Revoke the credential
            credential.is_revoked = true;

            // Update the credential
            self.user_credentials.entry((user, credential_id)).write(credential);

            // Emit event
            self.emit(Event::CredentialRevoked(CredentialRevoked { user, credential_id }));
        }

        fn get_credential(
            self: @ContractState, user: ContractAddress, credential_id: u64,
        ) -> Credential {
            // Ensure the credential count is enough
            let count = self.user_credential_count.entry(user).read();
            assert(credential_id < count, ErrorsImpl::credential_not_found());

            // Return the credential
            //self.user_credentials.read((user, credential_id))
            self.user_credentials.entry((user, credential_id)).read()
        }

        fn is_valid_credential(
            self: @ContractState, user: ContractAddress, credential_id: u64,
        ) -> bool {
            // Ensure the credential exists
            let count = self.user_credential_count.entry(user).read();
            if credential_id >= count {
                return false;
            }

            let credential = self.user_credentials.entry((user, credential_id)).read();

            // Check if credential is revoked
            if credential.is_revoked {
                return false;
            }

            // Check if credential is expired
            if credential.expires_at != 0 && credential.expires_at < get_block_timestamp() {
                return false;
            }

            // Check if user is still verified in Identity Registry (if verification is required)
            if self.require_identity_verification.read() {
                let registry_address = self.identity_registry.read();
                // Check if registry is set (not zero address)
                if registry_address.into() != 0 {
                    let identity_registry = IIdentityRegistryDispatcher {
                        contract_address: registry_address,
                    };

                    if !identity_registry.is_verified(user) {
                        return false;
                    }
                }
            }

            true
        }

        fn get_user_credential_count(self: @ContractState, user: ContractAddress) -> u64 {
            self.user_credential_count.entry(user).read()
        }

        fn authorize_issuer(
            ref self: ContractState, credential_type: felt252, issuer: ContractAddress,
        ) {
            // Only the owner can authorize issuers
            self.ownable.assert_only_owner();

            // Authorize the issuer for this credential type
            self.authorized_issuers.entry((credential_type, issuer)).write(true);

            // Emit event
            self.emit(Event::IssuerAuthorized(IssuerAuthorized { credential_type, issuer }));
        }

        fn revoke_issuer(
            ref self: ContractState, credential_type: felt252, issuer: ContractAddress,
        ) {
            // Only the owner can revoke issuers
            self.ownable.assert_only_owner();

            // Revoke the issuer for this credential type
            self.authorized_issuers.entry((credential_type, issuer)).write(false);

            // Emit event
            self.emit(Event::IssuerRevoked(IssuerRevoked { credential_type, issuer }));
        }

        fn is_authorized_issuer(
            self: @ContractState, credential_type: felt252, issuer: ContractAddress,
        ) -> bool {
            self.is_authorized_issuer_internal(credential_type, issuer)
        }

        fn get_identity_registry(self: @ContractState) -> ContractAddress {
            self.identity_registry.read()
        }
    }

    // Additional external methods not in the original interface
    #[generate_trait]
    impl ExternalFunctionsImpl of ExternalFunctionsTrait {
        #[external(v0)]
        fn set_identity_registry(
            ref self: ContractState, identity_registry_address: ContractAddress,
        ) {
            // Only owner can set the identity registry
            self.ownable.assert_only_owner();

            // Set the identity registry address
            self.identity_registry.write(identity_registry_address);

            // Emit event
            self
                .emit(
                    Event::IdentityRegistrySet(
                        IdentityRegistrySet { registry_address: identity_registry_address },
                    ),
                );
        }

        #[external(v0)]
        fn set_verification_requirement(ref self: ContractState, require_verification: bool) {
            // Only owner can change verification requirements
            self.ownable.assert_only_owner();

            // Set verification requirement
            self.require_identity_verification.write(require_verification);

            // Emit event
            self
                .emit(
                    Event::VerificationRequirementUpdated(
                        VerificationRequirementUpdated { require_verification },
                    ),
                );
        }
    }

    // Internal methods
    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn is_authorized_issuer_internal(
            self: @ContractState, credential_type: felt252, issuer: ContractAddress,
        ) -> bool {
            // The contract owner is always authorized, or check the mapping
            issuer == self.ownable.owner()
                || self.authorized_issuers.entry((credential_type, issuer)).read()
        }

        fn verify_user_in_registry(self: @ContractState, user: ContractAddress) {
            let registry_address = self.identity_registry.read();

            // Skip if no registry is set (zero address)
            if registry_address.into() == 0 {
                return;
            }

            // Check if user is verified in the Identity Registry
            let identity_registry = IIdentityRegistryDispatcher {
                contract_address: registry_address,
            };

            assert(identity_registry.is_verified(user), ErrorsImpl::user_not_verified());
        }
    }
}
