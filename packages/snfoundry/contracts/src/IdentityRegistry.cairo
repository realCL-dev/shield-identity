use starknet::ContractAddress;

#[starknet::interface]
pub trait IIdentityRegistry<TContractState> {
    fn register_identity(ref self: TContractState, identity_hash: felt252);
    fn get_identity_hash(self: @TContractState, user: ContractAddress) -> felt252;
    fn update_verification_status(
        ref self: TContractState, user: ContractAddress, is_verified: bool,
    );
    fn authorize_verifier(ref self: TContractState, verifier: ContractAddress);
    fn revoke_verifier(ref self: TContractState, verifier: ContractAddress);
    fn is_verified(self: @TContractState, user: ContractAddress) -> bool;
    fn is_authorized_verifier(self: @TContractState, verifier: ContractAddress) -> bool;
}

#[starknet::contract]
pub mod IdentityRegistry {
    use openzeppelin_access::ownable::interface::IOwnableTwoStep;
    use openzeppelin_access::ownable::{OwnableComponent};
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};

    #[generate_trait]
    impl ErrorsImpl of Errors {
        fn already_registered() -> felt252 {
            'Identity already registered'
        }

        fn invalid_hash() -> felt252 {
            'Invalid identity hash'
        }
    }

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[storage]
    pub struct Storage {
        // Mapping from user address to identity hash
        identity_hashes: Map<ContractAddress, felt252>,
        // Mapping from user address to verification status
        verification_status: Map<ContractAddress, bool>,
        // Mapping for authorized verifiers
        authorized_verifiers: Map<ContractAddress, bool>,
        // Contract owner (from Openzeppelin ownable)
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        IdentityRegistered: IdentityRegistered,
        VerificationStatusUpdated: VerificationStatusUpdated,
        VerifierAuthorized: VerifierAuthorized,
        VerifierRevoked: VerifierRevoked,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct IdentityRegistered {
        user: ContractAddress,
        identity_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct VerificationStatusUpdated {
        user: ContractAddress,
        is_verified: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct VerifierAuthorized {
        verifier: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct VerifierRevoked {
        verifier: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        // Initialize the ownable component with the provided owner address
        self.ownable.initializer(owner);

        // Automatically authorize the deployer as a verifier
        self.authorized_verifiers.entry(owner).write(true);
    }

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl InternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl IdentityRegistryImpl of super::IIdentityRegistry<ContractState> {
        fn register_identity(ref self: ContractState, identity_hash: felt252) {
            let caller = get_caller_address();

            // Validate inputs
            assert(identity_hash != 0, ErrorsImpl::invalid_hash());

            // Check if identity already exists
            let existing = self.identity_hashes.entry(caller).read();
            assert(existing == 0, ErrorsImpl::already_registered());

            // Register identity
            self.identity_hashes.entry(caller).write(identity_hash);

            // Set verification status to false by default
            self.verification_status.entry(caller).write(false);

            // Emit event
            self
                .emit(
                    Event::IdentityRegistered(IdentityRegistered { user: caller, identity_hash }),
                );
        }

        fn update_verification_status(
            ref self: ContractState, user: ContractAddress, is_verified: bool,
        ) {
            // Only authorized verifiers can update verification status
            let caller = get_caller_address();
            assert(self.authorized_verifiers.entry(caller).read(), 'Not a verifier');

            // Update the verification status
            self.verification_status.entry(user).write(is_verified);

            // Emit verification update event
            self
                .emit(
                    Event::VerificationStatusUpdated(
                        VerificationStatusUpdated { user, is_verified },
                    ),
                );
        }

        fn authorize_verifier(ref self: ContractState, verifier: ContractAddress) {
            // Only the owner can authorize verifiers
            let caller = get_caller_address();
            assert(caller == self.owner(), 'Not authorized');

            // Authorize the verifier
            self.authorized_verifiers.entry(verifier).write(true);
            // Emit authorization event
            self.emit(Event::VerifierAuthorized(VerifierAuthorized { verifier }));
        }

        fn revoke_verifier(ref self: ContractState, verifier: ContractAddress) {
            // Only the owner can revoke verifiers
            let caller = get_caller_address();
            assert(caller == self.owner(), 'Not authorized');

            // Revoke the verifier
            self.authorized_verifiers.entry(verifier).write(false);

            // Emit revocation event
            self.emit(Event::VerifierRevoked(VerifierRevoked { verifier }));
        }

        fn get_identity_hash(self: @ContractState, user: ContractAddress) -> felt252 {
            self.identity_hashes.entry(user).read()
        }

        fn is_verified(self: @ContractState, user: ContractAddress) -> bool {
            self.verification_status.entry(user).read()
        }

        fn is_authorized_verifier(self: @ContractState, verifier: ContractAddress) -> bool {
            self.authorized_verifiers.entry(verifier).read()            
        }
    }
}
