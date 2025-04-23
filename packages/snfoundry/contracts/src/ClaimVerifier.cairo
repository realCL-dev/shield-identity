use starknet::ContractAddress;

#[starknet::interface]
pub trait IClaimVerifier<TContractState> {
    fn verify_age_claim(
        ref self: TContractState,
        proof: Array<felt252>,
        public_inputs: Array<felt252>,
        min_age: u64,
    ) -> bool;
    fn add_verification_type(ref self: TContractState, claim_type: felt252);
    fn is_verification_type_supported(self: @TContractState, claim_type: felt252) -> bool;
    fn get_identity_registry(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod ClaimVerifier {
    // Import the Identity Registry dispatcher traits
    use contracts::IdentityRegistry::{
        IIdentityRegistryDispatcher, IIdentityRegistryDispatcherTrait,
    };
    use openzeppelin_access::ownable::{OwnableComponent};
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};

    #[generate_trait]
    impl ErrorsImpl of Errors {
        fn not_verified() -> felt252 {
            'User not verified'
        }
        fn invalid_proof() -> felt252 {
            'Invalid ZK proof'
        }
        fn unsupported_claim_type() -> felt252 {
            'Claim type not supported'
        }
    }

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[storage]
    pub struct Storage {
        identity_registry: ContractAddress,      // Points to Identity Registry contract
        verification_types: Map<felt252, bool>,  // Tracks supported verification types
        #[substorage(v0)]
        ownable: OwnableComponent::Storage, //owner management
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ClaimVerified: ClaimVerified,
        VerificationTypeAdded: VerificationTypeAdded,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimVerified {
        user: ContractAddress,
        claim_type: felt252,
        success: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct VerificationTypeAdded {
        claim_type: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, identity_registry_address: ContractAddress, owner: ContractAddress,
    ) {
        // Initialize the ownable component with the provided owner address
        self.ownable.initializer(owner);

        // Set the identity registry address
        self.identity_registry.write(identity_registry_address);

        // Add default verification type for age verification
        self.verification_types.entry('age_verification'.into()).write(true);
    }

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl InternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl ClaimVerifierImpl of super::IClaimVerifier<ContractState> {
        fn verify_age_claim(
            ref self: ContractState,
            proof: Array<felt252>,
            public_inputs: Array<felt252>,
            min_age: u64,
        ) -> bool {
            // Get caller address
            let user = get_caller_address();

            // Check if age verification is supported
            assert(
                self.verification_types.entry('age_verification'.into()).read(),
                ErrorsImpl::unsupported_claim_type(),
            );

            // Check if user is registered and verified in the Identity Registry
            let identity_registry = IIdentityRegistryDispatcher {
                contract_address: self.identity_registry.read(),
            };

            assert(identity_registry.is_verified(user), ErrorsImpl::not_verified());

            // Get the user's identity hash from the registry
            //let identity_hash = identity_registry.get_identity_hash(user);

            // TODO: Implement proper ZK proof verification here
            // For the MVP, we'll use a simplified verification
            // In production, this would be replaced with an actual ZK verification

            // Simplified verification logic (to be enhanced in future iterations)
            let verification_success = true; // Replace with actual verification result

            // Ensure proof has at least one element
            assert(proof.len() > 0, ErrorsImpl::invalid_proof());

            // Emit verification event
            self
                .emit(
                    Event::ClaimVerified(
                        ClaimVerified {
                            user,
                            claim_type: 'age_verification'.into(),
                            success: verification_success,
                        },
                    ),
                );

            verification_success
        }

        fn add_verification_type(ref self: ContractState, claim_type: felt252) {
            // Only owner can add verification types
            self.ownable.assert_only_owner();

            // Add the verification type to supported types
            self.verification_types.entry(claim_type).write(true);

            // Emit event
            self.emit(Event::VerificationTypeAdded(VerificationTypeAdded { claim_type }));
        }

        fn is_verification_type_supported(self: @ContractState, claim_type: felt252) -> bool {
            self.verification_types.entry(claim_type).read()
        }

        fn get_identity_registry(self: @ContractState) -> ContractAddress {
            self.identity_registry.read()
        }
    }

    // Additional internal methods
    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        // Function to verify ZK proofs (placeholder to be implemented later)
        fn verify_zk_proof(
            self: @ContractState, proof: Array<felt252>, public_inputs: Array<felt252>,
        ) -> bool {
            // TODO: Implement actual ZK proof verification
            // For hackathon MVP, we return true
            // This should be replaced with proper verification logic
            true
        }
    }
}
