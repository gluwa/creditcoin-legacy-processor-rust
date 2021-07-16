use crate::sdk::processor::handler::TransactionContext;
use mockall::mock;

mock! {
    pub TransactionContext {}

    impl TransactionContext for TransactionContext {
        fn get_state_entry(&self, address: &str) -> Result<Option<Vec<u8>>, sawtooth_sdk::processor::handler::ContextError>;

        fn get_state_entries(
            &self,
            addresses: &[String],
        ) -> Result<Vec<(String, Vec<u8>)>, sawtooth_sdk::processor::handler::ContextError>;

        fn set_state_entry(
            &self,
            address: String,
            data: Vec<u8>,
        ) -> Result<(), sawtooth_sdk::processor::handler::ContextError>;

        fn set_state_entries(&self, entries: Vec<(String, Vec<u8>)>) -> Result<(), sawtooth_sdk::processor::handler::ContextError>;

        fn delete_state_entry(
            &self,
            address: &str,
        ) -> Result<Option<String>, sawtooth_sdk::processor::handler::ContextError>;

        fn delete_state_entries(&self, addresses: &[String]) -> Result<Vec<String>, sawtooth_sdk::processor::handler::ContextError> ;

        fn add_receipt_data(&self, data: &[u8]) -> Result<(), sawtooth_sdk::processor::handler::ContextError> ;

        fn add_event(
            &self,
            event_type: String,
            attributes: Vec<(String, String)>,
            data: &[u8],
        ) -> Result<(), sawtooth_sdk::processor::handler::ContextError> ;

        fn get_sig_by_num(&self, block_num: u64) -> Result<String, sawtooth_sdk::processor::handler::ContextError> ;

        fn get_reward_block_signatures(
            &self,
            block_id: &str,
            first_pred: u64,
            last_pred: u64,
        ) -> Result<Vec<String>, sawtooth_sdk::processor::handler::ContextError> ;

        fn get_state_entries_by_prefix(
            &self,
            address: &str,
        ) -> Result<Vec<(String, Vec<u8>)>, sawtooth_sdk::processor::handler::ContextError> ;
    }
}

mock! {
    pub Settings {
        pub fn get(&self, key: &str) -> Option<&'static str>;
    }
}
