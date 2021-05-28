use crate::handler::State;
use rug::Integer;
use sawtooth_sdk::processor::handler::ApplyError;

pub trait IntegerExt {
    fn try_parse<S: AsRef<str>>(s: S) -> Result<Integer, ApplyError> {
        Integer::try_parse(s.as_ref())
    }
}

impl IntegerExt for Integer {}

use prost::Message;
pub trait MessageExt<M> {
    fn try_parse<B: AsRef<[u8]>>(b: B) -> Result<M, ApplyError>;
}

impl<M: Message + Default> MessageExt<M> for M {
    fn try_parse<B: AsRef<[u8]>>(buf: B) -> Result<M, ApplyError> {
        M::decode(buf.as_ref()).map_err(|e| {
            ApplyError::InternalError(format!("Failed to parse protobuf message : {}", e))
        })
    }
}
