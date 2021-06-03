use crate::handler::State;
use rug::Integer;
use sawtooth_sdk::processor::handler::ApplyError;

pub trait IntegerExt {
    fn try_parse<S: AsRef<str>>(s: S) -> Result<Integer, ApplyError> {
        let parsed = <Integer as IntegerExt>::try_parse_signed(s)?;

        if parsed < 0 {
            return Err(ApplyError::InvalidTransaction(
                "Expecting a positive value".into(),
            ));
        }

        Ok(parsed)
    }

    fn try_parse_signed<S: AsRef<str>>(s: S) -> Result<Integer, ApplyError> {
        Integer::parse(s.as_ref())
            .map(Integer::from)
            .map_err(|_| ApplyError::InvalidTransaction("Invalid number format".into()))
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
            ApplyError::InvalidTransaction(format!("Failed to parse protobuf message : {}", e))
        })
    }
}
