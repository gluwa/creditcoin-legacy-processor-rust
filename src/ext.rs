use crate::handler::{
    constants::{INVALID_NUMBER_FORMAT_ERR, NEGATIVE_NUMBER_ERR},
    types::{CCApplyError, TxnResult},
};
use crate::sdk::processor::handler::ApplyError;
use anyhow::Context;
use rug::Integer;

pub trait IntegerExt {
    fn try_parse<S: AsRef<str>>(s: S) -> TxnResult<Integer> {
        let parsed = <Integer as IntegerExt>::try_parse_signed(s)?;

        if parsed < 0 {
            return Err(CCApplyError::InvalidTransaction(NEGATIVE_NUMBER_ERR.into()))?;
        }

        Ok(parsed)
    }

    fn try_parse_signed<S: AsRef<str>>(s: S) -> TxnResult<Integer> {
        Ok(Integer::parse(s.as_ref())
            .map(Integer::from)
            .map_err(|_| CCApplyError::InvalidTransaction(INVALID_NUMBER_FORMAT_ERR.into()))
            .with_context(|| format!("The string {:?} is not a valid number", s.as_ref()))?)
    }
}

impl IntegerExt for Integer {}

use prost::Message;

pub trait MessageExt<M> {
    fn try_parse<B: AsRef<[u8]>>(b: B) -> TxnResult<M>;

    fn to_bytes(&self) -> Vec<u8>;
}

impl<M: Message + Default> MessageExt<M> for M {
    fn try_parse<B: AsRef<[u8]>>(buf: B) -> TxnResult<M> {
        M::decode(buf.as_ref()).map_err(|e| {
            CCApplyError::InvalidTransaction(format!("Failed to parse protobuf message : {}", e))
                .into()
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf).unwrap();
        buf
    }
}

pub trait ErrorExt: Sized {
    type Return;
    fn to_apply_error(self) -> Self::Return;

    fn log_err(self) -> Self;
}

impl ErrorExt for anyhow::Error {
    type Return = ApplyError;

    fn to_apply_error(self) -> Self::Return {
        let e: Result<CCApplyError, _> = self.downcast();
        match e {
            Ok(e) => e.into(),
            Err(f) => ApplyError::InvalidTransaction(f.to_string()),
        }
    }

    fn log_err(self) -> Self {
        log::error!("An error occured: {:#}", &self);
        self
    }
}

impl ErrorExt for ApplyError {
    type Return = ApplyError;

    fn to_apply_error(self) -> Self::Return {
        self
    }

    fn log_err(self) -> Self {
        log::error!("An error occurred: {:#}", &self);
        self
    }
}

impl<T> ErrorExt for TxnResult<T> {
    type Return = Result<T, ApplyError>;

    fn to_apply_error(self) -> Self::Return {
        self.map_err(|err| {
            let e: Result<CCApplyError, _> = err.downcast();
            match e {
                Ok(e) => e.into(),
                Err(f) => ApplyError::InvalidTransaction(f.to_string()),
            }
        })
    }

    fn log_err(self) -> Self {
        if let Err(e) = &self {
            log::error!("An error occurred: {:#}", &e);
        }
        self
    }
}
