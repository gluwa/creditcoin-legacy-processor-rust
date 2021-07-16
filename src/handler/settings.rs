use std::{
    ops::Deref,
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::sdk::{messaging::stream::ReceiveError, processor::EmptyTransactionContext};
use dashmap::DashMap;
use log::{info, trace, warn};

use crate::handler::{constants::SETTINGS_NAMESPACE, filter, types::CCApplyError};

use super::types::TxnResult;

pub struct Settings {
    inner: Arc<DashMap<String, String>>,
}

impl Settings {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }
}

impl Clone for Settings {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Deref for Settings {
    type Target = DashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &*self.inner
    }
}

pub(crate) struct SettingsUpdater {
    handle: Option<JoinHandle<()>>,
    pub(crate) sender: mpsc::Sender<()>,
}

impl SettingsUpdater {
    fn should_stop(receiver: &mpsc::Receiver<()>) -> bool {
        match receiver.try_recv() {
            Ok(_) => {
                log::info!("Received stop command");
                true
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                log::error!("other end of channel disconnected!");
                true
            }
            Err(mpsc::TryRecvError::Empty) => false,
        }
    }
    fn update_settings(tx_ctx: &EmptyTransactionContext, settings: &Settings) -> TxnResult<()> {
        tx_ctx.flush();
        trace!("updating settings");
        use crate::sdk::messages::Message;
        filter(tx_ctx, SETTINGS_NAMESPACE, |_, proto| {
            let setting = sawtooth_sdk::messages::setting::Setting::parse_from_bytes(&proto)
                .map_err(|e| {
                    CCApplyError::InternalError(format!(
                        "Failed to parse setting from bytes: {}",
                        e
                    ))
                })?;

            for entry in setting.entries {
                settings.insert(entry.key, entry.value);
            }
            Ok(())
        })?;
        trace!("finished updating setings");

        Ok(())
    }
    pub fn new(tx_ctx: EmptyTransactionContext, settings: Settings) -> Self {
        let (sender, receiver) = mpsc::channel();

        let handle = thread::spawn(move || 'outer: loop {
            if SettingsUpdater::should_stop(&receiver) {
                log::info!("stopping settings updater");
                break;
            }
            thread::sleep(Duration::from_secs(6));
            if let Err(e) = SettingsUpdater::update_settings(&tx_ctx, &settings) {
                if let Some(ReceiveError::TimeoutError) = e.downcast_ref::<ReceiveError>() {
                    log::trace!("settings updater timed out waiting on reply from the validator");
                } else {
                    log::warn!("Error occurred while updating settings: {}", e);
                }
            }
            for _ in 0..10 {
                thread::sleep(Duration::from_secs(6));
                if SettingsUpdater::should_stop(&receiver) {
                    log::info!("stopping settings updater");
                    break 'outer;
                }
            }
        });

        Self {
            sender,
            handle: Some(handle),
        }
    }

    pub fn exit(&self) {
        if let Err(e) = self.sender.send(()) {
            warn!("send error occurred while exiting: {}", e);
        }
    }
}

impl Drop for SettingsUpdater {
    fn drop(&mut self) {
        info!("dropping settings updater");
        self.exit();
        info!("joining updater thread");
        self.handle.take().unwrap().join().unwrap();
    }
}
