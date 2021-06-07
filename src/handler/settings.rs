use std::{
    ops::Deref,
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

use dashmap::DashMap;
use log::info;
use sawtooth_sdk::processor::{handler::ApplyError, EmptyTransactionContext};

use crate::handler::{constants::SETTINGS_NAMESPACE, filter};

use super::types::TxnResult;

pub struct Settings {
    inner: Arc<DashMap<String, String>>,
}

impl Settings {
    pub fn new() -> Self {
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
    _tx_ctx: Arc<EmptyTransactionContext>,
}

impl SettingsUpdater {
    fn should_stop(receiver: &mpsc::Receiver<()>) -> bool {
        match receiver.try_recv() {
            Ok(_) => {
                log::warn!("Received stop command");
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
        info!("updating settings");
        use sawtooth_sdk::messages::Message;
        filter(tx_ctx, SETTINGS_NAMESPACE, |_, proto| {
            let setting = sawtooth_sdk::messages::setting::Setting::parse_from_bytes(&proto)
                .map_err(|e| {
                    ApplyError::InternalError(format!("Failed to parse setting from bytes: {}", e))
                })?;

            for entry in setting.entries {
                settings.insert(entry.key, entry.value);
            }
            Ok(())
        })?;

        Ok(())
    }
    pub fn new(tx_ctx: EmptyTransactionContext, settings: Settings) -> Self {
        let (sender, receiver) = mpsc::channel();
        let tx_ctx = Arc::new(tx_ctx);

        let ctx_copy = Arc::clone(&tx_ctx);

        let handle = thread::spawn(move || 'outer: loop {
            if SettingsUpdater::should_stop(&receiver) {
                log::warn!("stopping settings updater");
                break;
            }
            thread::sleep(Duration::from_secs(6));
            if let Err(e) = SettingsUpdater::update_settings(&tx_ctx, &settings) {
                log::error!("Error occurred while updating settings: {}", e);
            }
            for _ in 0..10 {
                thread::sleep(Duration::from_secs(6));
                if SettingsUpdater::should_stop(&receiver) {
                    log::warn!("stopping settings updater");
                    break 'outer;
                }
            }
        });

        Self {
            sender,
            handle: Some(handle),
            _tx_ctx: ctx_copy,
        }
    }

    pub fn exit(&self) {
        self.sender.send(()).unwrap();
    }
}

impl Drop for SettingsUpdater {
    fn drop(&mut self) {
        log::warn!("dropping settings updater");
        self.sender.send(()).unwrap();
        log::warn!("joining updater thread");
        self.handle.take().unwrap().join().unwrap();
    }
}
