use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;

use crate::rustls_utils::RustlsStream;
use std::pin::Pin;
use tls_api::spi::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi::async_as_sync::AsyncWrapperOps;
use tls_api::spi::async_as_sync::TlsStreamOverSyncIo;
use tls_api::spi_async_socket_impl_delegate;
use tls_api::spi_tls_stream_over_sync_io_wrapper;
use tls_api::AsyncSocket;
use tls_api::ImplInfo;

#[derive(Debug)]
pub(crate) struct TlsStream<A: AsyncSocket>(
    pub(crate) TlsStreamOverSyncIo<A, AsyncWrapperOpsImpl<AsyncIoAsSyncIo<A>, A>>,
);

impl<A: AsyncSocket> TlsStream<A> {
    pub(crate) fn new(stream: RustlsStream<AsyncIoAsSyncIo<A>>) -> TlsStream<A> {
        TlsStream(TlsStreamOverSyncIo::new(stream))
    }

    fn get_socket_pin_for_delegate(
        self: Pin<&mut Self>,
    ) -> Pin<&mut TlsStreamOverSyncIo<A, AsyncWrapperOpsImpl<AsyncIoAsSyncIo<A>, A>>> {
        Pin::new(&mut self.get_mut().0)
    }

    fn get_socket_ref_for_delegate(
        &self,
    ) -> &TlsStreamOverSyncIo<A, AsyncWrapperOpsImpl<AsyncIoAsSyncIo<A>, A>> {
        &self.0
    }
}

spi_tls_stream_over_sync_io_wrapper!(TlsStream);

#[derive(Debug)]
pub(crate) struct AsyncWrapperOpsImpl<S, A>(PhantomData<(S, A)>)
where
    S: fmt::Debug + Unpin + Send + 'static,
    A: AsyncSocket;

#[derive(Debug)]
struct StreamOwnedDebug;

impl<S, A> AsyncWrapperOps<A> for AsyncWrapperOpsImpl<S, A>
where
    S: fmt::Debug + Unpin + Send + 'static,
    A: AsyncSocket,
{
    type SyncWrapper = RustlsStream<AsyncIoAsSyncIo<A>>;

    fn impl_info() -> ImplInfo {
        crate::info()
    }

    fn debug(_w: &Self::SyncWrapper) -> &dyn Debug {
        // TODO: remove on next release https://github.com/ctz/rustls/pull/524
        &StreamOwnedDebug
    }

    fn get_mut(w: &mut Self::SyncWrapper) -> &mut AsyncIoAsSyncIo<A> {
        w.get_socket_mut()
    }

    fn get_ref(w: &Self::SyncWrapper) -> &AsyncIoAsSyncIo<A> {
        w.get_socket_ref()
    }

    fn get_alpn_protocol(w: &Self::SyncWrapper) -> tls_api::Result<Option<Vec<u8>>> {
        Ok(w.get_alpn_protocol().map(Vec::from))
    }
}
