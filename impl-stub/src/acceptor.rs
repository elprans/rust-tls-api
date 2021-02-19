use void::Void;

use tls_api::AsyncSocket;
use tls_api::BoxFuture;

use crate::Error;

pub struct TlsAcceptorBuilder(Void);
pub struct TlsAcceptor(Void);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = Void;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        Err(tls_api::Error::new(Error))
    }

    fn underlying_mut(&mut self) -> &mut Void {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<TlsAcceptor> {
        Err(tls_api::Error::new(Error))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    const IMPLEMENTED: bool = false;
    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = false;

    fn version() -> &'static str {
        "stub"
    }

    fn accept<'a, S>(&'a self, _stream: S) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
    where
        S: AsyncSocket,
    {
        BoxFuture::new(async { Err(tls_api::Error::new(Error)) })
    }
}
