#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::handshake::ClientHandshakeFuture;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::certificate::SecCertificate;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::secure_transport::ClientBuilder;

use std::fmt;
use std::str;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::BoxFuture;
use tls_api::X509Cert;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
type ClientBuilder = ();

pub struct TlsConnector(ClientBuilder);
pub struct TlsConnectorBuilder(ClientBuilder);

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;
    type Underlying = ClientBuilder;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let protocols: Vec<&str> = protocols
                .iter()
                .map(|p| {
                    str::from_utf8(p).map_err(|e| {
                        // TODO: better error
                        tls_api::Error::new(e)
                    })
                })
                .collect::<Result<_, _>>()?;
            self.0.alpn_protocols(&protocols);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            crate::not_ios_or_macos()
        }
    }

    fn set_verify_hostname(&mut self, verify: bool) -> tls_api::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            self.0.danger_accept_invalid_hostnames(!verify);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            crate::not_ios_or_macos()
        }
    }

    fn add_root_certificate(&mut self, cert: &X509Cert) -> tls_api::Result<&mut Self> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let cert = SecCertificate::from_der(cert.as_bytes()).map_err(tls_api::Error::new)?;
            // TODO: overrides, not adds: https://github.com/kornelski/rust-security-framework/pull/116
            self.0.anchor_certificates(&[cert]);
            Ok(self)
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            crate::not_ios_or_macos()
        }
    }

    fn build(self) -> tls_api::Result<TlsConnector> {
        Ok(TlsConnector(self.0))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    const IMPLEMENTED: bool = crate::IMPLEMENTED;
    const SUPPORTS_ALPN: bool = true;

    fn builder() -> tls_api::Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder(ClientBuilder::new()))
    }

    fn connect<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            BoxFuture::new(ClientHandshakeFuture::Initial(
                move |stream| self.0.handshake(domain, stream),
                AsyncIoAsSyncIo::new(stream),
            ))
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            BoxFuture::new(async { crate::not_ios_or_macos() })
        }
    }
}
