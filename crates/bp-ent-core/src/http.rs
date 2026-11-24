//! HTTP glue shared by every service: the auth middleware and the
//! [`Principal`] extractor.

use crate::{auth, AppCtx, AuthKind, Error, Principal};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;

/// Header the web portal sends on every state-changing request.
pub const CSRF_HEADER: &str = "x-bp-csrf";

/// Require a verified caller on every route of `router`.
///
/// Credentials are a bearer token (`Authorization: Bearer bpe_…`) or the
/// session cookie. Handlers then take [`Principal`] as an argument. Applying
/// it twice (a feature crate and the API both wrap the same routes) is fine.
pub fn with_auth(router: Router, ctx: &AppCtx) -> Router {
    router.layer(axum::middleware::from_fn_with_state(ctx.clone(), auth_middleware))
}

async fn auth_middleware(State(ctx): State<AppCtx>, mut req: Request, next: Next) -> Response {
    if req.extensions().get::<Principal>().is_some() {
        return next.run(req).await;
    }
    match authenticate(&ctx, req.method(), req.headers()).await {
        Ok(p) => {
            req.extensions_mut().insert(p);
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

/// Verify the credentials on a request. Usable directly by services that do
/// their own upgrade handling (the relay's WebSocket endpoint).
pub async fn authenticate(ctx: &AppCtx, method: &Method, headers: &HeaderMap) -> Result<Principal, Error> {
    if let Some(token) = bearer_token(headers) {
        let p = auth::verify_bearer(ctx, token).await?;
        // A session token is only valid as a cookie, where the CSRF rules
        // below apply; it must not double as an API key if it leaks.
        if p.auth == AuthKind::Session {
            return Err(Error::Unauthorized);
        }
        return Ok(p);
    }
    let token = cookie(headers, ctx.config.session_cookie_name()).ok_or(Error::Unauthorized)?;
    // Cookies are sent by the browser automatically, so check that the
    // request really comes from the portal before using one.
    check_csrf(&ctx.config.public_origin, method, headers)?;
    let p = auth::verify_bearer(ctx, token).await?;
    if p.auth != AuthKind::Session {
        return Err(Error::Unauthorized);
    }
    Ok(p)
}

/// CSRF defence for cookie-authenticated requests:
/// - state-changing methods need `Origin` == the portal origin AND the
///   custom `X-BP-CSRF` header (which a cross-site form cannot set);
/// - WebSocket upgrades (GET, but they open a two-way channel) need the
///   matching `Origin`;
/// - other safe requests need a matching `Origin` only if one is sent.
pub fn check_csrf(public_origin: &str, method: &Method, headers: &HeaderMap) -> Result<(), Error> {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let origin_ok = origin == Some(public_origin);
    let safe = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let upgrade = headers.contains_key(header::UPGRADE);
    if !safe {
        if origin_ok && headers.contains_key(CSRF_HEADER) {
            return Ok(());
        }
        return Err(Error::Forbidden);
    }
    if upgrade && !origin_ok {
        return Err(Error::Forbidden);
    }
    if origin.is_some() && !origin_ok {
        return Err(Error::Forbidden);
    }
    Ok(())
}

pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Read one cookie. With duplicates the first wins (and `__Host-` cookies
/// cannot be shadowed from a subdomain).
pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

impl<S: Send + Sync> FromRequestParts<S> for Principal {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Present only if `with_auth` verified the caller. A route that takes
        // a Principal without the middleware fails closed.
        parts.extensions.get::<Principal>().cloned().ok_or(Error::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const ORIGIN: &str = "https://portal.example.com";

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn csrf_blocks_cross_site_writes() {
        let ok = headers(&[("origin", ORIGIN), ("x-bp-csrf", "1")]);
        assert!(check_csrf(ORIGIN, &Method::POST, &ok).is_ok());
        // missing custom header
        assert!(check_csrf(ORIGIN, &Method::POST, &headers(&[("origin", ORIGIN)])).is_err());
        // wrong origin
        assert!(check_csrf(ORIGIN, &Method::POST, &headers(&[("origin", "https://evil.example"), ("x-bp-csrf", "1")])).is_err());
        // no origin at all
        assert!(check_csrf(ORIGIN, &Method::DELETE, &headers(&[("x-bp-csrf", "1")])).is_err());
        // look-alike origins
        for o in ["https://portal.example.com.evil.example", "http://portal.example.com", "https://portal.example.com:8443", "null"] {
            let h = headers(&[("origin", o), ("x-bp-csrf", "1")]);
            assert!(check_csrf(ORIGIN, &Method::PUT, &h).is_err(), "{o}");
        }
    }

    #[test]
    fn csrf_allows_plain_reads_but_not_cross_site_websockets() {
        assert!(check_csrf(ORIGIN, &Method::GET, &headers(&[])).is_ok());
        assert!(check_csrf(ORIGIN, &Method::GET, &headers(&[("origin", ORIGIN)])).is_ok());
        assert!(check_csrf(ORIGIN, &Method::GET, &headers(&[("origin", "https://evil.example")])).is_err());
        assert!(check_csrf(ORIGIN, &Method::GET, &headers(&[("upgrade", "websocket")])).is_err());
        assert!(check_csrf(ORIGIN, &Method::GET, &headers(&[("upgrade", "websocket"), ("origin", "https://evil.example")])).is_err());
        assert!(check_csrf(ORIGIN, &Method::GET, &headers(&[("upgrade", "websocket"), ("origin", ORIGIN)])).is_ok());
    }

    #[test]
    fn header_parsing() {
        assert_eq!(bearer_token(&headers(&[("authorization", "Bearer abc")])), Some("abc"));
        assert_eq!(bearer_token(&headers(&[("authorization", "bearer abc")])), Some("abc"));
        assert_eq!(bearer_token(&headers(&[("authorization", "Basic abc")])), None);
        assert_eq!(bearer_token(&headers(&[])), None);
        let h = headers(&[("cookie", "a=1; __Host-bpe_session=tok; b=2")]);
        assert_eq!(cookie(&h, "__Host-bpe_session"), Some("tok"));
        assert_eq!(cookie(&h, "bpe_session"), None);
        assert_eq!(cookie(&h, "c"), None);
    }
}
