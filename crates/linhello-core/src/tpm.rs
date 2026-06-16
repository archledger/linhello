//! TPM2 seal / unseal against a PCR policy.
//!
//! Per operation:
//!   1. Open a TPM context via the resource-manager device.
//!   2. Create a transient SRK under the Owner hierarchy.
//!   3. Build a PolicyPCR digest over the chosen PCRs (or empty for BASIC).
//!   4. Seal the secret as a keyed-hash child of the SRK, with that policy.
//!   5. Marshal public+private blobs into the on-disk envelope.
//!
//! Unseal is the mirror: load the blobs under a fresh SRK, start a policy
//! session, replay PolicyPCR, unseal.
//!
//! Every transient handle (SRK, loaded sealed object, trial session, policy
//! session) is flushed on both success and error paths via scope helpers.
//! TPMs expose only a handful of session/transient-object slots, so leaking
//! them bricks the daemon after a few operations.

use crate::envelope::{PcrValue, PolicyKind, SealedEnvelope};
use crate::policy;
use linhello_common::{LinuxHelloError, Result, SecurityLevel};
use std::convert::TryFrom;
use std::str::FromStr;
use zeroize::Zeroizing;

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{
    HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::tss2_esys::ESYS_TR;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Auth, Digest, KeyedHashScheme, Nonce, PcrSelectionList, PcrSelectionListBuilder, PcrSlot,
    Private, Public, PublicBuilder, PublicKeyRsa, PublicKeyedHashParameters, PublicRsaParameters,
    RsaExponent, RsaScheme, RsaSignature, SensitiveData, Signature, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, TctiNameConf};

use crate::policy::PolicyPlan;
use sha2::{Digest as _, Sha256};

const TCTI_DEFAULT: &str = "device:/dev/tpmrm0";

/// TPM2_PolicyAuthorize command code (big-endian), used to recompute the
/// authorized-policy digest in software (matches what a trial session would
/// produce, without needing a null verification ticket).
const TPM_CC_POLICY_AUTHORIZE: [u8; 4] = [0x00, 0x00, 0x01, 0x6A];

fn tpm_err<E: std::fmt::Display>(e: E) -> LinuxHelloError {
    LinuxHelloError::Tpm(e.to_string())
}

fn open_context() -> Result<Context> {
    let tcti = std::env::var("LINHELLO_TCTI").unwrap_or_else(|_| TCTI_DEFAULT.into());
    let conf = TctiNameConf::from_str(&tcti).map_err(tpm_err)?;
    Context::new(conf).map_err(tpm_err)
}

fn pcr_selection(pcrs: &[u32]) -> Result<PcrSelectionList> {
    let slots: Vec<PcrSlot> = pcrs.iter().map(|&p| pcr_slot(p)).collect::<Result<_>>()?;
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
        .map_err(tpm_err)
}

fn pcr_slot(index: u32) -> Result<PcrSlot> {
    Ok(match index {
        0 => PcrSlot::Slot0,
        1 => PcrSlot::Slot1,
        2 => PcrSlot::Slot2,
        3 => PcrSlot::Slot3,
        4 => PcrSlot::Slot4,
        5 => PcrSlot::Slot5,
        6 => PcrSlot::Slot6,
        7 => PcrSlot::Slot7,
        8 => PcrSlot::Slot8,
        9 => PcrSlot::Slot9,
        10 => PcrSlot::Slot10,
        11 => PcrSlot::Slot11,
        12 => PcrSlot::Slot12,
        13 => PcrSlot::Slot13,
        14 => PcrSlot::Slot14,
        15 => PcrSlot::Slot15,
        16 => PcrSlot::Slot16,
        23 => PcrSlot::Slot23,
        other => return Err(LinuxHelloError::Tpm(format!("unsupported PCR {other}"))),
    })
}

fn srk_template() -> Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(tpm_err)?;

    let params = PublicRsaParameters::new(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaScheme::create(tss_esapi::interface_types::algorithm::RsaSchemeAlgorithm::Null, None)
            .map_err(tpm_err)?,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    );

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_rsa_parameters(params)
        .with_rsa_unique_identifier(tss_esapi::structures::PublicKeyRsa::default())
        .build()
        .map_err(tpm_err)
}

/// Read the SHA-256 values for `pcrs` and return them in the same order. We
/// stash these in the envelope so an unseal failure can point at the PCR
/// that shifted.
fn read_pcr_values(ctx: &mut Context, pcrs: &[u32]) -> Result<Vec<PcrValue>> {
    let mut out = Vec::with_capacity(pcrs.len());
    for &p in pcrs {
        let sel = pcr_selection(&[p])?;
        let (_c, _s, digests) = ctx.pcr_read(sel).map_err(tpm_err)?;
        let value = digests
            .value()
            .first()
            .map(|d| d.value().to_vec())
            .unwrap_or_default();
        out.push(PcrValue { pcr: p, value });
    }
    Ok(out)
}

/// Run `body` with an auth session of `kind`; flush the session on the way
/// out regardless of whether `body` succeeded. Also clears `ctx.sessions()`
/// if `body` had set them, so a failure doesn't leave stale defaults behind.
fn with_session<T>(
    ctx: &mut Context,
    kind: SessionType,
    body: impl FnOnce(&mut Context, AuthSession) -> Result<T>,
) -> Result<T> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            kind,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(tpm_err)?
        .ok_or_else(|| LinuxHelloError::Tpm("start_auth_session returned None".into()))?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    if let Err(e) = ctx.tr_sess_set_attributes(session, attrs, mask) {
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        return Err(tpm_err(e));
    }
    let result = body(ctx, session);
    ctx.clear_sessions();
    let _ = ctx.flush_context(SessionHandle::from(session).into());
    result
}

/// Same pattern for a transient key created by `spawn`.
fn with_handle<T, H>(
    ctx: &mut Context,
    spawn: impl FnOnce(&mut Context) -> Result<H>,
    body: impl FnOnce(&mut Context, &H) -> Result<T>,
) -> Result<T>
where
    H: Copy + Into<ObjectHandle>,
{
    let handle = spawn(ctx)?;
    let result = body(ctx, &handle);
    let _ = ctx.flush_context(handle.into());
    result
}

/// Compute the PolicyPCR digest for a given PCR selection using a trial
/// session. The digest is what the sealed object commits to.
fn compute_policy_digest(ctx: &mut Context, pcrs: Option<&PcrSelectionList>) -> Result<Digest> {
    with_session(ctx, SessionType::Trial, |ctx, session| {
        if let Some(sel) = pcrs {
            let policy = PolicySession::try_from(session).map_err(tpm_err)?;
            ctx.policy_pcr(policy, Digest::default(), sel.clone())
                .map_err(tpm_err)?;
        }
        let policy = PolicySession::try_from(session).map_err(tpm_err)?;
        ctx.policy_get_digest(policy).map_err(tpm_err)
    })
}

fn sealed_template(policy_digest: Digest) -> Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .build()
        .map_err(tpm_err)?;

    let params = PublicKeyedHashParameters::new(KeyedHashScheme::Null);

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(policy_digest)
        .with_keyed_hash_parameters(params)
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(tpm_err)
}

fn create_srk(ctx: &mut Context) -> Result<KeyHandle> {
    let tmpl = srk_template()?;
    let primary = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, tmpl, None, None, None, None)
        })
        .map_err(tpm_err)?;
    Ok(primary.key_handle)
}

/// Owner-hierarchy persistent handle where linhello caches its SRK. In the
/// owner persistent range (0x81000000–0x817FFFFF) but deliberately distinct
/// from the conventional 0x81000001 SRK, so we never collide with another
/// stack's storage key. Override with `LINHELLO_SRK_HANDLE` (hex) if needed.
const PERSISTENT_SRK_HANDLE: u32 = 0x8101_0001;

fn persistent_srk_handle() -> Result<PersistentTpmHandle> {
    let raw = std::env::var("LINHELLO_SRK_HANDLE")
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(PERSISTENT_SRK_HANDLE);
    PersistentTpmHandle::new(raw).map_err(tpm_err)
}

/// Get linhello's SRK, persisting it on first use.
///
/// `create_primary` over [`srk_template`] is deterministic (same owner seed +
/// template ⇒ the same key), but on some TPMs — notably slow firmware TPMs —
/// deriving an RSA-2048 primary costs >10s (measured 12.7s on one fTPM). Paying
/// that on every seal/unseal made face-unlock exceed the PAM client's timeout.
/// We instead derive it once and `evict_control` it to a persistent handle;
/// every later call just loads that handle. The persisted key is bit-for-bit
/// identical to the old transient one, so envelopes sealed before this change
/// still load — no re-seal needed.
///
/// Returns the handle and whether it is persistent (a persistent handle must
/// NOT be flushed by the caller).
fn load_or_create_srk(ctx: &mut Context) -> Result<(KeyHandle, bool)> {
    let persistent = persistent_srk_handle()?;

    // Fast path: already persisted — get an ESYS handle for the persistent key.
    if let Ok(object) = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
        // ESYS only tracks an entity's auth for handles IT created; a handle
        // obtained via tr_from_tpm_public starts with no auth, so loading a
        // child under it fails with TPM_RC_AUTH_UNAVAILABLE. Our SRK was created
        // with an empty authValue, so tell ESYS exactly that.
        ctx.tr_set_auth(object, Auth::default()).map_err(tpm_err)?;
        return Ok((KeyHandle::from(ESYS_TR::from(object)), true));
    }

    // First run: derive the primary (the one-time slow step) and persist it so
    // every subsequent open is a cheap handle load.
    let transient = create_srk(ctx)?;
    let persisted = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                transient.into(),
                Persistent::Persistent(persistent),
            )
        })
        .map_err(tpm_err)?;
    // Drop the transient copy; the persistent object now lives in TPM NV.
    let _ = ctx.flush_context(transient.into());
    // Same as above: set the empty auth on the freshly-persisted handle.
    ctx.tr_set_auth(persisted, Auth::default()).map_err(tpm_err)?;
    Ok((KeyHandle::from(ESYS_TR::from(persisted)), true))
}

/// Run `body` with linhello's persistent SRK as the parent key. Unlike
/// [`with_handle`], it never flushes the SRK — persistence is the whole point
/// (avoids re-deriving a slow RSA primary on every call).
fn with_srk<T>(
    ctx: &mut Context,
    body: impl FnOnce(&mut Context, &KeyHandle) -> Result<T>,
) -> Result<T> {
    let (srk, persistent) = load_or_create_srk(ctx)?;
    let result = body(ctx, &srk);
    if !persistent {
        let _ = ctx.flush_context(srk.into());
    }
    result
}

/// Seal `secret` under the policy plan chosen for this machine's current
/// state ([`policy::plan`]). This is the entry point new code should use — it
/// picks the signed (authorized) policy when available and falls back to a
/// stable PCR-7 literal otherwise.
pub fn seal_secret(secret: &[u8]) -> Result<SealedEnvelope> {
    seal_with_plan(secret, &policy::plan())
}

/// Seal `secret` under an explicit plan.
pub fn seal_with_plan(secret: &[u8], plan: &PolicyPlan) -> Result<SealedEnvelope> {
    match plan {
        PolicyPlan::Authorized {
            pcrs,
            pubkey_pem,
            policy_ref,
        } => seal_authorized(secret, pcrs, pubkey_pem, policy_ref),
        PolicyPlan::Literal { pcrs } => seal_literal(secret, pcrs),
        PolicyPlan::None => seal_literal(secret, &[]),
    }
}

/// Back-compat shim: seal under a literal PolicyPCR over the PCRs implied by
/// `level`. Prefer [`seal_secret`].
pub fn seal(secret: &[u8], level: SecurityLevel) -> Result<SealedEnvelope> {
    seal_literal(secret, policy::pcrs_for(level))
}

/// Seal `secret` under a literal `PolicyPCR` over `pcrs` (empty ⇒ no binding).
fn seal_literal(secret: &[u8], pcrs: &[u32]) -> Result<SealedEnvelope> {
    let pcrs = pcrs.to_vec();
    let mut ctx = open_context()?;

    let pcr_values = read_pcr_values(&mut ctx, &pcrs)?;

    with_srk(&mut ctx, |ctx, srk| {
        let selection = if pcrs.is_empty() {
            None
        } else {
            Some(pcr_selection(&pcrs)?)
        };
        let policy_digest = compute_policy_digest(ctx, selection.as_ref())?;
        let tmpl = sealed_template(policy_digest)?;

        let sensitive = SensitiveData::try_from(secret.to_vec()).map_err(tpm_err)?;
        let created = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(*srk, tmpl, None, Some(sensitive), None, None)
            })
            .map_err(tpm_err)?;

        Ok(SealedEnvelope {
            version: crate::envelope::CURRENT_VERSION,
            mode: PolicyPlan::Literal { pcrs: pcrs.clone() }.security_level(),
            pcrs: pcrs.clone(),
            policy: PolicyKind::PcrLiteral,
            public: created.out_public.marshall().map_err(tpm_err)?,
            private: created.out_private.to_vec(),
            pcr_values: pcr_values.clone(),
        })
    })
}

/// Seal `secret` under a `PolicyAuthorize` over `pubkey_pem`. The object's
/// `authPolicy` commits only to the signing key's Name (not to any concrete
/// PCR value), so any PCR state for which a valid signature exists can unseal —
/// the basis for surviving kernel updates without a reseal.
///
/// HARDWARE-VALIDATION PENDING: the seal/unseal round-trip and systemd
/// signature-convention (empty `policy_ref`, aHash = H(policy‖ref)) must be
/// confirmed on a real TPM before this path is enabled in production. The
/// software digest math below mirrors the TPM2 spec's PolicyAuthorize update.
fn seal_authorized(
    secret: &[u8],
    pcrs: &[u32],
    pubkey_pem: &str,
    policy_ref: &[u8],
) -> Result<SealedEnvelope> {
    // Only ever bind to the pinned trusted signing key. The plan layer already
    // selects this key via `load_pubkey_pem`, but enforce it here too so no
    // caller can seal `Full` under an untrusted key.
    crate::pcrsig::ensure_trusted_pubkey(pubkey_pem)?;

    let mut ctx = open_context()?;
    let pcr_values = read_pcr_values(&mut ctx, pcrs)?;

    // The authorized policy depends only on the signing key's Name + policyRef.
    // Load the public key to obtain its TPM Name, then compute the digest.
    let key_name = with_handle(
        &mut ctx,
        |ctx| load_external_pubkey(ctx, pubkey_pem),
        |ctx, kh| ctx.tr_get_name((*kh).into()).map_err(tpm_err),
    )?;
    let auth_policy = authorize_policy_digest(key_name.value(), policy_ref)?;

    with_srk(&mut ctx, |ctx, srk| {
        let tmpl = sealed_template(auth_policy.clone())?;
        let sensitive = SensitiveData::try_from(secret.to_vec()).map_err(tpm_err)?;
        let created = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(*srk, tmpl, None, Some(sensitive), None, None)
            })
            .map_err(tpm_err)?;

        Ok(SealedEnvelope {
            version: crate::envelope::CURRENT_VERSION,
            mode: SecurityLevel::Full,
            pcrs: pcrs.to_vec(),
            policy: PolicyKind::Authorized {
                pubkey_pem: pubkey_pem.to_string(),
                policy_ref: policy_ref.to_vec(),
            },
            public: created.out_public.marshall().map_err(tpm_err)?,
            private: created.out_private.to_vec(),
            pcr_values: pcr_values.clone(),
        })
    })
}

pub fn unseal(env: &SealedEnvelope) -> Result<Zeroizing<Vec<u8>>> {
    match &env.policy {
        PolicyKind::PcrLiteral => unseal_literal(env),
        PolicyKind::Authorized {
            pubkey_pem,
            policy_ref,
        } => unseal_authorized(env, pubkey_pem, policy_ref),
    }
}

// The `(|| { … })()` blocks below deliberately scope a fallible region so the
// surrounding handle/session is flushed on every exit path; not a code smell.
#[allow(clippy::redundant_closure_call)]
fn unseal_literal(env: &SealedEnvelope) -> Result<Zeroizing<Vec<u8>>> {
    let mut ctx = open_context()?;

    with_srk(&mut ctx, |ctx, srk| {
        let public = Public::unmarshall(&env.public).map_err(tpm_err)?;
        let private = Private::try_from(env.private.clone()).map_err(tpm_err)?;

        let sealed_handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(*srk, private, public))
            .map_err(tpm_err)?;

        let result: Result<Zeroizing<Vec<u8>>> = (|| {
            with_session(ctx, SessionType::Policy, |ctx, session| {
                if !env.pcrs.is_empty() {
                    let sel = pcr_selection(&env.pcrs)?;
                    let policy = PolicySession::try_from(session).map_err(tpm_err)?;
                    ctx.policy_pcr(policy, Digest::default(), sel)
                        .map_err(tpm_err)?;
                }

                let data = ctx
                    .execute_with_session(Some(session), |ctx| ctx.unseal(sealed_handle.into()))
                    .map_err(|e| policy_aware_err(e, env))?;

                Ok(Zeroizing::new(data.to_vec()))
            })
        })();

        let _ = ctx.flush_context(sealed_handle.into());
        result
    })
}

/// Unseal a `PolicyAuthorize`-bound object: replay `PolicyPCR` over the current
/// PCRs, find a signature whose authorized policy matches the resulting digest,
/// verify it under the public key, and run `PolicyAuthorize` to satisfy the
/// object's policy. Survives kernel updates so long as a signature exists for
/// the new PCR state.
///
/// HARDWARE-VALIDATION PENDING — see [`seal_authorized`].
#[allow(clippy::redundant_closure_call)]
fn unseal_authorized(
    env: &SealedEnvelope,
    pubkey_pem: &str,
    policy_ref: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // The object's authPolicy commits only to the signing key's Name, NOT to a
    // concrete PCR set — so the PCR set replayed below is taken from the
    // (on-disk, tamperable) envelope. Pin it to the constant the authorized
    // path always seals with, so a rewritten envelope cannot steer unsealing
    // onto an attacker-chosen PCR set for which they happen to hold a signed
    // policy.
    if env.pcrs.as_slice() != crate::policy::AUTHORIZED_PCRS {
        return Err(LinuxHelloError::Policy(format!(
            "authorized envelope binds unexpected PCR set {:?} (expected {:?}); refusing to unseal",
            env.pcrs,
            crate::policy::AUTHORIZED_PCRS,
        )));
    }
    // Pin the signing key recorded in the envelope to the trusted anchor before
    // it is loaded into the TPM. `verify_signature` already enforces the key
    // cryptographically, but this fails closed earlier and with a clear message
    // if an envelope was rewritten to reference a different (attacker) key.
    crate::pcrsig::ensure_trusted_pubkey(pubkey_pem)?;
    let mut ctx = open_context()?;

    with_srk(&mut ctx, |ctx, srk| {
        let public = Public::unmarshall(&env.public).map_err(tpm_err)?;
        let private = Private::try_from(env.private.clone()).map_err(tpm_err)?;
        let sealed_handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(*srk, private, public))
            .map_err(tpm_err)?;

        let result: Result<Zeroizing<Vec<u8>>> = (|| {
            with_session(ctx, SessionType::Policy, |ctx, session| {
                let policy_session = PolicySession::try_from(session).map_err(tpm_err)?;

                // 1. Fold the current PCR state into the session and read the
                //    resulting policy digest — this is the "approved policy"
                //    that must carry a valid signature.
                let sel = pcr_selection(&env.pcrs)?;
                ctx.policy_pcr(policy_session, Digest::default(), sel)
                    .map_err(tpm_err)?;
                let approved = ctx.policy_get_digest(policy_session).map_err(tpm_err)?;

                // 2. Find a signature for exactly this PCR set + policy digest.
                let sigs = crate::pcrsig::load_signatures(crate::pcrsig::DEFAULT_BANK)?;
                let sig = crate::pcrsig::find_for_policy(&sigs, &env.pcrs, approved.value())
                    .ok_or_else(|| {
                        LinuxHelloError::Policy(
                            "no signed PCR policy matches the current boot state \
                             (kernel/UKI not yet enrolled — re-sign required)"
                                .into(),
                        )
                    })?;

                // 3. Verify the signature over aHash = H(approvedPolicy ‖ ref)
                //    under the public key, yielding a verification ticket.
                let key_handle = load_external_pubkey(ctx, pubkey_pem)?;
                let verify_result: Result<Zeroizing<Vec<u8>>> = (|| {
                    let key_name = ctx.tr_get_name(key_handle.into()).map_err(tpm_err)?;
                    let a_hash = a_hash(approved.value(), policy_ref)?;
                    let signature = Signature::RsaSsa(
                        RsaSignature::create(
                            HashingAlgorithm::Sha256,
                            PublicKeyRsa::try_from(sig.sig.clone()).map_err(tpm_err)?,
                        )
                        .map_err(tpm_err)?,
                    );
                    let ticket = ctx
                        .verify_signature(key_handle, a_hash, signature)
                        .map_err(tpm_err)?;

                    // 4. Authorize: rewrite the session policy to the key-bound
                    //    value, which equals the object's authPolicy.
                    let ref_nonce = Nonce::try_from(policy_ref.to_vec()).map_err(tpm_err)?;
                    ctx.policy_authorize(
                        policy_session,
                        approved.clone(),
                        ref_nonce,
                        &key_name,
                        ticket,
                    )
                    .map_err(tpm_err)?;

                    // 5. Unseal under the now-satisfied policy session.
                    let data = ctx
                        .execute_with_session(Some(session), |ctx| {
                            ctx.unseal(sealed_handle.into())
                        })
                        .map_err(|e| policy_aware_err(e, env))?;
                    Ok(Zeroizing::new(data.to_vec()))
                })();
                let _ = ctx.flush_context(key_handle.into());
                verify_result
            })
        })();

        let _ = ctx.flush_context(sealed_handle.into());
        result
    })
}

/// Load an external RSA public key (SPKI PEM) into the TPM under the Owner
/// hierarchy so its Name can be taken and signatures verified against it (the
/// hierarchy must be non-NULL for the verification ticket to be usable by
/// `TPM2_PolicyAuthorize` — see the note in the body).
fn load_external_pubkey(ctx: &mut Context, pubkey_pem: &str) -> Result<KeyHandle> {
    let public = rsa_pem_to_public(pubkey_pem)?;
    // Load under the Owner hierarchy, NOT Null. TPM2_VerifySignature against a
    // key in the NULL hierarchy yields a "null ticket" (empty digest), which
    // TPM2_PolicyAuthorize then rejects with TPM_RC_VALUE on checkTicket. A
    // non-NULL hierarchy makes VerifySignature return a real ticket that
    // PolicyAuthorize accepts. The key Name (and thus the sealed authPolicy) is
    // independent of the hierarchy, so seal/unseal stay consistent.
    ctx.load_external_public(public, Hierarchy::Owner)
        .map_err(tpm_err)
}

/// Build a tss-esapi `Public` for an external RSA verification key from a
/// SubjectPublicKeyInfo PEM.
fn rsa_pem_to_public(pubkey_pem: &str) -> Result<Public> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let key = rsa::RsaPublicKey::from_public_key_pem(pubkey_pem)
        .map_err(|e| LinuxHelloError::Policy(format!("parse PCR public key: {e}")))?;
    let modulus = key.n().to_bytes_be();
    let key_bits = match modulus.len() * 8 {
        2048 => RsaKeyBits::Rsa2048,
        3072 => RsaKeyBits::Rsa3072,
        4096 => RsaKeyBits::Rsa4096,
        other => {
            return Err(LinuxHelloError::Policy(format!(
                "unsupported PCR key size: {other} bits"
            )))
        }
    };
    let exponent = {
        let e = key.e().to_bytes_be();
        let mut buf = [0u8; 4];
        if e.len() > 4 {
            return Err(LinuxHelloError::Policy("PCR key exponent too large".into()));
        }
        buf[4 - e.len()..].copy_from_slice(&e);
        RsaExponent::create(u32::from_be_bytes(buf)).map_err(tpm_err)?
    };

    let attrs = ObjectAttributesBuilder::new()
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_restricted(false)
        .with_fixed_tpm(false)
        .with_fixed_parent(false)
        .with_sensitive_data_origin(false)
        .build()
        .map_err(tpm_err)?;

    // Null scheme: the verification scheme (RSASSA/SHA-256) is supplied per
    // operation in the `Signature` passed to `verify_signature`.
    let params = PublicRsaParameters::new(
        SymmetricDefinitionObject::Null,
        RsaScheme::create(RsaSchemeAlgorithm::Null, None).map_err(tpm_err)?,
        key_bits,
        exponent,
    );

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_rsa_parameters(params)
        .with_rsa_unique_identifier(PublicKeyRsa::try_from(modulus).map_err(tpm_err)?)
        .build()
        .map_err(tpm_err)
}

/// Compute the object `authPolicy` produced by `TPM2_PolicyAuthorize` from an
/// empty starting policy: it resets to a zero digest, then folds in the command
/// code + the signing key's Name, then the policyRef. Mirrors the TPM2 spec so
/// we don't need a null verification ticket in a trial session.
fn authorize_policy_digest(key_name: &[u8], policy_ref: &[u8]) -> Result<Digest> {
    let mut h = Sha256::new();
    h.update([0u8; 32]); // reset to Zero Digest (SHA-256 size)
    h.update(TPM_CC_POLICY_AUTHORIZE);
    h.update(key_name);
    let d1 = h.finalize();

    let mut h2 = Sha256::new();
    h2.update(d1);
    h2.update(policy_ref);
    Digest::try_from(h2.finalize().to_vec()).map_err(tpm_err)
}

/// aHash = H(approvedPolicy ‖ policyRef), the message a PolicyAuthorize
/// signature must cover.
fn a_hash(approved_policy: &[u8], policy_ref: &[u8]) -> Result<Digest> {
    let mut h = Sha256::new();
    h.update(approved_policy);
    h.update(policy_ref);
    Digest::try_from(h.finalize().to_vec()).map_err(tpm_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_digest_deterministic_and_ref_sensitive() {
        let name = [0x00, 0x0b]
            .iter()
            .chain([0xab; 32].iter())
            .copied()
            .collect::<Vec<u8>>();
        let d1 = authorize_policy_digest(&name, &[]).unwrap();
        let d2 = authorize_policy_digest(&name, &[]).unwrap();
        assert_eq!(d1.value(), d2.value(), "must be deterministic");
        assert_eq!(d1.value().len(), 32);
        let d3 = authorize_policy_digest(&name, &[0x01]).unwrap();
        assert_ne!(d1.value(), d3.value(), "policyRef must change the digest");
        // A different key Name must change the authPolicy.
        let d4 = authorize_policy_digest(&[0x00, 0x0b, 0x00], &[]).unwrap();
        assert_ne!(d1.value(), d4.value());
    }

    #[test]
    fn a_hash_is_32_bytes_and_ref_sensitive() {
        let a = a_hash(&[0xaa; 32], &[]).unwrap();
        let b = a_hash(&[0xaa; 32], &[0x01]).unwrap();
        assert_eq!(a.value().len(), 32);
        assert_ne!(a.value(), b.value());
    }

    #[test]
    fn rsa_spki_pem_converts_to_public() {
        use rsa::pkcs8::{EncodePublicKey, LineEnding};
        let mut rng = rand::thread_rng();
        let sk = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let pem = rsa::RsaPublicKey::from(&sk)
            .to_public_key_pem(LineEnding::LF)
            .expect("pem");
        // Building the Public must succeed (modulus size + exponent handling).
        assert!(rsa_pem_to_public(&pem).is_ok());
    }
}

/// If the TSS error looks like a policy mismatch, enrich it with the list of
/// PCRs that have changed since seal time.
fn policy_aware_err<E: std::fmt::Display>(e: E, env: &SealedEnvelope) -> LinuxHelloError {
    let base = e.to_string();
    match diagnose_pcrs(env) {
        Ok(changed) if !changed.is_empty() => {
            LinuxHelloError::Policy(format!("{base}: PCR mismatch: {changed:?} changed since seal"))
        }
        _ => LinuxHelloError::Tpm(base),
    }
}

/// Compare current PCR values against those stored in the envelope. Returns
/// the list of PCRs whose SHA-256 differs. Empty means no drift (or no
/// values were captured at seal time).
pub fn diagnose_pcrs(env: &SealedEnvelope) -> Result<Vec<u32>> {
    if env.pcr_values.is_empty() {
        return Ok(Vec::new());
    }
    let mut ctx = open_context()?;
    let current = read_pcr_values(&mut ctx, &env.pcrs)?;
    Ok(env
        .pcr_values
        .iter()
        .zip(current.iter())
        .filter(|(expected, now)| expected.pcr == now.pcr && expected.value != now.value)
        .map(|(expected, _)| expected.pcr)
        .collect())
}
