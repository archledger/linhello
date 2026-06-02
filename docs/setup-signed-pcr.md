# Enabling signed PCR policy (Authorized tier) on Arch Linux

By default LinuxHello binds its TPM secrets to **PCR 7 only** (Secure Boot state),
which is stable across kernel updates. This guide adds the **signed PCR-11
policy** (the `Authorized` tier) so the binding also covers the exact UKI
(kernel + initrd + cmdline) — Windows-Hello-class granularity — *without*
breaking on kernel updates, because each new UKI ships a fresh signature.

It mirrors how `systemd-cryptenroll --tpm2-public-key` keeps LUKS unlocking
across kernel updates. LinuxHello consumes the **same** artifacts systemd produces:
`/run/systemd/tpm2-pcr-signature.json` + `/run/systemd/tpm2-pcr-public-key.pem`.

> Prerequisite: Secure Boot ON and a **UKI** boot (LinuxHello `linhello doctor`
> should show Boot mode = UKI). Without a UKI there is nothing to sign PCR 11
> over; you stay on the PCR-7 tier, which is fine.

---

## 1. Install ukify

```
sudo pacman -S --needed systemd-ukify sbsigntools
```

## 2. Generate a PCR signing keypair

This key authorizes PCR states. Treat it like a code-signing key — ideally keep
the **private** half offline; it only needs to be present when a UKI is built.

```
sudo install -d -m 700 /etc/kernel
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out /etc/kernel/tpm2-pcr-private-key.pem
sudo chmod 600 /etc/kernel/tpm2-pcr-private-key.pem
sudo openssl rsa -pubout \
    -in  /etc/kernel/tpm2-pcr-private-key.pem \
    -out /etc/kernel/tpm2-pcr-public-key.pem
```

> Security note: while the private key is on the local disk and root-readable,
> an attacker with root (or who can mount the disk offline) could sign an
> arbitrary PCR state. LinuxHello mitigates this by *also* binding **PCR 7** in the
> authorized policy (`AUTHORIZED_PCRS = [7, 11]`): an offline/rogue-OS boot
> changes PCR 7, so no signature for that state will match. For higher
> assurance, keep the private key offline (sign UKIs on a separate machine) or
> on a hardware token.

## 3. Point kernel-install/ukify at the keys

Create `/etc/kernel/uki.conf` (copy the template from
`/usr/lib/kernel/uki.conf` if present) with:

```ini
[UKI]
PCRBanks=sha256
PCRPrivateKey=/etc/kernel/tpm2-pcr-private-key.pem
PCRPublicKey=/etc/kernel/tpm2-pcr-public-key.pem
PCRPKey=/etc/kernel/tpm2-pcr-public-key.pem
```

If you build UKIs directly via a mkinitcpio preset + `ukify`, pass the
equivalent flags instead:
`--pcr-private-key=… --pcr-public-key=… --pcr-banks=sha256 --pcrpkey=…`.

## 4. Rebuild the UKI and reboot

```
sudo mkinitcpio -P            # or your kernel-install path
sudo bootctl status           # sanity-check the UKI
sudo reboot
```

After reboot, confirm systemd-stub exposed the artifacts:

```
ls -l /run/systemd/tpm2-pcr-signature.json /run/systemd/tpm2-pcr-public-key.pem
```

Both must exist. `linhello doctor` should now report **Signed PCR policy: [ OK ]**.

## 5. Re-seal LinuxHello onto the Authorized tier

LinuxHello picks the tier at seal time. Once the artifacts exist, re-seal so the
secrets move from PCR-7-literal to signed PCR-11:

```
sudo linhello reseal-user-envelopes --user "$USER"   # password + template key
# If a new key/template is needed (e.g. coming from drift), re-enroll instead:
#   sudo linhello enroll --user "$USER" --reset
#   sudo linhello seal-password "$USER"
linhello status      # security level should now read "Full"
linhello diag        # tracked PCRs should include 11; no drift
```

## 6. Validate update-resilience (the whole point)

```
sudo pacman -S linux        # or wait for the next kernel update
sudo reboot
linhello verify --user "$USER"   # must still match — NO re-seal, NO re-enroll
```

Because the new UKI shipped a fresh `tpm2-pcr-signature.json`, the new PCR 11
value is already authorized.

---

## How LinuxHello uses these files

- `linhello-core::pcrsig` discovers `tpm2-pcr-signature.json` /
  `tpm2-pcr-public-key.pem` (search order `/etc/systemd`, `/run/systemd`,
  `/usr/lib/systemd`; override with `LINHELLO_PCR_SIGNATURE` / `LINHELLO_PCR_PUBKEY`).
- `linhello-core::policy::plan()` selects `Authorized([7,11])` when Secure Boot is
  on, the boot mode is UKI, and both artifacts are present; otherwise it falls
  back to the stable `Literal([7])` tier.
- At unseal, `tpm::unseal_authorized` replays `PolicyPCR(7,11)`, finds the
  signature whose authorized policy matches the resulting digest, verifies it
  with `TPM2_VerifySignature`, and satisfies the object policy with
  `TPM2_PolicyAuthorize`.

### ⚠️ Status: hardware-validation pending

The Authorized seal/unseal path is implemented to the TPM2 spec but has **not
yet been validated end-to-end on real hardware**. Two assumptions about
systemd's signing convention need confirming against your box (and possibly
`systemd`'s `src/shared/tpm2-util.c`):

1. The policy reference is **empty** (`policy_ref = []`).
2. The signed message is `aHash = H(approvedPolicy ‖ policy_ref)` (RSASSA /
   SHA-256).

If the `Authorized` path errors at unseal after setup, capture
`journalctl -u linhellod` around the failure — the message will indicate whether
it was signature verification (convention mismatch) or no-matching-signature
(prediction/phase mismatch), which tells us which assumption to adjust. Until
then the PCR-7 tier remains the safe, working default.
