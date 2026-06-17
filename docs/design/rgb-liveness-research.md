# RGB-only face liveness & tiered policy — research basis

Evidence behind [`tiered-biometric-policy.md`](tiered-biometric-policy.md).
Synthesised 2026-06-17 from a multi-source, adversarially-verified review (25
sources, 111 candidate claims, 25 verified — 24 confirmed, 1 refuted). Sources
are predominantly primary peer-reviewed (CVPR/ECCV/TPAMI/NDSS) and authoritative
specs (AOSP, FIDO v4.0 2024, Microsoft Learn).

## TL;DR
RGB-only face unlock is defensible **only** as an explicit convenience tier,
gated entirely out of credential release and privilege elevation. No software-
only RGB pipeline meets a "secure" bar on uncertifiable webcams; the standards
themselves separate "convenience" from "strong (crypto-capable)" biometrics, and
all certified secure face systems use IR/depth hardware.

## Key verified findings

1. **RGB software PAD collapses cross-camera.** Best single-frame RGB model
   (AENet) on CelebA-Spoof: ACER **1.63%** in-dataset, but **11.9–14.3% HTER**
   trained CelebA-Spoof → tested CASIA-MFSD (~7–13× worse). Traditional models
   Replay-Attack → CASIA-MFSD exceed **20% HTER** "due to serious lighting and
   camera resolution variations." Benchmarks have saturated (ResNet-18 hits
   ~100% recall in-dataset), so headline numbers don't reflect the wild.
   *(arXiv 2007.12342, 2212.03680, 2112.14796; CVPRW-2023 Liu)*
2. **Even best domain-generalisation RGB PAD leaves ~10% HTER** on unseen targets
   (SSDG 10.44%, SSAN 10.00%, OCIM→C). Newest CLIP/ViT methods (FLIP, CFPL) reach
   ~3–6% HTER — but still benchmark leave-one-out, not arbitrary webcams, and far
   from the near-zero needed to gate privilege. *(arXiv 2212.03680, 2203.14325)*
3. **Single-frame passive PAD is, by design, for low-value transactions on
   trusted/secured sensors only** — not high-value or untrusted-sensor use; robust
   PAD "should harness sensors for active sensing." Binary live/spoof CNNs latch
   onto cues like the screen bezel rather than true liveness, motivating
   depth+rPPG auxiliary supervision. This is directly load-bearing: a Linux UVC
   webcam is untrusted, and releasing a TPM-sealed password is high-value.
   *(arXiv 2406.03684; CVPR-2018 Liu "Learning Deep Models")*
4. **Multimodal RGB+NIR+Depth is the most robust; RGB alone is weakest.**
   ChaLearn FAS@CVPR2020: multimodal **1.02% ACER** vs single-RGB **4.84% ACER**.
   Specialised sensors "offer an acceptable level of performance"; the universally
   available device is "a plain RGB camera lacking any specific sensor" — the
   reason linhello must support RGB-only *and* the reason it can't call it secure.
   *(arXiv 2212.03680, 2112.14796)*
5. **Certified secure systems all use IR/depth; IR specifically defeats
   photo/LCD-replay.** Windows Hello "utilizes a camera specially configured for
   near infrared"; IR "doesn't display in photos … or on an LCD display." The
   April 2025 update requires **both** IR and RGB. (Even IR isn't absolute:
   CVE-2021-34466 beat Hello with a crafted ~340×340 NIR printout.)
   *(Microsoft Learn — Windows Hello face authentication)*
6. **The standards encode linhello's exact tiering.** Android **Class 3 (Strong)**
   is the only class allowed Keystore/crypto integration: SAR ≤7%, FAR 1/50k.
   **Class 1 (Convenience)**: SAR 20–30%, may run an insecure pipeline, **no app
   API, device-unlock only, never yields a biometric-bound key.** FIDO Biometric
   Component Certification: IAPAR ≤15% (BioLevel 1) / ≤7% (BioLevel 2), per-PAI-
   species across 6+8 species. ⇒ RGB-only = Class-1-equivalent (device-unlock
   only); IR-gated aspires to Class-3. **Because linhello releases the sealed
   password on match, any tier that releases it is functionally crypto-bound and
   must demand the stronger modality.** *(AOSP biometric/measure + keystore/
   features; FIDO Biometrics-Requirements v4.0)*
7. **Active screen-"face-flashing" works but is unavailable to linhello.** Face
   Flashing (NDSS 2018) reaches 98.8% (97.3% worst-case) RGB-only and discriminates
   2D vs 3D — but it requires controlled display output at the subject. The
   linhello daemon has **no display** (confined) and the lock screen is owned by
   the compositor → not deployable. (Its timing-replay sub-claim was **refuted
   0–3** in verification.) *(CUHK Face Flashing, NDSS 2018)*

## Refuted / not relied upon
- Face Flashing's timing-based replay defense ("zero false positive, 99.2%") —
  **refuted 0–3**; do not cite.

## Caveats
- PAD is fast-moving; the ~10% DG floor is a 2020–2022 figure improved to ~3–6%
  by 2023–2024 CLIP/ViT methods *under controlled DG protocols* — treat any single
  benchmark number as a ceiling, not a field guarantee on commodity webcams.
- Cross-dataset evidence is strongest for **print/screen-replay** (CASIA-MFSD has
  no 3D masks); 3D-mask cross-camera numbers are thinner.
- One advocacy source (arXiv 2406.03684) is a non-peer-reviewed preprint arguing
  its own thesis, but corroborated by the broader generalisation-failure literature.

## Primary sources
- arXiv 2007.12342, 2212.03680, 2112.14796, 2203.14325, 2406.03684, 2010.04145, 1902.10311
- CVPR-2018 "Learning Deep Models for Face Anti-Spoofing"; CVPRW-2023 "Attack-Agnostic Deep FAS"
- NDSS-2018 "Face Flashing"; SP-2023 3D-spoof
- AOSP: security/features/biometric{,/measure}, keystore/features
- FIDO Biometrics-Requirements v4.0 (2024); FIDO Authenticator L3+
- NIST SP 800-63B; Microsoft Learn — Windows Hello face authentication
- Howdy (github.com/boltgolt/howdy; Arch wiki) — RGB-only prior art & its photo-bypass class
