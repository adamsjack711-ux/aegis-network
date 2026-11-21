# Studio operator enrollment and approval

**Status on Studio.** This handoff extends the reviewed launcher at `3db1668`.
Jack's local operator UID is **501**. The root-owned ancestry through
`/private/etc` was present and had no additional ACL entries. The directory
`/private/etc/aegis`, its enrollment key, and the create-attempt marker were
absent. Enrollment only installs a public verifier. A signed approval
requires a separate owner decision. [One-shot launcher and controls](studio-phase6-openai-one-shot.md)

## Review the exact create request

- One foreground HTTPS `POST` to `https://api.openai.com/v1/responses`, model
  `gpt-5.4-mini-2026-03-17`, standard tier, `store=false`, no tools, no
  conversation or previous response, at most 512 output tokens, and zero
  retry. The launcher sends the exact 2,914 bytes from
  `~/.aegis-phase6-request-review/m82-ca82ce718189.json`, SHA-256
  `ca82ce718189b2d7ba48137b0220391b09038fa6bbf2d794d825e6b72121085b`.
- The body contains 391 bytes of fixed research instructions, the strict
  advisory reply schema, and a 640-byte synthetic JSON input. The input
  declares `advisory-input-v1`, vulnerability ID `CVE-2099-72537`, fixed alias
  `asset-1`, version `8.6`, and one source `S1` with kind `osv`, digest
  `4b198b662553f839d626f6383ad983590f9134dfb871268dee4b3fee83705f3a` and the
  341-byte source text. That text includes synthetic ID `OSV-2099-72437`,
  the alias, package `PyPI/plumrill-sheet`, introduced/fixed versions
  `8.1`/`8.6`, fixture publication/modification times and a summary about
  separate inventory. The baseline, asset configuration and flag, inventory
  ID and full local asset identity, source URI, local paths, approval
  and receipt stay local.
- Outside the body, OpenAI receives the project bearer credential for HTTPS
  authentication and ordinary request metadata. The request uses JSON accept
  and content-type headers, identity encoding and connection close. Keychain
  contents, the operator signing key and evidence files are outside this
  export.
- Review this project under standard retention unless Jack can verify different
  effective settings. `store=false` disables normal saved-response retrieval.
  OpenAI's standard abuse-monitoring logs can contain prompts, responses and
  derived metadata and generally persist up to 30 days, with documented
  exceptions for legal or safety needs. API data is excluded from training
  unless the account opts in to sharing. Confirm the designated project's
  effective retention and data-sharing settings. Zero Data Retention requires
  separate confirmation. Keep the returned local record owner-only with the
  approval and evidence for independent scoring and billing reconciliation.
  [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data) · [Saved response behavior](https://developers.openai.com/api/docs/guides/conversation-state?api-mode=responses)

The recorded successful count was **436 tokens** with HTTP 200. The
replacement receipt `m82-count-bc320ef005ca.replacement.receipt.json` has
SHA-256 `c0c512bb78db723a3beeccde629ee7edd844853c5e6f768ef4ab9d3f3f956984`
and binds the exact 1,958-byte count projection at SHA-256
`bc320ef005cafeae439d0eb80dc5411a9b4e50248a8a46fa5ce25afef0184d3b`.
It contains all six compatible fields from the frozen create request,
including the identical strict schema. The original HTTP 401 count receipt
remains in the record. At the standard published rates, 436 uncached input
tokens and the full 512 output tokens total **$0.002631** before any applicable
additional fee. Jack accepted this calculated-charge basis for the single m82 trial against
the **$0.01 review threshold**. The approval records the estimate and the
residual risk that billed create usage, rates or fees may differ. An unexpected
response usage is refused locally after dispatch, when billing may already
have occurred. The signature carries no billing-ceiling attestation. [Model pricing](https://developers.openai.com/api/docs/models/gpt-5.4-mini) · [Count contract](https://developers.openai.com/api/reference/resources/responses/subresources/input_tokens/methods/count)

## Owner steps

1. **Start one local signing command in Jack's independent offline account.**
   Use the exact candidate and reviewed CPython 3.12 dependencies. Copy in
   only the frozen create file and the replacement receipt. Run from the
   candidate worktree, with control of the terminal and workspace separate
   from the requesting agent. The signer checks the full canonical plan
   digest `452361fc865c1e270ef5d90075d4f577a22085e2268b8c78f7d8eeb25f84d05b`,
   request, sealed fixture and receipt. It records the project retention
   mode and Jack's confirmation that data sharing is off. The signer
   generates a one-time Ed25519 key in memory and pauses to allow public-key
   enrollment. The private key never leaves the signing process.

   ```sh
   (
     set -eu
     umask 077
     review="$HOME/.aegis-phase6-request-review"
     inputs=$(mktemp)
     trap '/bin/rm -f "$inputs"' 0
     git show aec2456:benchmarks/studio-offline-citation-support/unseen-holdout-39d580a/seal/inputs.json > "$inputs"
     PYTHONPATH=src python3.12 -B benchmarks/phase6-offline-fixture-freeze/sign_openai_trial.py \
       "$review/m82-ca82ce718189.json" "$inputs" \
       "$review/m82-count-bc320ef005ca.replacement.receipt.json" "$HOME/phase6-m82-approval"
   )
   ```

2. **Enroll only the public key in Jack's separate Studio administrator
   terminal.** Take the 64-character public hex and expected SHA-256 directly
   from the signing session and set `owner_public_hex` and
   `owner_public_sha256` in that terminal. This initial-enrollment command
   requires fresh sudo authentication and copies from root-owned staging.
   It checks the decoded bytes against the independently transmitted digest.
   The verification transcript must show a root-owned, non-symlink verifier
   and ancestors with no additional writer, including effective ACLs. Return
   the installed digest from Studio to the still-running signer. The signing
   step only proceeds after this readback matches and Jack types
   `APPROVE M82 ESTIMATE AND EXPORT`. The envelope expires 30 minutes after
   signing. Review any existing directory or expired key separately.

   ```sh
   (
     set -eu
     trap '/usr/bin/sudo -k' 0
     /usr/bin/sudo -k /bin/sh -eu -c '
       case "$1$2" in *[!0-9a-f]*) exit 1 ;; esac
       test "${#1}" -eq 64 && test "${#2}" -eq 64
       target=/private/etc/aegis
       test ! -e "$target" && test ! -L "$target" || exit 1
       umask 077
       stage=$(/usr/bin/mktemp -d /private/var/root/aegis-phase6-public.XXXXXX)
       trap "/bin/rm -f \"$stage/verifier\"; /bin/rmdir \"$stage\"" 0
       printf "%s" "$1" | /usr/bin/xxd -r -p > "$stage/verifier"
       test "$(/usr/bin/stat -f %z "$stage/verifier")" -eq 32
       readback=$(/usr/bin/shasum -a 256 "$stage/verifier")
       test "${readback%% *}" = "$2"
       /bin/mkdir -m 0755 "$target"
       /usr/bin/install -o root -g wheel -m 0644 "$stage/verifier" "$target/phase6-openai-operator.pub"
       /bin/ls -lde / /private /private/etc "$target" "$target/phase6-openai-operator.pub"
       /usr/bin/shasum -a 256 "$target/phase6-openai-operator.pub"
     ' sh "$owner_public_hex" "$owner_public_sha256"
   )
   ```

3. **Check the signed artifacts offline on Studio.** Bring the envelope and
   retention record into an owner-controlled directory. From the exact
   launcher worktree, run the verification below as UID 501. It checks
   the signature, retention-record binding, plan, UID, estimate and expiry
   without reading the API credential or consuming the create attempt.

   ```sh
   bundle="$HOME/phase6-m82-approval"
   PYTHONPATH="src:benchmarks/phase6-offline-fixture-freeze" python3.12 -B - "$bundle" <<'PY'
   from datetime import datetime, timezone
   from hashlib import sha256
   import os
   from pathlib import Path
   import sys
   from openai_one_shot import authorize, decode_json, load_owner_key, read_bounded

   directory = Path(sys.argv[1])
   if os.getuid() != 501:
       raise SystemExit("Use the enrolled Studio operator UID 501")
   approval = read_bounded(directory / "phase6-openai-approval.json", 8192)
   envelope = decode_json(approval)
   retention = read_bounded(directory / "retention-review.json", 8192)
   if sha256(retention).hexdigest() != envelope["statement"]["retention_evidence_sha256"]:
       raise SystemExit("Retention evidence hash mismatch")
   bound, expiry = authorize(envelope, load_owner_key(), datetime.now(timezone.utc), os.getuid())
   print("Verified approval", sha256(approval).hexdigest(), "expires", expiry.isoformat())
   print("Local response check", bound, "input tokens maximum; signed billing basis is an estimate")
   PY
   ```

Return the installed public-key digest, approval digest, retention-review digest,
expiry and offline verification result to the coordinator. The coordinator owns
dispatch. This procedure uses no Keychain or API access. The installed key is
public. Treat the signed envelope and local review record as private.
