# The Semantic Supply Chain
## Toward a W3C VCDM Assurance Framework

**A Comparative Risk Analysis of Credential Meaning Distribution in W3C VCDM, SD-JWT VC, and ISO mdoc**

**Working paper for technical and policy discussion**

**Current as of:** 7 May 2026

> [!IMPORTANT]
> **Core thesis**
>
> The broad assertion that "JSON-LD is unsafe because it uses links" is not a valid technical conclusion. A more precise and defensible statement is: **uncontrolled semantic resolution is unsafe**. That statement applies to every credential format. W3C VCDM exposes semantic dependencies through `@context`, `type`, vocabularies, schemas, and related resources. SD-JWT VC moves semantic dependencies to `vct`, Type Metadata, issuer metadata, registries, rulebooks, and local configuration. ISO mdoc moves semantic dependencies to `doctype`, namespaces, data-element definitions, and rulebooks. The assurance question is whether those dependencies are governed, versioned, integrity-protected, locally available, privacy-preserving, auditable, and tied to issuer authorisation.

## Proposed W3C framing

The **W3C VCDM Assurance Framework** is a W3C-native assurance model for verifiable credentials based on the W3C Verifiable Credentials Data Model. It defines assurance levels for W3C VCDM credentials and the control areas needed to use them in regulated and high-trust ecosystems.

This framing is important because high assurance is not only a protocol question. It also depends on how semantic dependencies, issuer and verifier trust, holder binding, wallet assurance, credential status, privacy protections, and conformance evidence are governed. The assurance-level model allows different deployments to select controls that match their risk level: simple credentials may need a smaller control set, while semantically rich enterprise, DPP, supply-chain, Industry 4.0, and trusted-AI credentials need stronger controls over vocabularies, schemas, rulebooks, provenance, and ecosystem governance.

```text
W3C VCDM Assurance Framework
  └── Assurance Levels for W3C VCDM Credentials
        ├── Semantic Dependency Assurance
        ├── Issuer and Verifier Assurance
        ├── Holder Binding and Wallet Assurance
        ├── Status and Revocation Assurance
        ├── Privacy Assurance
        └── Conformance Testing
```

This framework gives standardisation bodies a neutral basis for defining mandatory controls without prescribing a single credential transport protocol or creating unnecessary platform-controlled registration points. It supports the reuse of OpenID4VC, SD-JWT VC, and ISO mdoc where appropriate, while defining W3C-specific controls for semantic dependency assurance in W3C VCDM credentials.

**Audience:** senior cybersecurity architects, eIDAS 2.0 technical experts, EUDI ARF experts, HAIP and OpenID4VC contributors, W3C VC experts, ETSI contributors, and standardisation bodies.

## Document orientation and balance check

This paper is written in an architectural commonality tone. It does not claim that W3C VCDM, SD-JWT VC, or ISO mdoc is categorically superior. It narrows an overbroad security claim and compares the real control planes needed by all three formats.

- **What the paper accepts:** Uncontrolled remote JSON-LD context retrieval is unsafe in high-assurance validation. Context substitution, mutable context documents, privacy leakage, inconsistent JSON-LD processing, and uncontrolled extension points are real risks.
- **What the paper rejects:** The statement "JSON-LD is unsafe" as a general claim. W3C VCDM 2.0 and W3C Data Integrity provide controls such as mandatory base context handling, related-resource integrity, known-good context validation, local caching, and proof verification that does not require network requests. [1][2]
- **What the paper adds:** SD-JWT VC and mdoc do not remove semantic dependency risk. SD-JWT VC introduces a metadata-registry model based on `vct`, Type Metadata, issuer metadata, registries, and local configuration. ISO mdoc uses `doctype`, namespaces, data-element definitions, ISO or national definitions, and rulebooks.
- **What the paper avoids:** It does not turn the analysis into an anti-SD-JWT VC or anti-mdoc argument. SD-JWT VC is a strong fit for compact selective-disclosure credentials. mdoc is strong for mobile documents and device binding. W3C VCDM/JSON-LD is strong for semantically rich, extensible, cross-domain credentials. All three need semantic dependency assurance.
- **What policymakers should take away:** The standardisation target is secured semantic dependencies, not the removal of all links.

## Table of contents

- [Proposed W3C framing](#proposed-w3c-framing)
- [Document orientation and balance check](#document-orientation-and-balance-check)
- [1. Executive Summary and Risk Taxonomy](#1-executive-summary-and-risk-taxonomy)
- [2. Deep Dive: The Semantic Supply Chain](#2-deep-dive-the-semantic-supply-chain)
- [3. Format Analysis: The Visible and the Hidden](#3-format-analysis-the-visible-and-the-hidden)
- [4. The Rulebook and Governance Gap](#4-the-rulebook-and-governance-gap)
- [5. Credential-Format Fit: Semantic Richness and Extensibility](#5-credential-format-fit-semantic-richness-and-extensibility)
- [6. HAIP and Assurance-Framework Gap Analysis](#6-haip-and-assurance-framework-gap-analysis)
- [7. Unified Semantic Control Set and Assurance Levels](#7-unified-semantic-control-set-and-assurance-levels)
- [8. Strategic Recommendations](#8-strategic-recommendations)
- [9. Final Position](#9-final-position)
- [Appendix A. Worked Examples](#appendix-a-worked-examples)
- [Appendix B. Semantic Risk Register](#appendix-b-semantic-risk-register)
- [References](#references)

## 1. Executive Summary and Risk Taxonomy

Digital credential systems do not only distribute signed data. They distribute meaning. A credential signature can prove that a payload was issued by a signing key. It does not, by itself, prove that the verifier has applied the correct schema, vocabulary, Type Metadata, namespace, rulebook, issuer-authorisation policy, or legal interpretation.

The common criticism that W3C VCDM JSON-LD is unsafe because it contains `@context` links is useful as a warning against uncontrolled remote semantic resolution. It is not a sound conclusion about the format as a whole. W3C VCDM 2.0 requires the base context to be the first `@context` item, allows related-resource integrity protection for contexts, and W3C Data Integrity requires context validation against known-good values or equivalent protections. W3C Data Integrity also states that proof verification is designed so that no network requests are necessary. [1][2]

SD-JWT VC does not use JSON-LD contexts. That removes JSON-LD expansion and JSON-LD canonicalisation concerns. It does not remove semantic-distribution risk. SD-JWT VC uses the required `vct` claim as the credential type identifier. The current SD-JWT VC draft says ecosystems must define `vct` values, claim semantics, and issuing and validation rules. It also defines Type Metadata retrieval and documents risks such as SSRF, circular type inheritance, untrusted Type Metadata publishers, issuer-authorisation confusion, and metadata tracking. [3]

ISO mdoc uses `doctype`, namespaces, and data-element identifiers. Its core cryptographic mechanisms are strong and mature for mDL-style credentials, but semantic meaning for other mobile documents is left to the respective issuing authority or to ecosystem rulebooks. The EUDI ARF places such definitions into Attestation Rulebooks and machine-readable attestation schemes. [8][10]

> [!IMPORTANT]
> **Pointed finding**
>
> The risk is not gone with SD-JWT VC. It moves from `@context` to `vct`, Type Metadata, issuer metadata, registries, rulebooks, and local configuration. The same pattern appears in mdoc through `doctype`, namespaces, and rulebooks.

This paper uses five risk pillars:

| **Pillar** | **Question** | **Typical failure** |
|---|---|---|
| Governance / Authority | Who is authorised to define the type, attribute meaning, rulebook, and issuer permission? | A malicious or unauthorised issuer uses a legitimate-looking type identifier. |
| Integrity / Semantic Supply Chain | Is the semantic artifact versioned, signed, hash-pinned, cached, and auditable? | A context, Type Metadata document, namespace, schema, or rulebook changes silently. |
| Operational / Availability and SSRF | Does validation depend on live remote metadata fetches? | The verifier fetches attacker-controlled metadata, leaks information, fails offline, or triggers SSRF. |
| Privacy / Metadata Tracking | Does semantic lookup reveal where, when, or by whom a credential is used? | Fetching a context, `vct` URL, issuer metadata, status URL, or rulebook endpoint becomes a tracking signal. |
| Ecosystem Openness / Centralisation | Does the assurance model create unnecessary platform-controlled registration points? | Issuers, verifiers, credential types, or semantic artifacts become gated by private platform processes instead of transparent ecosystem governance. |

High-level comparison of type-to-meaning-to-rulebook resolution:

| **Format** | **Type anchor** | **Attribute meaning** | **Rulebook binding** | **Main semantic risk** |
|---|---|---|---|---|
| W3C VCDM JSON-LD | `type` plus `@context` | JSON-LD terms mapped to IRIs; optional credential schema and vocabulary | Credential type, vocabulary, schema, and EUDI rulebook | Visible external dependency through context and vocabulary links. Unsafe only if resolution is uncontrolled. |
| SD-JWT VC | `vct` | Claim names plus Type Metadata, issuer metadata, OpenID4VCI credential configuration, and local rules | `vct` Type Metadata, registry, OpenID4VCI metadata, EUDI rulebook | Hidden or registry-based dependency. Unsafe if metadata is mutable, unauthorised, unpinned, or hardcoded inconsistently. |
| ISO mdoc | `doctype` | Namespace plus data-element identifiers | ISO definition, national scheme, attestation rulebook | Out-of-band dependency. Unsafe if namespace, data-element meaning, or issuer authorisation is stale or ambiguous. |

The main conclusion for HAIP, W3C, ETSI, and EUDI work is that high assurance requires a semantic control plane. The debate should move from "links vs. no links" to "secured vs. unsecured semantic dependencies".

## 2. Deep Dive: The Semantic Supply Chain

The Semantic Supply Chain is the full chain that connects a signed credential payload to its operational, technical, and legal meaning. It is format-neutral.

```text
signed payload
-> credential type identifier
-> attribute identifiers
-> context / Type Metadata / namespace / schema
-> human-readable rulebook
-> machine-readable attestation scheme or catalogue entry
-> issuer-authorisation policy
-> verifier policy
-> user-interface rendering
-> conformance tests
-> audit evidence
```

A high-assurance verifier must secure the full chain. A cryptographically valid payload can still be semantically invalid if the verifier applies the wrong rulebook, trusts the wrong Type Metadata publisher, uses a stale namespace mapping, or accepts an issuer that is not authorised for the credential type.

### 2.1 Why a signature is insufficient

Consider this signed payload:

```json
{
  "legal_name": "Example GmbH",
  "registry_number": "HRB 123456",
  "status": "active"
}
```

The signature can establish integrity and issuer key possession. It does not answer these questions:

- Does `legal_name` mean registered legal entity name, trade name, tax name, or issuer-internal onboarding name?
- Does `registry_number` refer to a national commercial register, a local chamber register, a VAT register, or an issuer-specific identifier?
- Does `active` mean legally active, tax active, account active, not dissolved, or merely active in the issuer portal?
- Which rulebook version defines these terms?
- Which authority approved that rulebook?
- Is the issuer authorised to issue this credential type in this jurisdiction and for this purpose?

This is not a W3C-only problem. It exists whenever a compact identifier is used to trigger external interpretation logic.

### 2.2 Machine semantics and legal semantics

Machine-readable semantics and legal semantics are related but not the same. A JSON-LD context, SD-JWT Type Metadata document, mdoc namespace definition, or JSON Schema can describe how a machine should interpret a property. A legal trust decision also needs rulebook governance, issuer authorisation, supervisory acceptance, and verifier policy.

| **Layer** | **Example question** | **Common artifact** |
|---|---|---|
| Machine syntax | Is the payload structurally valid? | JSON Schema, CBOR structure, credential format profile |
| Machine semantics | What does this property identify? | JSON-LD context, Type Metadata, namespace registry |
| Operational policy | Which claims are required or selectively disclosable? | Rulebook, Type Metadata claim rules, DCQL policy |
| Trust decision | Who may issue or receive this credential type? | Trusted list, accreditation registry, EUDI catalogue, scheme governance |
| Legal acceptance | Does this attestation have intended legal effect? | eIDAS rule, ETSI profile, CAB/supervisory assessment, national law |

### 2.3 Shared pattern across formats

```text
W3C VCDM:
@context + type
-> vocabulary / schema
-> attestation rulebook
-> issuer-authorisation check

SD-JWT VC:
vct
-> Type Metadata / registry / local configuration
-> attestation rulebook
-> issuer-authorisation check

ISO mdoc:
doctype + namespace
-> ISO / national / sectoral data-element definition
-> attestation rulebook
-> issuer-authorisation check
```

The common architectural burden is semantic dependency assurance. Each format must distribute meaning. Each ecosystem must govern that distribution.

## 3. Format Analysis: The Visible and the Hidden

### 3.1 W3C VCDM JSON-LD: explicit linkage

W3C VCDM JSON-LD places semantic dependencies in the credential. The `@context` maps JSON terms to URLs, while `type` identifies the credential and extension type. This gives visibility and supports cross-domain semantic reuse. It also makes the dependency obvious to critics.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://semantic.example.eu/contexts/company-registration/v1"
  ],
  "type": [
    "VerifiableCredential",
    "CompanyRegistrationCredential"
  ],
  "credentialSubject": {
    "legalName": "Example GmbH",
    "registrationNumber": "HRB 123456"
  }
}
```

The valid criticism is narrow: live retrieval of arbitrary `@context` URLs during high-assurance verification is unsafe. It can create context substitution, mutable semantic references, network dependency, fingerprinting, and SSRF-like risks. W3C Data Integrity recognises this class of problem. It requires consuming applications to validate contexts against known-good values or equivalent protections and states that no network requests are necessary for proof verification. [2]

The broad assertion that JSON-LD is unsafe is not supported by the standards. W3C VCDM 2.0 mandates the base context as the first `@context` item and defines related-resource integrity mechanisms. [1]

VCDM `relatedResource` can bind external resources, including contexts, to `digestSRI` or `digestMultibase` values. A verifier using such a resource must compute the digest and fail if the digest does not match. [1]

```json
{
  "relatedResource": [
    {
      "id": "https://semantic.example.eu/contexts/company-registration/v1",
      "mediaType": "application/ld+json",
      "digestSRI": "sha384-base64DigestValue..."
    }
  ]
}
```

> [!NOTE]
> **Balanced assessment: W3C VCDM**
>
> W3C VCDM is not safe merely because it is standardised. It is safe only when JSON-LD context processing is constrained. But the format also exposes semantic dependencies in a way that can be audited, pinned, cached, and governed. The visible link is not the weakness. Uncontrolled resolution is the weakness.

#### 3.1.1 Example: context substitution

A credential says `"status": "active"`. A trusted context defines `status` as company-register legal status. A changed context defines `status` as issuer-portal account status. The signed JSON did not change. The semantic interpretation changed.

A high-assurance W3C VCDM assurance level should therefore require:

- approved context allow-list;
- pinned context hashes or signed context bundles;
- local context cache populated before validation;
- rejection of unknown contexts and unknown terms;
- strict control over inline contexts and `@vocab`;
- test vectors for expansion, canonicalisation, and proof verification.

W3C VCDM warns that `@vocab` in production can disable undefined-term errors and change semantics. [1] This warning should become a normative prohibition or strong constraint in high-assurance assurance levels.

### 3.2 SD-JWT VC: metadata registry and hidden semantics

SD-JWT VC avoids JSON-LD contexts. It uses JSON payloads with SD-JWT selective disclosure and the required `vct` claim as the credential type identifier. SD-JWT itself is defined in RFC 9901, while SD-JWT VC defines the credential-type layer on top of it. The SD-JWT VC draft states that `vct` is associated with rules defining permitted or required claims and selective-disclosure rules. It also states that the draft does not define `vct` values; ecosystems are expected to define `vct` values, claim semantics, and issuing and validation policies. [3][4]

```json
{
  "iss": "https://issuer.example.eu",
  "vct": "https://schemas.example.eu/eaa/company-registration/v1",
  "vct#integrity": "sha256-base64DigestValue...",
  "legal_name": "Example GmbH",
  "registry_number": "HRB 123456"
}
```

The Type Metadata document linked to `vct` can describe the credential type, display information, claims, mandatory claim rules, selective-disclosure rules, and type inheritance. It can be retrieved from an HTTPS URL, a registry, an ecosystem-defined method, or a local cache. If `vct#integrity` is present, it must be checked when retrieving the Type Metadata. [3]

```json
{
  "vct": "https://schemas.example.eu/eaa/company-registration/v1",
  "name": "Company Registration Credential",
  "description": "Attestation of legal-entity registration",
  "claims": [
    {
      "path": ["legal_name"],
      "mandatory": "always",
      "sd": "never"
    },
    {
      "path": ["registry_number"],
      "mandatory": "always",
      "sd": "never"
    },
    {
      "path": ["registered_address"],
      "mandatory": "allowed",
      "sd": "allowed"
    }
  ]
}
```

This is the SD-JWT VC semantic supply chain. It is not JSON-LD. But it is still an external semantic dependency. It can be remote, mutable, inherited, cached, registry-provided, or hardcoded.

OpenID4VCI issuer metadata can add another semantic channel. Credential issuer metadata describes supported credential configurations, including format, proof requirements, display information, and claim descriptions. In a high-assurance ecosystem, issuer metadata must therefore be validated against scheme authority and issuer authorisation. It must not be treated as proof that the issuer is allowed to issue the credential type. [6]

#### 3.2.1 SD-JWT VC risks similar to JSON-LD context risks

| **Risk** | **SD-JWT VC manifestation** | **Source-backed observation** |
|---|---|---|
| Untrusted remote fetch | Issuer metadata and Type Metadata URLs may be attacker-controlled. | The SD-JWT VC draft warns that issuer metadata URLs are untrusted and can be SSRF vectors. [3] |
| Semantic substitution | Type Metadata can change claim requirements or display and validation rules. | Type Metadata defines type information, claims, display, and extensions. Consumers must trust the publisher. [3] |
| Circular dependencies | Type Metadata can extend another type, creating cycles. | Circular `extends` dependencies must be detected and credentials rejected. [3] |
| Metadata availability | Network-based Type Metadata retrieval may fail offline or under DoS. | The draft recommends local caches where possible. [3] |
| Issuer-authorisation confusion | A rogue issuer can use or extend a known `vct`. | The draft states type reference does not confer authorisation to issue. [3] |
| Metadata tracking | Fetching `vct` Type Metadata can disclose credential use. | The draft warns that issuers or third parties may track usage through Type Metadata URL requests. [3] |

> [!IMPORTANT]
> **Pointed finding**
>
> The SD-JWT VC draft itself documents the same class of problem that critics often attribute only to JSON-LD: remote semantic metadata, SSRF, circular inheritance, untrusted publishers, issuer-authorisation confusion, and metadata tracking.

#### 3.2.2 Example: metadata substitution in SD-JWT VC

A verifier receives a credential with `vct` set to `company-registration/v1`. The verifier retrieves Type Metadata from a URL. A compromised metadata endpoint marks `registry_number` as optional or selectively disclosable. The payload signature remains valid. The interpretation and validation rule changed.

Mitigation is the same architectural pattern used for JSON-LD contexts:

- versioned `vct` identifiers;
- mandatory `vct#integrity` or signed registry entries for high assurance;
- preloaded and locally cached Type Metadata;
- authorised Type Metadata publishers;
- rejection of untrusted metadata and circular inheritance;
- conformance tests for positive and negative semantic cases.

#### 3.2.3 Example: hidden hardcoding risk

An SD-JWT VC verifier can avoid live Type Metadata fetching by hardcoding claim meanings and `vct` rules. This reduces runtime network risk. It can increase audit and drift risk.

```text
Local verifier rule, version unknown:
company_registration.status = legally active

Updated rulebook, version 2:
company_registration.legalStatus = legally active
company_registration.portalStatus = issuer portal state
```

If the verifier continues to accept `status` without knowing the rulebook version, the system may pass cryptographic validation while failing semantic validation. Hidden semantics are not automatically safer; they are harder to audit unless the configuration package is signed, versioned, and traceable.

### 3.3 ISO mdoc: namespace and rulebook model

ISO mdoc has strong payload encoding, issuer authentication, and device authentication properties. In OpenID4VP, mdoc uses the `mso_mdoc` credential format identifier and core data structures encoded in CBOR and secured using COSE_Sign1. [7]

However, semantic meaning is still external. ISO/IEC 18013-5 is centred on mobile driving licence functionality. Its mechanisms can support other mobile documents, but the details of data elements for such documents are left to the respective issuing authority. [10]

```text
doctype:
eu.europa.ec.eudi.company_registration.1

namespace:
eu.europa.ec.eudi.company

data elements:
legal_name
registry_number
legal_status
```

The verifier must still know the `doctype`, namespace, data-element definitions, rulebook version, and issuer authorisation. In EUDI, the ARF states that attestation schemes are machine-readable, that each scheme published in the catalogue refers to a human-readable Attestation Rulebook, and that the catalogue of attestation schemes enables actors to discover identifiers, syntax, and semantics of attributes within each attestation type. [8]

> [!NOTE]
> **Balanced assessment: mdoc**
>
> mdoc reduces some processing risks through compact CBOR/COSE structures and mature device authentication. It does not remove semantic governance. `doctype`, namespace, data-element definitions, and issuer authorisation still have to be secured and audited.

#### 3.3.1 Example: namespace drift

An mdoc data element named `status` can be interpreted under two versions of a national business-register namespace. Version 1 means legal entity status. Version 2 separates `legalStatus` and `portalStatus`. A verifier that hardcodes version 1 semantics may accept a credential according to stale rules. The COSE signature does not resolve the semantic drift.

### 3.4 Comparative severity view

| **Risk** | **W3C VCDM JSON-LD** | **SD-JWT VC** | **ISO mdoc** |
|---|---|---|---|
| Remote semantic fetch | High if arbitrary `@context` retrieval is allowed; controllable with known-good context validation and pinned resources. | High if arbitrary `vct` / Type Metadata / issuer metadata retrieval is allowed; controllable with `vct#integrity`, registries, and local caches. | Lower in core mdoc payload processing, but present through catalogue, status, rulebook, and trust-list lookup. |
| Semantic substitution | Context or vocabulary substitution. | Type Metadata or registry substitution. | Namespace, `doctype`, or rulebook substitution. |
| Hidden semantic drift | Lower when contexts and schemas are explicit and archived; higher if inline contexts are uncontrolled. | Medium to high when semantics are local code or issuer config without signed versioning. | Medium to high when namespaces or national rulebooks are hardcoded. |
| Issuer-authorisation confusion | A known type does not prove issuer authority. | Explicitly documented in the SD-JWT VC draft. | A valid `doctype` does not prove issuer authority. |
| Metadata privacy leakage | Context and verification method URLs can fingerprint validation. | `vct`, issuer metadata, and Type Metadata URLs can reveal credential use. | Status, catalogue, and trust anchor lookup can reveal usage patterns. |
| Auditability | Strong when contexts, schemas, and rulebooks are pinned and archived. | Strong when Type Metadata, registries, and rulebooks are signed and archived. | Strong when namespace and rulebook versions are signed and archived. |
| Extensibility | Strong when vocabularies and extension contexts are governed. | Moderate; extensibility depends on `vct`, Type Metadata, registries, and local claim interpretation. | Strong for predefined document families; less flexible for open cross-domain semantic extension. |

## 4. The Rulebook and Governance Gap

### 4.1 EUDI rulebooks and semantic hubs

The EUDI ARF already recognises the semantic supply-chain problem. It distinguishes between machine-readable attestation schemes and human-readable Attestation Rulebooks. The catalogue of attestation schemes is intended to let relying parties, attestation providers, and other actors discover attestation types and understand the identifiers, syntax, and semantics of attributes within each type. [8][9]

This is the semantic hub pattern. It applies to all three credential formats. A semantic hub should not be treated as a convenience catalogue only. It is a trust-relevant control plane.

```text
semantic hub / catalogue
-> attribute identifiers
-> syntax and data types
-> semantic descriptions
-> machine-readable attestation scheme
-> human-readable rulebook
-> governance and trust model
-> issuer and verifier requirements
```

A catalogue entry can support discovery. It does not automatically create legal effect or issuer authorisation. The EUDI ARF states that registration in the catalogue of attestation schemes does not automatically create an obligation of acceptance or imply cross-border recognition. [8]

### 4.2 The real vulnerability: uncontrolled semantic resolution

A link is not unsafe by nature. A local hardcoded mapping is not safe by nature. The control question is whether the semantic dependency is governed and secured.

| **Format** | **Controlled semantic resolution** | **Uncontrolled semantic resolution** |
|---|---|---|
| W3C VCDM | Approved context, pinned hash, local cache, archived vocabulary version. | Live fetch of arbitrary context URL, unknown inline context, or `@vocab` override. |
| SD-JWT VC | Approved `vct`, signed or hash-pinned Type Metadata, local cache, authorised publisher. | Live fetch of untrusted Type Metadata, unknown registry, or issuer-defined display metadata treated as validation logic. |
| ISO mdoc | Approved `doctype` and namespace, signed rulebook, certified issuer key and authority list. | Local hardcoded mapping with unknown version, unmanaged national extension, or stale namespace definition. |
| OpenID4VCI | Credential configuration validated against scheme authority and issuer authorisation. | Issuer metadata accepted as proof that the issuer may issue the credential type. |

### 4.3 The issuer-authorisation trap

A credential type identifier is not an issuer licence. This is a critical separation for eIDAS, QEAA, PuB-EAA, EUDI Wallet, Business Wallet, and DPP ecosystems.

A credential can claim any of these:

```text
W3C type: CompanyRegistrationCredential
SD-JWT VC vct: https://schemas.example.eu/qeaa/company-registration/v1
mdoc doctype: eu.europa.ec.eudi.company_registration.1
```

None of these proves that the issuer is authorised.

The current SD-JWT VC draft is explicit: verifiers and holders must not assume that any issuer that references or extends a known type is authorised to issue it. Issuer authorisation must be checked independently of the credential type and its extensions. [3]

A high-assurance verifier therefore needs four distinct checks:

| **Check** | **Question** | **Example failure if missing** |
|---|---|---|
| Payload integrity | Was the credential signed or secured correctly? | Tampered claim accepted. |
| Semantic validity | Is the type, namespace, context, or Type Metadata known and accepted? | Valid signature processed with wrong meaning. |
| Issuer identity | Who signed or sealed the credential? | Credential signed by unknown or spoofed issuer key. |
| Issuer authorisation | Is that issuer authorised for this type, rulebook, jurisdiction, and assurance level? | Rogue issuer uses legitimate-looking type. |

### 4.4 Governance centralisation and vendor lock-in risk

High-assurance profiles often introduce registration and certification steps. Some of those steps are necessary. For example, a regulated ecosystem needs to know which issuers are authorised to issue QEAAs, PuB-EAAs, business attestations, or product-compliance credentials.

The risk arises when a profile creates unnecessary platform-controlled registration points for issuers, verifiers, credential types, semantic artifacts, or trust decisions. Such controls may improve onboarding and operational assurance, but they can also create vendor lock-in, reduce portability, and move governance from public or ecosystem rulebooks into private platform policies.

A high-assurance assurance framework should therefore distinguish between:

| **Control type** | **Acceptable purpose** | **Risk if misused** |
|---|---|---|
| Ecosystem issuer registry | Verify that an issuer is authorised for a credential type and assurance level. | Registry becomes opaque or controlled by one platform. |
| Verifier registration | Protect users and restrict access to high-risk attributes. | Verifier access becomes platform-gated without transparent criteria. |
| Semantic catalogue | Publish approved type, context, schema, namespace, and rulebook versions. | Semantic artifacts become privately controlled or non-portable. |
| Wallet assurance | Confirm that a wallet meets security and privacy requirements. | Wallet certification becomes a market-entry barrier unrelated to risk. |
| Protocol-specific certificates | Bind protocol participants to credentials in a narrow technical flow. | Trust becomes tied to one protocol or platform instead of interoperable web and ecosystem trust signals. |

The framework should prefer transparent, auditable, non-discriminatory governance. Domain names, web origins, organisational identity, trusted lists, and ecosystem rulebooks should be usable as trust signals where they are sufficient. Protocol-specific certificates or private platform registrations should be required only when there is a clear risk-based reason and a transparent governance process.

> [!NOTE]
> **Evidence note**
>
> Specific claims about individual platforms using HAIP as a registration gate should not be cited in this paper without public evidence. This paper treats platform-controlled registration as a general governance risk pattern and recommends controls to avoid it.

## 5. Credential-Format Fit: Semantic Richness and Extensibility

Credential-format selection should be driven by use-case requirements. The decision is not only about cryptographic security. It is also about semantic richness, extensibility, governance, privacy, payload size, selective disclosure, device binding, and conformance.

### 5.1 Simple, stable attribute credentials

Some credentials contain a small, stable, and well-understood attribute set. Examples include:

- natural-person identity credentials;
- age-over credentials;
- mobile driving licence data;
- membership cards;
- simple permits or licences;
- employee badge credentials with a few attributes.

A typical natural-person identity credential may contain about 10 to 20 stable attributes, such as:

```text
family name
given name
date of birth
place of birth
nationality
document number
issuing authority
validity period
portrait reference
address
age-over-18 flag
age-over-21 flag
```

In these cases, the semantic model is narrow and stable. It can be governed by a clear rulebook and implemented with compact claim names or predefined data elements. SD-JWT VC or ISO mdoc can be a strong fit:

- SD-JWT VC is useful where compact JSON-based credentials and selective disclosure are primary requirements.
- ISO mdoc is useful where mobile-document conventions, CBOR/COSE compactness, proximity presentation, and device authentication are primary requirements.

For these cases, W3C VCDM/JSON-LD may still be usable, but its semantic expressiveness may not be the decisive requirement.

### 5.2 Semantically rich enterprise, product, and industrial credentials

Other credentials contain or reference a much richer semantic structure. Examples include:

- enterprise KYC and KYB records;
- beneficial ownership and authority-to-act attestations;
- mandates and powers of attorney;
- supply-chain due-diligence attestations;
- Digital Product Passports;
- product conformity and lifecycle credentials;
- Industry 4.0 asset credentials;
- digital twin records;
- object identity and provenance credentials;
- trusted-AI provenance, model, dataset, and assurance attestations.

These credentials can contain tens or hundreds of data elements and controlled vocabularies. They often include nested structures and cross-domain references:

```text
legal entity identifiers
commercial-register references
beneficial ownership structures
sanctions and risk-screening evidence
authority-to-act chains
registered and operating addresses
tax identifiers
sector classification codes
product identifiers
batch and serial numbers
material composition
component relationships
lifecycle events
supply-chain events
country-of-origin evidence
carbon-footprint data
conformity evidence
certification references
provenance links
units of measure
jurisdiction-specific meanings
```

In these settings, the core requirement is not only compact selective disclosure. The core requirement is shared machine meaning across organisations, systems, jurisdictions, and value chains.

This is where W3C VCDM and JSON-LD are structurally important. They support explicit semantic models, reusable vocabularies, global identifiers, linked data, and cross-domain extension. This is relevant to W3C work on Digital Product Passport and Business Wallet vocabularies, and consistent with existing industry semantic models such as GS1 EPCIS/CBV for supply-chain visibility and the Asset Administration Shell for Industry 4.0 information exchange. [13][14][15]

The European Business Wallet is proposed as a harmonised digital solution that enables companies and public-sector bodies to identify, authenticate, and exchange data securely with legal effect across the EU. It also includes trusted documents, digital signatures, timestamps, seals, delegation, and communication with other businesses or public administrations. [12]

If the European Business Wallet is expected to support enterprise onboarding, regulated product data, supply-chain due diligence, industrial asset data, and trusted-AI attestations, then support for semantically rich credentials is a foundational capability. For such use cases, the semantic model is not an implementation detail. It is part of the business, legal, and interoperability requirement.

### 5.3 Architectural consequence

The conclusion is not that W3C VCDM/JSON-LD should replace SD-JWT VC or mdoc. The conclusion is that credential formats should be selected according to semantic complexity and ecosystem requirements.

| **Use-case class** | **Semantic profile** | **Likely fit** |
|---|---|---|
| Age proof, simple identity, simple licence | Small, stable, regulated attribute set | SD-JWT VC or mdoc often fit well; W3C VCDM can also be used if ecosystem requires it. |
| Natural-person PID or mDL-style credential | Stable attributes, strong need for compactness and device binding | mdoc or SD-JWT VC often fit well under HAIP-style protocol constraints. |
| Enterprise KYC / KYB | Many attributes, nested legal and risk semantics, cross-jurisdictional interpretation | W3C VCDM/JSON-LD is structurally strong because it supports explicit semantic models and vocabularies. |
| Digital Product Passport | Product, material, lifecycle, conformity, and sustainability data | W3C VCDM/JSON-LD is structurally strong because DPP semantics require reusable industry vocabularies and linked data. |
| Supply-chain and Industry 4.0 | Events, assets, objects, provenance, digital twins, units, classifications | W3C VCDM/JSON-LD is structurally strong because industrial semantics already rely on standardised models and identifiers. |
| Trusted AI | Dataset, model, provenance, assurance, audit, policy, and risk evidence | W3C VCDM/JSON-LD is structurally strong because linked provenance and cross-domain semantics are central. |

## 6. HAIP and Assurance-Framework Gap Analysis

### 6.1 What HAIP does well

OpenID4VC HAIP 1.0 profiles OpenID4VC for ecosystems that need a high level of security and privacy. It profiles OpenID4VCI, OpenID4VP, W3C Digital Credentials API flows, SD-JWT VC, and ISO mdoc. It requires support for at least one of the two credential-format profiles: SD-JWT VC or ISO mdoc. EUDI high-level requirements also track these protocol and format expectations for the EUDI Wallet context. [5][11]

HAIP is strong where it is meant to be strong: reducing optionality in issuance and presentation protocols, key binding, wallet and key attestation, status handling, issuer key resolution, and baseline cryptographic algorithms. For SD-JWT VC, HAIP mandates `dc+sd-jwt` as format identifier, compact serialization support, status-list handling where status is present, X.509 certificate-based issuer key resolution, and KB-JWT presence when cryptographic holder binding is used. [5]

### 6.2 What HAIP leaves outside

HAIP 1.0 explicitly leaves trust management out of scope. Its out-of-scope section defines trust management as authorisation of issuers to issue certain credential types, wallets to be issued certain credential types, and verifiers to receive certain credential types. The methods for establishing trust or obtaining root certificates are also outside HAIP scope. [5]

This is a reasonable scope boundary for a technical interoperability profile. But it means HAIP conformance alone does not solve semantic governance, rulebook governance, issuer authorisation, verifier authorisation, or ecosystem openness.

### 6.3 Critical gap: SD-JWT VC semantic dependency assurance

HAIP 1.0 focuses on credential security and protocol interoperability. It does not add a cross-format semantic dependency assurance section. In particular, HAIP does not appear to make `vct#integrity` mandatory for all high-assurance SD-JWT VC Type Metadata, does not require a governed `vct` registry, and does not require that Type Metadata be preloaded, locally cached, signed, or pinned. It relies on the underlying SD-JWT VC draft and on ecosystem profiles for many of these semantic controls.

This matters because the current SD-JWT VC draft describes Type Metadata as a semantic artifact used by issuers, verifiers, and holders to understand semantics and rules. It also warns about SSRF, circular dependencies, untrusted metadata publishers, issuer-authorisation confusion, and privacy-preserving retrieval. [3]

> [!IMPORTANT]
> **Critical finding for the JSON-LD controversy**
>
> Critics who identify JSON-LD context links as a security risk should apply the same analysis to SD-JWT VC Type Metadata, `vct` URLs, issuer metadata, registries, and local configuration. Otherwise, the criticism is format-selective rather than risk-based.

### 6.4 Hidden semantics can be worse for auditability

A system can avoid visible links by hardcoding semantic meaning in wallet or verifier software. This may reduce runtime network risk. It can also reduce auditability.

A CAB, supervisory body, or ecosystem auditor can inspect a pinned JSON-LD context, signed Type Metadata document, or signed namespace rulebook. It is harder to inspect hidden semantic assumptions embedded in local code or private configuration. Hidden semantics become especially risky when multiple vendors, Member States, industry consortia, or platforms interpret the same claim names differently.

The audit question is therefore not:

```text
Does the format use links?
```

The audit question is:

```text
Can the ecosystem prove which semantic version was used,
who approved it,
how it was integrity-protected,
and whether the issuer was authorised for it?
```

### 6.5 Why not a simple HAIP clone for W3C VCDM

A direct "HAIP for W3C" framing risks importing design assumptions from a protocol-specific profile into the W3C credential data model. It can also create a perception that high assurance requires protocol-specific certificates, platform-specific registration, or private gatekeeping for issuers, verifiers, credential types, and semantic artifacts.

The better formal direction is a W3C-native assurance model:

```text
W3C VCDM Assurance Framework
  └── Assurance Levels for W3C VCDM Credentials
```

This framework can still reuse useful HAIP lessons:

- reduce optionality;
- define mandatory controls per assurance level;
- require issuer and verifier metadata discipline;
- require holder-binding and wallet-assurance controls where needed;
- define status and revocation controls;
- require privacy controls;
- include conformance tests and negative tests.

But it should avoid unnecessary platform-controlled registration points and avoid treating protocol-specific certificates as the default trust model. Domain names, web origins, organisational identity, trusted lists, rulebooks, and ecosystem registries should remain available trust signals, depending on assurance level and regulatory context.

### 6.6 Proposed formal naming

| **Name** | **Recommended use** |
|---|---|
| `W3C VCDM Assurance Framework` | Preferred umbrella name for the W3C-aligned workstream. |
| `Assurance Levels for W3C VCDM Credentials` | Preferred concrete specification title. |
| `Semantic Dependency Assurance` | First major module of the assurance-level specification. |

## 7. Unified Semantic Control Set and Assurance Levels

### 7.1 Unified semantic control set

High-assurance ecosystems should apply a shared control set to all credential formats.

| **Control** | **Requirement** | **W3C VCDM example** | **SD-JWT VC example** | **mdoc example** |
|---|---|---|---|---|
| Identify semantic artifacts | List all artifacts that affect meaning. | Contexts, vocabularies, schemas. | `vct`, Type Metadata, issuer metadata. | `doctype`, namespace, rulebook. |
| Version artifacts | Avoid mutable versionless semantics. | `/company/v1` context. | `/company-registration/v1` `vct`. | namespace version or rulebook version. |
| Integrity-protect artifacts | Use hashes, signatures, seals, or signed catalogues. | `relatedResource` digest. | `vct#integrity` or signed registry. | signed namespace/rulebook catalogue. |
| Use local validation cache | Avoid live semantic fetch in validation path. | static context cache. | local Type Metadata cache. | local namespace/rulebook cache. |
| Authorise publishers | Define who may publish semantics. | vocabulary owner or scheme authority. | authorised Type Metadata publisher. | ISO, national, or sectoral authority. |
| Separate issuer authorisation | Type validity is not issuer authority. | issuer authorised for `type`. | issuer authorised for `vct`. | issuer authorised for `doctype`. |
| Treat display as non-authoritative | UI text must not drive validation. | credential display metadata. | Type Metadata display fields. | wallet or reader labels. |
| Preserve privacy | Avoid metadata lookup as tracking. | no holder-specific context URLs. | no holder-specific `vct` or issuer metadata URLs. | privacy-safe status/catalogue lookup. |
| Test semantics | Include positive and negative semantic tests. | unknown context rejection. | wrong `vct#integrity` rejection. | stale namespace rejection. |
| Archive versions | Enable post-event audit. | archived contexts and schemas. | archived Type Metadata and registry entries. | archived namespace and rulebook versions. |
| Preserve ecosystem openness | Avoid unnecessary private gatekeeping. | public vocabulary governance. | public or accredited `vct` registry. | public namespace/rulebook governance. |

### 7.2 Assurance levels for semantic dependencies

| **Level** | **Description** | **Suitable use** |
|---|---|---|
| Level 0: Uncontrolled | Live remote fetch, no integrity, no governance, no cache. | Not suitable for production. |
| Level 1: Basic web trust | HTTPS URL and human documentation. | Low-risk demos and proofs of concept. |
| Level 2: Profiled ecosystem | Versioned identifiers, known schemas, local configuration, limited conformance tests. | Controlled pilots and limited ecosystems. |
| Level 3: High assurance | Signed or pinned artifacts, local cache, explicit issuer authorisation, verifier authentication where needed, negative tests, audit trail. | Regulated systems and HAIP-style deployments. |
| Level 4: Qualified / regulated trust | Accredited publisher, signed catalogue, CAB-assessable controls, supervisory acceptance, archived versions, trust-list integration. | eIDAS, QEAA, PuB-EAA, EU Business Wallet, regulated DPP. |

### 7.3 Proposed modules for W3C VCDM Assurance Framework

The proposed W3C VCDM Assurance Framework should define mandatory controls per assurance level in six modules.

#### 7.3.1 Semantic Dependency Assurance

This module should define how contexts, vocabularies, schemas, credential types, related resources, and rulebooks are approved, pinned, cached, archived, and tested.

Minimum high-assurance controls:

- approved context allow-list;
- no uncontrolled live context fetching during validation;
- pinned context and schema integrity;
- strict extension and `@vocab` control;
- rulebook binding;
- semantic test vectors.

#### 7.3.2 Issuer and Verifier Assurance

This module should define issuer identity, verifier identity, issuer authorisation, verifier authorisation, and trust signals.

Minimum high-assurance controls:

- issuer identity validation;
- issuer authorisation for exact credential type and rulebook version;
- verifier authentication when sensitive or high-risk credentials are requested;
- support for web-origin and domain-based trust signals where sufficient;
- support for trusted lists and regulated registries where required;
- no unnecessary platform-controlled registration points.

#### 7.3.3 Holder Binding and Wallet Assurance

This module should define how a credential presentation is bound to the holder or wallet where the use case requires this.

Minimum high-assurance controls:

- proof of possession or equivalent holder-binding mechanism;
- wallet key protection requirements;
- wallet attestation or equivalent assurance only where risk justifies it;
- clear separation between wallet assurance and platform lock-in.

#### 7.3.4 Status and Revocation Assurance

This module should define status-list, revocation, suspension, and validity controls.

Minimum high-assurance controls:

- explicit status mechanism;
- privacy-preserving status lookup;
- no issuer phone-home for routine validation unless justified by rulebook;
- cache and freshness rules;
- audit record of status source and version.

#### 7.3.5 Privacy Assurance

This module should define data minimisation, selective disclosure, unlinkability goals, metadata privacy, and transaction logging limits.

Minimum high-assurance controls:

- purpose-bound disclosure;
- no holder-specific semantic URLs;
- local semantic and status caches where possible;
- avoidance of metadata lookup tracking;
- transparency to the holder about disclosed type and context information.

#### 7.3.6 Conformance Testing

This module should define positive and negative tests for all assurance levels.

Minimum high-assurance tests:

- valid credential with approved context and rulebook;
- credential with unknown context;
- credential with changed context hash;
- credential with unknown vocabulary term;
- credential with unauthorised issuer;
- credential with stale rulebook version;
- credential with misleading display metadata;
- privacy test for metadata lookup behaviour.

## 8. Strategic Recommendations

### 8.1 Cross-format recommendation

High-assurance profiles should add a mandatory cross-format clause named **Semantic Dependency Assurance**. This clause should state that credentials must not be accepted based only on a valid signature and known type string. The verifier must validate the semantic artifact, the rulebook version, and the issuer authorisation.

### 8.2 W3C VCDM Assurance Framework recommendation

Use this formal structure:

```text
W3C VCDM Assurance Framework
  └── Assurance Levels for W3C VCDM Credentials
        ├── Semantic Dependency Assurance
        ├── Issuer and Verifier Assurance
        ├── Holder Binding and Wallet Assurance
        ├── Status and Revocation Assurance
        ├── Privacy Assurance
        └── Conformance Testing
```

This should be the public standards framing. The formal output should be expressed as assurance levels for W3C VCDM credentials.

The next step should be a W3C-aligned assurance framework for VCDM credentials. It should define assurance levels and mandatory controls for semantic dependency assurance, issuer authorisation, verifier authentication, holder binding, wallet assurance, status, privacy, and conformance testing.

### 8.3 W3C VCDM / JSON-LD recommendation

- Require approved context allow-lists and local context caches.
- Require context integrity through `relatedResource`, signed bundles, or equivalent pinned-hash mechanisms.
- Forbid uncontrolled live remote context fetching during high-assurance validation.
- Forbid or strictly constrain `@vocab` and unapproved inline contexts.
- Bind credential type to a versioned rulebook and machine-readable schema.
- Define mandatory proof suites, canonicalisation algorithms, and test vectors.
- Require issuer-authorisation checks independent of W3C `type` values.
- Preserve the ability to use explicit, standardised semantic models for enterprise, DPP, supply-chain, Industry 4.0, and trusted-AI credentials.

### 8.4 SD-JWT VC recommendation

- Require governed and versioned `vct` values for high-assurance credential types.
- Require `vct#integrity` or signed registry entries for Type Metadata used in high-assurance validation.
- Require local Type Metadata cache and prohibit live untrusted Type Metadata retrieval in the validation path.
- Limit type inheritance depth and require circular dependency rejection.
- Treat display metadata as non-authoritative.
- Require privacy-safe Type Metadata distribution and no holder-specific metadata URLs.
- Check issuer authorisation independently of `vct` and any extension hierarchy.

### 8.5 ISO mdoc recommendation

- Require governed `doctype` and namespace registries.
- Require signed or sealed data-element definitions and rulebooks.
- Bind `doctype` and namespace versions to the attestation rulebook.
- Require issuer authorisation by `doctype`, namespace, jurisdiction, and assurance level.
- Test namespace interpretation and stale-rulebook rejection.
- Ensure privacy-safe status, catalogue, and trust-anchor lookup.

### 8.6 EUDI ARF / ETSI recommendation

- Treat the catalogue of attestation schemes as semantic trust infrastructure, not only discovery infrastructure.
- Require explicit binding between human-readable rulebooks and machine-readable schemes.
- Require signed, versioned, archived machine-readable schemes.
- Add negative semantic test cases to conformance testing.
- Publish issuer-authorisation data by credential type and rulebook version.
- Align W3C VCDM JSON-LD, SD-JWT VC, and mdoc under the same Semantic Dependency Assurance model.

### 8.7 Governance and openness recommendation

A high-assurance framework must not create unnecessary platform-controlled registration points for issuers, verifiers, credential types, or semantic artifacts. Such controls may improve operational onboarding, but they can also create vendor lock-in and reduce ecosystem openness.

The assurance framework should therefore require that any registration, certification, or approval step is:

- risk-based;
- transparent;
- auditable;
- non-discriminatory;
- portable across conforming wallets and verifiers;
- governed by public, regulatory, or ecosystem rulebooks rather than private platform policy alone.

## 9. Final Position

The assertion "JSON-LD is unsafe" is too broad. A more precise statement is: uncontrolled semantic resolution is unsafe. That statement applies to all credential formats.

W3C VCDM makes semantic dependencies visible through `@context`, `type`, vocabularies, schemas, and related resources. This creates real operational duties. Those duties can be addressed through known-good context validation, resource integrity, local caches, strict extension control, and conformance tests. W3C VCDM and W3C Data Integrity already provide relevant building blocks for this control model. [1][2]

SD-JWT VC removes JSON-LD-specific processing concerns. It does not remove semantic dependency risk. The semantic dependency moves to `vct`, Type Metadata, issuer metadata, registries, local configuration, and rulebooks. The SD-JWT VC draft itself documents several of these risks, including metadata retrieval risks, Type Metadata trust, issuer-authorisation confusion, circular inheritance, and privacy leakage through Type Metadata lookup. [3]

ISO mdoc provides strong compact credential and device-authentication mechanisms. It still depends on external `doctype`, namespace, data-element, issuer-authorisation, and rulebook governance. In the EUDI context, this semantic layer is handled through attestation schemes, namespaces, catalogues, and Attestation Rulebooks. [8][9][10]

Credential-format decisions should therefore be requirements-driven. For a compact and well-bounded credential, such as a natural-person identity card with a small set of stable attributes, SD-JWT VC or ISO mdoc can be a good choice. A typical example is an identity credential with about ten attributes, such as family name, given name, date of birth, nationality, document number, issuing authority, validity period, portrait reference, address, and age-over flags. In such cases, the semantic model is narrow, stable, and easy to govern. Compact payloads, selective disclosure, mature OpenID4VC profiling, and device-binding models fit these constrained identity use cases well.

The decision changes when the credential is semantically rich. Enterprise KYC and KYB records, business-wallet owner identity credentials, mandates, powers of attorney, supply-chain due-diligence attestations, Digital Product Passports, Industry 4.0 asset credentials, and trusted-AI provenance records can contain or reference tens or hundreds of attributes. They can include legal-entity identifiers, beneficial ownership, sanctions-screening evidence, authority-to-act chains, registered-address structures, tax identifiers, sector codes, product identifiers, batch and serial numbers, material composition, lifecycle events, carbon-footprint data, conformity evidence, provenance links, units of measure, and jurisdiction-specific meanings. In those settings, the core requirement is not only compact disclosure. It is shared machine meaning across organisations, systems, jurisdictions, and value chains.

This is where W3C VCDM and JSON-LD are strategically important. They support explicit, standardised semantic models and reusable vocabularies. This is visible in W3C work on Digital Product Passport and Business Wallet vocabularies, and it is consistent with existing industry semantic models for Digital Product Passports (DPPs), supply-chain visibility, Manufacturing-X data spaces, and the Asset Administration Shell for Industry 4.0 information exchange. [13][14][15]

The European Business Wallet is intended as a harmonised digital solution that enables companies and public-sector bodies to identify, authenticate, and exchange data securely with legal effect across the EU. It is also expected to support trusted documents, digital signatures, timestamps, seals, delegation, and communication with businesses and public administrations. [12] If the European Business Wallet is to support enterprise onboarding, regulated product data, supply-chain due diligence, industrial asset data, and trusted-AI attestations, support for semantically rich credentials is a foundational capability, not an optional convenience.

The security implication is clear. JSON-LD does not become unsafe because it exposes semantic dependencies. It becomes suitable for high assurance when those dependencies are governed and controlled. The same is true for SD-JWT VC and mdoc. Removing JSON-LD does not remove the semantic requirement; it only moves the requirement into Type Metadata, registries, schemas, rulebooks, or local configuration. This paper shows that the semantic supply-chain risks of JSON-LD are comparable to the corresponding risks in other credential formats, and that they can be mitigated with similar mechanisms: versioning, integrity protection, local caching, authorised semantic publishers, issuer-authorisation checks, privacy-preserving metadata distribution, auditability, and conformance tests.

This paper therefore does not argue that W3C VCDM/JSON-LD should replace SD-JWT VC or mdoc in every use case. It argues that W3C VCDM/JSON-LD must be available as a high-assurance option where the use case requires semantically rich credentials. The recommended formal direction is not a direct HAIP clone. It is a **W3C VCDM Assurance Framework** with **Assurance Levels for W3C VCDM Credentials**. The first module should be **Semantic Dependency Assurance**. The broader framework should also cover issuer and verifier assurance, holder binding and wallet assurance, status and revocation assurance, privacy assurance, and conformance testing.

> [!IMPORTANT]
> **Final statement**
>
> The debate must move from "links vs. no links" to "secured vs. unsecured semantic dependencies". High assurance requires governed, versioned, integrity-protected, locally available, privacy-preserving, auditable semantic dependencies for every credential format. Credential-format selection should follow the use-case requirements: compact formats for simple, stable attribute sets; explicit, standardised semantic models for complex business, product, supply-chain, Industry 4.0, and trusted-AI credentials. That is why a W3C VCDM Assurance Framework is needed.

## Appendix A. Worked Examples

### A.1 Same business credential, three semantic anchors

The following examples are illustrative and not normative. They show how the same business credential depends on external semantic meaning in each format.

#### W3C VCDM example

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://semantic.example.eu/contexts/business-wallet/company/v1"
  ],
  "type": [
    "VerifiableCredential",
    "CompanyRegistrationCredential"
  ],
  "issuer": "https://authentic-source.example.eu/issuer",
  "credentialSubject": {
    "legalName": "Example GmbH",
    "registrationNumber": "HRB 123456"
  },
  "relatedResource": [
    {
      "id": "https://semantic.example.eu/contexts/business-wallet/company/v1",
      "digestSRI": "sha384-base64DigestValue..."
    }
  ]
}
```

Validation dependency: approved context, context digest, credential type, schema, rulebook, issuer authorisation.

#### SD-JWT VC example

```json
{
  "iss": "https://authentic-source.example.eu/issuer",
  "vct": "https://schemas.example.eu/business-wallet/company-registration/v1",
  "vct#integrity": "sha256-base64DigestValue...",
  "legal_name": "Example GmbH",
  "registration_number": "HRB 123456"
}
```

Validation dependency: governed `vct`, Type Metadata integrity, claim rules, rulebook, issuer authorisation.

#### ISO mdoc example

```text
doctype = eu.europa.ec.eudi.business.company_registration.1
namespace = eu.europa.ec.eudi.business.company
data elements = legal_name, registration_number
```

Validation dependency: `doctype` registry, namespace definition, data-element semantics, rulebook, issuer authorisation.

### A.2 Same failure mode, three formats

| **Failure mode** | **W3C VCDM** | **SD-JWT VC** | **ISO mdoc** |
|---|---|---|---|
| Wrong meaning of status | Context changes status from legal status to portal status. | Type Metadata or local rules define status differently. | Namespace version changes status meaning. |
| Unauthorised issuer | Issuer signs `CompanyRegistrationCredential` but is not the register. | Issuer signs credential with known `vct` but lacks authorisation. | Issuer signs mdoc `doctype` but is not authorised for that `doctype`. |
| Metadata tracking | Verifier fetches unique context URL. | Verifier fetches holder-specific issuer or Type Metadata URL. | Verifier performs unique status/catalogue lookup. |
| Audit failure | Context not archived. | Type Metadata or local config not archived. | Namespace or rulebook version not archived. |

### A.3 Simple identity credential versus semantically rich enterprise credential

#### Simple identity credential

```json
{
  "family_name": "Muster",
  "given_name": "Erika",
  "birthdate": "1990-01-01",
  "nationality": "DE",
  "age_over_18": true
}
```

This can be governed with a small rulebook and a stable attribute list. SD-JWT VC or mdoc can be a strong choice.

#### Semantically rich enterprise credential

```json
{
  "legalEntity": {
    "legalName": "Example GmbH",
    "registration": {
      "register": "DE.HRB",
      "registrationNumber": "HRB 123456",
      "registrationCourt": "Dortmund"
    },
    "taxIdentifiers": [
      {
        "scheme": "VAT",
        "value": "DE123456789"
      }
    ],
    "beneficialOwnership": [
      {
        "ownerType": "naturalPerson",
        "ownershipPercentage": 25.5,
        "controlType": "direct"
      }
    ],
    "authorityToAct": [
      {
        "actor": "did:example:person123",
        "role": "ManagingDirector",
        "scope": "signingAuthority",
        "validUntil": "2027-12-31"
      }
    ]
  }
}
```

This credential needs explicit semantics for legal entities, registers, tax identifiers, ownership, control, roles, authority, dates, jurisdictions, and governance. W3C VCDM/JSON-LD is structurally strong for this class because it can bind properties to reusable semantic identifiers and industry vocabularies.

## Appendix B. Semantic Risk Register

| **Risk** | **Description** | **Applies to** | **Mitigation** |
|---|---|---|---|
| Semantic substitution | External artifact changes the meaning of signed data. | All formats | Version, pin, sign, cache, archive semantic artifacts. |
| Untrusted metadata publisher | Consumer treats a publisher as authoritative without accreditation. | W3C, SD-JWT VC, EUDI catalogues | Authorised publisher registry and governance. |
| Issuer-authorisation confusion | Known type accepted as proof of issuer right. | All formats | Independent issuer-authorisation check. |
| Live fetch dependency | Validation fails offline or leaks use. | All formats | Local cache, batch updates, neutral mirrors. |
| SSRF | Verifier resolves attacker-controlled URL. | W3C contexts, SD-JWT metadata, issuer metadata | URL allow-list, no internal network access, size/time limits. |
| Circular inheritance | Type dependencies recurse indefinitely or ambiguously. | SD-JWT VC Type Metadata; analogous schema graphs | Cycle detection, inheritance-depth limits. |
| Display deception | UI labels or logos mislead user or verifier. | All formats | Treat display metadata as non-authoritative; escape text. |
| Semantic drift | Local hardcoded meaning diverges from rulebook. | All formats | Signed config packages, version checks, deprecation policy. |
| Privacy leakage | Metadata or status lookup reveals credential use. | All formats | No holder-specific URLs, shared caches, no issuer phone-home. |
| Conformance gap | Implementations verify signatures but not semantic meaning. | All formats | Positive and negative semantic test vectors. |
| Vendor lock-in | Assurance controls become private platform registration gates. | All formats and protocols | Transparent governance, portability, public rulebooks, risk-based registration. |

## References

[1] W3C. Verifiable Credentials Data Model v2.0. W3C Recommendation, 15 May 2025. [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)

[2] W3C. Verifiable Credential Data Integrity 1.0. W3C Recommendation, 15 May 2025. [https://www.w3.org/TR/vc-data-integrity/](https://www.w3.org/TR/vc-data-integrity/)

[3] IETF OAuth Working Group. SD-JWT-based Verifiable Digital Credentials (SD-JWT VC), draft-ietf-oauth-sd-jwt-vc-16, April 2026. [https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)

[4] IETF. RFC 9901: Selective Disclosure for JSON Web Tokens (SD-JWT), 19 November 2025. [https://datatracker.ietf.org/doc/rfc9901/](https://datatracker.ietf.org/doc/rfc9901/)

[5] OpenID Foundation. OpenID4VC High Assurance Interoperability Profile 1.0, Final Specification. [https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)

[6] OpenID Foundation. OpenID for Verifiable Credential Issuance 1.0, Final Specification, 16 September 2025. [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

[7] OpenID Foundation. OpenID for Verifiable Presentations 1.0, Final Specification, 9 July 2025. [https://openid.net/specs/openid-4-verifiable-presentations-1_0.html](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

[8] EUDI Wallet Architecture and Reference Framework, current public version. [https://eudi.dev/latest/architecture-and-reference-framework-main/](https://eudi.dev/latest/architecture-and-reference-framework-main/)

[9] EUDI ARF Topic O: Catalogues for Attestations. [https://eudi.dev/2.5.0/discussion-topics/o-catalogues-for-attestations/](https://eudi.dev/2.5.0/discussion-topics/o-catalogues-for-attestations/)

[10] ISO/IEC 18013-5:2021, Personal identification - ISO-compliant driving licence - Part 5: Mobile driving licence application. [https://www.iso.org/standard/69084.html](https://www.iso.org/standard/69084.html)

[11] EUDI Wallet High-Level Requirements, current public repository CSV. [https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/refs/heads/main/hltr/high-level-requirements.csv](https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/refs/heads/main/hltr/high-level-requirements.csv)

[12] European Commission. European Business Wallets, Shaping Europe's Digital Future. [https://digital-strategy.ec.europa.eu/en/policies/business-wallets](https://digital-strategy.ec.europa.eu/en/policies/business-wallets)

[13] W3C Verifiable Credentials Working Group. DPP & Business Wallet Vocabularies Task Force repository. [https://github.com/w3c/vc-dpp-bw](https://github.com/w3c/vc-dpp-bw)

[14] GS1. EPCIS and CBV standard artefacts, including CBV ontology and JSON-LD context artefacts. [https://ref.gs1.org/standards/epcis/artefacts](https://ref.gs1.org/standards/epcis/artefacts)

[15] Industrial Digital Twin Association. Asset Administration Shell specifications. [https://industrialdigitaltwin.org/en/content-hub/aasspecifications](https://industrialdigitaltwin.org/en/content-hub/aasspecifications)

Source note: This paper uses standards and public technical documents available on 7 May 2026. SD-JWT VC remains an Internet-Draft in the cited version; ecosystem profiles should pin exact versions and migration rules. Specific claims about individual platform registration practices should not be cited without public evidence.
