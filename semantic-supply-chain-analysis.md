# The Semantic Supply Chain

**A Comparative Risk Analysis of Credential Meaning Distribution in W3C VCDM, SD-JWT VC, and ISO mdoc**

**Working paper for technical and policy discussion**

**Current as of:** 4 May 2026

> [!IMPORTANT]
> **Core thesis**
>
> The overbroad assertion that "JSON-LD is unsafe because it uses links" is technically incomplete. Uncontrolled semantic resolution is unsafe. The same architectural risk exists in SD-JWT VC and ISO mdoc through vct metadata, issuer metadata, namespaces, rulebooks, catalogues, and local configuration. The relevant assurance question is whether semantic dependencies are governed, versioned, integrity-protected, locally available, privacy-preserving, auditable, and tied to issuer authorisation.

**Audience:** senior cybersecurity architects, eIDAS 2.0 technical experts, HAIP/HAIP4W3C contributors, EUDI ARF experts, and standardisation bodies.

## Document orientation and balance check

This paper is written to evaluate credential format architectur options with **focus on semantic supply chain security** while not adressing other security controls. It does not claim that W3C VCDM, SD-JWT VC, or ISO mdoc is categorically superior. It narrows an overbroad security claim and compares the real control planes needed by all three formats.

- **What the paper accepts:** Uncontrolled remote JSON-LD context retrieval is unsafe in high-assurance validation. Context substitution, mutable context documents, privacy leakage, and inconsistent JSON-LD processing are real risks.
- **What the paper rejects:** The statement "JSON-LD is unsafe" as a general claim. W3C VCDM 2.0 and W3C Data Integrity define controls such as mandatory base context handling, context validation, resource integrity, known-good context checking, and no need for network requests during proof verification.
- **What the paper adds:** SD-JWT VC and mdoc shift semantic dependencies to other places. SD-JWT VC uses vct, Type Metadata, issuer metadata, registries, and local configuration. mdoc uses doctype, namespaces, data-element definitions, ISO or national definitions, and rulebooks.
- **What policymakers should take away:** The standardisation target is secured semantic dependencies, not the removal of all links.

## Table of contents

- [Document orientation and balance check](#document-orientation-and-balance-check)
- [1. Executive Summary and Risk Taxonomy](#1-executive-summary-and-risk-taxonomy)
- [2. Deep Dive: The Semantic Supply Chain](#2-deep-dive-the-semantic-supply-chain)
- [3. Format Analysis: The Visible and the Hidden](#3-format-analysis-the-visible-and-the-hidden)
- [4. The Rulebook and Governance Gap](#4-the-rulebook-and-governance-gap)
- [5. HAIP Gap Analysis](#5-haip-gap-analysis)
- [6. Unified Semantic Control Set](#6-unified-semantic-control-set)
- [7. Strategic Recommendations](#7-strategic-recommendations)
- [8. Final Position](#8-final-position)
- [Appendix A. Worked Examples](#appendix-a-worked-examples)
- [Appendix B. Semantic Risk Register](#appendix-b-semantic-risk-register)
- [References](#references)

## 1. Executive Summary and Risk Taxonomy

Digital credential systems do not only distribute signed data. They distribute meaning. A credential signature can prove that a payload was issued by a signing key. It does not, by itself, prove that the verifier has applied the correct schema, vocabulary, Type Metadata, namespace, rulebook, issuer-authorisation policy, or legal interpretation.

The common criticism that W3C VCDM JSON-LD is unsafe because it contains @context links is useful as a warning against uncontrolled remote semantic resolution. It is not a sound conclusion about the format as a whole. W3C VCDM 2.0 requires the base context to be the first @context item, allows related-resource integrity protection for contexts, and W3C Data Integrity requires context validation against known-good values or equivalent protections. W3C Data Integrity also states that proof verification is designed so that no network requests are necessary. [1][2]

SD-JWT VC does not use JSON-LD contexts. That removes JSON-LD expansion and JSON-LD canonicalisation concerns. But it does not remove semantic-distribution risk. SD-JWT VC uses the required vct claim as the credential type identifier. The current SD-JWT VC draft says ecosystems must define vct values, claim semantics, and issuing and validation rules. It also defines Type Metadata retrieval and documents risks such as SSRF, circular type inheritance, untrusted Type Metadata publishers, issuer-authorisation confusion, and metadata tracking. [3]

ISO mdoc uses doctype, namespaces, and data-element identifiers. Its core cryptographic mechanisms are strong and mature for mDL-style credentials, but semantic meaning for other mobile documents is left to the respective issuing authority or to ecosystem rulebooks. The EUDI ARF places such definitions into Attestation Rulebooks and machine-readable attestation schemes. [8][10]

> [!IMPORTANT]
> **Pointed finding**
>
> The risk is not gone with SD-JWT. It moves from @context to vct, Type Metadata, issuer metadata, registries, rulebooks, and local configuration. The same pattern appears in mdoc through doctype, namespaces, and rulebooks.

This paper uses four risk pillars:

| **Pillar**                          | **Question**                                                                              | **Typical failure**                                                                                       |
|-------------------------------------|-------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Governance / Authority              | Who is authorised to define the type, attribute meaning, rulebook, and issuer permission? | A malicious or unauthorised issuer uses a legitimate-looking type identifier.                             |
| Integrity / Semantic Supply Chain   | Is the semantic artifact versioned, signed, hash-pinned, cached, and auditable?           | A context, Type Metadata document, namespace, schema, or rulebook changes silently.                       |
| Operational / Availability and SSRF | Does validation depend on live remote metadata fetches?                                   | The verifier fetches attacker-controlled metadata, leaks information, fails offline, or triggers SSRF.    |
| Privacy / Metadata Tracking         | Does semantic lookup reveal where, when, or by whom a credential is used?                 | Fetching a context, vct URL, issuer metadata, status URL, or rulebook endpoint becomes a tracking signal. |

High-level comparison of type-to-meaning-to-rulebook resolution:

| **Format**       | **Type anchor**    | **Attribute meaning**                                                                                 | **Rulebook binding**                                            | **Main semantic risk**                                                                                                   |
|------------------|--------------------|-------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| W3C VCDM JSON-LD | type plus @context | JSON-LD terms mapped to IRIs; optional credential schema and vocabulary                               | Credential type, vocabulary, schema, and EUDI rulebook          | Visible external dependency through context and vocabulary links. Unsafe only if resolution is uncontrolled.             |
| SD-JWT VC        | vct                | Claim names plus Type Metadata, issuer metadata, OpenID4VCI credential configuration, and local rules | vct Type Metadata, registry, OpenID4VCI metadata, EUDI rulebook | Hidden or registry-based dependency. Unsafe if metadata is mutable, unauthorised, unpinned, or hardcoded inconsistently. |
| ISO mdoc         | doctype            | Namespace plus data-element identifiers                                                               | ISO definition, national scheme, attestation rulebook           | Out-of-band dependency. Unsafe if namespace, data-element meaning, or issuer authorisation is stale or ambiguous.        |

The main conclusion for HAIP, HAIP4W3C, ETSI, and EUDI work is that a high-assurance profile must add a cross-format semantic control plane. The debate should move from "links vs. no links" to "secured vs. unsecured semantic dependencies".

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

- Does legal_name mean registered legal entity name, trade name, tax name, or issuer-internal onboarding name?
- Does registry_number refer to a national commercial register, a local chamber register, a VAT register, or an issuer-specific identifier?
- Does active mean legally active, tax active, account active, not dissolved, or merely active in the issuer portal?
- Which rulebook version defines these terms?
- Which authority approved that rulebook?
- Is the issuer authorised to issue this credential type in this jurisdiction and for this purpose?

This is not a W3C-only problem. It exists whenever a compact identifier is used to trigger external interpretation logic.

### 2.2 Machine semantics and legal semantics

Machine-readable semantics and legal semantics are related but not the same. A JSON-LD context, SD-JWT Type Metadata document, mdoc namespace definition, or JSON Schema can describe how a machine should interpret a property. A legal trust decision also needs rulebook governance, issuer authorisation, supervisory acceptance, and verifier policy.

| **Layer**          | **Example question**                                  | **Common artifact**                                                     |
|--------------------|-------------------------------------------------------|-------------------------------------------------------------------------|
| Machine syntax     | Is the payload structurally valid?                    | JSON Schema, CBOR structure, credential format profile                  |
| Machine semantics  | What does this property identify?                     | JSON-LD context, Type Metadata, namespace registry                      |
| Operational policy | Which claims are required or selectively disclosable? | Rulebook, Type Metadata claim rules, DCQL policy                        |
| Trust decision     | Who may issue or receive this credential type?        | Trusted list, accreditation registry, EUDI catalogue, scheme governance |
| Legal acceptance   | Does this attestation have intended legal effect?     | eIDAS rule, ETSI profile, CAB/supervisory assessment, national law      |

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

The common architectural burden is therefore semantic dependency assurance. Each format must distribute meaning. Each ecosystem must govern that distribution.

## 3. Format Analysis: The Visible and the Hidden

### 3.1 W3C VCDM JSON-LD: explicit linkage

W3C VCDM JSON-LD places semantic dependencies in the credential. The @context maps JSON terms to URLs, while type identifies the credential and extension type. This gives visibility and supports cross-domain semantic reuse. It also makes the dependency obvious to critics.

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

The valid criticism is narrow: live retrieval of arbitrary @context URLs during high-assurance verification is unsafe. It can create context substitution, mutable semantic references, network-dependency, fingerprinting, and SSRF-like risks. W3C Data Integrity recognises this class of problem. It requires consuming applications to validate contexts against known-good values or equivalent protections and states that no network requests are necessary for proof verification. [2]

The broad assertion that JSON-LD is unsafe is not supported by the standards. W3C VCDM 2.0 mandates the base context as the first @context item and describes the base context as a static, permanently cacheable document. It also states that specifications building on VCDM may require JSON-LD contexts to be integrity-protected using relatedResource or an equivalent mechanism. [1]

VCDM relatedResource can bind external resources, including contexts, to digestSRI or digestMultibase values. A verifier using such a resource must compute the digest and fail if the digest does not match. [1]

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

A credential says "status": "active". A trusted context defines status as company-register legal status. A changed context defines status as issuer-portal account status. The signed JSON did not change. The semantic interpretation changed.

A high-assurance W3C VCDM profile should therefore require:

- approved context allow-list;
- pinned context hashes or signed context bundles;
- local context cache populated before validation;
- rejection of unknown contexts and unknown terms;
- strict control over inline contexts and @vocab;
- test vectors for expansion, canonicalisation, and proof verification.

W3C VCDM warns that @vocab in production can disable undefined-term errors and change semantics. [1] This warning should become a normative prohibition or strong constraint in a high-assurance profile.

### 3.2 SD-JWT VC: metadata registry and hidden semantics

SD-JWT VC avoids JSON-LD contexts. It uses JSON payloads with SD-JWT selective disclosure and the required vct claim as the credential type identifier. The SD-JWT VC draft states that vct is associated with rules defining permitted or required claims and selective-disclosure rules. It also states that the draft does not define vct values; ecosystems are expected to define vct values, claim semantics, and issuing and validation policies. [3]

```json
{
  "iss": "https://issuer.example.eu",
  "vct": "https://schemas.example.eu/eaa/company-registration/v1",
  "vct#integrity": "sha256-base64DigestValue...",
  "legal_name": "Example GmbH",
  "registry_number": "HRB 123456"
}
```

The Type Metadata document linked to vct can describe the credential type, display information, claims, mandatory claim rules, selective-disclosure rules, and type inheritance. It can be retrieved from an HTTPS URL, a registry, an ecosystem-defined method, or a local cache. If vct#integrity is present, it must be checked when retrieving the Type Metadata. [3]

```json
{
  "vct": "https://schemas.example.eu/eaa/company-registration/v1",
  "name": "Company Registration Credential",
  "description": "Attestation of legal-entity registration",
  "claims": [
    {
      "path": [
        "legal_name"
      ],
      "mandatory": "always",
      "sd": "never"
    },
    {
      "path": [
        "registry_number"
      ],
      "mandatory": "always",
      "sd": "never"
    },
    {
      "path": [
        "registered_address"
      ],
      "mandatory": "allowed",
      "sd": "allowed"
    }
  ]
}
```

This is the SD-JWT VC semantic supply chain. It is not JSON-LD. But it is an external semantic dependency. It can be remote, mutable, inherited, cached, registry-provided, or hardcoded.

#### 3.2.1 SD-JWT VC risks similar to JSON-LD context risks

| **Risk**                       | **SD-JWT VC manifestation**                                                  | **Source-backed observation**                                                                                      |
|--------------------------------|------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| Untrusted remote fetch         | Issuer metadata and Type Metadata URLs may be attacker-controlled.           | The SD-JWT VC draft warns that issuer metadata URLs are untrusted and can be SSRF vectors. [3]                   |
| Semantic substitution          | Type Metadata can change claim requirements or display and validation rules. | Type Metadata defines type information, claims, display, and extensions. Consumers must trust the publisher. [3] |
| Circular dependencies          | Type Metadata can extend another type, creating cycles.                      | Circular extends dependencies must be detected and credentials rejected. [3]                                     |
| Metadata availability          | Network-based Type Metadata retrieval may fail offline or under DoS.         | The draft recommends local caches where possible. [3]                                                            |
| Issuer-authorisation confusion | A rogue issuer can use or extend a known vct.                                | The draft states type reference does not confer authorisation to issue. [3]                                      |
| Metadata tracking              | Fetching vct Type Metadata can disclose credential use.                      | The draft warns that issuers or third parties may track usage through Type Metadata URL requests. [3]            |

> [!IMPORTANT]
> **Pointed finding**
>
> The SD-JWT VC draft itself documents the same class of problem that critics often attribute only to JSON-LD: remote semantic metadata, SSRF, circular inheritance, untrusted publishers, issuer-authorisation confusion, and metadata tracking.

#### 3.2.2 Example: metadata substitution in SD-JWT VC

A verifier receives a credential with vct set to company-registration/v1. The verifier retrieves Type Metadata from a URL. A compromised metadata endpoint marks registry_number as optional or selectively disclosable. The payload signature remains valid. The interpretation and validation rule changed.

Mitigation is the same architectural pattern used for JSON-LD contexts:

- versioned vct identifiers;
- mandatory vct#integrity or signed registry entries for high assurance;
- preloaded and locally cached Type Metadata;
- authorised Type Metadata publishers;
- rejection of untrusted metadata and circular inheritance;
- conformance tests for positive and negative semantic cases.

#### 3.2.3 Example: hidden hardcoding risk

An SD-JWT verifier can avoid live Type Metadata fetching by hardcoding claim meanings and vct rules. This reduces runtime network risk. It can increase audit and drift risk.

```text
Local verifier rule, version unknown:
company_registration.status = legally active

Updated rulebook, version 2:
company_registration.legalStatus = legally active
company_registration.portalStatus = issuer portal state
```

If the verifier continues to accept status without knowing the rulebook version, the system may pass cryptographic validation while failing semantic validation. Hidden semantics are not automatically safer; they are harder to audit unless the configuration package is signed, versioned, and traceable.

### 3.3 ISO mdoc: namespace and rulebook model

ISO mdoc has strong payload encoding, issuer authentication, and device authentication properties. In OpenID4VP, mdoc uses the mso_mdoc credential format identifier and core data structures encoded in CBOR and secured using COSE_Sign1. [7]

However, semantic meaning is still external. ISO/IEC 18013-5 is centred on mobile driving licence functionality. Its mechanisms can support other mobile documents, but the details of data elements for other mobile documents are left to the respective issuing authority. [10]

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

The verifier must still know the doctype, namespace, data-element definitions, rulebook version, and issuer authorisation. In EUDI, the ARF states that attestation schemes are machine-readable, that each scheme published in the catalogue refers to a human-readable Attestation Rulebook, and that the catalogue of attestation schemes enables actors to discover identifiers, syntax, and semantics of attributes within each attestation type. [8]

> [!NOTE]
> **Balanced assessment: mdoc**
>
> mdoc reduces some processing risks through compact CBOR/COSE structures and mature device authentication. It does not remove semantic governance. doctype, namespace, data-element definitions, and issuer authorisation still have to be secured and audited.

#### 3.3.1 Example: namespace drift

An mdoc data element named status can be interpreted under two versions of a national business-register namespace. Version 1 means legal entity status. Version 2 separates legalStatus and portalStatus. A verifier that hardcodes version 1 semantics may accept a credential according to stale rules. The COSE signature does not resolve the semantic drift.

### 3.4 Comparative severity view

| **Risk**                       | **W3C VCDM JSON-LD**                                                                                                   | **SD-JWT VC**                                                                                                                                | **ISO mdoc**                                                                                                   |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| Remote semantic fetch          | High if arbitrary @context retrieval is allowed; controllable with known-good context validation and pinned resources. | High if arbitrary vct / Type Metadata / issuer metadata retrieval is allowed; controllable with vct#integrity, registries, and local caches. | Lower in core mdoc payload processing, but present through catalogue, status, rulebook, and trust-list lookup. |
| Semantic substitution          | Context or vocabulary substitution.                                                                                    | Type Metadata or registry substitution.                                                                                                      | Namespace, doctype, or rulebook substitution.                                                                  |
| Hidden semantic drift          | Lower when contexts and schemas are explicit and archived; higher if inline contexts are uncontrolled.                 | Medium to high when semantics are local code or issuer config without signed versioning.                                                     | Medium to high when namespaces or national rulebooks are hardcoded.                                            |
| Issuer-authorisation confusion | A known type does not prove issuer authority.                                                                          | Explicitly documented in the SD-JWT VC draft.                                                                                                | A valid doctype does not prove issuer authority.                                                               |
| Metadata privacy leakage       | Context and verification method URLs can fingerprint validation.                                                       | vct, issuer metadata, and Type Metadata URLs can reveal credential use.                                                                      | Status, catalogue, and trust anchor lookup can reveal usage patterns.                                          |
| Auditability                   | Strong when contexts, schemas, and rulebooks are pinned and archived.                                                  | Strong when Type Metadata, registries, and rulebooks are signed and archived.                                                                | Strong when namespace and rulebook versions are signed and archived.                                           |

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

A catalogue entry can support discovery. It does not automatically create legal effect or issuer authorisation. The EUDI discussion paper on catalogues states that catalogue entries include namespaces, attribute identifiers, semantic descriptions, status and version of schemes, references to laws or standards, trust model, governance mechanisms, and provider/source requirements. [9]

### 4.2 The real vulnerability: uncontrolled semantic resolution

A link is not unsafe by nature. A local hardcoded mapping is not safe by nature. The control question is whether the semantic dependency is governed and secured.

| **Format** | **Controlled semantic resolution**                                                        | **Uncontrolled semantic resolution**                                                                                     |
|------------|-------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| W3C VCDM   | Approved context, pinned hash, local cache, archived vocabulary version.                  | Live fetch of arbitrary context URL, unknown inline context, or @vocab override.                                         |
| SD-JWT VC  | Approved vct, signed or hash-pinned Type Metadata, local cache, authorised publisher.     | Live fetch of untrusted Type Metadata, unknown registry, or issuer-defined display metadata treated as validation logic. |
| ISO mdoc   | Approved doctype and namespace, signed rulebook, certified issuer key and authority list. | Local hardcoded mapping with unknown version, unmanaged national extension, or stale namespace definition.               |
| OpenID4VCI | Credential configuration validated against scheme authority and issuer authorisation.     | Issuer metadata accepted as proof that the issuer may issue the credential type.                                         |

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

| **Check**            | **Question**                                                                          | **Example failure if missing**                      |
|----------------------|---------------------------------------------------------------------------------------|-----------------------------------------------------|
| Payload integrity    | Was the credential signed or secured correctly?                                       | Tampered claim accepted.                            |
| Semantic validity    | Is the type, namespace, context, or Type Metadata known and accepted?                 | Valid signature processed with wrong meaning.       |
| Issuer identity      | Who signed or sealed the credential?                                                  | Credential signed by unknown or spoofed issuer key. |
| Issuer authorisation | Is that issuer authorised for this type, rulebook, jurisdiction, and assurance level? | Rogue issuer uses legitimate-looking type.          |

## 5. HAIP Gap Analysis

### 5.1 What HAIP does well

OpenID4VC HAIP 1.0 profiles OpenID4VC for ecosystems that need a high level of security and privacy. It profiles OpenID4VCI, OpenID4VP, W3C Digital Credentials API flows, SD-JWT VC, and ISO mdoc. It requires support for at least one of the two credential-format profiles: SD-JWT VC or ISO mdoc. [5]

HAIP is strong where it is meant to be strong: reducing optionality in issuance and presentation protocols, key binding, wallet and key attestation, status handling, issuer key resolution, and baseline cryptographic algorithms. For SD-JWT VC, HAIP mandates dc+sd-jwt as format identifier, compact serialization support, status-list handling where status is present, X.509 certificate-based issuer key resolution, and KB-JWT presence when cryptographic holder binding is used. [5]

### 5.2 What HAIP leaves outside

HAIP 1.0 explicitly leaves trust management out of scope. Its out-of-scope section defines trust management as authorisation of issuers to issue certain credential types, wallets to be issued certain credential types, and verifiers to receive certain credential types. The methods for establishing trust or obtaining root certificates are also outside HAIP scope. [5]

This is a reasonable scope boundary for a technical interoperability profile. But it means HAIP conformance alone does not solve semantic governance, rulebook governance, or issuer authorisation.

### 5.3 Critical gap: SD-JWT semantic dependency assurance

HAIP 1.0 focuses on credential security and protocol interoperability. It does not add a cross-format semantic dependency assurance section. In particular, HAIP does not appear to make vct#integrity mandatory for all high-assurance SD-JWT VC Type Metadata, does not require a governed vct registry, and does not require that Type Metadata be preloaded, locally cached, signed, or pinned. It relies on the underlying SD-JWT VC draft and on ecosystem profiles for many of these semantic controls.

This matters because the current SD-JWT VC draft describes Type Metadata as a semantic artifact used by issuers, verifiers, and holders to understand semantics and rules. It also warns about SSRF, circular dependencies, untrusted metadata publishers, issuer-authorisation confusion, and privacy-preserving retrieval. [3]

> [!IMPORTANT]
> **Critical finding for the JSON-LD controversy**
>
> Critics who identify remote @context as a JSON-LD weakness are right about uncontrolled context fetching. But the same kind of weakness exists in SD-JWT VC if vct Type Metadata, issuer metadata, registries, or local semantic configuration are not governed, pinned, cached, and audited. HAIP currently does not fully close this semantic assurance gap.

### 5.4 Hidden semantics can be worse for auditability

A common intuition is that avoiding links improves security. It can improve operational robustness if it removes live runtime fetches. It can also reduce auditability if meaning is embedded in software, configuration files, or private scheme documents that are not signed, versioned, or archived.

| **Model**          | **Strength**                                                                                   | **Weakness**                                                                 |
|--------------------|------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| Explicit semantics | Semantic dependencies are visible in the credential or metadata and can be pinned and audited. | Unsafe if URLs are fetched live without validation.                          |
| Hidden semantics   | Few runtime dependencies; simple for closed deployments.                                       | Meaning may live in code or local config; semantic drift is hard to detect.  |
| Registry semantics | Can centralise governance and versioning.                                                      | Registry becomes critical infrastructure and privacy-sensitive lookup point. |
| Rulebook semantics | Strong legal and policy anchoring.                                                             | Human and machine rulebooks can diverge without strict change control.       |

### 5.5 Standards recommendation for HAIP and HAIP4W3C

HAIP and HAIP4W3C should add a format-neutral clause for Semantic Dependency Assurance. The clause should apply to W3C contexts, SD-JWT vct Type Metadata, mdoc namespaces, OpenID4VCI credential configurations, OpenID4VP/DCQL constraints, EUDI catalogues, and attestation rulebooks.

A W3C VCDM high-assurance profile should be added as a peer to the existing SD-JWT VC and ISO mdoc credential-format profiles. That addition should not merely define proof suites. It should define context governance, schema/rulebook binding, issuer-authorisation linkage, privacy-safe metadata retrieval, and conformance tests.

## 6. Unified Semantic Control Set

The following control set should apply across all high-assurance credential formats. It is designed to be format-neutral and CAB-assessable.

| **Control**                          | **Purpose**                                                                                                                                                             | **Implementation example**                                                                                    |
|--------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| 1. Semantic artifact inventory      | Identify every artifact that influences meaning: context, vct, Type Metadata, schema, namespace, rulebook, issuer metadata, verifier request template, catalogue entry. | All artifacts are listed in a signed implementation profile or rulebook annex.                                |
| 2. Versioned identifiers            | Avoid mutable or versionless type identifiers for high-assurance use.                                                                                                   | Use company-registration/v1, not company-registration/latest.                                                 |
| 3. Integrity protection             | Bind semantic artifacts to hashes, signatures, seals, or signed catalogue entries.                                                                                      | Use W3C relatedResource digestSRI, SD-JWT vct#integrity, or signed mdoc namespace registry.                   |
| 4. Local validation cache           | Do not depend on live remote semantic fetches during normal validation.                                                                                                 | Preload contexts, Type Metadata, namespaces, and rulebook bundles.                                            |
| 5. Authorised semantic publishers   | Define who may publish semantic artifacts for each domain and assurance level.                                                                                          | EU, Member State, authentic source, sector scheme owner, or accredited body.                                  |
| 6. Independent issuer authorisation | Check issuer authority separately from credential type.                                                                                                                 | Verify issuer identity, accreditation, trusted-list status, rulebook permission, and jurisdiction.            |
| 7. Display metadata separation      | Treat labels, logos, and descriptions as UI hints, not validation rules.                                                                                                | Do not accept a credential because the wallet displays "Qualified" or shows an official-looking logo.         |
| 8. Privacy-safe metadata resolution | Prevent semantic lookup from becoming a tracking channel.                                                                                                               | No holder-specific context/vct/metadata URLs; no issuer phone-home; use shared caches or neutral registries.  |
| 9. Conformance and negative tests   | Test meaning, not only signatures.                                                                                                                                      | Reject unknown context, changed metadata hash, circular type extension, unauthorised issuer, stale namespace. |
| 10. Semantic archive                | Preserve the exact semantic state used for validation.                                                                                                                  | Archive old context, metadata, schema, namespace, catalogue, and rulebook versions.                           |

### 6.1 Assurance levels for semantic dependencies

| **Level**                            | **Description**                                                                                                                     | **Suitable for**                                         |
|--------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Level 0: Uncontrolled                | Live remote fetch, no integrity, no governance, no cache.                                                                           | Not suitable for production.                             |
| Level 1: Basic web trust             | HTTPS URL and human documentation.                                                                                                  | Low-risk demos and proofs of concept.                    |
| Level 2: Profiled ecosystem          | Versioned identifiers, known schemas, local configuration, limited conformance tests.                                               | Controlled pilots and limited ecosystems.                |
| Level 3: High assurance              | Signed or pinned artifacts, local cache, explicit issuer authorisation, negative tests, audit trail.                                | HAIP-style regulated systems.                            |
| Level 4: Qualified / regulated trust | Accredited publisher, signed catalogue, CAB-assessable controls, supervisory acceptance, archived versions, trust-list integration. | eIDAS, QEAA, PuB-EAA, EU Business Wallet, regulated DPP. |

## 7. Strategic Recommendations

### 7.1 Cross-format recommendation

High-assurance profiles should add a mandatory cross-format clause named Semantic Dependency Assurance. This clause should state that credentials must not be accepted based only on a valid signature and known type string. The verifier must validate the semantic artifact, the rulebook version, and the issuer authorisation.

### 7.2 W3C VCDM / HAIP4W3C recommendation

- Require approved context allow-lists and local context caches.
- Require context integrity through relatedResource, signed bundles, or equivalent pinned-hash mechanisms.
- Forbid uncontrolled live remote context fetching during high-assurance validation.
- Forbid or strictly constrain @vocab and unapproved inline contexts.
- Bind credential type to a versioned rulebook and machine-readable schema.
- Define mandatory proof suites, canonicalisation algorithms, and test vectors.
- Require issuer-authorisation checks independent of W3C type values.

### 7.3 SD-JWT VC recommendation

- Require governed and versioned vct values for high-assurance credential types.
- Require vct#integrity or signed registry entries for Type Metadata used in high-assurance validation.
- Require local Type Metadata cache and prohibit live untrusted Type Metadata retrieval in the validation path.
- Limit type inheritance depth and require circular dependency rejection.
- Treat display metadata as non-authoritative.
- Require privacy-safe Type Metadata distribution and no holder-specific metadata URLs.
- Check issuer authorisation independently of vct and any extension hierarchy.

### 7.4 ISO mdoc recommendation

- Require governed doctype and namespace registries.
- Require signed or sealed data-element definitions and rulebooks.
- Bind doctype and namespace versions to the attestation rulebook.
- Require issuer authorisation by doctype, namespace, jurisdiction, and assurance level.
- Test namespace interpretation and stale-rulebook rejection.
- Ensure privacy-safe status, catalogue, and trust-anchor lookup.

### 7.5 EUDI ARF / ETSI recommendation

- Treat the catalogue of attestation schemes as semantic trust infrastructure, not only discovery infrastructure.
- Require explicit binding between human-readable rulebooks and machine-readable schemes.
- Require signed, versioned, archived machine-readable schemes.
- Add negative semantic test cases to conformance testing.
- Publish issuer-authorisation data by credential type and rulebook version.
- Align W3C VCDM JSON-LD, SD-JWT VC, and mdoc under the same Semantic Dependency Assurance model.

## 8. Final Position

The assertion "JSON-LD is unsafe" is too broad. A more precise statement is: uncontrolled semantic resolution is unsafe. That statement applies to all credential formats.

W3C VCDM makes semantic dependencies visible through `@context`, `type`, vocabularies, schemas, and related resources. This creates real operational duties. Those duties can be addressed through known-good context validation, resource integrity, local caches, strict extension control, and conformance tests. W3C VCDM and W3C Data Integrity already provide relevant building blocks for this control model [1], [2].

SD-JWT VC removes JSON-LD-specific processing concerns. It does not remove semantic dependency risk. The semantic dependency moves to `vct`, Type Metadata, issuer metadata, registries, local configuration, and rulebooks. The SD-JWT VC draft itself documents several of these risks, including metadata retrieval risks, Type Metadata trust, issuer-authorisation confusion, circular inheritance, and privacy leakage through Type Metadata lookup [3].

ISO mdoc provides strong compact credential and device-authentication mechanisms. It still depends on external `doctype`, namespace, data-element, issuer-authorisation, and rulebook governance. In the EUDI context, this semantic layer is handled through attestation schemes, namespaces, catalogues, and Attestation Rulebooks [8], [9], [10].

**Credential-format decisions are therefore be requirements-driven:** 
- For a *compact, small and well-bounded credential*, such as a natural-person identity card with a small set of stable attributes, SD-JWT VC or ISO mdoc can be a strong choice. A typical example is an identity credential with about ten attributes, such as family name, given name, date of birth, nationality, document number, issuing authority, validity period, portrait reference, address, and age-over flags. In such cases, the semantic model is narrow, stable, and easy to govern. Compact payloads, selective disclosure, mature OpenID4VC profiling, and device-binding models fit these constrained identity use cases well.
- The decision changes when the *credential is semantically rich*. Enterprise KYC and KYB records, business-wallet owner identity credentials, mandates, powers of attorney, supply-chain due-diligence attestations, Digital Product Passports, Industry 4.0 asset credentials, and trusted-AI provenance records can contain tens, hundreds or thousands of different attributes types. They can include legal-entity identifiers, beneficial ownership, sanctions-screening evidence, authority-to-act chains, registered-address structures, tax identifiers, sector codes, product identifiers, batch and serial numbers, material composition, lifecycle events, carbon-footprint data, conformity evidence, provenance links, units of measure, and jurisdiction-specific meanings. In those settings, the core requirement is not compact disclosure. It is shared machine meaning across organisations, systems, jurisdictions, and value chains for real-time machine validation.

This is where W3C VCDM and JSON-LD are strategically important. They support explicit, standardised semantic models and reusable vocabularies. This is visible in W3C work on Digital Product Passport and Business Wallet vocabularies, and it is consistent with existing industry semantic models such as GS1 EPCIS/CBV for supply-chain visibility and the Asset Administration Shell for Industry 4.0 information exchange [13], [14], [15]. The European Business Wallet is intended as a harmonised tool for companies and public-sector bodies to identify, authenticate, and exchange trusted data and documents with legal effect across the EU [12]. If the European Business Wallet is to support enterprise onboarding, regulated product data, supply-chain due diligence, industrial asset data, and trusted-AI attestations, support for semantically rich credentials is a foundational capability, not an optional convenience.

The security implication is clear. JSON-LD does not become unsafe because it exposes semantic dependencies. It becomes suitable for high assurance when those dependencies are governed and controlled. The same is true for SD-JWT VC and mdoc. Removing JSON-LD does not remove the semantic requirement; it only moves the requirement into Type Metadata, registries, schemas, rulebooks, or local configuration. This paper shows that the semantic supply-chain risks of JSON-LD are comparable to the corresponding risks in other credential formats, and that they can be mitigated with similar mechanisms: versioning, integrity protection, local caching, authorised semantic publishers, issuer-authorisation checks, privacy-preserving metadata distribution, auditability, and conformance tests.

This paper therefore does not argue that W3C VCDM/JSON-LD should replace SD-JWT VC or mdoc in every use case. It argues that W3C VCDM/JSON-LD must be available as a high-assurance option where the use case requires semantically rich credentials. This is the motivation for a `HAIP4@W3CVC` profile, or more formally a high-assurance interoperability profile for W3C VCDM credentials: to apply the same HAIP-style discipline already expected for SD-JWT VC and mdoc, while preserving the semantic richness needed for enterprise, supply-chain, DPP, Industry 4.0, and trusted-AI use cases.

> [!IMPORTANT]
> **Final statement**
>
> The debate must move from "links vs. no links" to "secured vs. unsecured semantic dependencies". High assurance requires governed, versioned, integrity-protected, locally available, privacy-preserving, auditable semantic dependencies for every credential format. Credential-format selection should then follow the use-case requirements: compact formats for simple, stable attribute sets; explicit, standardised semantic models for complex business, product, supply-chain, Industry 4.0, and trusted-AI credentials. That is why a high-assurance W3C VCDM profile is needed.


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

Validation dependency: governed vct, Type Metadata integrity, claim rules, rulebook, issuer authorisation.

#### ISO mdoc example

```text
doctype = eu.europa.ec.eudi.business.company_registration.1
namespace = eu.europa.ec.eudi.business.company
data elements = legal_name, registration_number
```

Validation dependency: doctype registry, namespace definition, data-element semantics, rulebook, issuer authorisation.

### A.2 Same failure mode, three formats

| **Failure mode**        | **W3C VCDM**                                                        | **SD-JWT VC**                                                   | **ISO mdoc**                                                      |
|-------------------------|---------------------------------------------------------------------|-----------------------------------------------------------------|-------------------------------------------------------------------|
| Wrong meaning of status | Context changes status from legal status to portal status.          | Type Metadata or local rules define status differently.         | Namespace version changes status meaning.                         |
| Unauthorised issuer     | Issuer signs CompanyRegistrationCredential but is not the register. | Issuer signs credential with known vct but lacks authorisation. | Issuer signs mdoc doctype but is not authorised for that doctype. |
| Metadata tracking       | Verifier fetches unique context URL.                                | Verifier fetches holder-specific issuer or Type Metadata URL.   | Verifier performs unique status/catalogue lookup.                 |
| Audit failure           | Context not archived.                                               | Type Metadata or local config not archived.                     | Namespace or rulebook version not archived.                       |

## Appendix B. Semantic Risk Register

| **Risk**                       | **Description**                                                     | **Applies to**                                   | **Mitigation**                                                |
|--------------------------------|---------------------------------------------------------------------|--------------------------------------------------|---------------------------------------------------------------|
| Semantic substitution          | External artifact changes the meaning of signed data.               | All formats                                      | Version, pin, sign, cache, archive semantic artifacts.        |
| Untrusted metadata publisher   | Consumer treats a publisher as authoritative without accreditation. | W3C, SD-JWT VC, EUDI catalogues                  | Authorised publisher registry and governance.                 |
| Issuer-authorisation confusion | Known type accepted as proof of issuer right.                       | All formats                                      | Independent issuer-authorisation check.                       |
| Live fetch dependency          | Validation fails offline or leaks use.                              | All formats                                      | Local cache, batch updates, neutral mirrors.                  |
| SSRF                           | Verifier resolves attacker-controlled URL.                          | W3C contexts, SD-JWT metadata, issuer metadata   | URL allow-list, no internal network access, size/time limits. |
| Circular inheritance           | Type dependencies recurse indefinitely or ambiguously.              | SD-JWT VC Type Metadata; analogous schema graphs | Cycle detection, inheritance-depth limits.                    |
| Display deception              | UI labels or logos mislead user or verifier.                        | All formats                                      | Treat display metadata as non-authoritative; escape text.     |
| Semantic drift                 | Local hardcoded meaning diverges from rulebook.                     | All formats                                      | Signed config packages, version checks, deprecation policy.   |
| Privacy leakage                | Metadata or status lookup reveals credential use.                   | All formats                                      | No holder-specific URLs, shared caches, no issuer phone-home. |
| Conformance gap                | Implementations verify signatures but not semantic meaning.         | All formats                                      | Positive and negative semantic test vectors.                  |

## References

[1] W3C. Verifiable Credentials Data Model v2.0. W3C Recommendation, 15 May 2025. [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)

[2] W3C. Verifiable Credential Data Integrity 1.0. W3C Recommendation, 15 May 2025. [https://www.w3.org/TR/vc-data-integrity/](https://www.w3.org/TR/vc-data-integrity/)

[3] IETF OAuth Working Group. SD-JWT-based Verifiable Digital Credentials (SD-JWT VC), draft-ietf-oauth-sd-jwt-vc-16, April 2026. [https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)

[4] IETF. RFC 9901: Selective Disclosure for JSON Web Tokens (SD-JWT), 19 November 2025. [https://datatracker.ietf.org/doc/rfc9901/](https://datatracker.ietf.org/doc/rfc9901/)

[5] OpenID Foundation. OpenID4VC High Assurance Interoperability Profile 1.0, Final Specification. [https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)

[6] OpenID Foundation. OpenID for Verifiable Credential Issuance 1.0, Final Specification, 16 September 2025. [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

[7] OpenID Foundation. OpenID for Verifiable Presentations 1.0, Final Specification, 9 July 2025. [https://openid.net/specs/openid-4-verifiable-presentations-1_0.html](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

[8] EUDI Wallet Architecture and Reference Framework 2.8.0, Section 5.4 and 5.5. [https://eudi.dev/2.8.0/architecture-and-reference-framework-main/](https://eudi.dev/2.8.0/architecture-and-reference-framework-main/)

[9] EUDI ARF Topic O: Catalogues for Attestations, version 2.5.0. [https://eudi.dev/2.5.0/discussion-topics/o-catalogues-for-attestations/](https://eudi.dev/2.5.0/discussion-topics/o-catalogues-for-attestations/)

[10] ISO/IEC 18013-5:2021, Personal identification - ISO-compliant driving licence - Part 5: Mobile driving licence application, ISO/IEC preview material. [https://www.iso.org/standard/69084.html](https://www.iso.org/standard/69084.html)

[11] EUDI Wallet High-Level Requirements, current public repository CSV. [https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/refs/heads/main/hltr/high-level-requirements.csv](https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/refs/heads/main/hltr/high-level-requirements.csv)

Source note: This paper uses standards and public technical documents available on 4 May 2026. SD-JWT VC remains an Internet-Draft in the cited version; HAIP 1.0 references SD-JWT VC draft -13 while the current IETF draft cited here is draft -16. Ecosystem profiles should pin exact versions and migration rules.
