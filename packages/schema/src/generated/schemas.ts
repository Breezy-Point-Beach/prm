// GENERATED FILE — do not edit.
// Source: spec/schemas/*.json  ·  Regenerate: pnpm --filter @prm/schema generate
/* eslint-disable */

export const policySchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://rightsroot.org/spec/prm/schemas/prm-policy-v1.schema.json",
  "title": "PRM Personal Data Policy v1",
  "description": "A cryptographically signed, versioned statement by a natural person of the terms under which information about them may be processed after initial observation. HASHING NOTE: the canonical digest is SHA-256(JCS(document with 'id' and 'proof' members removed)).",
  "type": "object",
  "required": [
    "@context",
    "type",
    "policyChainId",
    "version",
    "previousPolicyHash",
    "issuer",
    "effectiveDate",
    "jurisdictions",
    "rules",
    "proof"
  ],
  "additionalProperties": true,
  "$comment": "additionalProperties is true by design: unknown members are inside the signed bytes and must not break verification. Verifiers MUST surface unknown members to a human and MUST treat unknown rule categories as 'deny' when processing conservatively.",
  "properties": {
    "@context": {
      "type": "array",
      "minItems": 2,
      "items": {
        "type": "string",
        "format": "uri"
      },
      "prefixItems": [
        {
          "const": "https://www.w3.org/ns/credentials/v2"
        },
        {
          "const": "https://rightsroot.org/spec/prm/ns/v1"
        }
      ]
    },
    "type": {
      "type": "array",
      "contains": {
        "const": "PersonalDataPolicy"
      },
      "items": {
        "type": "string"
      }
    },
    "id": {
      "$ref": "#/$defs/policyUrn",
      "description": "Self-referential canonical identifier. EXCLUDED from the hashed bytes."
    },
    "policyChainId": {
      "type": "string",
      "pattern": "^urn:prm:chain:u[A-Za-z0-9_-]{40,}$",
      "description": "Digest of version 1 of this chain. Stable across all versions."
    },
    "version": {
      "type": "integer",
      "minimum": 1
    },
    "previousPolicyHash": {
      "oneOf": [
        {
          "$ref": "#/$defs/multihash"
        },
        {
          "type": "null"
        }
      ],
      "description": "MUST be null if and only if version == 1."
    },
    "supersedes": {
      "$ref": "#/$defs/multihash"
    },
    "issuer": {
      "type": "object",
      "required": [
        "id",
        "did",
        "keyEventHash"
      ],
      "additionalProperties": false,
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^prm:[a-z2-7]{26,52}$",
          "description": "Self-certifying account identifier = base32(SHA-256(JCS(genesis key event)))."
        },
        "did": {
          "type": "string",
          "pattern": "^did:(key|web):",
          "description": "Interop alias resolving to the same public key."
        },
        "keyEventLog": {
          "type": "string",
          "format": "uri"
        },
        "keyEventHash": {
          "$ref": "#/$defs/multihash",
          "description": "Digest of the KEL head event that authorized the signing key."
        },
        "displayName": {
          "type": "string",
          "maxLength": 128,
          "description": "OPTIONAL and user-chosen. May be a pseudonym. Never required."
        }
      }
    },
    "effectiveDate": {
      "$ref": "#/$defs/utcInstant"
    },
    "expirationDate": {
      "$ref": "#/$defs/utcInstant",
      "description": "Absent means: effective until superseded or revoked."
    },
    "jurisdictions": {
      "type": "array",
      "minItems": 1,
      "uniqueItems": true,
      "items": {
        "type": "string",
        "pattern": "^[A-Z]{2}(-[A-Z0-9]{1,3})?$|^EU$",
        "description": "ISO 3166-1 alpha-2, optionally with a 3166-2 subdivision. Declared by the user, not adjudicated by PRM."
      }
    },
    "rules": {
      "type": "array",
      "minItems": 1,
      "items": {
        "$ref": "#/$defs/rule"
      }
    },
    "exceptions": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/inlineException"
      },
      "description": "Public standing carve-outs. Prefer private Authorization records; inline exceptions leak relationships."
    },
    "authorizationSetHash": {
      "$ref": "#/$defs/multihash",
      "description": "Merkle root over the set of currently valid private Authorization records. Proves grants exist without disclosing grantees."
    },
    "identifierCommitments": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/identifierCommitment"
      },
      "description": "Salted commitments to identifiers this policy covers. Openable only by a party given the salt."
    },
    "requests": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "deletionOnPurposeCompletion": {
          "type": "boolean"
        },
        "doNotSellOrShare": {
          "type": "boolean"
        },
        "globalPrivacyControl": {
          "type": "boolean"
        },
        "accessRequestContact": {
          "type": "string",
          "format": "uri"
        }
      }
    },
    "humanReadable": {
      "type": "object",
      "required": [
        "mediaType",
        "language",
        "text"
      ],
      "additionalProperties": false,
      "properties": {
        "mediaType": {
          "enum": [
            "text/markdown",
            "text/plain"
          ]
        },
        "language": {
          "type": "string",
          "pattern": "^[a-z]{2}(-[A-Z]{2})?$"
        },
        "text": {
          "type": "string",
          "minLength": 1,
          "maxLength": 20000
        }
      },
      "description": "Carried INSIDE the signed bytes so prose and rules cannot drift."
    },
    "legalNotice": {
      "type": "string",
      "maxLength": 20000
    },
    "distribution": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "canonicalUrl": {
          "type": "string",
          "format": "uri"
        },
        "machineUrl": {
          "type": "string",
          "format": "uri"
        },
        "shortUrl": {
          "type": "string",
          "format": "uri"
        },
        "statusList": {
          "type": "string",
          "format": "uri"
        }
      }
    },
    "proof": {
      "$ref": "#/$defs/dataIntegrityProof"
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "version": {
            "const": 1
          }
        },
        "required": [
          "version"
        ]
      },
      "then": {
        "properties": {
          "previousPolicyHash": {
            "type": "null"
          }
        }
      },
      "else": {
        "properties": {
          "previousPolicyHash": {
            "$ref": "#/$defs/multihash"
          }
        }
      }
    }
  ],
  "$defs": {
    "multihash": {
      "type": "string",
      "pattern": "^u[A-Za-z0-9_-]{40,}$",
      "description": "Multibase 'u' (base64url, no pad) over a multihash: 0x12 0x20 || SHA-256 digest."
    },
    "policyUrn": {
      "type": "string",
      "pattern": "^urn:prm:policy:u[A-Za-z0-9_-]{40,}$"
    },
    "utcInstant": {
      "type": "string",
      "format": "date-time",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$",
      "description": "RFC 3339 in UTC with 'Z' and no fractional seconds. Enforced for canonicalization determinism."
    },
    "category": {
      "type": "string",
      "anyOf": [
        {
          "enum": [
            "prm:observation",
            "prm:transactional",
            "prm:retention",
            "prm:location-history",
            "prm:correlation",
            "prm:profiling",
            "prm:inference",
            "prm:third-party-sharing",
            "prm:sale",
            "prm:commercialization",
            "prm:advertising",
            "prm:ai-training",
            "prm:biometric",
            "prm:law-enforcement",
            "prm:emergency",
            "prm:deletion"
          ]
        },
        {
          "pattern": "^[a-z][a-z0-9+.-]*:[A-Za-z0-9._~%!$&'()*+,;=:@/-]+$"
        }
      ],
      "description": "A v1 core term or any extension URI. Unknown categories MUST be treated as 'deny' by conservative processors."
    },
    "rule": {
      "type": "object",
      "required": [
        "category",
        "decision"
      ],
      "additionalProperties": false,
      "properties": {
        "category": {
          "$ref": "#/$defs/category"
        },
        "decision": {
          "enum": [
            "allow",
            "deny",
            "conditional"
          ]
        },
        "conditions": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "maxRetention": {
              "type": "string",
              "pattern": "^P(?!$)(\\d+Y)?(\\d+M)?(\\d+W)?(\\d+D)?(T(?=\\d)(\\d+H)?(\\d+M)?(\\d+S)?)?$",
              "description": "ISO 8601 duration. 'P0D' means no retention beyond the transaction."
            },
            "purposes": {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            "recipients": {
              "type": "array",
              "items": {
                "type": "string"
              },
              "description": "Organization identifiers or classes. 'prm:none' denies all recipients."
            },
            "jurisdictions": {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            "requiresLegalProcess": {
              "type": "boolean"
            },
            "requiresNotice": {
              "type": "boolean"
            },
            "note": {
              "type": "string",
              "maxLength": 2000
            }
          }
        },
        "basisAcknowledged": {
          "type": "array",
          "items": {
            "enum": [
              "statutory-override",
              "court-order",
              "vital-interest",
              "contract"
            ]
          },
          "description": "Bases the user concedes may lawfully override this rule. Stating them strengthens the rest of the policy."
        },
        "note": {
          "type": "string",
          "maxLength": 2000
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "decision": {
                "const": "conditional"
              }
            },
            "required": [
              "decision"
            ]
          },
          "then": {
            "required": [
              "conditions"
            ]
          }
        }
      ]
    },
    "inlineException": {
      "type": "object",
      "required": [
        "organization",
        "purposes",
        "categories"
      ],
      "additionalProperties": false,
      "properties": {
        "organization": {
          "type": "string"
        },
        "organizationId": {
          "type": "string"
        },
        "purposes": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "string"
          }
        },
        "categories": {
          "type": "array",
          "minItems": 1,
          "items": {
            "$ref": "#/$defs/category"
          }
        },
        "expires": {
          "$ref": "#/$defs/utcInstant"
        },
        "note": {
          "type": "string",
          "maxLength": 2000
        }
      }
    },
    "identifierCommitment": {
      "type": "object",
      "required": [
        "namespace",
        "commitment"
      ],
      "additionalProperties": false,
      "properties": {
        "namespace": {
          "type": "string",
          "examples": [
            "email",
            "phone",
            "us-license-plate",
            "device-id",
            "account-id",
            "vin"
          ],
          "description": "Normalization rules are namespace-specific and defined in @prm/schema."
        },
        "commitment": {
          "$ref": "#/$defs/multihash",
          "description": "SHA-256(namespace || 0x00 || normalize(identifier) || 0x00 || salt). Salt is per-identifier, 16 random bytes, disclosed only to chosen parties."
        },
        "hint": {
          "type": "string",
          "maxLength": 24,
          "description": "OPTIONAL low-entropy display hint, e.g. '***1234'. Increases correlation risk; default off."
        }
      }
    },
    "dataIntegrityProof": {
      "type": "object",
      "required": [
        "type",
        "cryptosuite",
        "created",
        "verificationMethod",
        "proofPurpose",
        "proofValue"
      ],
      "additionalProperties": false,
      "properties": {
        "type": {
          "const": "DataIntegrityProof"
        },
        "cryptosuite": {
          "const": "eddsa-jcs-2022"
        },
        "created": {
          "$ref": "#/$defs/utcInstant"
        },
        "verificationMethod": {
          "type": "string"
        },
        "proofPurpose": {
          "const": "assertionMethod"
        },
        "proofValue": {
          "type": "string",
          "pattern": "^z[1-9A-HJ-NP-Za-km-z]{80,100}$",
          "description": "Multibase base58btc Ed25519 signature over 'PRM-POLICY-v1\\x00' || SHA-256(JCS(doc minus id, proof))."
        },
        "previousProof": {
          "type": "string"
        }
      }
    }
  }
} as const

export const authorizationSchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://rightsroot.org/spec/prm/schemas/prm-authorization-v1.schema.json",
  "title": "PRM Authorization (Exception Grant) v1",
  "description": "A signed, scoped, expiring grant from an individual to one named organization, carving an exception out of that individual's Personal Data Policy. Digest = SHA-256(JCS(doc minus 'id' and 'proof')); signature domain prefix 'PRM-AUTHZ-v1\\x00'.",
  "type": "object",
  "required": [
    "@context",
    "type",
    "policyChainId",
    "boundPolicyHash",
    "grantee",
    "purposes",
    "categories",
    "issued",
    "expires",
    "proof"
  ],
  "additionalProperties": false,
  "properties": {
    "@context": {
      "type": "array",
      "prefixItems": [
        {
          "const": "https://www.w3.org/ns/credentials/v2"
        },
        {
          "const": "https://rightsroot.org/spec/prm/ns/v1"
        }
      ],
      "items": {
        "type": "string",
        "format": "uri"
      }
    },
    "type": {
      "type": "array",
      "contains": {
        "const": "PRMAuthorization"
      },
      "items": {
        "type": "string"
      }
    },
    "id": {
      "type": "string",
      "pattern": "^urn:prm:authz:u[A-Za-z0-9_-]{40,}$"
    },
    "policyChainId": {
      "type": "string",
      "pattern": "^urn:prm:chain:u[A-Za-z0-9_-]{40,}$"
    },
    "boundPolicyHash": {
      "$ref": "#/$defs/multihash",
      "description": "The exact policy version this grant modifies. A new policy version does not silently re-scope an existing grant."
    },
    "grantee": {
      "type": "object",
      "required": [
        "name"
      ],
      "additionalProperties": false,
      "properties": {
        "name": {
          "type": "string",
          "maxLength": 256
        },
        "id": {
          "type": "string",
          "description": "Organization DID, domain, or PRM org id."
        },
        "did": {
          "type": "string",
          "pattern": "^did:"
        },
        "domain": {
          "type": "string"
        },
        "contact": {
          "type": "string",
          "format": "email"
        }
      }
    },
    "subjectRef": {
      "type": "object",
      "additionalProperties": false,
      "description": "How the grantee locates this person in their own records. Pairwise by default.",
      "properties": {
        "pairwiseId": {
          "type": "string",
          "description": "HKDF(S_bind, 'prm/v1/pairwise' || granteeId) — unique to this relationship, uncorrelatable across grantees."
        },
        "disclosedIdentifiers": {
          "type": "array",
          "items": {
            "type": "object",
            "required": [
              "namespace",
              "value",
              "salt"
            ],
            "additionalProperties": false,
            "properties": {
              "namespace": {
                "type": "string"
              },
              "value": {
                "type": "string"
              },
              "salt": {
                "type": "string",
                "description": "base64url; opens the matching identifierCommitment in the policy."
              }
            }
          },
          "description": "Selective disclosure. Only present when the grantee genuinely needs the raw identifier."
        }
      }
    },
    "purposes": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string"
      }
    },
    "categories": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string"
      },
      "description": "Processing categories permitted by this grant, overriding the base policy for this grantee only."
    },
    "dataCategories": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Which classes of data the grant covers, e.g. 'location', 'plate-read', 'contact'."
    },
    "issued": {
      "$ref": "#/$defs/utcInstant"
    },
    "notBefore": {
      "$ref": "#/$defs/utcInstant"
    },
    "expires": {
      "$ref": "#/$defs/utcInstant",
      "description": "REQUIRED. Perpetual grants are not expressible by design; re-grant instead."
    },
    "maxRetention": {
      "type": "string",
      "pattern": "^P(?!$)(\\d+Y)?(\\d+M)?(\\d+W)?(\\d+D)?(T(?=\\d)(\\d+H)?(\\d+M)?(\\d+S)?)?$"
    },
    "onwardSharing": {
      "enum": [
        "prohibited",
        "processors-only",
        "named-only"
      ],
      "default": "prohibited"
    },
    "onwardRecipients": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "revocation": {
      "type": "object",
      "required": [
        "statusListCredential",
        "statusListIndex"
      ],
      "additionalProperties": false,
      "properties": {
        "statusListCredential": {
          "type": "string",
          "format": "uri"
        },
        "statusListIndex": {
          "type": "integer",
          "minimum": 0
        },
        "statusPurpose": {
          "const": "revocation"
        }
      },
      "description": "W3C Bitstring Status List v1.0 entry. Absence of a status list means the grantee cannot check revocation and MUST honour 'expires' strictly."
    },
    "receiptRequested": {
      "type": "boolean",
      "default": true
    },
    "note": {
      "type": "string",
      "maxLength": 2000
    },
    "proof": {
      "$ref": "https://rightsroot.org/spec/prm/schemas/prm-policy-v1.schema.json#/$defs/dataIntegrityProof"
    }
  },
  "$defs": {
    "multihash": {
      "type": "string",
      "pattern": "^u[A-Za-z0-9_-]{40,}$"
    },
    "utcInstant": {
      "type": "string",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"
    }
  }
} as const

export const keyEventSchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://rightsroot.org/spec/prm/schemas/prm-key-event-v1.schema.json",
  "title": "PRM Key Event v1",
  "description": "One entry in a self-certifying, hash-chained Key Event Log. accountId = 'prm:' + base32-nopad-lower(SHA-256(JCS(genesis event minus proof)))[0..25]. Signature domain prefix 'PRM-KEYEVENT-v1\\x00'.",
  "type": "object",
  "required": [
    "type",
    "eventType",
    "sequence",
    "previousEventHash",
    "created",
    "keys",
    "nextKeyDigests",
    "threshold",
    "proof"
  ],
  "additionalProperties": false,
  "properties": {
    "type": {
      "const": "prm/KeyEvent/v1"
    },
    "eventType": {
      "enum": [
        "genesis",
        "rotation",
        "recovery",
        "revocation",
        "delegation"
      ],
      "description": "genesis: sequence 0. rotation: signed by current AND pre-committed next key. recovery: signed by a pre-committed recovery key. revocation: marks a key compromised from an instant. delegation: registers an additional authorized signer (including any opt-in custodial arrangement, which is therefore publicly visible)."
    },
    "sequence": {
      "type": "integer",
      "minimum": 0
    },
    "previousEventHash": {
      "oneOf": [
        {
          "$ref": "#/$defs/multihash"
        },
        {
          "type": "null"
        }
      ]
    },
    "created": {
      "$ref": "#/$defs/utcInstant"
    },
    "keys": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": [
          "id",
          "alg",
          "publicKeyMultibase"
        ],
        "additionalProperties": false,
        "properties": {
          "id": {
            "type": "string",
            "pattern": "^#[A-Za-z0-9_-]{1,32}$"
          },
          "alg": {
            "enum": [
              "Ed25519",
              "ES256"
            ],
            "$comment": "ES256 permitted so a Secure Enclave / StrongBox device key can be an authorized signer without ever reconstructing the seed. Algorithm-tagged so ML-DSA can be added later by rotation, not redesign."
          },
          "publicKeyMultibase": {
            "type": "string",
            "pattern": "^z[1-9A-HJ-NP-Za-km-z]{40,}$"
          },
          "use": {
            "type": "array",
            "items": {
              "enum": [
                "assertion",
                "authentication",
                "capability"
              ]
            }
          },
          "device": {
            "type": "string",
            "maxLength": 64,
            "description": "User-facing label only. No device fingerprinting."
          }
        }
      }
    },
    "nextKeyDigests": {
      "type": "array",
      "minItems": 1,
      "items": {
        "$ref": "#/$defs/multihash"
      },
      "description": "PRE-ROTATION COMMITMENT. A rotation is valid only if it reveals a public key whose digest appears here. This is what prevents an attacker holding the current signing key from taking over the account."
    },
    "recoveryKeyDigests": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/multihash"
      }
    },
    "threshold": {
      "type": "integer",
      "minimum": 1
    },
    "revokedKeys": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "publicKeyMultibase",
          "effectiveFrom"
        ],
        "additionalProperties": false,
        "properties": {
          "publicKeyMultibase": {
            "type": "string"
          },
          "effectiveFrom": {
            "$ref": "#/$defs/utcInstant"
          },
          "reason": {
            "enum": [
              "compromise",
              "superseded",
              "device-loss",
              "unspecified"
            ]
          }
        }
      },
      "$comment": "CRL semantics: signatures whose log inclusion time precedes effectiveFrom REMAIN valid. Revoking must not destroy the evidentiary value of past signatures."
    },
    "services": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "type",
          "endpoint"
        ],
        "additionalProperties": false,
        "properties": {
          "type": {
            "type": "string",
            "examples": [
              "PRMPublisher",
              "PRMLedger",
              "PRMContact"
            ]
          },
          "endpoint": {
            "type": "string",
            "format": "uri"
          }
        }
      }
    },
    "proof": {
      "type": "array",
      "minItems": 1,
      "items": {
        "$ref": "https://rightsroot.org/spec/prm/schemas/prm-policy-v1.schema.json#/$defs/dataIntegrityProof"
      },
      "description": "Array because a rotation carries TWO signatures: one by the outgoing key, one by the newly revealed pre-committed key."
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "eventType": {
            "const": "genesis"
          }
        },
        "required": [
          "eventType"
        ]
      },
      "then": {
        "properties": {
          "sequence": {
            "const": 0
          },
          "previousEventHash": {
            "type": "null"
          }
        },
        "required": [
          "recoveryKeyDigests"
        ]
      },
      "else": {
        "properties": {
          "sequence": {
            "minimum": 1
          },
          "previousEventHash": {
            "$ref": "#/$defs/multihash"
          }
        }
      }
    },
    {
      "if": {
        "properties": {
          "eventType": {
            "const": "rotation"
          }
        },
        "required": [
          "eventType"
        ]
      },
      "then": {
        "properties": {
          "proof": {
            "minItems": 2
          }
        }
      }
    }
  ],
  "$defs": {
    "multihash": {
      "type": "string",
      "pattern": "^u[A-Za-z0-9_-]{40,}$"
    },
    "utcInstant": {
      "type": "string",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"
    }
  }
} as const

export const ledgerEntrySchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://rightsroot.org/spec/prm/schemas/prm-ledger-entry-v1.schema.json",
  "title": "PRM Ledger Entry v1",
  "description": "One entry in an individual's append-only personal hash chain. The chain is the user's own evidence record; only entryHash values are submitted to the global Merkle transparency log, so the log learns nothing about content. Signature domain prefix 'PRM-LEDGER-v1\\x00'.",
  "type": "object",
  "required": [
    "type",
    "accountId",
    "sequence",
    "previousEntryHash",
    "recorded",
    "entryType",
    "subjectHash",
    "proof"
  ],
  "additionalProperties": false,
  "properties": {
    "type": {
      "const": "prm/LedgerEntry/v1"
    },
    "accountId": {
      "type": "string",
      "pattern": "^prm:[a-z2-7]{26,52}$"
    },
    "sequence": {
      "type": "integer",
      "minimum": 0
    },
    "previousEntryHash": {
      "oneOf": [
        {
          "$ref": "#/$defs/multihash"
        },
        {
          "type": "null"
        }
      ]
    },
    "recorded": {
      "$ref": "#/$defs/utcInstant"
    },
    "entryType": {
      "enum": [
        "policy.published",
        "policy.superseded",
        "key.event",
        "authorization.granted",
        "authorization.revoked",
        "notice.sent",
        "notice.delivered",
        "request.deletion",
        "request.access",
        "acknowledgment.received",
        "dispute.raised",
        "dispute.resolved"
      ]
    },
    "subjectHash": {
      "$ref": "#/$defs/multihash",
      "description": "Digest of the object this entry is about (policy, authorization, notice, acknowledgment...). The object itself is NOT in the entry."
    },
    "counterparty": {
      "type": "object",
      "additionalProperties": false,
      "description": "OPTIONAL and local-only. Omit from anything published; it is the single most correlating field in the system.",
      "properties": {
        "name": {
          "type": "string",
          "maxLength": 256
        },
        "id": {
          "type": "string"
        },
        "channel": {
          "enum": [
            "api",
            "email",
            "webform",
            "postal",
            "in-person",
            "qr",
            "nfc"
          ]
        }
      }
    },
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "kind",
          "digest"
        ],
        "additionalProperties": false,
        "properties": {
          "kind": {
            "enum": [
              "smtp-receipt",
              "http-response",
              "usps-tracking",
              "pdf",
              "screenshot",
              "signed-receipt",
              "tsa-token",
              "certified-mail-receipt"
            ]
          },
          "digest": {
            "$ref": "#/$defs/multihash"
          },
          "storedAt": {
            "type": "string",
            "format": "uri",
            "description": "Where the artifact lives. Ciphertext if server-side."
          },
          "note": {
            "type": "string",
            "maxLength": 1000
          }
        }
      }
    },
    "logInclusion": {
      "type": "object",
      "additionalProperties": false,
      "description": "Populated after the entry hash is included in the global transparency log.",
      "properties": {
        "logId": {
          "type": "string"
        },
        "leafIndex": {
          "type": "integer",
          "minimum": 0
        },
        "treeSize": {
          "type": "integer",
          "minimum": 1
        },
        "rootHash": {
          "$ref": "#/$defs/multihash"
        },
        "inclusionProof": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/multihash"
          }
        },
        "signedTreeHead": {
          "type": "string",
          "description": "Detached JWS over {logId, treeSize, rootHash, timestamp} by the log key."
        },
        "timestampToken": {
          "type": "string",
          "description": "base64 RFC 3161 TimeStampToken over rootHash."
        }
      }
    },
    "proof": {
      "$ref": "https://rightsroot.org/spec/prm/schemas/prm-policy-v1.schema.json#/$defs/dataIntegrityProof"
    }
  },
  "$defs": {
    "multihash": {
      "type": "string",
      "pattern": "^u[A-Za-z0-9_-]{40,}$"
    },
    "utcInstant": {
      "type": "string",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"
    }
  }
} as const

export const noticeSchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://rightsroot.org/spec/prm/schemas/prm-notice-v1.schema.json",
  "title": "PRM Recipient Notice v1",
  "description": "A signed, recipient-specific notice directing a standing Personal Data Policy at one named organization. Distinct from the policy itself: the policy is public and general, a notice is targeted and may carry a private matching identifier that MUST NOT appear in the published policy. Digest = SHA-256(JCS(doc minus 'id' and 'proof')); signature domain prefix 'PRM-NOTICE-v1\\u0000'.",
  "type": "object",
  "required": [
    "@context",
    "type",
    "policyChainId",
    "policyDigest",
    "policyByteDigest",
    "policyVersion",
    "issuer",
    "recipient",
    "issued",
    "requestedTreatment",
    "legalEffect",
    "proof"
  ],
  "additionalProperties": false,
  "properties": {
    "@context": {
      "type": "array",
      "prefixItems": [
        {
          "const": "https://www.w3.org/ns/credentials/v2"
        },
        {
          "const": "https://rightsroot.org/spec/prm/ns/v1"
        }
      ],
      "items": {
        "type": "string",
        "format": "uri"
      }
    },
    "type": {
      "type": "array",
      "contains": {
        "const": "PRMNotice"
      },
      "items": {
        "type": "string"
      }
    },
    "id": {
      "type": "string",
      "pattern": "^urn:prm:notice:u[A-Za-z0-9_-]{40,}$"
    },
    "policyChainId": {
      "type": "string",
      "pattern": "^urn:prm:chain:u[A-Za-z0-9_-]{40,}$"
    },
    "policyDigest": {
      "$ref": "#/$defs/multihash",
      "description": "PROTOCOL identity of the policy: SHA-256(JCS(policy minus id, proof)). Stable across reserialization."
    },
    "policyByteDigest": {
      "$ref": "#/$defs/multihash",
      "description": "STORAGE identity: SHA-256 of the exact policy bytes delivered. Changes if a single byte moves. Recording both is what lets a recipient prove which serialization they received."
    },
    "policyVersion": {
      "type": "integer",
      "minimum": 1
    },
    "policyUrl": {
      "type": "string",
      "format": "uri"
    },
    "issuer": {
      "type": "object",
      "required": [
        "id",
        "did",
        "keyEventHash"
      ],
      "additionalProperties": false,
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^prm:[a-z2-7]{26,52}$"
        },
        "did": {
          "type": "string",
          "pattern": "^did:(key|web):"
        },
        "keyEventLog": {
          "type": "string",
          "format": "uri"
        },
        "keyEventHash": {
          "$ref": "#/$defs/multihash"
        },
        "displayName": {
          "type": "string",
          "maxLength": 128
        }
      }
    },
    "recipient": {
      "type": "object",
      "required": [
        "name",
        "type"
      ],
      "additionalProperties": false,
      "properties": {
        "name": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256
        },
        "type": {
          "enum": [
            "government-agency",
            "law-enforcement",
            "company",
            "data-processor",
            "vendor",
            "attorney",
            "other"
          ],
          "description": "Descriptive only. Carries no legal consequence and asserts nothing about the recipient's obligations."
        },
        "id": {
          "type": "string"
        },
        "did": {
          "type": "string",
          "pattern": "^did:"
        },
        "domain": {
          "type": "string"
        },
        "contact": {
          "type": "string"
        },
        "postalAddress": {
          "type": "string",
          "maxLength": 512
        },
        "department": {
          "type": "string",
          "maxLength": 256
        },
        "jurisdiction": {
          "type": "string",
          "pattern": "^[A-Z]{2}(-[A-Z0-9]{1,3})?$"
        }
      }
    },
    "purpose": {
      "type": "string",
      "maxLength": 2000,
      "description": "Why this notice was sent to this recipient. Not a demand and not a request for information."
    },
    "issued": {
      "$ref": "#/$defs/utcInstant"
    },
    "matchingIdentifiers": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "namespace",
          "value",
          "salt"
        ],
        "additionalProperties": false,
        "properties": {
          "namespace": {
            "type": "string"
          },
          "value": {
            "type": "string"
          },
          "salt": {
            "type": "string",
            "description": "base64url; opens the matching identifierCommitment in the signed policy."
          }
        }
      },
      "description": "PRIVATE. Present so the recipient can associate the policy with the right records, and only where that is genuinely needed. MUST NOT be copied into the published policy, any public page, transparency log, server log, or analytics."
    },
    "requestedTreatment": {
      "type": "string",
      "minLength": 1,
      "maxLength": 4000,
      "description": "What the issuer asks the recipient to do. Must be phrased as a request qualified by applicable law, policy, contract and technical capability — never as an assertion of obligation."
    },
    "legalEffect": {
      "type": "string",
      "minLength": 1,
      "maxLength": 4000,
      "description": "REQUIRED disclaimer. A notice that omits it would imply PRM supplies legal authority it does not."
    },
    "note": {
      "type": "string",
      "maxLength": 4000
    },
    "proof": {
      "$ref": "https://rightsroot.org/spec/prm/schemas/prm-policy-v1.schema.json#/$defs/dataIntegrityProof"
    }
  },
  "$defs": {
    "multihash": {
      "type": "string",
      "pattern": "^u[A-Za-z0-9_-]{40,}$"
    },
    "utcInstant": {
      "type": "string",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"
    }
  }
} as const

export const deliverySchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://rightsroot.org/spec/prm/schemas/prm-delivery-v1.schema.json",
  "title": "PRM Delivery Record v1",
  "description": "A signed record that the issuer delivered a specific notice packet to a specific recipient, by a stated method, at a stated time. The timestamp is USER-ASSERTED: it records what the issuer says they did, and is evidence of their claim rather than proof of receipt. Independent corroboration comes from the transparency log (when the record was published) and from private supporting evidence. Digest = SHA-256(JCS(doc minus 'id' and 'proof')); signature domain prefix 'PRM-DELIVERY-v1\\u0000'.",
  "type": "object",
  "required": [
    "@context",
    "type",
    "noticeDigest",
    "policyDigest",
    "recipient",
    "method",
    "deliveredAt",
    "recorded",
    "proof"
  ],
  "additionalProperties": false,
  "properties": {
    "@context": {
      "type": "array",
      "prefixItems": [
        {
          "const": "https://www.w3.org/ns/credentials/v2"
        },
        {
          "const": "https://rightsroot.org/spec/prm/ns/v1"
        }
      ],
      "items": {
        "type": "string",
        "format": "uri"
      }
    },
    "type": {
      "type": "array",
      "contains": {
        "const": "PRMDeliveryRecord"
      },
      "items": {
        "type": "string"
      }
    },
    "id": {
      "type": "string",
      "pattern": "^urn:prm:delivery:u[A-Za-z0-9_-]{40,}$"
    },
    "noticeDigest": {
      "$ref": "#/$defs/multihash"
    },
    "policyDigest": {
      "$ref": "#/$defs/multihash"
    },
    "manifestDigest": {
      "$ref": "#/$defs/multihash",
      "description": "Digest of the proof-bundle manifest that was delivered, when a bundle accompanied the notice. Pins exactly which packet went out."
    },
    "packetDigest": {
      "$ref": "#/$defs/multihash",
      "description": "Digest of the delivered PDF or other packet file, if one was produced."
    },
    "recipient": {
      "type": "object",
      "required": [
        "name"
      ],
      "additionalProperties": false,
      "properties": {
        "name": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256
        },
        "id": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "contact": {
          "type": "string",
          "description": "The address actually used, e.g. the email or postal address."
        }
      }
    },
    "method": {
      "enum": [
        "email",
        "certified-mail",
        "postal-mail",
        "hand-delivery",
        "web-form",
        "other"
      ]
    },
    "deliveredAt": {
      "$ref": "#/$defs/utcInstant",
      "description": "USER-ASSERTED time of delivery. PRM does not and cannot witness this."
    },
    "recorded": {
      "$ref": "#/$defs/utcInstant",
      "description": "When the issuer signed this record. Independently corroborated once the record is included in the transparency log."
    },
    "reference": {
      "type": "string",
      "maxLength": 256,
      "description": "External tracking or reference id: certified mail number, message id, web form confirmation."
    },
    "notes": {
      "type": "string",
      "maxLength": 4000
    },
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "kind",
          "digest"
        ],
        "additionalProperties": false,
        "properties": {
          "kind": {
            "enum": [
              "smtp-receipt",
              "email-headers",
              "sent-message",
              "usps-tracking",
              "certified-mail-receipt",
              "screenshot",
              "web-form-confirmation",
              "photo",
              "other"
            ]
          },
          "digest": {
            "$ref": "#/$defs/multihash"
          },
          "note": {
            "type": "string",
            "maxLength": 1000
          }
        }
      },
      "description": "DIGESTS ONLY. The artifacts themselves stay in the encrypted personal ledger and are never published by default."
    },
    "proof": {
      "$ref": "https://rightsroot.org/spec/prm/schemas/prm-policy-v1.schema.json#/$defs/dataIntegrityProof"
    }
  },
  "$defs": {
    "multihash": {
      "type": "string",
      "pattern": "^u[A-Za-z0-9_-]{40,}$"
    },
    "utcInstant": {
      "type": "string",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"
    }
  }
} as const

export const responseSchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://rightsroot.org/spec/prm/schemas/prm-response-v1.schema.json",
  "title": "PRM Response Record v1",
  "description": "A signed record that the issuer received (or did not receive) a response to a notice. PRM PRESERVES the response; it does not evaluate it. The status is the issuer's own characterisation, and carries no assertion that the recipient's legal position is right or wrong. Digest = SHA-256(JCS(doc minus 'id' and 'proof')); signature domain prefix 'PRM-RESPONSE-v1\\u0000'.",
  "type": "object",
  "required": [
    "@context",
    "type",
    "noticeDigest",
    "status",
    "recorded",
    "proof"
  ],
  "additionalProperties": false,
  "properties": {
    "@context": {
      "type": "array",
      "prefixItems": [
        {
          "const": "https://www.w3.org/ns/credentials/v2"
        },
        {
          "const": "https://rightsroot.org/spec/prm/ns/v1"
        }
      ],
      "items": {
        "type": "string",
        "format": "uri"
      }
    },
    "type": {
      "type": "array",
      "contains": {
        "const": "PRMResponseRecord"
      },
      "items": {
        "type": "string"
      }
    },
    "id": {
      "type": "string",
      "pattern": "^urn:prm:response:u[A-Za-z0-9_-]{40,}$"
    },
    "noticeDigest": {
      "$ref": "#/$defs/multihash"
    },
    "deliveryDigest": {
      "$ref": "#/$defs/multihash"
    },
    "recipient": {
      "type": "object",
      "required": [
        "name"
      ],
      "additionalProperties": false,
      "properties": {
        "name": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256
        },
        "id": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "contact": {
          "type": "string"
        }
      }
    },
    "status": {
      "enum": [
        "acknowledged",
        "accepted",
        "partially-accepted",
        "declined",
        "no-response",
        "superseded"
      ],
      "description": "The ISSUER'S characterisation of what came back. Not an adjudication, and PRM attaches no legal meaning to it."
    },
    "receivedAt": {
      "$ref": "#/$defs/utcInstant",
      "description": "Omitted for status 'no-response', where nothing arrived to date."
    },
    "recorded": {
      "$ref": "#/$defs/utcInstant"
    },
    "responseDigest": {
      "$ref": "#/$defs/multihash",
      "description": "Digest of the recipient's actual response, if one was received and preserved. The artifact itself stays private unless the issuer chooses otherwise."
    },
    "responseMediaType": {
      "type": "string",
      "maxLength": 128
    },
    "notes": {
      "type": "string",
      "maxLength": 8000,
      "description": "The issuer's own words about the response. PRM does not interpret them."
    },
    "proof": {
      "$ref": "https://rightsroot.org/spec/prm/schemas/prm-policy-v1.schema.json#/$defs/dataIntegrityProof"
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "status": {
            "const": "no-response"
          }
        },
        "required": [
          "status"
        ]
      },
      "then": {
        "not": {
          "required": [
            "receivedAt"
          ]
        }
      },
      "else": {
        "required": [
          "receivedAt"
        ]
      }
    }
  ],
  "$defs": {
    "multihash": {
      "type": "string",
      "pattern": "^u[A-Za-z0-9_-]{40,}$"
    },
    "utcInstant": {
      "type": "string",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"
    }
  }
} as const

export const allSchemas = [policySchema, authorizationSchema, keyEventSchema, ledgerEntrySchema, noticeSchema, deliverySchema, responseSchema]
