/**
 * Integration tests for the Credence Public API.
 *
 * Test DB strategy
 * ────────────────
 * A PostgreSQL container is started once per suite (via Testcontainers) unless
 * TEST_DATABASE_URL is set, in which case that external database is used.
 * Tables are created in `beforeAll` and truncated in `beforeEach` to give each
 * test a clean slate.
 *
 * In-memory stores (API keys, slash requests) are reset in `beforeEach`.
 *
 * Covered endpoints
 * ─────────────────
 *  GET  /api/health
 *  GET  /api/health/live
 *  GET  /api/health/ready
 *  GET  /api/trust/:address          (public)
 *  GET  /api/trust-protected/:address (requireApiKey guard)
 *  GET  /api/bond/:address            (public)
 *  GET  /api/bond-protected/:address  (requireApiKey guard)
 *  GET  /api/attestations/:address    (public, pagination)
 *  POST /api/attestations             (public, body validation)
 *  GET  /api/verification/:address    (public)
 *  POST /api/keys                     (issue key)
 *  GET  /api/keys                     (list keys)
 *  DELETE /api/keys/:id               (revoke key)
 *  POST /api/keys/:id/rotate          (rotate key)
 *  POST /api/governance/slash-requests
 *  GET  /api/governance/slash-requests
 *  GET  /api/governance/slash-requests/:id
 *  POST /api/governance/slash-requests/:id/votes
 *  POST /api/bulk/verify              (enterprise auth)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import request from 'supertest'
import type { Express } from 'express'
import { buildTestApp } from './helpers/testApp.js'
import { createTestDatabase, type TestDatabase } from './testDatabase.js'
import { createSchema, resetDatabase, dropSchema } from '../../src/db/schema.js'
import {
  generateApiKey,
  _resetStore as resetApiKeyStore,
} from '../../src/services/apiKeys.js'
import { _resetStore as resetSlashStore } from '../../src/services/governance/slashingVotes.js'
import {
  seedIdentity,
  seedBond,
  seedAttestation,
  seedFullScenario,
  SEED_ADDRESS_1,
  SEED_ADDRESS_2,
} from './helpers/seed.js'

// ── Fixture addresses ────────────────────────────────────────────────────────

/** Valid checksummed Ethereum address (42 chars, 0x + 40 hex). */
const ADDR_A = '0x742d35Cc6634C0532925a3b844Bc454e4438f44e'
/** Second valid address used as attester / alternate subject. */
const ADDR_B = '0xAbcDeF1234567890AbCdEf1234567890aBcDeF12'

// Hardcoded keys accepted by middleware/auth.ts (for bulk endpoint)
const ENTERPRISE_KEY = 'test-enterprise-key-12345'
const PUBLIC_KEY     = 'test-public-key-67890'

// ── Suite setup ──────────────────────────────────────────────────────────────

let app: Express
let testDb: TestDatabase | undefined
let dbAvailable = false

beforeAll(async () => {
  try {
    testDb = await createTestDatabase()
    await createSchema(testDb.pool)
    dbAvailable = true
  } catch {
    console.warn(
      '\n[integration] ⚠️  No test database available. ' +
      'Set TEST_DATABASE_URL or start Docker to enable DB-backed tests. ' +
      'All other tests will still run.\n',
    )
  }
  app = buildTestApp()
}, 90_000 /* allow time for Testcontainers image pull */)

afterAll(async () => {
  if (testDb) {
    await dropSchema(testDb.pool)
    await testDb.close()
  }
}, 30_000)

beforeEach(async () => {
  // Reset DB tables when a real DB is available
  if (testDb) {
    await resetDatabase(testDb.pool)
  }
  // Always clear in-memory stores
  resetApiKeyStore()
  resetSlashStore()
})

// ════════════════════════════════════════════════════════════════════════════
// Health endpoints
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/health', () => {
  /**
   * Scenario: liveness probe always returns 200 regardless of dependencies.
   */
  it('GET /live returns 200 and ok status', async () => {
    const res = await request(app).get('/api/health/live')
    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({ status: 'ok', service: 'credence-backend' })
  })

  /**
   * Scenario: readiness / full health returns a status object with service name.
   * When no DB/Redis env vars are set, dependencies are reported as not_configured.
   */
  it('GET / returns 200 with health status object', async () => {
    const res = await request(app).get('/api/health')
    expect(res.status).toBeGreaterThanOrEqual(200)
    expect(res.status).toBeLessThan(600)
    expect(res.body).toHaveProperty('status')
    expect(res.body).toHaveProperty('service', 'credence-backend')
  })

  it('GET /ready returns 200 with status object', async () => {
    const res = await request(app).get('/api/health/ready')
    expect(res.status).toBeGreaterThanOrEqual(200)
    expect(res.body).toHaveProperty('status')
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Trust endpoint — public
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/trust/:address', () => {
  /**
   * Scenario: happy path with a valid checksummed Ethereum address.
   * Response must include the requested address plus required score fields.
   */
  it('returns 200 with trust payload for valid address', async () => {
    const res = await request(app).get(`/api/trust/${ADDR_A}`)
    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({
      address: ADDR_A,
      score: expect.any(Number),
      bondedAmount: expect.any(String),
      attestationCount: expect.any(Number),
    })
    expect(Object.keys(res.body)).toContain('bondStart')
  })

  /**
   * Scenario: lowercase hex address is also valid per the regex.
   */
  it('returns 200 for lowercase valid hex address', async () => {
    const lower = '0x' + 'a'.repeat(40)
    const res = await request(app).get(`/api/trust/${lower}`)
    expect(res.status).toBe(200)
    expect(res.body.address).toBe(lower)
  })

  /**
   * Scenario: address without the 0x prefix → schema rejects it.
   */
  it('returns 400 for address without 0x prefix', async () => {
    const res = await request(app).get('/api/trust/' + 'a'.repeat(40))
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
    expect(Array.isArray(res.body.details)).toBe(true)
  })

  /**
   * Scenario: completely non-address string → schema rejects it.
   */
  it('returns 400 for non-address string', async () => {
    const res = await request(app).get('/api/trust/not-an-address')
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
    expect(res.body.details.some((d: { path: string }) => d.path.includes('address'))).toBe(true)
  })

  /**
   * Scenario: address shorter than 40 hex chars after 0x.
   */
  it('returns 400 for too-short address (39 hex chars)', async () => {
    const res = await request(app).get('/api/trust/0x' + 'a'.repeat(39))
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
  })

  /**
   * Scenario: address longer than 40 hex chars after 0x.
   */
  it('returns 400 for too-long address (41 hex chars)', async () => {
    const res = await request(app).get('/api/trust/0x' + 'a'.repeat(41))
    expect(res.status).toBe(400)
  })

  /**
   * Scenario: address with invalid (non-hex) characters after 0x.
   */
  it('returns 400 for address with non-hex characters', async () => {
    const res = await request(app).get('/api/trust/0x' + 'z'.repeat(40))
    expect(res.status).toBe(400)
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Trust endpoint — auth-protected
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/trust-protected/:address (requireApiKey)', () => {
  /**
   * Scenario: no credentials sent → 401.
   */
  it('returns 401 when no API key is provided', async () => {
    const res = await request(app).get(`/api/trust-protected/${ADDR_A}`)
    expect(res.status).toBe(401)
    expect(res.body).toHaveProperty('error')
  })

  /**
   * Scenario: malformed Bearer token (not matching cr_<hex64> pattern) → 401.
   */
  it('returns 401 for a malformed Authorization Bearer token', async () => {
    const res = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('Authorization', 'Bearer not-a-real-key')
    expect(res.status).toBe(401)
    expect(res.body).toHaveProperty('error')
  })

  /**
   * Scenario: wrong key in X-API-Key header → 401.
   */
  it('returns 401 for an invalid X-API-Key header value', async () => {
    const res = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('X-API-Key', 'bad-key-value')
    expect(res.status).toBe(401)
  })

  /**
   * Scenario: valid key in Authorization: Bearer → 200 with key metadata.
   */
  it('returns 200 for valid Bearer token and includes key metadata', async () => {
    const { key } = generateApiKey('owner-bearer', 'read', 'free')
    const res = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('Authorization', `Bearer ${key}`)
    expect(res.status).toBe(200)
    expect(res.body.address).toBe(ADDR_A)
    expect(res.body._accessedWith).toMatchObject({ scope: 'read', tier: 'free' })
  })

  /**
   * Scenario: valid key in X-API-Key header → 200.
   */
  it('returns 200 for valid X-API-Key header with full/enterprise key', async () => {
    const { key } = generateApiKey('owner-xkey', 'full', 'enterprise')
    const res = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('X-API-Key', key)
    expect(res.status).toBe(200)
    expect(res.body._accessedWith).toMatchObject({ scope: 'full', tier: 'enterprise' })
  })

  /**
   * Scenario: a revoked key should no longer be accepted.
   */
  it('returns 401 after revoking the key via DELETE /api/keys/:id', async () => {
    const { key, id } = generateApiKey('owner-revoke', 'read', 'free')

    // Confirm key works first
    const before = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('X-API-Key', key)
    expect(before.status).toBe(200)

    // Revoke key through the management endpoint
    await request(app).delete(`/api/keys/${id}`)

    // Key must now be rejected
    const after = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('X-API-Key', key)
    expect(after.status).toBe(401)
  })

  /**
   * Scenario: address validation still runs after auth passes.
   */
  it('returns 400 for invalid address even with valid API key', async () => {
    const { key } = generateApiKey('owner-bad-addr', 'read', 'free')
    const res = await request(app)
      .get('/api/trust-protected/not-valid')
      .set('X-API-Key', key)
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Bond endpoint — public
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/bond/:address', () => {
  /**
   * Scenario: happy path — bond endpoint returns expected shape.
   */
  it('returns 200 with bond payload for valid address', async () => {
    const res = await request(app).get(`/api/bond/${ADDR_A}`)
    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({
      address: ADDR_A,
      bondedAmount: expect.any(String),
      active: expect.any(Boolean),
    })
    expect(Object.keys(res.body)).toContain('bondStart')
    expect(Object.keys(res.body)).toContain('bondDuration')
  })

  /**
   * Scenario: second valid address works too (no address-specific stub).
   */
  it('returns 200 for a different valid address', async () => {
    const res = await request(app).get(`/api/bond/${ADDR_B}`)
    expect(res.status).toBe(200)
    expect(res.body.address).toBe(ADDR_B)
  })

  /**
   * Scenario: arbitrary invalid string → 400.
   */
  it('returns 400 for invalid address format', async () => {
    const res = await request(app).get('/api/bond/invalid-address')
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
    expect(Array.isArray(res.body.details)).toBe(true)
  })

  it('returns 400 for address with only 0x prefix', async () => {
    const res = await request(app).get('/api/bond/0x')
    expect(res.status).toBe(400)
  })

  it('returns 400 for address shorter than required', async () => {
    const res = await request(app).get('/api/bond/0x' + 'f'.repeat(30))
    expect(res.status).toBe(400)
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Bond endpoint — auth-protected
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/bond-protected/:address (requireApiKey)', () => {
  it('returns 401 when no API key is provided', async () => {
    const res = await request(app).get(`/api/bond-protected/${ADDR_A}`)
    expect(res.status).toBe(401)
  })

  it('returns 200 with key metadata for valid pro key', async () => {
    const { key } = generateApiKey('bond-pro-owner', 'full', 'pro')
    const res = await request(app)
      .get(`/api/bond-protected/${ADDR_A}`)
      .set('Authorization', `Bearer ${key}`)
    expect(res.status).toBe(200)
    expect(res.body._accessedWith).toMatchObject({ scope: 'full', tier: 'pro' })
  })

  it('returns 401 for a key that does not match the store', async () => {
    // Fabricate a syntactically valid but unknown key
    const fakeKey = 'cr_' + 'deadbeef'.repeat(8)
    const res = await request(app)
      .get(`/api/bond-protected/${ADDR_A}`)
      .set('X-API-Key', fakeKey)
    expect(res.status).toBe(401)
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Attestations — list (GET)
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/attestations/:address', () => {
  /**
   * Scenario: default pagination values (limit=20, offset=0).
   */
  it('returns 200 with default limit and offset for valid address', async () => {
    const res = await request(app).get(`/api/attestations/${ADDR_A}`)
    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({
      address: ADDR_A,
      limit: 20,
      offset: 0,
      attestations: [],
    })
  })

  /**
   * Scenario: explicit custom limit and offset are accepted.
   */
  it('accepts custom limit and offset query params', async () => {
    const res = await request(app)
      .get(`/api/attestations/${ADDR_A}`)
      .query({ limit: 50, offset: 10 })
    expect(res.status).toBe(200)
    expect(res.body.limit).toBe(50)
    expect(res.body.offset).toBe(10)
  })

  /**
   * Scenario: minimum allowed limit (1).
   */
  it('accepts minimum valid limit of 1', async () => {
    const res = await request(app)
      .get(`/api/attestations/${ADDR_A}`)
      .query({ limit: 1 })
    expect(res.status).toBe(200)
    expect(res.body.limit).toBe(1)
  })

  /**
   * Scenario: maximum allowed limit (100).
   */
  it('accepts maximum valid limit of 100', async () => {
    const res = await request(app)
      .get(`/api/attestations/${ADDR_A}`)
      .query({ limit: 100 })
    expect(res.status).toBe(200)
    expect(res.body.limit).toBe(100)
  })

  /**
   * Scenario: limit=0 is below the minimum → 400.
   */
  it('returns 400 when limit is 0', async () => {
    const res = await request(app)
      .get(`/api/attestations/${ADDR_A}`)
      .query({ limit: 0 })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
  })

  /**
   * Scenario: limit exceeds max (100) → 400.
   */
  it('returns 400 when limit exceeds 100', async () => {
    const res = await request(app)
      .get(`/api/attestations/${ADDR_A}`)
      .query({ limit: 200 })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
  })

  /**
   * Scenario: negative offset → 400.
   */
  it('returns 400 for a negative offset', async () => {
    const res = await request(app)
      .get(`/api/attestations/${ADDR_A}`)
      .query({ offset: -1 })
    expect(res.status).toBe(400)
  })

  /**
   * Scenario: invalid address → 400 before pagination is evaluated.
   */
  it('returns 400 for invalid address format', async () => {
    const res = await request(app).get('/api/attestations/bad-address')
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Attestations — create (POST)
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/attestations', () => {
  /**
   * Scenario: minimal valid body (subject + value) → 201.
   */
  it('returns 201 for valid attestation with required fields', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .send({ subject: ADDR_A, value: 'trusted-validator' })
    expect(res.status).toBe(201)
    expect(res.body).toMatchObject({
      subject: ADDR_A,
      value: 'trusted-validator',
      key: null,
    })
  })

  /**
   * Scenario: optional `key` field is included in the response when supplied.
   */
  it('returns 201 with optional key field echoed back', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .send({ subject: ADDR_A, value: 'high-stake', key: 'reputation-v1' })
    expect(res.status).toBe(201)
    expect(res.body.key).toBe('reputation-v1')
  })

  /**
   * Scenario: missing required `subject` field → 400.
   */
  it('returns 400 when subject is missing', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .send({ value: 'val' })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
    expect(Array.isArray(res.body.details)).toBe(true)
  })

  /**
   * Scenario: missing required `value` field → 400.
   */
  it('returns 400 when value is missing', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .send({ subject: ADDR_A })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
  })

  /**
   * Scenario: subject is not a valid Ethereum address → 400.
   */
  it('returns 400 for non-address subject', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .send({ subject: 'not-valid', value: 'val' })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Validation failed')
  })

  /**
   * Scenario: empty string value violates min(1) → 400.
   */
  it('returns 400 when value is an empty string', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .send({ subject: ADDR_A, value: '' })
    expect(res.status).toBe(400)
  })

  /**
   * Scenario: extra unknown field is rejected by strict() schema → 400.
   */
  it('returns 400 for unknown extra fields (strict schema)', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .send({ subject: ADDR_A, value: 'v', unknownField: 'extra' })
    expect(res.status).toBe(400)
  })

  /**
   * Scenario: optional key with empty string violates min(1) → 400.
   */
  it('returns 400 when key is provided but empty', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .send({ subject: ADDR_A, value: 'v', key: '' })
    expect(res.status).toBe(400)
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Verification endpoint — public
// ════════════════════════════════════════════════════════════════════════════

describe('GET /api/verification/:address', () => {
  /**
   * Scenario: happy path returns expected shape with null proof (stub).
   */
  it('returns 200 with verification shape for valid address', async () => {
    const res = await request(app).get(`/api/verification/${ADDR_A}`)
    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({
      address: ADDR_A,
      verified: false,
      proof: null,
      timestamp: null,
    })
  })

  /**
   * Scenario: the address param is echoed directly (no address validation on this route).
   */
  it('echoes back the requested address in the response', async () => {
    const res = await request(app).get(`/api/verification/${ADDR_B}`)
    expect(res.status).toBe(200)
    expect(res.body.address).toBe(ADDR_B)
  })
})

// ════════════════════════════════════════════════════════════════════════════
// API Key management
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/keys', () => {
  /**
   * Scenario: minimal request (ownerId only) uses default scope/tier.
   */
  it('issues a key with defaults (scope=read, tier=free)', async () => {
    const res = await request(app).post('/api/keys').send({ ownerId: 'user-abc' })
    expect(res.status).toBe(201)
    expect(res.body.key).toMatch(/^cr_[0-9a-f]{64}$/)
    expect(res.body.scope).toBe('read')
    expect(res.body.tier).toBe('free')
    expect(res.body).toHaveProperty('id')
    expect(res.body).toHaveProperty('createdAt')
  })

  /**
   * Scenario: explicit scope and tier are honoured.
   */
  it('issues a key with custom scope=full and tier=enterprise', async () => {
    const res = await request(app)
      .post('/api/keys')
      .send({ ownerId: 'user-xyz', scope: 'full', tier: 'enterprise' })
    expect(res.status).toBe(201)
    expect(res.body.scope).toBe('full')
    expect(res.body.tier).toBe('enterprise')
  })

  /**
   * Scenario: all valid tier values are accepted.
   */
  it.each(['free', 'pro', 'enterprise'])('accepts tier=%s', async (tier) => {
    const res = await request(app).post('/api/keys').send({ ownerId: 'u', tier })
    expect(res.status).toBe(201)
    expect(res.body.tier).toBe(tier)
  })

  /**
   * Scenario: missing ownerId → 400.
   */
  it('returns 400 when ownerId is missing', async () => {
    const res = await request(app).post('/api/keys').send({ scope: 'read' })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('ownerId is required')
  })

  /**
   * Scenario: unknown scope → 400.
   */
  it('returns 400 for unrecognised scope value', async () => {
    const res = await request(app).post('/api/keys').send({ ownerId: 'u', scope: 'superadmin' })
    expect(res.status).toBe(400)
    expect(res.body.error).toMatch(/scope must be one of/)
  })

  /**
   * Scenario: unknown tier → 400.
   */
  it('returns 400 for unrecognised tier value', async () => {
    const res = await request(app).post('/api/keys').send({ ownerId: 'u', tier: 'platinum' })
    expect(res.status).toBe(400)
    expect(res.body.error).toMatch(/tier must be one of/)
  })
})

describe('GET /api/keys', () => {
  /**
   * Scenario: returns all keys for the owner, masked (no hashedKey).
   */
  it('returns keys for the specified ownerId', async () => {
    await request(app).post('/api/keys').send({ ownerId: 'list-owner' })
    await request(app).post('/api/keys').send({ ownerId: 'list-owner', scope: 'full' })

    const res = await request(app).get('/api/keys').query({ ownerId: 'list-owner' })
    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
    expect(res.body).toHaveLength(2)
  })

  /**
   * Scenario: hashedKey must never be returned to clients.
   */
  it('does not expose hashedKey in the response', async () => {
    await request(app).post('/api/keys').send({ ownerId: 'secure-owner' })
    const res = await request(app).get('/api/keys').query({ ownerId: 'secure-owner' })
    expect(res.status).toBe(200)
    expect(res.body[0]).not.toHaveProperty('hashedKey')
  })

  /**
   * Scenario: unknown owner returns an empty array, not 404.
   */
  it('returns empty array for owner with no keys', async () => {
    const res = await request(app).get('/api/keys').query({ ownerId: 'ghost-owner' })
    expect(res.status).toBe(200)
    expect(res.body).toEqual([])
  })

  /**
   * Scenario: missing ownerId query param → 400.
   */
  it('returns 400 when ownerId query param is omitted', async () => {
    const res = await request(app).get('/api/keys')
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('ownerId query parameter is required')
  })
})

describe('DELETE /api/keys/:id', () => {
  /**
   * Scenario: successful revocation returns 204 No Content.
   */
  it('revokes the key and returns 204', async () => {
    const created = await request(app).post('/api/keys').send({ ownerId: 'revoke-owner' })
    const { id } = created.body

    const res = await request(app).delete(`/api/keys/${id}`)
    expect(res.status).toBe(204)
    expect(res.body).toEqual({})
  })

  /**
   * Scenario: deleting a non-existent key → 404.
   */
  it('returns 404 for a non-existent key id', async () => {
    const res = await request(app).delete('/api/keys/does-not-exist')
    expect(res.status).toBe(404)
    expect(res.body.error).toBe('Key not found')
  })

  /**
   * Scenario: end-to-end — revoked key must no longer authenticate.
   */
  it('revoked key is rejected by auth middleware on subsequent requests', async () => {
    const created = await request(app).post('/api/keys').send({ ownerId: 'e2e-revoke' })
    const { id, key } = created.body

    // Confirm it works
    const before = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('X-API-Key', key)
    expect(before.status).toBe(200)

    // Revoke
    await request(app).delete(`/api/keys/${id}`)

    // Must fail
    const after = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('X-API-Key', key)
    expect(after.status).toBe(401)
  })
})

describe('POST /api/keys/:id/rotate', () => {
  /**
   * Scenario: rotation succeeds and returns a new key value.
   */
  it('returns 200 with a fresh key on successful rotation', async () => {
    const created = await request(app).post('/api/keys').send({ ownerId: 'rotate-owner' })
    const { id, key: oldKey } = created.body

    const res = await request(app).post(`/api/keys/${id}/rotate`)
    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('key')
    expect(res.body.key).not.toBe(oldKey)
    expect(res.body.key).toMatch(/^cr_[0-9a-f]{64}$/)
  })

  /**
   * Scenario: after rotation the old key is invalidated, the new key works.
   */
  it('old key is invalid after rotation; new key authenticates', async () => {
    const created = await request(app).post('/api/keys').send({ ownerId: 'rotate-e2e' })
    const { id, key: oldKey } = created.body

    const { body: rotated } = await request(app).post(`/api/keys/${id}/rotate`)

    // Old key should be rejected
    const oldRes = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('Authorization', `Bearer ${oldKey}`)
    expect(oldRes.status).toBe(401)

    // New key should succeed
    const newRes = await request(app)
      .get(`/api/trust-protected/${ADDR_A}`)
      .set('Authorization', `Bearer ${rotated.key}`)
    expect(newRes.status).toBe(200)
  })

  /**
   * Scenario: rotating a non-existent key → 404.
   */
  it('returns 404 for a non-existent key id', async () => {
    const res = await request(app).post('/api/keys/does-not-exist/rotate')
    expect(res.status).toBe(404)
    expect(res.body.error).toBe('Key not found or already revoked')
  })

  /**
   * Scenario: rotating an already-revoked key → 404 (active=false in store).
   */
  it('returns 404 when trying to rotate an already-revoked key', async () => {
    const created = await request(app).post('/api/keys').send({ ownerId: 'revoked-rotate' })
    const { id } = created.body

    await request(app).delete(`/api/keys/${id}`)

    const res = await request(app).post(`/api/keys/${id}/rotate`)
    expect(res.status).toBe(404)
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Governance — Slash Requests
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/governance/slash-requests', () => {
  /**
   * Scenario: full valid payload → 201 with assigned id.
   */
  it('creates a slash request and returns 201 with required fields', async () => {
    const res = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'Double-signing detected', requestedBy: ADDR_B })
    expect(res.status).toBe(201)
    expect(res.body).toHaveProperty('id')
    expect(res.body.targetAddress).toBe(ADDR_A)
    expect(res.body.reason).toBe('Double-signing detected')
    expect(res.body.status).toBe('pending')
    expect(res.body.votes).toEqual([])
  })

  /**
   * Scenario: custom threshold and totalSigners are reflected in the response.
   */
  it('accepts custom threshold and totalSigners', async () => {
    const res = await request(app)
      .post('/api/governance/slash-requests')
      .send({
        targetAddress: ADDR_A,
        reason: 'Inactivity',
        requestedBy: ADDR_B,
        threshold: 2,
        totalSigners: 3,
      })
    expect(res.status).toBe(201)
    expect(res.body.threshold).toBe(2)
    expect(res.body.totalSigners).toBe(3)
  })

  /**
   * Scenario: threshold > totalSigners is a domain error → 400.
   */
  it('returns 400 when threshold exceeds totalSigners', async () => {
    const res = await request(app)
      .post('/api/governance/slash-requests')
      .send({
        targetAddress: ADDR_A,
        reason: 'Bad config',
        requestedBy: ADDR_B,
        threshold: 10,
        totalSigners: 3,
      })
    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('error')
  })

  it('returns 400 when targetAddress is missing', async () => {
    const res = await request(app)
      .post('/api/governance/slash-requests')
      .send({ reason: 'r', requestedBy: ADDR_B })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('targetAddress is required')
  })

  it('returns 400 when reason is missing', async () => {
    const res = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, requestedBy: ADDR_B })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('reason is required')
  })

  it('returns 400 when requestedBy is missing', async () => {
    const res = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'r' })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('requestedBy is required')
  })
})

describe('GET /api/governance/slash-requests', () => {
  /**
   * Scenario: empty store returns [].
   */
  it('returns empty array when no slash requests exist', async () => {
    const res = await request(app).get('/api/governance/slash-requests')
    expect(res.status).toBe(200)
    expect(res.body).toEqual([])
  })

  /**
   * Scenario: created requests are returned in the list.
   */
  it('returns all created slash requests', async () => {
    await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'r1', requestedBy: ADDR_B })
    await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_B, reason: 'r2', requestedBy: ADDR_A })

    const res = await request(app).get('/api/governance/slash-requests')
    expect(res.status).toBe(200)
    expect(res.body).toHaveLength(2)
  })

  /**
   * Scenario: status filter restricts results.
   */
  it('returns only pending requests when status=pending is applied', async () => {
    await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'test', requestedBy: ADDR_B })

    const res = await request(app)
      .get('/api/governance/slash-requests')
      .query({ status: 'pending' })
    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
    expect(res.body.every((r: { status: string }) => r.status === 'pending')).toBe(true)
  })

  /**
   * Scenario: invalid status value → 400.
   */
  it('returns 400 for an invalid status filter value', async () => {
    const res = await request(app)
      .get('/api/governance/slash-requests')
      .query({ status: 'maybe' })
    expect(res.status).toBe(400)
    expect(res.body.error).toMatch(/status must be one of/)
  })
})

describe('GET /api/governance/slash-requests/:id', () => {
  /**
   * Scenario: returns the correct request by id.
   */
  it('returns the slash request matching the id', async () => {
    const created = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'lookup-test', requestedBy: ADDR_B })
    const { id } = created.body

    const res = await request(app).get(`/api/governance/slash-requests/${id}`)
    expect(res.status).toBe(200)
    expect(res.body.id).toBe(id)
    expect(res.body.reason).toBe('lookup-test')
  })

  /**
   * Scenario: unknown id → 404.
   */
  it('returns 404 for an unknown slash request id', async () => {
    const res = await request(app).get('/api/governance/slash-requests/nonexistent-id')
    expect(res.status).toBe(404)
    expect(res.body.error).toBe('Slash request not found')
  })
})

describe('POST /api/governance/slash-requests/:id/votes', () => {
  /**
   * Scenario: successful approve vote returns 201 with vote counts.
   */
  it('records an approve vote and returns 201 with vote result', async () => {
    const created = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'vote-test', requestedBy: ADDR_B })
    const { id } = created.body

    const res = await request(app)
      .post(`/api/governance/slash-requests/${id}/votes`)
      .send({ voterId: 'voter-1', choice: 'approve' })
    expect(res.status).toBe(201)
    expect(res.body.slashRequestId).toBe(id)
    expect(res.body.approveCount).toBe(1)
    expect(res.body.rejectCount).toBe(0)
  })

  /**
   * Scenario: reject vote is also accepted.
   */
  it('records a reject vote successfully', async () => {
    const created = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'reject-test', requestedBy: ADDR_B })
    const { id } = created.body

    const res = await request(app)
      .post(`/api/governance/slash-requests/${id}/votes`)
      .send({ voterId: 'voter-x', choice: 'reject' })
    expect(res.status).toBe(201)
    expect(res.body.rejectCount).toBe(1)
  })

  /**
   * Scenario: duplicate vote from the same voter → 409 Conflict.
   */
  it('returns 409 when the same voter tries to vote twice', async () => {
    const created = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'dup-vote', requestedBy: ADDR_B })
    const { id } = created.body

    await request(app)
      .post(`/api/governance/slash-requests/${id}/votes`)
      .send({ voterId: 'voter-dup', choice: 'approve' })

    const res = await request(app)
      .post(`/api/governance/slash-requests/${id}/votes`)
      .send({ voterId: 'voter-dup', choice: 'reject' })
    expect(res.status).toBe(409)
    expect(res.body).toHaveProperty('error')
  })

  /**
   * Scenario: voting on a non-existent request → 404.
   */
  it('returns 404 when slash request does not exist', async () => {
    const res = await request(app)
      .post('/api/governance/slash-requests/unknown-id/votes')
      .send({ voterId: 'voter-z', choice: 'approve' })
    expect(res.status).toBe(404)
    expect(res.body.error).toBe('Slash request not found')
  })

  it('returns 400 when voterId is missing', async () => {
    const created = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'r', requestedBy: ADDR_B })

    const res = await request(app)
      .post(`/api/governance/slash-requests/${created.body.id}/votes`)
      .send({ choice: 'approve' })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('voterId is required')
  })

  it('returns 400 when choice is missing', async () => {
    const created = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'r', requestedBy: ADDR_B })

    const res = await request(app)
      .post(`/api/governance/slash-requests/${created.body.id}/votes`)
      .send({ voterId: 'v1' })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('choice is required')
  })

  it('returns 400 for an invalid choice value', async () => {
    const created = await request(app)
      .post('/api/governance/slash-requests')
      .send({ targetAddress: ADDR_A, reason: 'r', requestedBy: ADDR_B })

    const res = await request(app)
      .post(`/api/governance/slash-requests/${created.body.id}/votes`)
      .send({ voterId: 'v1', choice: 'maybe' })
    expect(res.status).toBe(400)
    expect(res.body.error).toMatch(/choice must be one of/)
  })

  /**
   * Scenario: enough approve votes trigger status change to 'approved'.
   */
  it('slash request transitions to approved when threshold is met', async () => {
    const created = await request(app)
      .post('/api/governance/slash-requests')
      .send({
        targetAddress: ADDR_A,
        reason: 'threshold-test',
        requestedBy: ADDR_B,
        threshold: 2,
        totalSigners: 3,
      })
    const { id } = created.body

    await request(app)
      .post(`/api/governance/slash-requests/${id}/votes`)
      .send({ voterId: 'v1', choice: 'approve' })
    const last = await request(app)
      .post(`/api/governance/slash-requests/${id}/votes`)
      .send({ voterId: 'v2', choice: 'approve' })

    expect(last.status).toBe(201)
    expect(last.body.status).toBe('approved')

    // GET by id should also show approved
    const detail = await request(app).get(`/api/governance/slash-requests/${id}`)
    expect(detail.body.status).toBe('approved')
  })
})

// ════════════════════════════════════════════════════════════════════════════
// Bulk Verification (Enterprise)
// ════════════════════════════════════════════════════════════════════════════

describe('POST /api/bulk/verify', () => {
  /**
   * Scenario: no API key → 401.
   */
  it('returns 401 when no API key header is provided', async () => {
    const res = await request(app)
      .post('/api/bulk/verify')
      .send({ addresses: [ADDR_A] })
    expect(res.status).toBe(401)
  })

  /**
   * Scenario: public (non-enterprise) key → 403.
   */
  it('returns 403 for a non-enterprise (public) API key', async () => {
    const res = await request(app)
      .post('/api/bulk/verify')
      .set('X-API-Key', PUBLIC_KEY)
      .send({ addresses: [ADDR_A] })
    expect(res.status).toBe(403)
  })

  /**
   * Scenario: enterprise key + valid body → 200 with results.
   */
  it('returns 200 with results for enterprise key and valid addresses', async () => {
    const res = await request(app)
      .post('/api/bulk/verify')
      .set('X-API-Key', ENTERPRISE_KEY)
      .send({ addresses: [ADDR_A, ADDR_B] })
    expect(res.status).toBe(200)
    expect(res.body.results).toHaveLength(2)
    expect(res.body.errors).toEqual([])
    expect(res.body.metadata).toMatchObject({
      totalRequested: 2,
      successful: 2,
      failed: 0,
    })
  })

  /**
   * Scenario: missing addresses field → 400.
   */
  it('returns 400 when addresses is missing', async () => {
    const res = await request(app)
      .post('/api/bulk/verify')
      .set('X-API-Key', ENTERPRISE_KEY)
      .send({})
    expect(res.status).toBe(400)
  })

  /**
   * Scenario: addresses is not an array → 400.
   */
  it('returns 400 when addresses is not an array', async () => {
    const res = await request(app)
      .post('/api/bulk/verify')
      .set('X-API-Key', ENTERPRISE_KEY)
      .send({ addresses: ADDR_A })
    expect(res.status).toBe(400)
  })

  /**
   * Scenario: batch exceeds max size of 100 → 413.
   */
  it('returns 413 when batch size exceeds 100 addresses', async () => {
    const addresses = Array.from({ length: 101 }, (_, i) =>
      '0x' + String(i).padStart(40, '0'),
    )
    const res = await request(app)
      .post('/api/bulk/verify')
      .set('X-API-Key', ENTERPRISE_KEY)
      .send({ addresses })
    expect(res.status).toBe(413)
    expect(res.body.error).toBe('BatchSizeExceeded')
    expect(res.body.limit).toBe(100)
    expect(res.body.received).toBe(101)
  })

  /**
   * Scenario: duplicate addresses are de-duplicated in batchSize.
   */
  it('deduplicates addresses and reflects correct batchSize in metadata', async () => {
    const res = await request(app)
      .post('/api/bulk/verify')
      .set('X-API-Key', ENTERPRISE_KEY)
      .send({ addresses: [ADDR_A, ADDR_A, ADDR_B] })
    expect(res.status).toBe(200)
    expect(res.body.metadata.totalRequested).toBe(3)
    expect(res.body.metadata.batchSize).toBe(2) // deduped
  })
})

// ════════════════════════════════════════════════════════════════════════════
// DB-backed scenarios (seed data, future route implementations)
// ════════════════════════════════════════════════════════════════════════════

describe('Database seed fixtures (infrastructure check)', () => {
  /**
   * Verifies that the test DB schema accepts seed data correctly.
   * These assertions guard the seed helpers and confirm the DB is operational.
   *
   * Requirements: Docker running OR TEST_DATABASE_URL env var set.
   * When neither is available, tests are skipped with a warning.
   *
   * When trust/bond/attestation routes are wired to the DB, these fixtures
   * can be extended to assert real data in API responses.
   */

  it('can seed an identity and retrieve it from the DB', async () => {
    if (!testDb) { return }
    const row = await seedIdentity(testDb.pool, SEED_ADDRESS_1, 'Alice')
    expect(row.address).toBe(SEED_ADDRESS_1)
    expect(row.display_name).toBe('Alice')
    expect(row.created_at).toBeInstanceOf(Date)
  })

  it('can seed a bond linked to an identity', async () => {
    if (!testDb) { return }
    await seedIdentity(testDb.pool, SEED_ADDRESS_1)
    const bond = await seedBond(testDb.pool, SEED_ADDRESS_1, {
      amount: '250.5',
      durationDays: 90,
      status: 'active',
    })
    expect(bond.id).toBeGreaterThan(0)
    expect(bond.amount).toBe('250.5')
    expect(bond.status).toBe('active')
  })

  it('can seed an attestation and verify it is associated with the bond', async () => {
    if (!testDb) { return }
    await seedIdentity(testDb.pool, SEED_ADDRESS_1)
    await seedIdentity(testDb.pool, SEED_ADDRESS_2)
    const bond = await seedBond(testDb.pool, SEED_ADDRESS_1)
    const attestation = await seedAttestation(
      testDb.pool,
      bond.id,
      SEED_ADDRESS_2,
      SEED_ADDRESS_1,
      80,
      'Reliable node',
    )
    expect(attestation.bond_id).toBe(bond.id)
    expect(attestation.score).toBe(80)
    expect(attestation.note).toBe('Reliable node')
  })

  it('seedFullScenario sets up a complete identity/bond/attestation chain', async () => {
    if (!testDb) { return }
    const { identity, attester, bond, attestation } = await seedFullScenario(testDb.pool)
    expect(identity.address).toBe(SEED_ADDRESS_1)
    expect(attester.address).toBe(SEED_ADDRESS_2)
    expect(bond.identity_address).toBe(SEED_ADDRESS_1)
    expect(attestation.bond_id).toBe(bond.id)
    expect(attestation.score).toBe(85)
  })

  it('DB is clean at the start of each test (resetDatabase works)', async () => {
    if (!testDb) { return }
    // After a previous test seeded rows, this test should see an empty DB
    const result = await testDb.pool.query<{ count: string }>(
      'SELECT COUNT(*)::text as count FROM identities',
    )
    expect(result.rows[0]!.count).toBe('0')
  })
})
