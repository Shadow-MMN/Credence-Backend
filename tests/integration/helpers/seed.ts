/**
 * Test data seed helpers.
 *
 * Provides typed helpers to insert fixture rows into the integration test DB.
 * Use these inside beforeAll / beforeEach blocks to set up preconditions.
 *
 * The test DB is reset (TRUNCATE … CASCADE) between tests, so each helper
 * returns the inserted row for use in assertions.
 */
import type { Pool } from 'pg'

// ── Well-known test addresses ────────────────────────────────────────────────

/** Primary Ethereum-style address used as a subject/identity in seed data. */
export const SEED_ADDRESS_1 = '0x742d35Cc6634C0532925a3b844Bc454e4438f44e'

/** Secondary Ethereum-style address used as an attester in seed data. */
export const SEED_ADDRESS_2 = '0xAbcDeF1234567890AbCdEf1234567890aBcDeF12'

// ── Row types returned by seed helpers ──────────────────────────────────────

export interface SeededIdentity {
  address: string
  display_name: string | null
  created_at: Date
  updated_at: Date
}

export interface SeededBond {
  id: number
  identity_address: string
  amount: string
  start_time: Date
  duration_days: number
  status: 'active' | 'released' | 'slashed'
  created_at: Date
}

export interface SeededAttestation {
  id: number
  bond_id: number
  attester_address: string
  subject_address: string
  score: number
  note: string | null
  created_at: Date
}

export interface SeededSlashEvent {
  id: number
  bond_id: number
  slash_amount: string
  reason: string
  created_at: Date
}

// ── Seed helpers ─────────────────────────────────────────────────────────────

/**
 * Insert a single identity row.
 *
 * @example
 * const identity = await seedIdentity(pool, SEED_ADDRESS_1, 'Alice')
 */
export async function seedIdentity(
  pool: Pool,
  address: string,
  displayName?: string | null,
): Promise<SeededIdentity> {
  const result = await pool.query<SeededIdentity>(
    `INSERT INTO identities (address, display_name)
     VALUES ($1, $2)
     RETURNING *`,
    [address, displayName ?? null],
  )
  return result.rows[0]!
}

/**
 * Insert a bond row for an existing identity.
 * Caller must ensure the identity row already exists.
 */
export async function seedBond(
  pool: Pool,
  identityAddress: string,
  overrides: Partial<{
    amount: string
    startTime: Date
    durationDays: number
    status: 'active' | 'released' | 'slashed'
  }> = {},
): Promise<SeededBond> {
  const result = await pool.query<SeededBond>(
    `INSERT INTO bonds (identity_address, amount, start_time, duration_days, status)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [
      identityAddress,
      overrides.amount ?? '100.0',
      overrides.startTime ?? new Date('2025-01-01T00:00:00Z'),
      overrides.durationDays ?? 30,
      overrides.status ?? 'active',
    ],
  )
  return result.rows[0]!
}

/**
 * Insert an attestation for an existing bond.
 * Both attesterAddress and subjectAddress must exist as identity rows.
 */
export async function seedAttestation(
  pool: Pool,
  bondId: number,
  attesterAddress: string,
  subjectAddress: string,
  score: number = 75,
  note?: string | null,
): Promise<SeededAttestation> {
  const result = await pool.query<SeededAttestation>(
    `INSERT INTO attestations (bond_id, attester_address, subject_address, score, note)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [bondId, attesterAddress, subjectAddress, score, note ?? null],
  )
  return result.rows[0]!
}

/**
 * Insert a slash event for an existing bond.
 */
export async function seedSlashEvent(
  pool: Pool,
  bondId: number,
  slashAmount: string = '10.0',
  reason: string = 'Protocol violation',
): Promise<SeededSlashEvent> {
  const result = await pool.query<SeededSlashEvent>(
    `INSERT INTO slash_events (bond_id, slash_amount, reason)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [bondId, slashAmount, reason],
  )
  return result.rows[0]!
}

/**
 * Convenience: seed a complete scenario with identity + active bond + attestation.
 *
 * Returns all created rows so callers can reference their IDs in assertions.
 */
export async function seedFullScenario(pool: Pool): Promise<{
  identity: SeededIdentity
  attester: SeededIdentity
  bond: SeededBond
  attestation: SeededAttestation
}> {
  const identity = await seedIdentity(pool, SEED_ADDRESS_1, 'Alice')
  const attester = await seedIdentity(pool, SEED_ADDRESS_2, 'Bob')
  const bond = await seedBond(pool, SEED_ADDRESS_1)
  const attestation = await seedAttestation(
    pool,
    bond.id,
    SEED_ADDRESS_2,
    SEED_ADDRESS_1,
    85,
    'Reliable validator',
  )
  return { identity, attester, bond, attestation }
}
