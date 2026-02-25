/**
 * Test application factory.
 *
 * Builds a clean Express app that mirrors the production routes defined in
 * src/index.ts without startup side-effects (config loading, server binding,
 * real DB/Redis connections). Routes are wired with the same middleware so
 * integration tests exercise the real validation and auth logic.
 */
import express, { type Express } from 'express'
import { validate } from '../../../src/middleware/validate.js'
import { requireApiKey } from '../../../src/middleware/apiKey.js'
import {
  requireApiKey as requireEnterpriseKey,
  ApiScope,
} from '../../../src/middleware/auth.js'
import {
  generateApiKey,
  listApiKeys,
  revokeApiKey,
  rotateApiKey,
  type KeyScope,
  type SubscriptionTier,
} from '../../../src/services/apiKeys.js'
import {
  createSlashRequest,
  submitVote,
  getSlashRequest,
  listSlashRequests,
  type SlashRequestStatus,
  type VoteChoice,
} from '../../../src/services/governance/slashingVotes.js'
import {
  trustPathParamsSchema,
  bondPathParamsSchema,
  attestationsPathParamsSchema,
  attestationsQuerySchema,
  createAttestationBodySchema,
} from '../../../src/schemas/index.js'
import { createHealthRouter } from '../../../src/routes/health.js'
import { createDefaultProbes } from '../../../src/services/health/probes.js'

export function buildTestApp(): Express {
  const app = express()
  app.use(express.json())

  // ── Health ────────────────────────────────────────────────────────────────
  const healthProbes = createDefaultProbes()
  app.use('/api/health', createHealthRouter(healthProbes))

  // ── Trust (public) ────────────────────────────────────────────────────────
  app.get(
    '/api/trust/:address',
    validate({ params: trustPathParamsSchema }),
    (req, res) => {
      const { address } = req.validated!.params as { address: string }
      res.json({
        address,
        score: 0,
        bondedAmount: '0',
        bondStart: null,
        attestationCount: 0,
      })
    },
  )

  // ── Trust (auth-protected) ────────────────────────────────────────────────
  // Mirrors the requireApiKey() guarded version in src/index.ts
  app.get(
    '/api/trust-protected/:address',
    requireApiKey(),
    validate({ params: trustPathParamsSchema }),
    (req, res) => {
      const { address } = req.validated!.params as { address: string }
      res.json({
        address,
        score: 0,
        bondedAmount: '0',
        bondStart: null,
        attestationCount: 0,
        _accessedWith: { scope: req.apiKey?.scope, tier: req.apiKey?.tier },
      })
    },
  )

  // ── Bond (public) ─────────────────────────────────────────────────────────
  app.get(
    '/api/bond/:address',
    validate({ params: bondPathParamsSchema }),
    (req, res) => {
      const { address } = req.validated!.params as { address: string }
      res.json({
        address,
        bondedAmount: '0',
        bondStart: null,
        bondDuration: null,
        active: false,
      })
    },
  )

  // ── Bond (auth-protected) ─────────────────────────────────────────────────
  app.get(
    '/api/bond-protected/:address',
    requireApiKey(),
    validate({ params: bondPathParamsSchema }),
    (req, res) => {
      const { address } = req.validated!.params as { address: string }
      res.json({
        address,
        bondedAmount: '0',
        bondStart: null,
        bondDuration: null,
        active: false,
        _accessedWith: { scope: req.apiKey?.scope, tier: req.apiKey?.tier },
      })
    },
  )

  // ── Attestations (list) ───────────────────────────────────────────────────
  app.get(
    '/api/attestations/:address',
    validate({ params: attestationsPathParamsSchema, query: attestationsQuerySchema }),
    (req, res) => {
      const { address } = req.validated!.params as { address: string }
      const { limit, offset } = req.validated!.query as { limit: number; offset: number }
      res.json({ address, limit, offset, attestations: [] })
    },
  )

  // ── Attestations (create) ─────────────────────────────────────────────────
  app.post(
    '/api/attestations',
    validate({ body: createAttestationBodySchema }),
    (req, res) => {
      const body = req.validated!.body as { subject: string; value: string; key?: string }
      res.status(201).json({
        subject: body.subject,
        value: body.value,
        key: body.key ?? null,
      })
    },
  )

  // ── Verification (public) ─────────────────────────────────────────────────
  app.get('/api/verification/:address', (req, res) => {
    const { address } = req.params
    res.json({ address, proof: null, verified: false, timestamp: null })
  })

  // ── API Key Management ────────────────────────────────────────────────────

  /** POST /api/keys — issue a new key */
  app.post('/api/keys', (req, res) => {
    const { ownerId, scope, tier } = req.body as {
      ownerId?: string
      scope?: string
      tier?: string
    }

    if (!ownerId) {
      res.status(400).json({ error: 'ownerId is required' })
      return
    }

    const validScopes = ['read', 'full']
    const validTiers = ['free', 'pro', 'enterprise']

    if (scope && !validScopes.includes(scope)) {
      res.status(400).json({ error: `scope must be one of: ${validScopes.join(', ')}` })
      return
    }
    if (tier && !validTiers.includes(tier)) {
      res.status(400).json({ error: `tier must be one of: ${validTiers.join(', ')}` })
      return
    }

    const result = generateApiKey(
      ownerId,
      (scope as KeyScope) ?? 'read',
      (tier as SubscriptionTier) ?? 'free',
    )
    res.status(201).json(result)
  })

  /** GET /api/keys?ownerId= — list keys for owner */
  app.get('/api/keys', (req, res) => {
    const { ownerId } = req.query as { ownerId?: string }
    if (!ownerId) {
      res.status(400).json({ error: 'ownerId query parameter is required' })
      return
    }
    res.json(listApiKeys(ownerId))
  })

  /** DELETE /api/keys/:id — revoke a key */
  app.delete('/api/keys/:id', (req, res) => {
    const revoked = revokeApiKey(req.params['id'] as string)
    if (!revoked) {
      res.status(404).json({ error: 'Key not found' })
      return
    }
    res.status(204).send()
  })

  /** POST /api/keys/:id/rotate — rotate a key */
  app.post('/api/keys/:id/rotate', (req, res) => {
    const result = rotateApiKey(req.params['id'] as string)
    if (!result) {
      res.status(404).json({ error: 'Key not found or already revoked' })
      return
    }
    res.json(result)
  })

  // ── Governance: Slash Requests ────────────────────────────────────────────

  app.post('/api/governance/slash-requests', (req, res) => {
    const { targetAddress, reason, requestedBy, threshold, totalSigners } = req.body as {
      targetAddress?: string
      reason?: string
      requestedBy?: string
      threshold?: number
      totalSigners?: number
    }

    if (!targetAddress) { res.status(400).json({ error: 'targetAddress is required' }); return }
    if (!reason)        { res.status(400).json({ error: 'reason is required' }); return }
    if (!requestedBy)   { res.status(400).json({ error: 'requestedBy is required' }); return }

    try {
      const slashReq = createSlashRequest({
        targetAddress,
        reason,
        requestedBy,
        threshold,
        totalSigners,
      })
      res.status(201).json(slashReq)
    } catch (err) {
      res.status(400).json({ error: (err as Error).message })
    }
  })

  app.get('/api/governance/slash-requests', (req, res) => {
    const { status } = req.query as { status?: string }
    const validStatuses: SlashRequestStatus[] = ['pending', 'approved', 'rejected']
    if (status && !validStatuses.includes(status as SlashRequestStatus)) {
      res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` })
      return
    }
    res.json(listSlashRequests(status as SlashRequestStatus | undefined))
  })

  app.get('/api/governance/slash-requests/:id', (req, res) => {
    const slashReq = getSlashRequest(req.params['id'] as string)
    if (!slashReq) {
      res.status(404).json({ error: 'Slash request not found' })
      return
    }
    res.json(slashReq)
  })

  app.post('/api/governance/slash-requests/:id/votes', (req, res) => {
    const { voterId, choice } = req.body as { voterId?: string; choice?: string }

    if (!voterId) { res.status(400).json({ error: 'voterId is required' }); return }
    if (!choice)  { res.status(400).json({ error: 'choice is required' }); return }

    const validChoices: VoteChoice[] = ['approve', 'reject']
    if (!validChoices.includes(choice as VoteChoice)) {
      res.status(400).json({ error: `choice must be one of: ${validChoices.join(', ')}` })
      return
    }

    try {
      const result = submitVote(req.params['id'] as string, voterId, choice as VoteChoice)
      if (!result) { res.status(404).json({ error: 'Slash request not found' }); return }
      res.status(201).json(result)
    } catch (err) {
      res.status(409).json({ error: (err as Error).message })
    }
  })

  // ── Bulk Verification (Enterprise, via auth.ts middleware) ────────────────
  // Uses the hardcoded API_KEYS from middleware/auth.ts:
  //   'test-enterprise-key-12345' → Enterprise scope
  //   'test-public-key-67890'     → Public scope
  app.post(
    '/api/bulk/verify',
    requireEnterpriseKey(ApiScope.ENTERPRISE),
    (req, res) => {
      const { addresses } = req.body as { addresses?: unknown[] }

      if (!addresses || !Array.isArray(addresses)) {
        res.status(400).json({ error: 'InvalidRequest', message: 'addresses must be an array' })
        return
      }
      if (addresses.length === 0) {
        res.status(400).json({ error: 'BatchSizeTooSmall', message: 'Minimum batch size is 1 address' })
        return
      }
      if (addresses.length > 100) {
        res.status(413).json({
          error: 'BatchSizeExceeded',
          message: 'Maximum batch size is 100 addresses',
          limit: 100,
          received: addresses.length,
        })
        return
      }

      const uniqueAddresses = [...new Set(addresses)] as string[]
      const results = uniqueAddresses.map((address) => ({
        address,
        trustScore: 0,
        bondStatus: { bondedAmount: '0', bondStart: null, bondDuration: null, active: false },
        attestationCount: 0,
        lastUpdated: new Date().toISOString(),
      }))

      res.status(200).json({
        results,
        errors: [],
        metadata: {
          totalRequested: addresses.length,
          successful: results.length,
          failed: 0,
          batchSize: uniqueAddresses.length,
        },
      })
    },
  )

  return app
}
