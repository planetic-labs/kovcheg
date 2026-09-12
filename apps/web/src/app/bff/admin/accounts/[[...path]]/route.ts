import type { NextRequest } from 'next/server';
import { functionalGrants } from '@kovcheg/contracts';
import type { AdministrativeCapabilities, FunctionalGrant } from '@kovcheg/contracts';

import {
  bffError,
  readSession,
  relayJson,
  requestAuth,
} from '../../../../../a6/server/internal-http';

interface RouteContext {
  readonly params: Promise<{ readonly path?: readonly string[] }>;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

async function confirmedCapabilities(
  request: NextRequest,
): Promise<AdministrativeCapabilities | null> {
  try {
    return (await readSession(request))?.administrativeCapabilities ?? null;
  } catch {
    return null;
  }
}

type AdministrativeCapability = keyof AdministrativeCapabilities;

interface UpstreamTarget {
  readonly capability: AdministrativeCapability;
  readonly path: string;
  readonly platformAdministratorMutation: boolean;
}

function target(
  path: string,
  capability: AdministrativeCapability,
  platformAdministratorMutation = false,
): UpstreamTarget {
  return Object.freeze({ capability, path, platformAdministratorMutation });
}

function upstreamTarget(method: string, path: readonly string[]): UpstreamTarget | null {
  if (method === 'GET' && path.length === 0) return target('/admin/accounts', 'canManageAccounts');
  if (method === 'POST' && path.length === 0) {
    return target('/admin/accounts', 'canManageAccounts');
  }
  const accountId = path[0];
  if (accountId === undefined || !uuidPattern.test(accountId)) {
    return null;
  }
  if (method === 'PATCH' && path.length === 1) {
    return target(`/admin/accounts/${accountId}`, 'canManageAccounts');
  }
  if (method === 'GET' && path.length === 1)
    return target(`/admin/accounts/${accountId}`, 'canManageAccounts');
  if (method === 'PATCH' && path.length === 2 && path[1] === 'status') {
    return target(`/admin/accounts/${accountId}/status`, 'canManageAccounts');
  }
  if (method === 'PATCH' && path.length === 2 && path[1] === 'domain-status') {
    return target(`/admin/accounts/${accountId}/domain-status`, 'canManageDomainStatus');
  }
  if (method === 'POST' && path.length === 2 && path[1] === 'auth-security-reset') {
    return target(`/admin/accounts/${accountId}/auth-security-reset`, 'canManageAccounts');
  }
  const grant = path[2];
  if (
    (method === 'PUT' || method === 'DELETE') &&
    path.length === 3 &&
    path[1] === 'functional-grants' &&
    grant !== undefined &&
    functionalGrants.includes(grant as FunctionalGrant)
  ) {
    return target(
      `/admin/accounts/${accountId}/functional-grants/${grant}`,
      'canManageFunctionalGrants',
      grant === 'platform_administrator',
    );
  }
  if (method === 'DELETE' && path.length === 2 && path[1] === 'sessions') {
    return target(`/admin/accounts/${accountId}/sessions`, 'canManageAccounts');
  }
  const sessionId = path[2];
  if (
    method === 'DELETE' &&
    path.length === 3 &&
    path[1] === 'sessions' &&
    sessionId !== undefined &&
    uuidPattern.test(sessionId)
  ) {
    return target(`/admin/accounts/${accountId}/sessions/${sessionId}`, 'canManageAccounts');
  }
  return null;
}

async function forward(request: NextRequest, context: RouteContext) {
  const path = (await context.params).path ?? [];
  const route = upstreamTarget(request.method, path);
  if (route === null) {
    return bffError(400, 'a6.invalid-request');
  }
  const capabilities = await confirmedCapabilities(request);
  if (
    capabilities === null ||
    !capabilities[route.capability] ||
    (route.platformAdministratorMutation && !capabilities.canManagePlatformAdministrators)
  ) {
    return bffError(403, 'a6.forbidden');
  }
  const functionalGrantDeletion = request.method === 'DELETE' && path[1] === 'functional-grants';
  const bodylessSecurityOperation = path[1] === 'auth-security-reset';
  const body =
    request.method === 'GET' ||
    (request.method === 'DELETE' && !functionalGrantDeletion) ||
    bodylessSecurityOperation
      ? undefined
      : await request.text();
  try {
    let upstreamPath = route.path;
    if (request.method === 'GET') {
      const params = request.nextUrl.searchParams;
      if (
        [...params.keys()].some(
          (key) => !['limit', 'afterAccountId'].includes(key) || params.getAll(key).length !== 1,
        ) ||
        (path.length > 0 && params.size > 0)
      )
        return bffError(400, 'a6.invalid-request');
      if (params.size > 0) upstreamPath += `?${params.toString()}`;
    }
    return relayJson(
      await requestAuth(request, upstreamPath, {
        ...(body === undefined ? {} : { body }),
        method: request.method as 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT',
      }),
    );
  } catch {
    return bffError(503, 'a6.unavailable');
  }
}

export function POST(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export function GET(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export function PATCH(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export function PUT(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export function DELETE(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}
