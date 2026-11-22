const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/+$/, '');

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, options);
  } catch {
    throw new Error(`Could not connect to the SUSignal backend at ${API_BASE_URL}. Confirm that it is running and VITE_API_BASE_URL is correct.`);
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(response.ok
      ? 'The backend returned an unexpected response.'
      : `The request failed (${response.status}) and returned an invalid response.`);
  }

  if (!response.ok) {
    throw new Error(typeof data?.detail === 'string'
      ? data.detail
      : `Request failed (${response.status}).`);
  }

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('The backend returned an unexpected response.');
  }

  return data;
}

export async function checkBackendHealth() {
  const data = await request('/api/health', {
    headers: { Accept: 'application/json' },
  });
  if (data.status !== 'healthy') {
    throw new Error('The backend health response was unexpected.');
  }
  return data;
}

export async function uploadConfiguration(file) {
  if (!file) {
    throw new Error('Please select a configuration file to upload.');
  }

  const formData = new FormData();
  formData.append('file', file);
  const data = await request('/api/scan/upload', {
    method: 'POST',
    body: formData,
  });

  if (
    data.status !== 'success' ||
    typeof data.scan_id !== 'string' ||
    typeof data.filename !== 'string' ||
    !data.summary ||
    typeof data.summary !== 'object' ||
    !Array.isArray(data.findings)
  ) {
    throw new Error('The backend returned an unexpected scan response.');
  }

  return data;
}

export async function fetchScanHistory({
  limit = 100,
  offset = 0,
  search = '',
  networkFunction = '',
  severity = '',
  sort = 'date-desc',
} = {}) {
  const query = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
    search,
    network_function: networkFunction,
    severity,
    sort,
  });
  const data = await request(`/api/scan/history?${query}`, {
    headers: { Accept: 'application/json' },
  });

  if (
    data.status !== 'success' ||
    !Array.isArray(data.scans) ||
    !Number.isInteger(data.total) ||
    !data.scans.every((scan) =>
      scan &&
      typeof scan.scan_id === 'string' &&
      typeof scan.filename === 'string' &&
      typeof scan.file_type === 'string'
    )
  ) {
    throw new Error('The backend returned an unexpected scan history response.');
  }

  return data;
}

export async function fetchScanDetails(scanId) {
  const data = await request(`/api/scan/history/${encodeURIComponent(scanId)}`, {
    headers: { Accept: 'application/json' },
  });
  if (
    data.status !== 'success' ||
    data.scan_id !== scanId ||
    !data.summary ||
    typeof data.summary !== 'object' ||
    !Array.isArray(data.findings) ||
    typeof data.findings_available !== 'boolean'
  ) {
    throw new Error('The backend returned an unexpected scan details response.');
  }
  return data;
}

export async function fetchDashboardStatistics() {
  const data = await request('/api/scan/statistics', {
    headers: { Accept: 'application/json' },
  });
  if (
    data.status !== 'success' ||
    !data.stats ||
    !Array.isArray(data.vulnerabilities_by_network_function) ||
    !data.severity_distribution ||
    !Array.isArray(data.security_score_trend) ||
    !Array.isArray(data.frequent_rules) ||
    !Array.isArray(data.recent_scans)
  ) {
    throw new Error('The backend returned an unexpected analytics response.');
  }
  return data;
}

export async function fetchRuleCatalog() {
  const data = await request('/api/scan/rules', {
    headers: { Accept: 'application/json' },
  });
  if (
    data.status !== 'success' ||
    !Array.isArray(data.rules) ||
    !data.rules.every((rule) =>
      rule &&
      typeof rule.rule_id === 'string' &&
      typeof rule.title === 'string' &&
      typeof rule.severity === 'string' &&
      typeof rule.description === 'string' &&
      typeof rule.remediation === 'string'
    )
  ) {
    throw new Error('The backend returned an unexpected rule catalog response.');
  }
  return data.rules;
}

export async function updateRemediationStatus(scanId, ruleId, targetNF, status) {
  const data = await request(
    `/api/scan/history/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(ruleId)}/status`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ target_nf: targetNF, status }),
    }
  );
  if (
    data.status !== 'success' ||
    data.remediation?.scan_id !== scanId ||
    data.remediation?.rule_id !== ruleId ||
    data.remediation?.status !== status
  ) {
    throw new Error('The backend returned an unexpected remediation status response.');
  }
  return data.remediation;
}

function isEnvironment(value, expectedId) {
  return value &&
    value.id === expectedId &&
    typeof value.name === 'string' &&
    typeof value.description === 'string' &&
    typeof value.status === 'string' &&
    Number.isInteger(value.configured_network_functions) &&
    Number.isInteger(value.healthy_services) &&
    Array.isArray(value.services);
}

async function fetchNetworkEnvironment(networkId) {
  const data = await request(`/api/environments/${networkId}`, {
    headers: { Accept: 'application/json' },
  });
  if (data.status !== 'success' || !isEnvironment(data.environment, networkId)) {
    throw new Error('The backend returned an unexpected environment response.');
  }
  return data;
}

export function fetchNetworkAlpha() {
  return fetchNetworkEnvironment('alpha');
}

export function fetchNetworkBeta() {
  return fetchNetworkEnvironment('beta');
}

export async function fetchEnvironmentStatistics() {
  const data = await request('/api/environments/statistics', {
    headers: { Accept: 'application/json' },
  });
  if (
    data.status !== 'success' ||
    !Number.isInteger(data.total_test_networks) ||
    !Number.isInteger(data.running_networks) ||
    !Number.isInteger(data.runtime_assessments_completed) ||
    !Number.isInteger(data.total_runtime_findings) ||
    !Array.isArray(data.network_status_distribution) ||
    !Array.isArray(data.runtime_findings_by_severity) ||
    !Array.isArray(data.runtime_findings_by_network) ||
    !Array.isArray(data.findings_by_type)
  ) {
    throw new Error('The backend returned unexpected environment statistics.');
  }
  return data;
}

async function environmentAction(networkId, action) {
  const data = await request(`/api/environments/${networkId}/${action}`, {
    method: 'POST',
  });
  if (data.status !== 'success' || !isEnvironment(data.environment, networkId)) {
    throw new Error('The backend returned an unexpected environment operation response.');
  }
  return data.environment;
}

export function startNetworkAlpha() {
  return environmentAction('alpha', 'start');
}

export function stopNetworkAlpha() {
  return environmentAction('alpha', 'stop');
}

export function startNetworkBeta() {
  return environmentAction('beta', 'start');
}

export function stopNetworkBeta() {
  return environmentAction('beta', 'stop');
}

async function assessNetwork(networkId) {
  const data = await request(`/api/environments/${networkId}/assessments`, {
    method: 'POST',
  });
  if (
    data.status !== 'success' ||
    data.assessment_type !== 'runtime' ||
    typeof data.assessment_id !== 'string' ||
    data.network_id !== networkId ||
    !data.summary ||
    !Array.isArray(data.findings) ||
    !Array.isArray(data.observations)
  ) {
    throw new Error('The backend returned an unexpected runtime assessment response.');
  }
  return data;
}

export function assessNetworkAlpha() {
  return assessNetwork('alpha');
}

export function assessNetworkBeta() {
  return assessNetwork('beta');
}

export async function fetchRuntimeAssessment(assessmentId, networkId = 'alpha') {
  const data = await request(
    `/api/environments/${networkId}/assessments/${encodeURIComponent(assessmentId)}`,
    { headers: { Accept: 'application/json' } }
  );
  if (
    data.status !== 'success' ||
    data.assessment_id !== assessmentId ||
    data.assessment_type !== 'runtime' ||
    data.network_id !== networkId ||
    !data.summary ||
    !Array.isArray(data.findings) ||
    !Array.isArray(data.observations)
  ) {
    throw new Error('The backend returned an unexpected saved runtime assessment.');
  }
  return data;
}
