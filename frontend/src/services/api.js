/**
 * 5G Sentinel Frontend API Service Layer
 * Centralized HTTP communication for all backend interactions.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';

/**
 * Checks backend API health and connectivity status.
 * @returns {Promise<{status: string, service: string, version: string, modules: object}>}
 */
export async function checkBackendHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Health check failed with status: ${response.status}`);
    }

    return await response.json();
  } catch (err) {
    console.error('[API Service] Backend health check failed:', err);
    throw err;
  }
}

/**
 * Uploads a YAML or JSON configuration file to the backend scanner.
 * @param {File} file - The configuration file selected by the user.
 * @returns {Promise<object>} Parsed findings and scan summary.
 */
export async function uploadConfiguration(file) {
  if (!file) {
    throw new Error('Please select a configuration file to upload.');
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch(`${API_BASE_URL}/scan/upload`, {
      method: 'POST',
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      const errorMessage = data?.detail || `Upload failed with status code ${response.status}`;
      throw new Error(errorMessage);
    }

    return data;
  } catch (err) {
    console.error('[API Service] Upload and scan request failed:', err);
    throw err;
  }
}

/**
 * Fetches recent configuration scan records.
 * @returns {Promise<{status: string, count: number, scans: Array}>}
 */
export async function fetchScanHistory() {
  try {
    const response = await fetch(`${API_BASE_URL}/scan/history`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch scan history: ${response.status}`);
    }

    return await response.json();
  } catch (err) {
    console.error('[API Service] Failed to retrieve scan history:', err);
    throw err;
  }
}
