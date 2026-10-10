const CONFIG = {
    API_BASE_URL: "http://127.0.0",
    API_KEY: "secure_shared_lab_key_2026",
    POLL_INTERVAL_MS: 2000
};

async function labFetch(endpoint, options = {}) {
    const url = `${CONFIG.API_BASE_URL}${endpoint}`;
    const headers = {
        "X-API-Key": CONFIG.API_KEY,
        "Content-Type": "application/json",
        ...(options.headers || {})
    };

    const response = await fetch(url, { ...options, headers });
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }
    return response.json();
}
