const axios = require('axios');
const { URL } = require('url');

/**
 * Checks if an IP or hostname resolves to a local/private network range
 * (Simple regex check for standard private and loopback ranges)
 */
function isPrivateAddress(hostname) {
  const ipRegex = /^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+)$/i;
  return ipRegex.test(hostname);
}

/**
 * Fetch remote URL content.
 * Vulnerable mode: blindly fetches any URL.
 * Secure mode: validates URL and rejects private IP spaces or loopback ranges.
 */
async function fetchUrlMetadata(targetUrl, mode = 'VULNERABLE') {
  try {
    const parsedUrl = new URL(targetUrl);
    
    if (mode === 'MITIGATED') {
      // 1. Force HTTP/HTTPS protocol
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        throw new Error('Only HTTP and HTTPS protocols are allowed.');
      }
      
      // 2. Prevent local address space SSRF
      const host = parsedUrl.hostname;
      if (isPrivateAddress(host)) {
        throw new Error('Access denied: Requesting local or private network resources is prohibited.');
      }
    }

    // Perform request (timeout in 3 seconds to avoid hanging)
    const response = await axios.get(targetUrl, { 
      timeout: 3000,
      headers: { 'User-Agent': 'DVGA-Node-Scanner/1.0' }
    });

    // Return truncated body or content length as a preview
    const data = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    return `Status: ${response.status}\nContent-Length: ${data.length}\nPreview:\n${data.substring(0, 300)}`;
  } catch (err) {
    throw new Error(`SSRF Fetch Error: ${err.message}`);
  }
}

module.exports = {
  fetchUrlMetadata
};
