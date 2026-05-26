const fs = require('fs');
const path = require('path');

/**
 * Handle Base64 file upload (GraphQL mutation helper)
 * Vulnerable mode: writes whatever extension is provided.
 * Secure mode: restricts to image extensions and validates content type headers.
 */
async function processBase64Upload(filename, base64Content, mode = 'VULNERABLE') {
  const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
  
  // Clean filename to prevent Directory Traversal
  let safeFilename = path.basename(filename);
  if (mode === 'MITIGATED') {
    // Check for directory traversal attempts specifically in the original input
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      throw new Error('Directory Traversal detected in filename!');
    }
  }

  const ext = path.extname(safeFilename).toLowerCase();
  
  if (mode === 'MITIGATED') {
    // Enforce allowed extensions
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.txt', '.pdf'];
    if (!allowedExtensions.includes(ext)) {
      throw new Error(`Insecure file extension "${ext}". Only images, PDF, and TXT are permitted.`);
    }

    // Try to inspect base64 prefix for MIME type verification (e.g. data:image/png;base64,...)
    if (base64Content.startsWith('data:')) {
      const mime = base64Content.split(';')[0].substring(5);
      const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf'];
      if (!allowedMimes.includes(mime)) {
        throw new Error(`Insecure file type "${mime}".`);
      }
    }
  }

  // Extract raw base64 data (strip prefix if present)
  let rawData = base64Content;
  if (base64Content.includes(';base64,')) {
    rawData = base64Content.split(';base64,')[1];
  }

  const buffer = Buffer.from(rawData, 'base64');
  
  // Generate unique filename to prevent overwrites
  const uniqueName = `${Date.now()}-${safeFilename}`;
  const destPath = path.join(uploadDir, uniqueName);
  
  // Write to disk
  fs.writeFileSync(destPath, buffer);
  
  return {
    filename: uniqueName,
    filePath: `/uploads/${uniqueName}`,
    size: buffer.length
  };
}

module.exports = {
  processBase64Upload
};
