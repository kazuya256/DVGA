const { exec } = require('child_process');


/**
 * Executes a system command directly. This version runs the actual command on the host
 * environment (Windows, Linux, or Docker) and returns the real stdout/stderr.
 * A timeout of 5 seconds is applied to prevent hanging processes.
 */
function runCommand(cmd, callback) {
  // Execute the command with a timeout; the callback receives (error, output)
  exec(cmd, { timeout: 5000 }, (error, stdout, stderr) => {
    if (error) {
      // Return the error message along with any stderr output for debugging
      return callback(error, stderr || error.message);
    }
    // Successful execution – return stdout
    callback(null, stdout);
  });
}

module.exports = {
  runCommand
};
