require('dotenv').config();

let securityMode = process.env.SECURITY_MODE || 'VULNERABLE'; // VULNERABLE or MITIGATED
let learningMode = process.env.LEARNING_MODE || 'BEGINNER';   // BEGINNER or EXPERT

module.exports = {
  getSecurityMode: () => securityMode,
  setSecurityMode: (mode) => {
    if (['VULNERABLE', 'MITIGATED'].includes(mode)) {
      securityMode = mode;
      console.log(`[CONFIG] Security mode toggled to: ${securityMode}`);
      return securityMode;
    }
    throw new Error('Invalid Security Mode. Must be VULNERABLE or MITIGATED.');
  },
  
  getLearningMode: () => learningMode,
  setLearningMode: (mode) => {
    if (['BEGINNER', 'EXPERT'].includes(mode)) {
      learningMode = mode;
      console.log(`[CONFIG] Learning mode toggled to: ${learningMode}`);
      return learningMode;
    }
    throw new Error('Invalid Learning Mode. Must be BEGINNER or EXPERT.');
  },
  
  getJwtSecret: () => process.env.JWT_SECRET || 'super_secret_dev_key_do_not_use_in_prod'
};
