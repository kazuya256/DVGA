-- =========================================================================
-- DVGA-Node Database Seed Script
-- STRICTLY EDUCATIONAL USE ONLY - TRAINING DATA ONLY
-- =========================================================================

-- Seed Products
INSERT INTO products (name, price, description) VALUES
('GraphQL Security Audit Manual', 49.99, 'Comprehensive checklist for securing GraphQL endpoints, schemas, and resolvers.'),
('API Pentesting Guidebook', 34.50, 'Step-by-step instructions for intercepting, modifying, and abusing web APIs.'),
('DevSecOps Toolkit License', 199.00, 'Single-user annual license for continuous security scanning tools.'),
('Cyber Security Training Pass', 500.00, 'Admission pass to all vulnerability lab training modules.');

-- Seed Comments (Stored XSS can be placed here or created during challenges)
INSERT INTO comments (user_id, comment_text) VALUES
(2, 'This lab is amazing for learning BOLA! Can someone guide me on SQL Injection?'),
(3, 'Make sure to inspect the network tab to view the JWT token details.');

-- Seed Feedback
INSERT INTO feedback (email, message, status) VALUES
('developer@company.local', 'The endpoint performance is slow when fetching nested orders.', 'resolved'),
('pester@hacker.org', 'Nice lab. I found a couple of cool vulnerabilities.', 'pending');
