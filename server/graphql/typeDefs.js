const typeDefs = `#graphql
  type User {
    id: ID!
    email: String!
    role: String!
    is_admin: Boolean!
    # Excessive Data Exposure: Vulnerable schema includes password_hash!
    password_hash: String
    profile: Profile
  }

  type Profile {
    id: ID!
    userId: ID!
    fullName: String
    bio: String
    phone: String
    address: String
  }

  type Product {
    id: ID!
    name: String!
    price: Float!
    description: String
  }

  type Order {
    id: ID!
    userId: ID
    productId: ID
    quantity: Int!
    orderDate: String
    trackingNumber: String
    product: Product
    user: User
  }

  type Comment {
    id: ID!
    userId: ID!
    commentText: String!
    createdAt: String!
    user: User
  }

  type Feedback {
    id: ID!
    email: String!
    message: String!
    status: String!
  }

  type File {
    id: ID!
    filename: String!
    filePath: String!
    size: Int
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type SystemDiagnostics {
    command: String!
    output: String
    status: String
  }

  # API6: Coupon type for business flow abuse
  type Coupon {
    id: ID!
    code: String!
    discount_percent: Int!
    max_uses: Int!
    current_uses: Int!
    is_active: Boolean!
    created_by: ID
  }

  # API5: Transaction type for admin-level fund operations
  type Transaction {
    id: ID!
    from_user_id: ID
    to_user_id: ID
    amount: Float!
    description: String
    status: String!
    created_at: String
  }

  # API3: Mutation response for property-level updates
  type UserUpdateResult {
    id: ID!
    email: String!
    role: String!
    is_admin: Boolean!
    message: String
  }

  type Query {
    # BOLA / IDOR targets
    profile(id: ID!): Profile
    orders(userId: ID!): [Order]
    order(id: ID!): Order

    # SQL Injection target
    productsSearch(query: String!): [Product]

    # Stored XSS target
    comments: [Comment]

    # SSRF target
    fetchMetadata(url: String!): String

    # Command Execution target
    runDiagnostics(cmd: String!): SystemDiagnostics

    # Introspection Exposure check
    introspectionStatus: String

    # Excessive Data Exposure check
    users: [User]
    user(id: ID!): User

    # API5: Broken Function Level Authorization - transactions visible to any authenticated user
    transactions: [Transaction]

    # API6: Unrestricted Access to Sensitive Business Flows - coupon listing
    coupons: [Coupon]

    # Configuration queries
    securityMode: String!
    learningMode: String!
  }

  type Mutation {
    # Brute Force & Weak JWT targets
    login(email: String!, password: String!): AuthPayload

    # API2: Broken Authentication - login via refresh/session token without password
    loginWithToken(email: String!, sessionToken: String!): AuthPayload

    # Stored XSS target
    updateBio(bio: String!): Profile

    # IDOR / Write access control target
    updateProfileAddress(profileId: ID!, address: String!): Profile

    # API3: Broken Object Property Level Authorization - mass assignment on user properties
    updateUserProfile(userId: ID!, email: String, role: String, is_admin: Boolean): UserUpdateResult

    # API5: Broken Function Level Authorization - admin-only fund transfer exposed to all
    transferFunds(fromUserId: ID!, toUserId: ID!, amount: Float!, description: String): Transaction

    # API5: Broken Function Level Authorization - admin user deletion exposed
    deleteUser(userId: ID!): Boolean

    # API6: Unrestricted Access to Sensitive Business Flows - coupon redemption with no rate/abuse controls
    applyCoupon(code: String!): Coupon

    # File Upload target
    uploadFile(filename: String!, base64Content: String!): File!

    # Standard mutations
    createFeedback(email: String!, message: String!): Feedback
    
    # Lab Controls
    setSecurityMode(mode: String!): String!
    setLearningMode(mode: String!): String!
  }
`;

module.exports = typeDefs;

