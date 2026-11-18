'use strict';

const {
  buildSchema,
  validate,
  execute,
  parse,
  specifiedRules,
  NoSchemaIntrospectionCustomRule,
} = require('graphql');

const schema = buildSchema(`
  type User {
    id: ID!
    email: String!
    name: String!
    role: String!
    credits: Int!
    verified: Boolean!
  }

  type Product {
    id: ID!
    name: String!
    stock: Int!
    price: Float!
  }

  type Order {
    id: ID!
    productId: String!
    quantity: Int!
    status: String!
  }

  type Query {
    me: User
    user(id: ID!): User
    products: [Product!]!
  }

  type Mutation {
    createOrder(productId: ID!, quantity: Int!): Order
    ping(message: String): String
  }
`);

function sanitizeUser(row) {
  if (!row) return null;
  return {
    id: String(row.id), email: row.email, name: row.name,
    role: row.role, credits: row.credits, verified: !!row.verified,
  };
}

/**
 * Builds the GraphQL root resolver object. `policy.allowBolaBypass` controls
 * whether `user(id)` enforces object-level ownership (secure) or returns any
 * user's record to any authenticated caller (vulnerable) — this is the
 * GraphQL analogue of the REST BOLA tests (API1 / CWE-285,639).
 */
function createRootValue(db, currentUser, policy) {
  return {
    me: () => sanitizeUser(currentUser),

    user: ({ id }) => {
      const row = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(id));
      if (!row) return null;
      if (!policy.allowBolaBypass) {
        const isSelf = currentUser && currentUser.id === row.id;
        const isAdmin = currentUser && currentUser.role === 'admin';
        if (!isSelf && !isAdmin) {
          throw new Error('Forbidden: you may only query your own user record');
        }
      }
      return sanitizeUser(row);
    },

    products: () => db.prepare('SELECT * FROM products').all()
      .map(p => ({ id: p.id, name: p.name, stock: p.stock, price: p.price })),

    createOrder: ({ productId, quantity }) => {
      if (!currentUser) throw new Error('Authentication required');
      if (!quantity || quantity < 1) throw new Error('Invalid quantity');
      const product = db.prepare('SELECT * FROM products WHERE id = ?').get(productId);
      if (!product) throw new Error('Product not found');
      if (product.stock < quantity) throw new Error('Insufficient stock');
      db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?').run(quantity, productId);
      const id = `order-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      db.prepare('INSERT INTO orders (id, user_id, product_id, quantity, status, created_at) VALUES (?,?,?,?,?,?)')
        .run(id, currentUser.id, productId, quantity, 'created', new Date().toISOString());
      return { id, productId, quantity, status: 'created' };
    },

    ping: ({ message }) => `pong: ${message ?? ''}`,
  };
}

/**
 * One GraphQL operation: { query, variables?, operationName? }.
 */
async function runOperation(op, { db, currentUser, policy }) {
  let document;
  try {
    document = parse(op.query);
  } catch (e) {
    return { errors: [{ message: `Syntax Error: ${e.message}` }] };
  }

  const rules = policy.allowIntrospection
    ? specifiedRules
    : [...specifiedRules, NoSchemaIntrospectionCustomRule];

  const validationErrors = validate(schema, document, rules);
  if (validationErrors.length > 0) {
    return { errors: validationErrors.map(e => ({ message: e.message })) };
  }

  const result = await execute({
    schema,
    document,
    rootValue: createRootValue(db, currentUser, policy),
    variableValues: op.variables,
    operationName: op.operationName,
  });
  return result;
}

/**
 * Express handler factory.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {{allowIntrospection:boolean, allowBolaBypass:boolean, maxBatchSize:number}} policy
 */
function createGraphQLHandler(db, policy) {
  return async (req, res) => {
    const body = req.body;
    const isBatch = Array.isArray(body);
    const operations = isBatch ? body : [body];

    if (isBatch && operations.length > policy.maxBatchSize) {
      return res.status(400).json({
        errors: [{ message: `Batch size ${operations.length} exceeds the allowed maximum of ${policy.maxBatchSize}` }],
      });
    }

    const results = [];
    for (const op of operations) {
      // eslint-disable-next-line no-await-in-loop
      const result = await runOperation(op, { db, currentUser: req.user ?? null, policy });
      results.push(result);
    }

    res.json(isBatch ? results : results[0]);
  };
}

module.exports = { schema, createGraphQLHandler };
