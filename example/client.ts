import postgres from "postgres";
import { privateKeyToAccount } from "viem/accounts";

// Your private key (for testing only - never commit real keys!)
const PRIVATE_KEY = process.env.PRIVATE_KEY as `0x${string}`;

if (!PRIVATE_KEY) {
  console.error("Set PRIVATE_KEY environment variable");
  process.exit(1);
}

async function main() {
  const account = privateKeyToAccount(PRIVATE_KEY);
  console.log(`Connecting as ${account.address}`);

  // Create signed password: "timestamp:signature"
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = await account.signMessage({ message: timestamp });
  const password = `${timestamp}:${signature}`;

  // Connect to proxy using Ethereum address as user
  const sql = postgres({
    host: "localhost",
    port: 5433,
    user: account.address,
    password: password,
    database: "postgres",
  });

  try {
    // Test query
    const result = await sql`SELECT * FROM example_data`;
    console.log("Query result:", result);

    // Insert data
    const inserted = await sql`
      INSERT INTO example_data (content) 
      VALUES (${`Inserted by ${account.address} at ${new Date().toISOString()}`})
      RETURNING *
    `;
    console.log("Inserted:", inserted);
  } finally {
    await sql.end();
  }
}

main().catch(console.error);
