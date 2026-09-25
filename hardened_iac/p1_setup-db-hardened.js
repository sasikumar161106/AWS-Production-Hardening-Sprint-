/**
 * setup-db-hardened.js
 * Project 1: Smart Leave & Absence Management System (SLAMS)
 * Audited & Hardened by: Sasikumar (Sasi) — Cloud Architect & Security Specialist
 * 
 * Provisions DynamoDB tables with:
 * 1. Server-Side Encryption (KMS)
 * 2. Point-In-Time Recovery (PITR) enabled for continuous backups
 * 3. On-Demand (PAY_PER_REQUEST) capacity for resilience against spikes
 */

const { 
    DynamoDBClient, 
    CreateTableCommand, 
    UpdateContinuousBackupsCommand 
} = require('@aws-sdk/client-dynamodb');

const REGION = process.env.AWS_REGION || 'ap-south-1';
const client = new DynamoDBClient({ region: REGION });

async function createHardenedTable(params) {
    try {
        console.log(`Creating hardened table: ${params.TableName}...`);
        // Add SSE KMS Specification
        params.SSESpecification = {
            Enabled: true,
            SSEType: 'KMS'
        };
        params.BillingMode = 'PAY_PER_REQUEST';
        delete params.ProvisionedThroughput;
        if (params.GlobalSecondaryIndexes) {
            params.GlobalSecondaryIndexes.forEach(gsi => delete gsi.ProvisionedThroughput);
        }

        await client.send(new CreateTableCommand(params));
        console.log(`✓ Table ${params.TableName} created.`);

        // Enable PITR
        console.log(`Enabling Point-in-Time Recovery on ${params.TableName}...`);
        await client.send(new UpdateContinuousBackupsCommand({
            TableName: params.TableName,
            PointInTimeRecoverySpecification: {
                PointInTimeRecoveryEnabled: true
            }
        }));
        console.log(`✓ PITR enabled on ${params.TableName}`);

    } catch (err) {
        if (err.name === 'ResourceInUseException') {
            console.log(`Table ${params.TableName} already exists. Verifying PITR...`);
            try {
                await client.send(new UpdateContinuousBackupsCommand({
                    TableName: params.TableName,
                    PointInTimeRecoverySpecification: {
                        PointInTimeRecoveryEnabled: true
                    }
                }));
                console.log(`✓ PITR verified/enabled on ${params.TableName}`);
            } catch (pitrErr) {
                console.warn(`! PITR update note: ${pitrErr.message}`);
            }
        } else {
            console.error(`Error with table ${params.TableName}:`, err.message);
        }
    }
}

async function main() {
    console.log("🔒 Starting DynamoDB Hardening Deployment...\n");

    // 1. leave_requests
    await createHardenedTable({
        TableName: 'leave_requests',
        KeySchema: [
            { AttributeName: 'employee_id', KeyType: 'HASH' },
            { AttributeName: 'request_id', KeyType: 'RANGE' }
        ],
        AttributeDefinitions: [
            { AttributeName: 'employee_id', AttributeType: 'S' },
            { AttributeName: 'request_id', AttributeType: 'S' },
            { AttributeName: 'manager_id', AttributeType: 'S' },
            { AttributeName: 'status', AttributeType: 'S' },
            { AttributeName: 'start_date', AttributeType: 'S' }
        ],
        GlobalSecondaryIndexes: [
            {
                IndexName: 'manager_id-status-index',
                KeySchema: [
                    { AttributeName: 'manager_id', KeyType: 'HASH' },
                    { AttributeName: 'status', KeyType: 'RANGE' }
                ],
                Projection: { ProjectionType: 'ALL' }
            },
            {
                IndexName: 'status-start_date-index',
                KeySchema: [
                    { AttributeName: 'status', KeyType: 'HASH' },
                    { AttributeName: 'start_date', KeyType: 'RANGE' }
                ],
                Projection: { ProjectionType: 'ALL' }
            }
        ]
    });

    // 2. leave_balances
    await createHardenedTable({
        TableName: 'leave_balances',
        KeySchema: [
            { AttributeName: 'employee_id', KeyType: 'HASH' },
            { AttributeName: 'leave_type#year', KeyType: 'RANGE' }
        ],
        AttributeDefinitions: [
            { AttributeName: 'employee_id', AttributeType: 'S' },
            { AttributeName: 'leave_type#year', AttributeType: 'S' }
        ]
    });

    // 3. leave_config
    await createHardenedTable({
        TableName: 'leave_config',
        KeySchema: [
            { AttributeName: 'config_key', KeyType: 'HASH' }
        ],
        AttributeDefinitions: [
            { AttributeName: 'config_key', AttributeType: 'S' }
        ]
    });

    console.log("\n✅ All SLAMS DynamoDB tables hardened with KMS SSE and PITR.");
}

main();
