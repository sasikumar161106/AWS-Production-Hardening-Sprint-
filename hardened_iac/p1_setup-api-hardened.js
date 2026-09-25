/**
 * setup-api-hardened.js
 * Project 1: Smart Leave & Absence Management System (SLAMS)
 * Audited & Hardened by: Sasikumar (Sasi) — Cloud Architect & Security Specialist
 * 
 * Configures API Gateway HTTP API with:
 * 1. Amazon Cognito JWT Authorizer on all protected routes
 * 2. Strict CORS headers scoped to corporate frontend domain
 * 3. Documented intentional public exception on GET /approve (HMAC-SHA256 Token Verification)
 */

const { 
    ApiGatewayV2Client, 
    CreateApiCommand, 
    CreateIntegrationCommand, 
    CreateRouteCommand, 
    CreateStageCommand,
    CreateAuthorizerCommand 
} = require("@aws-sdk/client-apigatewayv2");
const { LambdaClient, AddPermissionCommand } = require("@aws-sdk/client-lambda");
const { STSClient, GetCallerIdentityCommand } = require("@aws-sdk/client-sts");

const REGION = process.env.AWS_REGION || 'ap-south-1';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'ap-south-1_xxxxxxxxx';
const CLIENT_ID = process.env.COGNITO_CLIENT_ID || 'xxxxxxxxxxxxxxxxxxxxxxxxxx';
const ALLOWED_ORIGIN = "https://slams.internal.company.com";

const apiGatewayClient = new ApiGatewayV2Client({ region: REGION });
const lambdaClient = new LambdaClient({ region: REGION });
const stsClient = new STSClient({ region: REGION });

async function setupHardenedApiGateway() {
    try {
        console.log("🔒 Setting up Hardened API Gateway for SLAMS...");
        const stsResponse = await stsClient.send(new GetCallerIdentityCommand({}));
        const accountId = stsResponse.Account;
        console.log(`Connected Account: ${accountId}`);

        // 1. Create HTTP API with restricted CORS
        const createApiResponse = await apiGatewayClient.send(new CreateApiCommand({
            Name: "SLAMS-API-Hardened",
            ProtocolType: "HTTP",
            CorsConfiguration: {
                AllowOrigins: [ALLOWED_ORIGIN],
                AllowMethods: ["GET", "POST", "PUT", "OPTIONS"],
                AllowHeaders: ["Content-Type", "Authorization", "X-Amz-Date"],
                AllowCredentials: true,
                MaxAge: 3600
            }
        }));
        
        const apiId = createApiResponse.ApiId;
        const apiEndpoint = createApiResponse.ApiEndpoint;
        console.log(`✓ API Created: ${apiId} (${apiEndpoint})`);

        // 2. Create Cognito JWT Authorizer
        console.log("\nAttaching Cognito JWT Authorizer...");
        const authorizerResponse = await apiGatewayClient.send(new CreateAuthorizerCommand({
            ApiId: apiId,
            AuthorizerType: "JWT",
            IdentitySource: ["$request.header.Authorization"],
            Name: "SLAMS-CognitoAuthorizer",
            JwtConfiguration: {
                Audience: [CLIENT_ID],
                Issuer: `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`
            }
        }));
        const authorizerId = authorizerResponse.AuthorizerId;
        console.log(`✓ Cognito Authorizer Created: ${authorizerId}`);

        // Helper to attach lambda routes
        async function attachLambdaToRoutes(lambdaName, routes) {
            const lambdaArn = `arn:aws:lambda:${REGION}:${accountId}:function:${lambdaName}`;

            try {
                await lambdaClient.send(new AddPermissionCommand({
                    FunctionName: lambdaName,
                    StatementId: `apigw-${apiId}-${Date.now()}`,
                    Action: "lambda:InvokeFunction",
                    Principal: "apigateway.amazonaws.com",
                    SourceArn: `arn:aws:execute-api:${REGION}:${accountId}:${apiId}/*/*`
                }));
            } catch (err) {
                // Ignore if permission already exists
            }

            const integration = await apiGatewayClient.send(new CreateIntegrationCommand({
                ApiId: apiId,
                IntegrationType: "AWS_PROXY",
                IntegrationUri: lambdaArn,
                PayloadFormatVersion: "1.0"
            }));

            for (const item of routes) {
                const routeParams = {
                    ApiId: apiId,
                    RouteKey: item.route,
                    Target: `integrations/${integration.IntegrationId}`
                };
                if (item.requiresAuth) {
                    routeParams.AuthorizationType = "JWT";
                    routeParams.AuthorizerId = authorizerId;
                } else {
                    routeParams.AuthorizationType = "NONE";
                }
                await apiGatewayClient.send(new CreateRouteCommand(routeParams));
                console.log(`  ✓ Route ${item.route} [Auth: ${item.requiresAuth ? 'Cognito JWT' : 'PUBLIC EXEMPTION (HMAC Token)'}]`);
            }
        }

        // Attach Routes
        await attachLambdaToRoutes("submitLeaveRequest", [
            { route: "POST /leave-requests", requiresAuth: true },
            { route: "POST /leave-requests/{request_id}/cancel", requiresAuth: true }
        ]);

        // GET /approve: Documented Public Exemption (tamper-proof signed URL from email)
        await attachLambdaToRoutes("approveRejectRequest", [
            { route: "GET /approve", requiresAuth: false }
        ]);

        await attachLambdaToRoutes("reportsCalendar", [
            { route: "GET /balances/{employee_id}", requiresAuth: true },
            { route: "GET /leave-requests/{employee_id}", requiresAuth: true },
            { route: "GET /approvals/pending", requiresAuth: true },
            { route: "GET /calendar", requiresAuth: true },
            { route: "GET /config/leave-types", requiresAuth: true },
            { route: "PUT /config/leave-types", requiresAuth: true }
        ]);

        // Create deployment stage
        await apiGatewayClient.send(new CreateStageCommand({
            ApiId: apiId,
            StageName: "$default",
            AutoDeploy: true
        }));

        console.log("\n=============================================");
        console.log("✅ SLAMS HARDENED API GATEWAY CONFIGURED ✅");
        console.log("=============================================\n");

    } catch (err) {
        console.error("Error setting up Hardened API Gateway:", err);
    }
}

setupHardenedApiGateway();
