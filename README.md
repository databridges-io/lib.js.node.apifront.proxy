![](https://img.shields.io/badge/Licence-Apache%202.0-green.svg) ![](https://shields.io/badge/node.js-%3E=14.0%20LTS-blue)

# APIFront Node.js Proxy

**Transform your internal functions into enterprise-grade REST APIs instantly - no additional infrastructure required.**

APIFront solves the fundamental challenge of exposing deep networked functions as secure, scalable APIs. Whether you're building microservices, integrating AI systems, or creating API-first architectures, APIFront provides the fastest path from function to production-ready API.

## 🌟 What is APIFront?

APIFront is an advanced API infrastructure platform that transforms any backend function into secure, real-time, enterprise-class APIs with OAuth2 protection, rate limiting, and monetization capabilities - all without requiring additional web infrastructure.

### ⚡ Key Benefits

- **🚀 Instant API Creation**: Transform functions to APIs in minutes, not months
- **🔒 Enterprise Security**: Built-in OAuth2, IP whitelisting, and access controls
- **⚖️ Auto Load Balancing**: Automatic horizontal scaling without configuration
- **🌐 Global Access**: Functions behind firewalls become globally accessible APIs
- **💰 Built-in Monetization**: Integrated payment processing and API credit management
- **🤖 AI-Ready**: Perfect for LLM function calling and AI agent integration

## 📋 Table of Contents

- [How APIFront Works](#how-apifront-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Function Definition](#function-definition)
- [API Registration](#api-registration)
- [Advanced Features](#advanced-features)
- [Error Handling](#error-handling)
- [Production Deployment](#production-deployment)
- [Integration Examples](#integration-examples)

## 🔧 How APIFront Works

### Architecture Overview

APIFront creates a secure bridge between your internal functions and the global internet:

**🏠 Your Functions** *(Internal Logic)*
↓ *Secure outbound connection*
**🔗 APIFront Proxy** *(Establishes secure tunnel)*
↓ *Encrypted communication*
**🌐 APIFront Network** *(OAuth2 authentication & intelligent routing)*
↓ *Public access*
**🌍 Global REST APIs** *(Accessible worldwide)*

**Key Benefits:**

- **No inbound ports required** - Works with existing firewalls
- **Enterprise security** - OAuth2, IP whitelisting, rate limiting
- **Automatic scaling** - Load balancing across multiple instances
- **Global accessibility** - Functions become REST APIs instantly

### API Path Structure

Your functions become accessible via this URL pattern:

[https://gateway.apifront.io/api/v1/{gateway_id}/{service_version}/{service_name}/{function_name}](https://gateway.apifront.io/api/v1/{gateway_id}/{service_version}/{service_name}/{function_name})

**Example URLs:**

- `https://gateway.apifront.io/api/v1/gw123/v1/user-service/create-user`
- `https://gateway.apifront.io/api/v1/gw123/v1/analytics/generate-report`
- `https://gateway.apifront.io/api/v1/gw123/v2/ai-tools/process-image`

### Service Organization

| Feature | Description | Benefit |
|---------|-------------|---------|
| 📦 **Logical Grouping** | Group related functions under service names | Clean API structure |
| 🔄 **Single Deployment** | All functions in a service deployed together | Version consistency |
| ⚖️ **Auto Load Balancing** | Multiple instances automatically balanced | High availability |
| 🛡️ **Service Integrity** | Consistent deployment per service | Reliable performance |

## 📦 Installation

```bash
npm install @databridges/apifront-proxy --save
```

**Requirements:** Node.js version 14 or newer (LTS recommended)

## 🚀 Quick Start

### 1. Initialize and Configure

```javascript
const ApiProxy = require('@databridges/apifront-proxy');
const apifront = new ApiProxy();

// Configure with credentials from APIFront Dashboard
apifront.config({
    apifront_gatewayId: 'YOUR_GATEWAY_ID',
    apifront_clientId: 'YOUR_CLIENT_ID', 
    apifront_clientSecret: 'YOUR_CLIENT_SECRET',
    apifront_authUrl: 'YOUR_AUTH_URL'
});
```

### 2. Define Your Functions

```javascript
// User creation function
async function createUser(inparameter, response, proxyPath) {
    try {
        const userData = JSON.parse(inparameter.inparam);
        const headerInfo = JSON.parse(inparameter.info);
        
        // Validation
        if (!userData.name || !userData.email) {
            throw new Error("Missing required fields: name or email");
        }
        // Your business logic here
        const newUser = {
            id: generateUserId(),
            name: userData.name,
            email: userData.email,
            created: new Date().toISOString()
        };
        
        // Save to database
        await database.users.create(newUser);
        
        // Return success response
        response.end(JSON.stringify({
            status: 'SUCCESS',
            user: newUser
        }));
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR',
            message: error.message
        }));
    }
}

// Analytics report function
async function generateReport(inparameter, response, proxyPath) {
    try {
        const params = JSON.parse(inparameter.inparam);
        // Validate input
        if (!params.reportType || !params.dateRange) {
            throw new Error("Missing required parameters: reportType or dateRange");
        }
        // Generate analytics report
        const report = await analyticsEngine.generateReport({
            type: params.reportType,
            dateRange: params.dateRange,
            filters: params.filters
        });
        
        response.end(JSON.stringify({
            status: 'SUCCESS',
            report: report
        }));
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR',
            message: error.message
        }));
    }
}
```

### 3. Register API Endpoints

```javascript
// Register functions as API endpoints
apifront.proxy('user-service/create-user', createUser);
apifront.proxy('user-service/get-profile', getUserProfile);
apifront.proxy('analytics/generate-report', generateReport);
apifront.proxy('analytics/get-metrics', getMetrics);
```

### 4. Start the Proxy

```javascript
apifront.start()
    .then(() => {
        console.log('🚀 APIFront proxy is online!');
        console.log('Your APIs are now accessible globally');
    })
    .catch(err => {
        console.error('❌ Startup error:', err);
    });
```

### 5. Monitor Status

```javascript
// Event listeners for monitoring
apifront.on('connected', () => {
    console.log('✅ Connected to APIFront network');
});

apifront.on('disconnected', () => {
    console.log('⚠️ Disconnected from APIFront network');
});

apifront.on('status', (status) => {
    console.log('📊 Status:', status);
});

if (process.env.DEBUG_MODE === 'true') {
    apifront.on('log', (...args) => {
        console.log('📝 Log:', ...args);
    });
}
```

## ⚙️ Configuration

### Configuration Options

| Property                | Type     | Required | Description                        |
| ----------------------- | -------- | -------- | ---------------------------------- |
| `apifront_gatewayId`    | `string` | ✅        | Gateway ID from APIFront Dashboard |
| `apifront_clientId`     | `string` | ✅        | Client ID for authentication       |
| `apifront_clientSecret` | `string` | ✅        | Client secret for authentication   |
| `apifront_authUrl`      | `string` | ✅        | Authentication URL from dashboard  |

### Configuration Methods

**Method 1: Object Configuration**

```javascript
apifront.config({
    apifront_gatewayId: 'gw123',
    apifront_clientId: 'client456', 
    apifront_clientSecret: 'secret789',
    apifront_authUrl: 'https://auth.apifront.io'
});
```

**Method 2: Property Assignment**

```javascript
apifront.config.apifront_gatewayId = 'gw123';
apifront.config.apifront_clientId = 'client456';
apifront.config.apifront_clientSecret = 'secret789';
apifront.config.apifront_authUrl = 'https://auth.apifront.io';
```

## 🔨 Function Definition

### Function Signature

Every API handler receives three parameters:

```javascript
function handlerName(inparameter, response, proxyPath) {
    // Function implementation
}
```

### Parameter Details

#### `inparameter` Object

| Property     | Type     | Description                          |
| ------------ | -------- | ------------------------------------ |
| `inparam`    | `string` | JSON-encoded input from client       |
| `info`       | `string` | JSON-encoded metadata and headers    |
| `sessionid`  | `string` | Unique client session identifier     |
| `libtype`    | `string` | Client library type (e.g., "nodejs") |
| `sourceipv4` | `string` | Client's IPv4 address                |

#### `info` Field Structure

```javascript
const headerInfo = JSON.parse(inparameter.info);
/*
{
    "sysid": "user@example.com",
    "sysinfo": {
        "keyid": "key123",
        "apiResourceOwner": "owner456", 
        "apiClient": "MyApp",
        "scope": "*"
    },
    "http-header": {
		//... Standard http headers.
    }
}
`headerInfo` structure:
   - sysid: System identity or user ID of the caller.
   - sysinfo:
       - keyid: Authentication key ID.
       - apiResourceOwner: Resource owner's identity.
       - apiClient: Identity of the calling client.
       - scope: Permissions or access scope (e.g. "*", "read write","user_read user-profile analytics_write").
*/
```

Below are few examples of `http-header`

✅ **Example 1 – Postman Request**

```json
"http-header": {
      "content-type": "text/plain",
      "user-agent": "PostmanRuntime/7.42.0",
      "accept": "*/*",
      "cache-control": "no-cache",
      "postman-token": "cf3b320b-6d6a-416a-a688-b082f52eabc4",
      "host": "eu-api-apigw02.databridges.io",
      "accept-encoding": "gzip, deflate, br",
      "connection": "keep-alive",
      "content-length": "2"
    }
```

✅ **Example 2 – Web Browser Client (Single-Page App)**

```json
"http-header": {
      "host": "eu-api-apigw02.databridges.io",
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "accept-language": "en-US,en;q=0.9",
      "origin": "https://client.myapp.com",
      "referer": "https://client.myapp.com/dashboard",
      "content-type": "application/json"
    }
```

✅ **Example 3 – Backend Microservice Call**

```json
"http-header": {
      "user-agent": "order-service/1.4.2",
      "x-correlation-id": "12b3f9ee-7812-4f8d-b918-2a000e41a345",
      "content-type": "application/json",
      "host": "eu-api-apigw02.databridges.io",
    }
```

✅ **Example 4 – Mobile App (iOS or Android)**

```json
"http-header": {
      "user-agent": "MyApp/3.2.1 (iOS; iPhone14,2)",
      "content-type": "application/json",
      "x-device-id": "dev-12345-ios",
      "host": "eu-api-apigw02.databridges.io",
    }
```



#### `response` Object

| Method      | Description                              |
| ----------- | ---------------------------------------- |
| `end(data)` | Send final response and close connection |

#### `proxyPath` String

Contains the full API path being called (e.g., `"v1/user-service/create-user"`)

### Example Function Implementation

```javascript
async function processPayment(inparameter, response, proxyPath) {
    try {
        // Parse input data
        const paymentData = JSON.parse(inparameter.inparam);
        const clientInfo = JSON.parse(inparameter.info);
        
        // Validate request
        if (!paymentData.amount || !paymentData.currency || !paymentData.source) {
            return response.end(JSON.stringify({
                status: 'ERROR',
                message: 'Amount and currency are required'
            }));
        }
        
        // Process payment
        const result = await paymentProcessor.charge({
            amount: paymentData.amount,
            currency: paymentData.currency,
            source: paymentData.source,
            description: paymentData.description
        });
        
        // Log transaction
        logger.info('Payment processed', {
            sessionId: inparameter.sessionid,
            clientId: clientInfo.sysinfo.apiClient,
            amount: paymentData.amount,
            result: result.id
        });
        
        // Return success
        response.end(JSON.stringify({
            status: 'SUCCESS',
            transactionId: result.id,
            amount: result.amount,
            currency: result.currency
        }));
        
    } catch (error) {
        logger.error('Payment processing failed', {
            error: error.message,
            sessionId: inparameter.sessionid
        });
        
        response.end(JSON.stringify({
            status: 'ERROR',
            message: 'Payment processing failed',
            errorCode: 'PAYMENT_ERROR'
        }));
    }
}
```

## 📡 API Registration

### Basic Registration

```javascript
apifront.proxy('service-name/function-name', functionHandler);
```

### With Function Metadata

```javascript
apifront.proxy('user-service/create-user', createUser, {
    mcp: {
        description: "Create a new user account",
        permissions: ["user:create"],
        rateLimit: 100
    },
    openapi: {
        summary: "Create User",
        description: "Creates a new user account in the system",
        tags: ["Users", "Authentication"],
        parameters: {
            name: { type: "string", required: true },
            email: { type: "string", required: true },
            password: { type: "string", required: true }
        }
    }
});
```

### Versioned APIs

```javascript
// Version 1
apifront.proxy('v1/user-service/create-user', createUserV1);

// Version 2 with enhanced features
apifront.proxy('v2/user-service/create-user', createUserV2);
```

> **Note :**  If no version is specified during proxy configuration, the default version `"v1"` will be automatically applied to the API route.

### Service Organization Best Practices

```javascript
// ✅ Recommended: Keep all functions of the same service within a single deployment
apifront.proxy('user-service/create-user', createUser);
apifront.proxy('user-service/update-user', updateUser);
apifront.proxy('user-service/delete-user', deleteUser);
apifront.proxy('user-service/get-user', getUser);

// ✅ Recommended: Group related functionalities in dedicated deployments
apifront.proxy('analytics/generate-report', generateReport);
apifront.proxy('analytics/get-metrics', getMetrics);
apifront.proxy('analytics/export-data', exportData);

// ❌ Not Allowed: Registering functions from the same service across multiple deployments is not allowed
// Example — Do NOT split service registration across separate scripts:
// Script A:
apifront.proxy('user-service/create-user', createUser);
// Script B:
apifront.proxy('user-service/delete-user', deleteUser);
```



## 🔐 Security & Access Control

APIFront provides enterprise-grade security with comprehensive OAuth2 protection and fine-grained access controls.

### Security Architecture

| Feature | Description | Benefit |
|---------|-------------|---------|
| 🔐 **Outbound-Only Connectivity** | All connections initiated from your environment, no inbound ports required | Maintains existing security posture |
| 🛡️ **Comprehensive Authentication** | Complete OAuth2 implementation with JWT token management | Enterprise-grade authorization |
| 🔍 **Granular Access Control** | Function-level permissions, IP whitelisting, usage quotas | Fine-grained security control |
| 🔒 **Secure Communication** | End-to-end encryption with TLS 1.3 and strong cipher suites | Data protection in transit |

### 🔐 OAuth2 Implementation

APIFront implements OAuth2 as a **gateway-level security layer**, protecting your entire API gateway. All exposed functions automatically inherit this protection without requiring individual security implementation.

#### Supported Grant Types

| Grant Type | Description | Best For |
|------------|-------------|----------|
| 🔑 **Authorization Code Flow** | Traditional OAuth2 web flow with user authentication | Web applications, server-side applications |
| 🔐 **Authorization Code with PKCE** | Enhanced flow with Proof Key for Code Exchange | Mobile apps, Single Page Applications |
| 🤖 **Client Credentials Flow** | Machine-to-machine authorization without user interaction | Microservices, backend services, APIs |
| 🎫 **Bearer Token Support** | Simple token-based authentication | Simple integrations, legacy systems, testing |

#### Authorization Code Flow - Resource Owner Context

For **Authorization Code Flow**, the `apiResourceOwner` field is critical as it identifies the user who authorized the client application to access APIs on their behalf:

```javascript
async function processUserData(inparameter, response, proxyPath) {
    try {
        const clientInfo = JSON.parse(inparameter.info);
        const requestData = JSON.parse(inparameter.inparam);
        
        // In Authorization Code Flow, apiResourceOwner is the authorizing user
        const authorizingUser = clientInfo.sysinfo.apiResourceOwner;
        const clientApp = clientInfo.sysinfo.apiClient;
        
        if (authorizingUser) {
        	// Basic validation
            if (!requestData.userId) {
                return response.end(JSON.stringify({
                    status: 'ERROR',
                    message: 'Missing required field: userId'
                }));
            }
            // Process data on behalf of the authorizing user
            console.log(`Processing request for ${authorizingUser} via ${clientApp}`);
            
            // Ensure the request is for the correct user
            if (requestData.userId !== authorizingUser) {
                return response.end(JSON.stringify({
                    status: 'ERROR',
                    message: 'Cannot access data for different user',
                    errorCode: 'UNAUTHORIZED_USER_ACCESS'
                }));
            }
            
            const userData = await processUserSpecificData(authorizingUser, requestData);
            
            response.end(JSON.stringify({
                status: 'SUCCESS',
                data: userData,
                processed_for: authorizingUser,
                via_client: clientApp
            }));
        } else {
            // Client Credentials Flow - no specific user context
            const systemData = await processSystemData(requestData);
            response.end(JSON.stringify({
                status: 'SUCCESS',
                data: systemData,
                flow_type: 'client_credentials'
            }));
        }
        
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR',
            message: error.message
        }));
    }
}
```



### 🔐 OAuth2 Client Example

This example demonstrates how to securely invoke your protected API using **OAuth2 authentication with the `client_credentials` grant type**.

------

#### ✅ Step-by-Step Overview

1. **Obtain an access token** from the OAuth2 authorization server using your `client_id` and `client_secret`.
2. **Use the access token** to call your secured API endpoint.

```javascript
const axios = require('axios');
const qs = require('querystring');

// ----------------------
// CONFIGURATION SECTION
// ----------------------
const config = {
    tokenUrl: 'TokenURL',
    clientId: 'ClientID',
    clientSecret: 'ClientSecret',
    scope: '', 
    apiUrl: 'Valid API URL'
};

// ----------------------
// STEP 1: Get Access Token
// ----------------------
async function getOAuthAccessToken() {
    const basicAuth = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');

    try {
        const response = await axios.post(
            config.tokenUrl,
            qs.stringify({
                grant_type: 'client_credentials',
                scope: config.scope
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${basicAuth}`
                }
            }
        );

        return response.data.access_token;
    } catch (err) {
        console.error('❌ Failed to get access token:', err.response?.data || err.message);
        throw new Error('Token retrieval failed');
    }
}

// ----------------------
// STEP 2: Call Protected API
// ----------------------
async function callProtectedAPI(accessToken) {
    try {
        const response = await axios.post(
            config.apiUrl,
            { message: "Hello from Node.js" }, // Replace with your actual payload
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log('✅ Protected API response:', response.data);
        return response.data;
    } catch (err) {
        console.error('❌ Error calling protected API:', err.response?.data || err.message);
    }
}

// ----------------------
// MAIN EXECUTION
// ----------------------
(async () => {
    try {
        const token = await getOAuthAccessToken();
        await callProtectedAPI(token);
    } catch (e) {
        console.error('💥 Script failed:', e.message);
    }
})(); 
```



## 🚀 Advanced Features

### Scopes and Permissions

Scopes are defined when creating OAuth2 client application keys in the APIFront Dashboard using JSON format:

#### Scope Definition Structure

```json
{
    "scopes": [
        {
            "name": "user_read",
            "description": "Allows read access to user data.",
            "selectable": true
        },
        {
            "name": "user-profile",
            "description": "Access to user profile information.",
            "selectable": true
        },
        {
            "name": "analytics_write",
            "description": "Permission to create and modify analytics data.",
            "selectable": false
        }
    ]
}
```

#### Field Definitions

| Field         | Required | Description                                                  |
| ------------- | -------- | ------------------------------------------------------------ |
| `name`        | ✅        | Scope identifier using lowercase/uppercase letters, numbers, underscores (`_`), and hyphens (`-`) only |
| `description` | ❌        | Brief explanation of scope permissions for developers and users |
| `selectable`  | ✅        | Whether end users can opt-in/opt-out during authorization process |

#### Validation Rules

- **No spaces or special characters** except underscores (`_`) and hyphens (`-`)
- **Case-sensitive** matching required during authorization requests
- **`selectable` flag** must be explicitly set for user authorization control

#### Using Scopes in Your Functions

Access granted scopes and user authorization information through the `info` parameter:

```javascript
function secureUserFunction(inparameter, response, proxyPath) {
    try {
        const clientInfo = JSON.parse(inparameter.info);
        const userData = JSON.parse(inparameter.inparam);
        
        // Extract authorization information
        const grantedScopes = clientInfo.sysinfo.scope; // e.g., "user_read user-profile"
        const apiResourceOwner = clientInfo.sysinfo.apiResourceOwner; // User who authorized access
        const apiClient = clientInfo.sysinfo.apiClient; // Client application name
        
        // Check if required scope is granted
        const hasUserReadScope = grantedScopes.includes('user_read');
        const hasUserProfileScope = grantedScopes.includes('user-profile');
        
        if (!hasUserReadScope) {
            return response.end(JSON.stringify({
                status: 'ERROR',
                message: 'Insufficient permissions: user_read scope required',
                errorCode: 'SCOPE_INSUFFICIENT'
            }));
        }
        
        // For Authorization Code Flow: apiResourceOwner contains the user who authorized access
        if (apiResourceOwner) {
            console.log(`API access authorized by user: ${apiResourceOwner}`);
            console.log(`Client application: ${apiClient}`);
        }
        
        // Implement scope-based logic
        let resultData = getUserBasicInfo(inparameter.sessionid);
        
        if (hasUserProfileScope) {
            // Add detailed profile information if scope permits
            resultData = { ...resultData, ...getUserDetailedProfile(inparameter.sessionid) };
        }
        
        response.end(JSON.stringify({
            status: 'SUCCESS',
            data: resultData,
            authorized_by: apiResourceOwner,
            granted_scopes: grantedScopes.split(' ')
        }));
        
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR',
            message: error.message
        }));
    }
}
```

### Load Balancing and Scaling

APIFront automatically load balances multiple instances:

```javascript
// Instance 1: Registers 'user-service/create-user' handler
const apifront1 = new ApiProxy();
apifront1.config(config);
apifront1.proxy('user-service/create-user', createUser);
apifront1.start();

// Instance 2: Registers the same 'user-service/create-user' handler
const apifront2 = new ApiProxy();
apifront2.config(config);
apifront2.proxy('user-service/create-user', createUser);
apifront2.start();

// APIFront Load Balancing:
// Multiple instances can register the same service function.
// APIFront automatically distributes incoming requests across these instances,
// enabling horizontal scaling and fault tolerance.
```

### Environment-Specific Deployment

```javascript
// Build APIFront configuration using environment variables
const config = {
    apifront_gatewayId: process.env.APIFRONT_GATEWAY_ID,
    apifront_clientId: process.env.APIFRONT_CLIENT_ID,
    apifront_clientSecret: process.env.APIFRONT_CLIENT_SECRET,
    apifront_authUrl: process.env.APIFRONT_AUTH_URL
};

// Override with production-specific gateway ID if applicable
if (process.env.NODE_ENV === 'production' && process.env.PROD_GATEWAY_ID) {
    config.apifront_gatewayId = process.env.PROD_GATEWAY_ID;
}

// Apply configuration to APIFront
apifront.config(config);
```

### Access Control Features

#### IP Whitelisting

Configure IP restrictions per OAuth2 client application key in the APIFront Dashboard:

```javascript
// IP whitelisting is configured per client application key
// Access the client information in your functions:
function restrictedFunction(inparameter, response, proxyPath) {
    const clientInfo = JSON.parse(inparameter.info);
    const sourceIP = inparameter.sourceipv4;
    
    console.log(`Request from IP: ${sourceIP}`);
    console.log(`Client Key ID: ${clientInfo.sysinfo.keyid}`);
    
    // APIFront automatically validates IP whitelist before reaching your function
    // If you reach this point, IP validation has already passed
    
    response.end(JSON.stringify({
        status: 'SUCCESS',
        message: 'Access granted from authorized IP',
        source_ip: sourceIP
    }));
}
```

#### Rate Limiting

Configure maximum API call limits per OAuth2 client application key:

```javascript
async function rateLimitedFunction(inparameter, response, proxyPath) {
    try {
        const clientInfo = JSON.parse(inparameter.info);
        
        // APIFront handles rate limiting automatically
        // Your function receives calls only if under the limit
        
        console.log(`Processing request from client: ${clientInfo.sysinfo.apiClient}`);
        
        // Business logic execution
        const result = await processBusinessLogic(JSON.parse(inparameter.inparam));
        
        response.end(JSON.stringify({
            status: 'SUCCESS',
            data: result
        }));
        
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR',
            message: error.message
        }));
    }
}
```

> **Note**: Rate limiting is automatically enforced by APIFront based on the maximum API calls configured for each client application key. Functions receive requests only if the client is within their allowed limits.



## 🏭 Production Deployment

### Graceful Shutdown

```javascript
// Graceful shutdown handling
process.on('SIGTERM', async () => {
    console.log('🛑 SIGTERM received, shutting down gracefully...');
    
    try {
        await apifront.stop();
        console.log('✅ APIFront proxy stopped successfully');
        process.exit(0);
    } catch (error) {
        console.error('❌ Error during shutdown:', error);
        process.exit(1);
    }
});

process.on('SIGINT', async () => {
    console.log('🛑 SIGINT received, shutting down gracefully...');
    
    try {
        await apifront.stop();
        console.log('✅ APIFront proxy stopped successfully');
        process.exit(0);
    } catch (error) {
        console.error('❌ Error during shutdown:', error);
        process.exit(1);
    }
});
// Handle uncaught exceptions
process.on('uncaughtException', async (err) => {
    console.error('💥 Uncaught Exception:', err);

    try {
        await apifront.stop();
        console.log('✅ APIFront proxy stopped successfully');
    } catch (shutdownErr) {
        console.error('❌ Error during shutdown:', shutdownErr);
    } finally {
        // Ensure process exits after handling the exception
        process.exit(1);
    }
});
```



## 📊 Event Listeners & Monitoring

APIFront provides comprehensive event monitoring capabilities to help you track the health and status of your API proxy in real-time.

### Event Listener Registration

The `apifront` instance emits several events during its lifecycle. You can listen to these events to monitor status changes, debug logs, and network connectivity updates.

#### Supported Events

| Event Name           | Trigger               | Parameters           | Description                                                  |
| -------------------- | --------------------- | -------------------- | ------------------------------------------------------------ |
| 🔍 **`log`**          | Internal operations   | `...args` (variable) | System-level messages, debugging information, and operational logs |
| 📊 **`status`**       | Status changes        | `state` (string)     | API proxy status changes (ONLINE/OFFLINE, connecting, etc.)  |
| ✅ **`connected`**    | Network connection    | None                 | Successful connection to dataBridges network established     |
| ❌ **`disconnected`** | Network disconnection | None                 | Connection lost or intentionally closed                      |

### Basic Event Monitoring

**Essential monitoring setup - copy this into your code:**

```javascript
// Essential event monitoring for all APIFront applications
apifront.on("log", (...args) => {
    const logMessage = args.join(' ');
    const timestamp = new Date().toISOString();
    
    // Log errors clearly with context
    if (/ERROR|failed/i.test(logMessage)) {
        console.error(`❌ [${timestamp}] APIFront Error: ${logMessage}`);
    } else if (/connected|online/i.test(logMessage)) {
        console.log(`✅ [${timestamp}] APIFront: ${logMessage}`);
    } else {
        // Debug or informational logs
        console.log(`📝 [${timestamp}] APIFront: ${logMessage}`);
    }
});

apifront.on("status", (state) => {
    const timestamp = new Date().toISOString();
    console.log(`📊 [${timestamp}] APIFront Status: ${state}`);
    
    // You can add custom logic based on status
    switch (state) {
        case 'ONLINE':
            console.log('🚀 APIs are ready to serve requests');
            break;
        case 'OFFLINE':
            console.warn('⚠️ APIs may be temporarily unavailable');
            break;
        default:
            console.log(`ℹ️ Unknown status: ${state}`);
    }
});

apifront.on("connected", () => {
    console.log('🚀 APIFront: Connected and ready to serve APIs');

    // Optional: Trigger actions after successful connection
    // startHealthChecks();
    // notifyOtherServices();
});

apifront.on("disconnected", () => {
    console.error('⚠️ APIFront: Disconnected - APIs may be unavailable');

    // Optional: Handle fallback/alerting logic
    // stopHealthChecks();
    // sendAlert('APIFront disconnected');
});
```

### Production Monitoring

**Advanced monitoring for production environments:**

```javascript
// Production-ready monitoring with health tracking and alerting
let healthStatus = {
    status: 'UNHEALTHY',
    lastConnected: null,
    lastDisconnected: null,
    connectionCount: 0,
    errors: []
};

// Simple health monitor
const healthMonitor = {
    isHealthy: () => healthStatus.status === 'HEALTHY',
    
    getStatus: () => ({
        status: healthStatus.status,
        service: 'apifront-proxy',
        timestamp: new Date().toISOString(),
        connectionCount: healthStatus.connectionCount,
        lastConnected: healthStatus.lastConnected,
        recentErrors: healthStatus.errors.slice(-3)
    }),
    
    logStatus: () => {
        const health = healthMonitor.getStatus();
        console.log(`[HEALTH] ${health.status} - Connections: ${health.connectionCount}`);
    }
};

// Simple alerting function - customize for your needs
async function sendAlert(message, level = 'error') {
    const alertData = {
        message,
        level,
        service: 'apifront-proxy',
        timestamp: new Date().toISOString()
    };
    
    console.error(`🚨 ALERT [${level.toUpperCase()}]: ${message}`);
    
    // Add your preferred alerting method here:
    // Slack webhook:
    // await fetch(process.env.SLACK_WEBHOOK_URL, { method: 'POST', ... });
    
    // Email service:
    // await emailService.send({ subject: 'APIFront Alert', body: message });
    
    // Monitoring service:
    // await monitoringService.alert(alertData);
}

// Track health status from events
apifront.on("connected", () => {
    healthStatus = {
        ...healthStatus,
        status: 'HEALTHY',
        lastConnected: new Date().toISOString(),
        connectionCount: healthStatus.connectionCount + 1
    };
    
    console.log('✅ APIFront: Service is healthy');
    
    // Send recovery notification if we were previously down
    if (healthStatus.connectionCount > 1) {
        sendAlert(`APIFront reconnected after ${healthStatus.connectionCount} attempts`, 'info');
    }
});

apifront.on("disconnected", () => {
    healthStatus = {
        ...healthStatus,
        status: 'UNHEALTHY',
        lastDisconnected: new Date().toISOString()
    };
    
    console.error('❌ APIFront: Service is unhealthy');
    sendAlert('APIFront proxy disconnected - APIs may be unavailable');
});

apifront.on("log", (...args) => {
    const logMessage = args.join(' ');
    
    // Track errors for health monitoring
    if (logMessage.includes('ERROR') || logMessage.includes('failed')) {
        healthStatus.errors.push({
            message: logMessage,
            timestamp: new Date().toISOString()
        });
        
        // Keep only last 10 errors
        if (healthStatus.errors.length > 10) {
            healthStatus.errors = healthStatus.errors.slice(-10);
        }
        
        // Alert on critical errors
        if (logMessage.includes('Channel subscribe.fail after max retries')) {
            sendAlert(`Critical connection failure: ${logMessage}`);
        }
    }
});

// Enhanced startup with error handling and retry logic
apifront.start()
    .then(() => {
        console.log('🚀 APIFront started successfully');
    })
    .catch(error => {
        console.error('❌ APIFront startup failed:', {
            code: error.code,
            message: error.message
        });
        
        // Send startup failure alert
        sendAlert(`APIFront startup failed: ${error.message} (${error.code})`);
        
        // Implement retry logic for recoverable errors
        const recoverableErrors = ['DBNET_DISCONNECT', 'DBAPP_REGISTRATION'];
        if (recoverableErrors.includes(error.code)) {
            console.log('🔄 Retrying startup in 5 seconds...');
            setTimeout(() => {
                console.log('🔄 Attempting restart...');
                apifront.start();
            }, 5000);
        }
    });

// Optional: Periodic health status logging
setInterval(() => {
    healthMonitor.logStatus();
    
    // Check for extended downtime
    if (!healthMonitor.isHealthy() && healthStatus.lastDisconnected) {
        const offlineTime = Date.now() - new Date(healthStatus.lastDisconnected).getTime();
        if (offlineTime > 300000) { // 5 minutes
            sendAlert(`APIFront has been offline for ${Math.floor(offlineTime / 60000)} minutes`);
        }
    }
}, 60000); // Check every minute

// Graceful shutdown monitoring
process.on('SIGTERM', async () => {
    console.log('🛑 Received SIGTERM, shutting down gracefully...');
    try {
        await apifront.stop();
        console.log('✅ APIFront stopped successfully');
        process.exit(0);
    } catch (error) {
        console.error('❌ Error during shutdown:', error);
        process.exit(1);
    }
});
```

### Error Codes

Errors raised by APIFront are internally managed and identified using numeric codes:

| Error Code | Source     | Code                        | Description                             | Common Causes                                              |
| ---------- | ---------- | --------------------------- | --------------------------------------- | ---------------------------------------------------------- |
| **101**    | `apiFront` | `DBNET_DISCONNECT`          | dataBridges network connection failed   | Network issues, firewall blocking, invalid credentials     |
| **102**    | `apiFront` | `DBAPP_REGISTRATION`        | dataBridges RPC registration failed     | Service conflicts, invalid gateway ID, quota exceeded      |
| **103**    | `apiFront` | `VALIDATION_ERROR`          | Invalid input parameters                | Invalid config, malformed proxy paths, missing credentials |
| **104**    | `apiFront` | `DBNET_SERVICEREGISTRATION` | dataBridges service registration failed | Service naming conflicts, permission issues                |

### Log Messages Reference

The `apifront` instance emits various internal log messages for debugging and operational monitoring:

#### Configuration & Validation Logs

| Log Message                                                  | Severity | Cause                                 | Solution                                                |
| ------------------------------------------------------------ | -------- | ------------------------------------- | ------------------------------------------------------- |
| `Invalid parameter: Expected a valid JSON object.`           | ERROR    | Invalid config object passed          | Ensure config is valid JSON object                      |
| `Invalid proxy path. Path should be version/server/function or server/function. Provided: <path>` | ERROR    | Malformed proxy path                  | Use format: `service/function` or `v1/service/function` |
| `Invalid format for version in proxy path. It should be in the format vXXXXX. Provided: <versionStr>` | ERROR    | Invalid version format                | Use version format: `v1`, `v2`, etc.                    |
| `Invalid proxy path. Neither server nor function can contain underscores. Provided: <path>` | ERROR    | Underscores in service/function names | Replace underscores with hyphens                        |
| `Invalid server value in proxy path: <rpcSvrName>`           | ERROR    | Invalid service name                  | Use alphanumeric, dots, colons, hyphens only            |
| `Invalid function value in proxy path: <funName>`            | ERROR    | Invalid function name                 | Use alphanumeric, dots, colons, hyphens only            |
| `<funName> is not a function in path <path>`                 | ERROR    | Non-function passed as handler        | Ensure handler is a valid function                      |


#### Connection & Registration Logs

| Log Message                                                  | Severity | Cause                        | Solution                                    |
| ------------------------------------------------------------ | -------- | ---------------------------- | ------------------------------------------- |
| `App connected and online`                                   | INFO     | Successful connection        | Normal operation                            |
| `rpc.server.connect.failed App is offline.`                  | ERROR    | RPC server connection failed | Check network and credentials               |
| `Channel subscribe.fail after max retries: <error message>`  | ERROR    | Channel subscription failed  | Check gateway ID and permissions            |
| `Only 250 functions are allowed against RPC Server <rpcSvrName>` | ERROR    | Function limit exceeded      | Split functions across multiple services    |
| `dBridge subscribe exception: <channel>, <source>, <code>, <message>` | ERROR    | Subscription exception       | Check channel permissions and credentials   |
| `rpc.server.unregistration.success App is offline: <regServerName>` | INFO     | Clean shutdown               | Normal shutdown process                     |
| `rpc.server.unregistration.fail: <regServerName>`            | WARN     | Unregistration failed        | May indicate network issues during shutdown |

> **💡 Pro Tip**: Start with the **Basic Event Monitoring** setup when developing. Upgrade to **Production Monitoring** when deploying to production environments. The monitoring setup helps you quickly identify and resolve connectivity issues, configuration problems, and service health concerns.



## 🤖 Integration Examples

### AI/LLM Function Calling

```javascript
// Expose AI-callable functions
function analyzeUserSentiment(inparameter, response, proxyPath) {
    try {
        const { text, options } = JSON.parse(inparameter.inparam);
        
        const analysis = sentimentAnalyzer.analyze(text, {
            language: options?.language || 'en',
            detailed: options?.detailed || false
        });
        
        response.end(JSON.stringify({
            status: 'SUCCESS',
            sentiment: analysis.sentiment,
            confidence: analysis.confidence,
            emotions: analysis.emotions
        }));
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR',
            message: error.message
        }));
    }
}

function generateUserInsights(inparameter, response, proxyPath) {
    try {
        const { userId, timeframe } = JSON.parse(inparameter.inparam);
        
        const insights = analyticsEngine.generateUserInsights(userId, timeframe);
        
        response.end(JSON.stringify({
            status: 'SUCCESS',
            insights: insights,
            generatedAt: new Date().toISOString()
        }));
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR', 
            message: error.message
        }));
    }
}

// Register AI-callable functions with metadata
apifront.proxy('ai-tools/analyze-sentiment', analyzeUserSentiment, {
    mcp: {
        description: "Analyze sentiment of given text",
        parameters: {
            text: { type: "string", required: true, description: "Text to analyze" },
            options: {
                type: "object",
                properties: {
                    language: { type: "string", default: "en" },
                    detailed: { type: "boolean", default: false }
                }
            }
        }
    }
});

apifront.proxy('ai-tools/user-insights', generateUserInsights, {
    mcp: {
        description: "Generate insights for a specific user",
        parameters: {
            userId: { type: "string", required: true },
            timeframe: { type: "string", enum: ["7d", "30d", "90d"], default: "30d" }
        }
    }
});
```

### Microservices Integration

```javascript
// -------------------- User Service --------------------
const userService = new ApiProxy();
userService.config(userServiceConfig);

// Register user-related RPC endpoints
userService.proxy('user-service/create', createUser);
userService.proxy('user-service/authenticate', authenticateUser);
userService.proxy('user-service/profile', getUserProfile);

// Start user service
userService.start()
    .then(() => console.log('✅ User Service started'))
    .catch(err => console.error('❌ Failed to start User Service:', err));

// -------------------- Order Service --------------------
const orderService = new ApiProxy();
orderService.config(orderServiceConfig);

// Register order-related RPC endpoints
orderService.proxy('order-service/create', createOrder);
orderService.proxy('order-service/status', getOrderStatus);
orderService.proxy('order-service/cancel', cancelOrder);

// Start order service
orderService.start()
    .then(() => console.log('✅ Order Service started'))
    .catch(err => console.error('❌ Failed to start Order Service:', err));


// -------------------- Notification Service --------------------
const notificationService = new ApiProxy();
notificationService.config(notificationServiceConfig);

// Register notification-related RPC endpoints
notificationService.proxy('notification-service/send', sendNotification);
notificationService.proxy('notification-service/preferences', getNotificationPreferences);

// Start notification service
notificationService.start()
    .then(() => console.log('✅ Notification Service started'))
    .catch(err => console.error('❌ Failed to start Notification Service:', err));
```

### External API Integration

```javascript
// Weather service that integrates with external APIs
async function getCurrentWeather(inparameter, response, proxyPath) {
    try {
        const { location, units } = JSON.parse(inparameter.inparam);
        
        // Validate input
        if (!location) {
            return response.end(JSON.stringify({
                status: 'ERROR',
                message: 'Missing required parameter: location',
                errorCode: 'INVALID_INPUT'
            }));
        }
        
        const apiKey = process.env.WEATHER_API_KEY;
        if (!apiKey) {
            throw new Error('WEATHER_API_KEY not set');
        }

        const url = `https://api.weather.com/v1/current?location=${encodeURIComponent(location)}&units=${units}`;

        const weatherRes = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${apiKey}`
            }
        });
        if (!weatherRes.ok) {
            throw new Error(`Weather API error: ${weatherRes.status} ${weatherRes.statusText}`);
        }
        const weatherData = await weatherRes.json();
        
        // Transform and return data
        response.end(JSON.stringify({
            status: 'SUCCESS',
            weather: {
                location: weatherData.location,
                temperature: weatherData.current.temp,
                condition: weatherData.current.condition,
                humidity: weatherData.current.humidity,
                windSpeed: weatherData.current.wind_speed,
                lastUpdated: weatherData.current.last_updated
            }
        }));
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR',
            message: 'Unable to fetch weather data',
            errorCode: 'WEATHER_API_ERROR'
        }));
    }
}

// Register as an APIFront proxy endpoint
apifront.proxy('weather-service/current', getCurrentWeather);
```

## 💰 API Monetization

Transform your internal functions into profitable API products with APIFront's complete monetization infrastructure.

### Monetization Models

APIFront provides flexible credit-based monetization with multiple billing approaches:

| Model                          | Description                                     | Best For                                         |
| ------------------------------ | ----------------------------------------------- | ------------------------------------------------ |
| 💰 **API Credit Top-Up**        | Adds credits to existing balance, no expiration | Usage-based billing, pay-as-you-go customers     |
| 🔄 **API Credit Refresh**       | Replaces existing balance with fixed amount     | Subscription services, predictable monthly costs |
| ⏱️ **Time-Bound Credit Bundle** | Adds credits with expiration (hourly/daily)     | Promotional offers, trial periods, campaigns     |
| 📅 **Periodic Service Plan**    | Regular renewal with time-limited credits       | True subscriptions, enterprise customers         |

### Monetization Features

#### Automated Payment Processing

- **Stripe Integration**: Direct integration with Stripe Payment Links
- **Automatic Credit Allocation**: Credits added immediately after successful payment
- **Zero Manual Intervention**: Complete automation from purchase to API access
- **Multiple Payment Methods**: Support for all Stripe-enabled payment options

#### Customer Management

- **Self-Service Onboarding**: Customers can sign up and start using APIs immediately
- **Usage Analytics**: Real-time tracking of API consumption and costs
- **Flexible Billing**: Support for prepaid credits, subscriptions, and hybrid models
- **Customer Portal**: Self-service account management and billing history

### Implementation Example

```javascript
// Example: API monetization configuration in APIFront
// This would typically be configured through the APIFront dashboard

// 1. Create API User
const apiUser = {
    email: "customer@example.com",
    name: "Example Customer",
    initial_credits: 1000,  	// Starting credits
    access_level: "standard"
};

// 2. Configure Stripe Product with APIFront
const stripeProduct = {
    name: "Enterprise AI API Access",
    description: "Access to enterprise data functions for AI processing",
    credit_model: "time_bound_addition", 	// Add credits with expiration
    credit_amount: 10000,
    expiration_hours: 720, 					// 30 days
    stripe_payment_link: "https://buy.stripe.com/your_payment_link"
};

// 3. When customer purchases through Stripe:
// - Stripe sends webhook notification to APIFront
// - APIFront automatically adds 10,000 credits to the customer's account
// - Credits are set to expire in 30 days
// - No manual intervention required

// 4. Your API functions automatically consume credits
async function createUser(inparameter, response, proxyPath) {
    try {
        const userData = JSON.parse(inparameter.inparam);
        const clientInfo = JSON.parse(inparameter.info);
        
        // APIFront automatically deducts credits based on configuration
        // Your function just needs to process the request
        
        const newUser = await userService.create(userData);
        
        response.end(JSON.stringify({
            status: 'SUCCESS',
            user: newUser,
            client: clientInfo.sysinfo.apiClient  // Credit information is available in client info if needed
        }));
    } catch (error) {
        response.end(JSON.stringify({
            status: 'ERROR',
            message: error.message
        }));
    }
}
```



## 📚 Resources

### Links

- **🌐 [APIFront Dashboard](https://dashboard.apifront.io/)** - Manage gateways and credentials
- **📖 [Technical Guide](https://apifront.databridges.io/technical-guide)** - Complete technical documentation
- **💡 [Examples Repository](https://github.com/databridges-io/apifront-examples)** - Sample implementations
- **🤝 [Support](mailto:tech@optomate.io)** - Technical support and questions

### Related Packages

- **`databridges-sio-server-lib`** - DataBridges server library
- **`databridges-sio-client-lib`** - DataBridges client library

## 📄 License

APIFront Node.js Proxy is released under the [Apache 2.0 license](LICENSE).

```
Copyright 2022 Optomate Technologies Private Limited.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

------

**Ready to transform your functions into enterprise APIs?** Get started with APIFront today and join the function-native API revolution! 🚀