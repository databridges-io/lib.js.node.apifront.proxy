/*
    Copyright 2022 Optomate Technologies Private Limited.
    https://www.databridges.io
    https://www.optomate.io

    maintainers - tech@optomate.io
    
    Version : v1.0.3
    ChangeLog: v1.0.3

*/
const dBridges = require('databridges-sio-server-lib');
const dBridgesCli = require('databridges-sio-client-lib');
const delay = require("delay");
const { customAlphabet } = require('nanoid');
const EventEmitter = require('events');
const nanoid = customAlphabet('1234567890abcdefghijklmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 10)

class databridges_apifront_proxy extends EventEmitter  {
    #configJson = null; 
    #proxyPaths = {};
    #started = false;
    #dberror = true;
    #controlChannelError = false;
    #connectWorkerRPCError = false;
    #proxyerror = true;
    #baseProxyAPIVersion = 'v1'; 

    constructor() {
        super();
        this.dataBridge = new dBridges();
        this.dBridgesCli = new dBridgesCli();
        this.rpcServer = {};
        this.rpcServerFunctionSpecs = {};
        this.proxyId = nanoid(6);
        this.rpcServerDBObj = {}; 
        this.rpcClientConn = null;
        this.sessionid = null;
        this.dbMiddlewareRoute = null;
        this.apiSysChannel = null;
        this.apiSysChannelName = null;
        // Bind `config` to act as both method and object with getters/setters
        this.config = this.config.bind(this);
        // Add getters and setters directly on the config method
        Object.defineProperties(this.config, {
            apifront_clientId: {
                get: () => this.#configJson.apifront_clientId,
                set: (value) => {
                    if (this.#configJson == null) { this.#configJson = {} };
                    this.#configJson.apifront_clientId = value;
                }
            },
            apifront_clientSecret: {
                get: () => this.#configJson.apifront_clientSecret,
                set: (value) => {
                    if (this.#configJson == null) { this.#configJson = {} };
                    this.#configJson.apifront_clientSecret = value;
                }
            },
            apifront_authUrl: {
                get: () => this.#configJson.apifront_authUrl,
                set: (value) => {
                    if (this.#configJson == null) { this.#configJson = {} };
                    this.#configJson.apifront_authUrl = value;
                }
            },
            apifront_gatewayId: {
                get: () => this.#configJson.apifront_gatewayId,
                set: (value) => {
                    if (this.#configJson == null) { this.#configJson = {} };
                    this.#configJson.apifront_gatewayId = value;
                }
            }
        });
    }

    config(configJson) {
        this.#configJson = configJson; 
    }

    #errorObj(errNo, addnMessage = '') {
        const errObj = {
            101: { source: 'apiFront', code: 'DBNET_DISCONNECT', message: 'dataBridges_network_connection_failed' + ':' + addnMessage },
            102: { source: 'apiFront', code: 'DBAPP_REGISTRATION', message: 'dataBridges_rpc_registration_failed' + ':' + addnMessage },
            103: { source: 'apiFront', code: 'VALIDATION_ERROR', message: 'Invlid input' + ':' + addnMessage },
            104: { source: 'apiFront', code: 'DBNET_SERVICEREGISTRATION', message: 'dataBridges_service_registration_failed' + ':' + addnMessage }
        }
        return errObj[errNo];
    }

    #validateConfig() {
        if (this.#configJson === null) {
            this.emit("log", 'Invalid parameter: Expected a valid JSON object.');
            return 'Invalid parameter: Expected a valid JSON object.';
        } 
        if (typeof this.#configJson != 'object') {
            this.emit("log", 'Invalid parameter: Expected a valid JSON object.');
            return 'Invalid parameter: Expected a valid JSON object.';
        }
        if (typeof this.#configJson.apifront_clientId !== 'string' || typeof this.#configJson.apifront_clientSecret !== 'string' ||
            typeof this.#configJson.apifront_authUrl !== 'string' || typeof this.#configJson.apifront_gatewayId !== 'string') {
            return 'Invalid configuration parameters';
        }
        if (!this.#configJson.apifront_gatewayId || this.#configJson.apifront_gatewayId == 'null') {
            return 'Invalid configuration parameters';
        }
        return '';
    }

    #validateProxy(path, rpcFunction) {
        const pathArr = path.split('/');
        if (pathArr.length !== 2 && pathArr.length !== 3) {
            this.emit("log", `Invalid proxy path. Path should be version/server/function or server/function. Provided: ${path}`);
            return `Invalid proxy path. Path should be version/server/function or server/function. Provided: ${path}`;
        }
        let [versionStr, rpcSvrName, funName] = pathArr.length === 2 ? [this.#baseProxyAPIVersion, ...pathArr] : pathArr;
        //if (!/^v[1-9]\d*$/.test(versionStr)) {  // if leading 0 not to be accepted.
        if (!/^v\d+$/.test(versionStr)) {
            this.emit("log", `Invalid format for version in proxy path. It should be in the format vXXXXX. Provided: ${versionStr}`);
            return `Invalid format for version in proxy path. It should be in the format vXXXXX. Provided: ${versionStr}`;
        }
        // Validate `rpcSvrName` and `funName` (cannot contain underscores)
        if (rpcSvrName.includes('_') || funName.includes('_')) {
            this.emit("log", `Invalid proxy path. Neither server nor function can contain underscores. Provided: ${path}`);
            return `Invalid proxy path. Neither server nor function can contain underscores. Provided: ${path}`;
        }
        // Validate `rpcSvrName` and `funName` as non-empty strings
        if (!rpcSvrName || typeof rpcSvrName !== 'string' || !/^[a-zA-Z0-9\.:-]+$/.test(rpcSvrName) || rpcSvrName.length > 64) {
            this.emit("log", `Invalid server value in proxy path: ${rpcSvrName}`);
            return `Invalid server value in proxy path: ${rpcSvrName}`;
        }
        if (!funName || typeof funName !== 'string' || !/^[a-zA-Z0-9\.:-]+$/.test(funName) || funName.length > 64) {
            this.emit("log", `Invalid function value in proxy path: ${funName}`);
            return `Invalid function value in proxy path: ${funName}`;
        }
        if (rpcSvrName.indexOf(':') > 0) {
            if (rpcSvrName.indexOf('prs:') != 0 ) {
                this.emit("log", 'Invalid proxy path. Path should be version/server/function or server/function ' + path);
                return 'Invalid proxy path. Path should be version/server/function or server/function ' + path;
            }
        }  
        if (typeof rpcFunction !== 'function') {
            this.emit("log", funName + ' is not a function  in path ' + path);
            return funName + ' is not a function' + ' in path ' + path;
        } 
        return '';
    }

    #validateOptionalParam(optionalParam) {
        if (optionalParam === null) return '';
        if (typeof optionalParam === 'object') { 
            return '';
        }
        try {
            const parsed = JSON.parse(optionalParam);
            return '';
        } catch (e) {
            return 'Invalid optionalParam, not a valid JSON';
        }
    }

    status() {
        if (!this.#dberror && !this.#proxyerror) {
            return 'ONLINE'
        } else {
            return 'OFFLINE'
        }
    }

    #emitStatus() {
        this.emit('status', this.status());
    }

    proxy(path, rpcFunction, functionSpecs = null) {
        this.#proxyPaths[nanoid()] = { path: path, fn: rpcFunction, optparm: functionSpecs }; 
    }

    #middlewareFn(inparameter, response, originalFunction, proxyPath) {
        // Process the payload or perform any necessary checks
        // verify and either pass same payload or send new payload
        // ChangeLog: v1.0.1 - No need to verify 'XFMW_'. This function is called only when rpcCall from Middlware
        let originalInParam = JSON.parse(inparameter.inparam);
        originalFunction(originalInParam, response, proxyPath);
    }

    #loadRpcFunctions(rpcServerName) {
        return new Promise(async (resolve, reject) => {
            for (const [functionName, funcObj] of Object.entries(this.rpcServer[rpcServerName])) {
                this.rpcServerDBObj[rpcServerName].regfn(functionName, (inparameter, response) => {
                    this.#middlewareFn(inparameter, response, funcObj, rpcServerName.replace(/_/g, '/') + '/' + functionName)
                });
            }
            resolve(true);
        });
    }

    #connectWorkerRPC() {
        return new Promise(async (resolve, reject) => {
            try {
                this.rpcClientConn = this.dataBridge.rpc.connect(this.#configJson.apifront_clientId.split(':')[0] == 1 ? 'prs:' + this.dbMiddlewareRoute : this.dbMiddlewareRoute);
            } catch (err) {
                this.emit("log", "rpc.server.connect.failed App is offline.", this.#configJson.apifront_clientId.split(':')[0] == 1 ? 'prs:' + this.dbMiddlewareRoute : this.dbMiddlewareRoute)
                this.#connectWorkerRPCError = true;
                reject(err.code);
            }
            this.rpcClientConn.bind("dbridges:rpc.server.connect.success", () => {
                this.#connectWorkerRPCError = false;
                resolve(true);
            });
            this.rpcClientConn.bind("dbridges:rpc.server.connect.fail", (payload, metadata) => {
                this.emit("log", "rpc.server.connect.failed App is offline.", this.#configJson.apifront_clientId.split(':')[0] == 1 ? 'prs:' + this.dbMiddlewareRoute : this.dbMiddlewareRoute)
                this.#connectWorkerRPCError = true;
                reject(payload.code);
            });
        });
    }

    async #connectWorkerRPCWithRetries() {
        await this.#connectWorkerRPC();
        if (this.#connectWorkerRPCError) {
            let retries = 0;
            const maxRetries = 100;
            const retryInterval = 5000;

            const retryTimer = setInterval(async () => {
                if (!this.#connectWorkerRPCError) {
                    clearInterval(retryTimer);
                    return;
                }
                if (retries >= maxRetries) {
                    clearInterval(retryTimer);
                    this.dBridgesCli.disconnect();
                    this.dataBridge.disconnect();
                    return;
                }
                retries++;
                try {
                    await this.#connectWorkerRPC();
                } catch (err) {
                    this.emit("log", 'Channel subscribe.fail after max retries', err.message)
                }
            }, retryInterval);
        }
    }

    #startdataBridge() {
        return new Promise(async (resolve, reject) => {
            const serverAppKey = this.#configJson.apifront_clientId.split(':')[1];
            this.dataBridge.appkey = serverAppKey;
            this.dataBridge.appsecret = this.#configJson.apifront_clientSecret;
            this.dataBridge.auth_url = this.#configJson.apifront_authUrl;
            this.dataBridge.connect().catch((err) => {
                reject(err.message);
                return false;
            });
            this.dataBridge.connectionstate.bind("reconnect_failed", () => this.emit("disconnected"));
            this.dataBridge.connectionstate.bind("disconnected", () => this.emit("disconnected"));
            this.dataBridge.connectionstate.bind("connect_error", (error) => {
                reject(error.message);
                this.emit("disconnected")
            });
            // Binding dataBridges connection events to EventEmitter
            this.dataBridge.connectionstate.bind("connected", async () => {
                this.sessionid = this.dataBridge.sessionid;
                this.emit("connected");
                resolve(true);
            });
        });
    }

    #getAccessTokenRPC = (channelName, sessionId) => {
        return new Promise(async (resolve, reject) => {
            const jsonParam = { ch: channelName, id: this.proxyId, sid: sessionId, svrsid: this.sessionid, aky: this.#configJson.apifront_clientId.split(':')[2], gid: this.dbMiddlewareRoute }
            this.rpcClientConn.call("proxyCreateJWTToken", JSON.stringify(jsonParam), 1000 * 10, null)
                .then((response) => {
                    resolve(JSON.parse(response));
                })
                .catch((err) => {
                    resolve({
                        statuscode: 1,
                        error_message: err.message,
                        accesskey: ''
                    });
                });
        });
    }

    async #listRpcServer(inparameter, response) {
        const liveRPCSvrs = Object.keys(this.rpcServer);
        let rpcSvrNameToSend = [];  // use multipart response. 
        for (let j = 0; j < liveRPCSvrs.length; j++) {
            rpcSvrNameToSend.push(this.rpcServerDBObj[liveRPCSvrs[j]].getServerName().split('_').slice(1).join('_'));//.split('_').pop());
        }
        if (rpcSvrNameToSend.length > 50) {
            // Split the array into chunks of 50 and use response.next() for each chunk
            const chunkSize = 50;
            for (let i = 0; i < rpcSvrNameToSend.length; i += chunkSize) {
                const chunk = rpcSvrNameToSend.slice(i, i + chunkSize);
                response.next(JSON.stringify({ rpc: chunk }));
                await delay(20);
            }
            // End the response with the last chunk
            response.end(JSON.stringify({ status: 1, msg: '', rpc: rpcSvrNameToSend.slice(-chunkSize) }));
        } else {
            // If the size is less than or equal to 50, send the entire response at once
            response.end(JSON.stringify({ status: 1, msg: '', rpc: rpcSvrNameToSend }));
        }
    }

    async #getFunctionSpecs(inparameter, response) {
        const rpcSvrName = inparameter; 
        for (const [functionName, functionSpecs] of Object.entries(this.rpcServerFunctionSpecs[rpcSvrName])) {
            response.next(JSON.stringify({
                functSpec: {
                    name: functionName,
                    fnspec: functionSpecs ?? null
                } }));
            await delay(20);  
        }
        response.end(JSON.stringify({ status: 1, msg: ''}));
    }

    async #listRpcFunction(inparameter, response) {
        const rpcSvrName = inparameter; //.split('_').pop()
        let functList = [];  // use multipart response.
        for (const [functionName, func] of Object.entries(this.rpcServer[rpcSvrName])) {
            functList.push(functionName)
        }
        if (functList.length > 50) {
            // Split the array into chunks of 50 and use response.next() for each chunk
            const chunkSize = 50;
            for (let i = 0; i < functList.length; i += chunkSize) {
                const chunk = functList.slice(i, i + chunkSize);
                response.next(JSON.stringify({ functs: chunk }));
                await delay(20);
            }
            // End the response with the last chunk
            response.end(JSON.stringify({ status: 1, msg: '', functs: [] }));  //functList.slice(-chunkSize)
        } else {
            // If the size is less than or equal to 50, send the entire response at once
            response.end(JSON.stringify({ status: 1, msg: '', functs: functList }));
        }
    }

    #proxyStatus(inparameter, response) {
        const recdParam = JSON.parse(inparameter);
        this.#proxyerror = !recdParam.proxystatus;
        this.#emitStatus();
        response.end(JSON.stringify({ status: 1, msg: '' }));
    }

    #registrationError(inparameter, response) {
        this.emit("log", inparameter)
        this.#proxyerror = true;
        this.#emitStatus();
        response.end(JSON.stringify({ status: 1, msg: '' }));
    } 

    #startdataBridgeCli() {
        return new Promise(async (resolve, reject) => {
            const clientAppKey = this.#configJson.apifront_clientId.split(':')[2];
            this.dBridgesCli.appkey = clientAppKey;
            this.dBridgesCli.auth_url = this.#configJson.apifront_authUrl;
            this.dBridgesCli.connect().catch((err) => {
                reject(err.message);
                return false;
            });
            this.dBridgesCli.connectionstate.bind("reconnect_failed", () => this.emit("disconnected"));
            this.dBridgesCli.connectionstate.bind("disconnected", () => this.emit("disconnected"));
            this.dBridgesCli.connectionstate.bind("connect_error", (error) => {
                reject(error.message);
                this.emit("disconnected")
            });
            this.dBridgesCli.access_token(async (channelName, sessionId, action, response) => {
                const accessResponse = await this.#getAccessTokenRPC(channelName, sessionId);
                response.end(accessResponse); 
            });

            this.dBridgesCli.cf.enable = true;
            this.dBridgesCli.cf.functions = function () { }
            this.dBridgesCli.cf.regfn("listRpcServer", (inparameter, response) => { this.#listRpcServer(inparameter, response) });
            this.dBridgesCli.cf.regfn("listRpcFunction", (inparameter, response) => { this.#listRpcFunction(inparameter, response) });
            this.dBridgesCli.cf.regfn("getFunctionSpecs", (inparameter, response) => { this.#getFunctionSpecs(inparameter, response) });
            this.dBridgesCli.cf.regfn("proxyStatus", (inparameter, response) => { this.#proxyStatus(inparameter, response) });
            this.dBridgesCli.cf.regfn("registrationError", (inparameter, response) => { this.#registrationError(inparameter, response) });
            // Binding dataBridges connection events to EventEmitter
            this.dBridgesCli.connectionstate.bind("connected", async () => {
                resolve(true);
            });

        });
    }

    #startRPCServer(rpcServerName) {
        return new Promise(async (resolve, reject) => { 
            const regServerName = 'prs:' + this.dbMiddlewareRoute + '_' +  rpcServerName
            this.rpcServerDBObj[rpcServerName] = this.dataBridge.rpc.init(regServerName);
            await this.#loadRpcFunctions(rpcServerName);
            this.rpcServerDBObj[rpcServerName].functions = function () {
            }
            // Register RPC server
            try {
                this.rpcServerDBObj[rpcServerName].register()
            } catch (err) {
                this.dataBridge.disconnect();
                reject(err.code);
                return false;
            }
            // RPC server state bindings
            this.rpcServerDBObj[rpcServerName].bind("dbridges:rpc.server.registration.fail", (payload, metadata) => {
                this.dataBridge.disconnect();
                reject(payload.code);
                return false;
            });

            this.rpcServerDBObj[rpcServerName].bind('dbridges:rpc.server.offline', (payload, metadata) => {
                this.emit("log", rpcServerName + " App is offline.")
                this.dataBridge.disconnect();
                return false;
            });
            // RPC server state bindings
            this.rpcServerDBObj[rpcServerName].bind('dbridges:rpc.server.registration.success', (payload, metadata) => {
                resolve(true);
            });
            this.rpcServerDBObj[rpcServerName].bind('dbridges:rpc.server.unregistration.success', (payload, metadata) => {
                this.emit("log", "rpc.server.unregistration.success App is offline.", regServerName)
            });
            this.rpcServerDBObj[rpcServerName].bind('dbridges:rpc.server.unregistration.fail', (payload, metadata) => {
                this.emit("log", "rpc.server.unregistration.fail", regServerName)
            });
        });
    }

    #startControlChannel() {
        return new Promise(async (resolve, reject) => { 
            this.apiSysChannelName = 'prs:' + this.dbMiddlewareRoute;
            try {
                this.apiSysChannel = this.dBridgesCli.channel.subscribe(this.apiSysChannelName);
            } catch (err) {
                this.emit("log", 'dBridge subscribe exception..', this.apiSysChannelName, err.source, err.code, err.message)
                reject(err.code);
            }
            this.apiSysChannel.bind("dbridges:subscribe.success", async (payload, metadata) => {
                this.#dberror = false;
                this.#emitStatus();
                this.emit("log", "App connected and online");
                this.#controlChannelError = false;
                resolve(true);
            });
            this.apiSysChannel.bind("dbridges:subscribe.fail", (payload, metadata) => {
                this.emit("log", 'Channel subscribe.fail', this.apiSysChannelName, payload.source, payload.code, payload.message) 
                this.#dberror = true;
                this.#controlChannelError = true;
                this.#emitStatus();
                resolve(true);
            }); 
        });
    }

    async #startControlChannelWithRetries() {
        await this.#startControlChannel();
        if (this.#controlChannelError) {
            let retries = 0;
            const maxRetries = 100;
            const retryInterval = 5000;

            const retryTimer = setInterval(async () => {
                if (!this.#controlChannelError) { 
                    clearInterval(retryTimer); 
                    return;
                } 
                if (retries >= maxRetries) { 
                    clearInterval(retryTimer); 
                    this.dBridgesCli.disconnect();
                    this.dataBridge.disconnect(); 
                    return;
                }
                retries++; 
                try {
                    await this.#startControlChannel();
                } catch (err) {
                    this.emit("log", 'Channel subscribe.fail after max retries', err.message) 
                }
            }, retryInterval);
        }
    }

    async start() {
        return new Promise(async (resolve, reject) => {
            if (this.#started) {
                reject(this.#errorObj(103, 'start() already called. To restart, stop() and then start()'));
                return false;
            } else {
                this.#started = true;
            }
            // .config validation...
            const valConfigResult = this.#validateConfig();
            if (!valConfigResult == '') {
                reject(this.#errorObj(103, valConfigResult));
                return false;
            }

            // .proxy validation...
            const pathKeys = Object.keys(this.#proxyPaths)
            let valPaxErrors = [];
            for (let i = 0; i < pathKeys.length; i++) {
                const pxPath = this.#proxyPaths[pathKeys[i]].path;
                const pxFn = this.#proxyPaths[pathKeys[i]].fn;
                const optParam = this.#proxyPaths[pathKeys[i]].optparm;
                const valPxPathResult = this.#validateProxy(pxPath, pxFn);
                if (valPxPathResult != '') {
                    valPaxErrors.push(valPxPathResult)
                }
                const valOptParamResult = this.#validateOptionalParam(optParam)
                if (valOptParamResult != '') {
                    valPaxErrors.push(valOptParamResult)
                }
            }
            if (valPaxErrors.length > 0) {
                reject(this.#errorObj(103, valPaxErrors.join('\n')));
                return false;
            }

            for (let i = 0; i < pathKeys.length; i++) {
                const pxPath = this.#proxyPaths[pathKeys[i]].path;
                const pxFn = this.#proxyPaths[pathKeys[i]].fn;
                const optParam = this.#proxyPaths[pathKeys[i]].optparm;
                const pathArr = pxPath.split('/');
                if (pathArr.length == 2) { pathArr.unshift(this.#baseProxyAPIVersion); }
                let rpcSvrName = pathArr[1];
                if (rpcSvrName.indexOf('prs:') == 0 || rpcSvrName.indexOf('pvt:') == 0) {
                    rpcSvrName = rpcSvrName.substring(4);
                }
                rpcSvrName = pathArr[0] + '_' + pathArr[1];
                const funName = pathArr[2];
                if (!(rpcSvrName in this.rpcServer)) {
                    this.rpcServer[rpcSvrName] = {};
                }
                if (!(rpcSvrName in this.rpcServerFunctionSpecs)) {
                    this.rpcServerFunctionSpecs[rpcSvrName] = {};
                } 
                if (Object.keys(this.rpcServer[rpcSvrName]).length > 250) {
                    this.emit("log", 'Only 250 functions are allowed against RPC Server ' + rpcSvrName);
                    reject(this.#errorObj(103, 'Only 250 functions are allowed against RPC Server ' + rpcSvrName));
                    return false;
                }
                if (optParam != null) { 
                    this.rpcServerFunctionSpecs[rpcSvrName][funName] = optParam;
                }
                this.rpcServer[rpcSvrName][funName] = pxFn;
            }
            this.#proxyPaths = {};

            try {
                this.dbMiddlewareRoute = this.#configJson.apifront_gatewayId;
                await this.#startdataBridge()
                await this.#connectWorkerRPCWithRetries()
                let rpcServerStartStatus = true;
                for (const [rpcSvrName, serverFunctions] of Object.entries(this.rpcServer)) {
                    try {
                        await this.#startRPCServer(rpcSvrName);
                    } catch (err) {
                        reject(this.#errorObj(102, err));
                        rpcServerStartStatus = false;
                        break;
                    }
                }
                if (rpcServerStartStatus) {
                    try {
                        await this.#startdataBridgeCli()
                        await this.#startControlChannelWithRetries();
                        resolve({status:'success'});
                        return true;
                    } catch (err) {
                        reject(this.#errorObj(104, err));
                        return false;
                    }
                }
            } catch (err) {
                reject(this.#errorObj(101, err))
                return false;
            }
        });
    }

    stop() {
        return new Promise(async (resolve, reject) => {
            try {
                this.dBridgesCli.channel.unsubscribe(this.apiSysChannelName); 
                const liveRPCSvrs = Object.keys(this.rpcServerDBObj);
                for (let j = 0; j < liveRPCSvrs.length; j++) {
                    this.rpcServerDBObj[liveRPCSvrs[j]].unregister();
                } 
                await delay(30);
                this.rpcServerDBObj = {}; 
                this.sessionid = null;
                this.#started = false;
                this.#dberror = true;
                this.#proxyerror = true;
                this.#controlChannelError = false;
                this.#connectWorkerRPCError = false;
                this.dataBridge.disconnect();
                this.dBridgesCli.disconnect();
                this.#emitStatus();
                resolve(true)
            } catch (err) {
                reject(this.#errorObj(101, err));
                return false;
            }
        });
    }
}

module.exports = databridges_apifront_proxy;

