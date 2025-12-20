/**
 * Fastls Fetch服务 Node.js客户端示例
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

class FastlsFetchClient {
    /**
     * 创建Fetch客户端
     * @param {string} baseUrl - 服务器地址
     */
    constructor(baseUrl = 'http://localhost:8800') {
        this.baseUrl = baseUrl;
    }

    /**
     * 发送HTTP请求
     * @param {object} options - 请求选项
     * @returns {Promise<object>}
     */
    async fetch(options) {
        const url = new URL(`${this.baseUrl}/fetch`);
        const isHttps = url.protocol === 'https:';
        const httpModule = isHttps ? https : http;

        const postData = JSON.stringify({
            url: options.url,
            method: options.method || 'GET',
            headers: options.headers || {},
            body: options.body || '',
            proxy: options.proxy || '',
            timeout: options.timeout || 30,
            disableRedirect: options.disableRedirect || false,
            userAgent: options.userAgent || '',
            fingerprint: options.fingerprint || null,
            browser: options.browser || '',
            cookies: options.cookies || []
        });

        return new Promise((resolve, reject) => {
            const requestOptions = {
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData)
                }
            };

            const req = httpModule.request(requestOptions, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    try {
                        const result = JSON.parse(data);
                        if (result.error) {
                            reject(new Error(result.error));
                        } else {
                            resolve(result);
                        }
                    } catch (error) {
                        reject(new Error(`Parse response failed: ${error.message}`));
                    }
                });
            });

            req.on('error', (error) => {
                reject(new Error(`Request failed: ${error.message}`));
            });

            req.write(postData);
            req.end();
        });
    }

    /**
     * 健康检查
     * @returns {Promise<object>}
     */
    async health() {
        const url = new URL(`${this.baseUrl}/health`);
        const isHttps = url.protocol === 'https:';
        const httpModule = isHttps ? https : http;

        return new Promise((resolve, reject) => {
            const requestOptions = {
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname,
                method: 'GET'
            };

            const req = httpModule.request(requestOptions, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (error) {
                        reject(new Error(`Parse response failed: ${error.message}`));
                    }
                });
            });

            req.on('error', (error) => {
                reject(new Error(`Request failed: ${error.message}`));
            });

            req.end();
        });
    }
}

// 示例用法
async function main() {
    const client = new FastlsFetchClient('http://localhost:8800');

    try {
        // 1. 健康检查
        console.log('1. 健康检查:');
        const health = await client.health();
        console.log('   ', health, '\n');

        // 2. 简单GET请求
        console.log('2. 简单GET请求:');
        const result1 = await client.fetch({
            url: 'https://tls.peet.ws/api/all'
        });
        console.log('   Status:', result1.status);
        console.log('   OK:', result1.ok);
        console.log('   Body length:', result1.body ? result1.body.length : 0, 'bytes\n');

        // 3. 使用浏览器指纹
        console.log('3. 使用Chrome142指纹:');
        const result2 = await client.fetch({
            url: 'https://tls.peet.ws/api/all',
            browser: 'chrome142'
        });
        console.log('   Status:', result2.status);
        console.log('   OK:', result2.ok, '\n');

        // 4. 使用自定义JA3指纹
        console.log('4. 使用自定义JA3指纹:');
        const result3 = await client.fetch({
            url: 'https://tls.peet.ws/api/all',
            fingerprint: {
                type: 'ja3',
                value: '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0'
            }
        });
        console.log('   Status:', result3.status);
        console.log('   OK:', result3.ok, '\n');

        // 5. POST请求
        console.log('5. POST请求:');
        const result4 = await client.fetch({
            url: 'https://httpbin.org/post',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ key: 'value' })
        });
        console.log('   Status:', result4.status);
        console.log('   OK:', result4.ok, '\n');

    } catch (error) {
        console.error('错误:', error.message);
    }
}

// 如果直接运行此文件
if (require.main === module) {
    main();
}

module.exports = FastlsFetchClient;

