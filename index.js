addEventListener('fetch', event => {
    event.respondWith(async function () {
        const response = await handleRequest(event.request);

        if (response.webSocket) {
            // No need to add CORS headers for WS.
            return response;
        }

        const newHeaders = new Headers(response.headers);
        newHeaders.set('Access-Control-Allow-Origin', '*');

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders,
        });
    }());
});

// Maximum number of bytes to generate for bytes and range endpoints.
const MAX_BYTES = 10 * 1024 * 1024;

async function handleRequest(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    switch (true) {
        case request.method === 'OPTIONS':
            return serveOptions();
        case path === "/":
            return serveAvailableMethods();
        case path.startsWith('/absolute-redirect/'):
            return absoluteRedirect(path, url);
        case path.startsWith('/anything'):
            return anythingResponse(request);
        case path.startsWith('/base64/decode/'):
            return decodeBase64(path);
        case path.startsWith('/base64/encode/'):
            return encodeBase64(path);
        case path.startsWith('/basic-auth/'):
            return challengeBasicAuth(request, path);
        case path.startsWith('/bytes/'):
            return generateRandomBytes(path, url);
        case path === '/cache':
            return checkCacheHeaders(request);
        case path.startsWith('/cache/'):
            return setCacheControl(request, path);
        case path === '/cookies':
            return getCookies(request);
        case path.startsWith('/cookies/delete'):
            return deleteCookies(request, url);
        case path.startsWith('/cookies/set'):
            return setCookies(request, url);
        case path.startsWith('/delay/'):
            return delayResponse(path);
        case path === '/delete':
            return handleDelete(request);
        case path === '/forms/post':
            return renderHtmlForm();
        case path === '/get':
            return handleGet(request);
        case path === '/head':
            return handleHead(request);
        case path === '/headers':
            return getHeaders(request);
        case path === '/html':
            return renderHTMLPage();
        case path === '/hostname':
            return getHostname(request);
        case path === '/image':
            return serveImageBasedOnHeader(request);
        case path === '/image/jpeg':
            return serveJpegImage();
        case path === '/image/png':
            return servePngImage();
        case path === '/image/svg':
            return serveSvgImage();
        case path === '/image/webp':
            return serveWebpImage();
        case path === '/ip':
            return getIp(request);
        case path === '/json':
            return serveJSON();
        case path.startsWith('/json/'):
            return serveJSONValue(path);
        case path.startsWith('/links/'):
            return serveLinks(path);
        case path === '/patch':
            return handlePatch(request);
        case path === '/post':
            return handlePost(request);
        case path === '/put':
            return handlePut(request);
        case path.startsWith('/range/'):
            return serveRange(path, request);
        case path.startsWith('/redirect-to'):
            return serveRedirectTo(url.searchParams);
        case path.startsWith('/redirect/'):
            return serveMultipleRedirects(path);
        case path.startsWith('/relative-redirect/'):
            return serveRelativeRedirects(path, url);
        case path.startsWith('/response-headers'):
            return serveResponseHeaders(url.searchParams);
        case path.startsWith('/status/'):
            return serveStatus(path);
        case path.startsWith('/status-no-response/'):
            return serveStatusNoResponse(path);
        case path === '/user-agent':
            return getUserAgent(request);
        case path === '/ws':
            return serveWs(request);
        case path === '/xml':
            return serveXML();
        case path.startsWith('/xml/'):
            return serveXMLValue(path);
        default:
            return new Response('Endpoint not found', { status: 404 });
    }
}

function serveOptions() {
    return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Methods': 'GET, POST, HEAD, PATCH, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*',
    } });
}

function serveAvailableMethods() {
    const htmlContent = `<!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HTTPBin Cloudflare Worker</title>

        <style type="text/css">
            /*!
            * Writ v1.0.4
            *
            * Copyright © 2015, Curtis McEnroe <curtis@cmcenroe.me>
            *
            * https://cmcenroe.me/writ/LICENSE (ISC)
            */dd,hr,ol ol,ol ul,ul ol,ul ul{margin:0}pre,table{overflow-x:auto}a,ins{text-decoration:none}html{font-family:Palatino,Georgia,Lucida Bright,Book Antiqua,serif;font-size:16px;line-height:1.5rem}code,kbd,pre,samp{font-family:Consolas,Liberation Mono,Menlo,Courier,monospace;font-size:.833rem;color:#111}kbd{font-weight:700}h1,h2,h3,h4,h5,h6,th{font-weight:400}h1{font-size:2.488em}h2{font-size:2.074em}h3{font-size:1.728em}h4{font-size:1.44em}h5{font-size:1.2em}h6{font-size:1em}small{font-size:.833em}h1,h2,h3{line-height:3rem}blockquote,dl,h1,h2,h3,h4,h5,h6,ol,p,pre,table,ul{margin:1.5rem 0 0}pre,table{margin-bottom:-1px}hr{border:none;padding:1.5rem 0 0}table{line-height:calc(1.5rem - 1px);width:100%;border-collapse:collapse}pre{margin-top:calc(1.5rem - 1px)}body{color:#222;margin:1.5rem 1ch}a,a code,header nav a:visited{color:#00e}a:visited,a:visited code{color:#60b}mark{color:inherit;background-color:#fe0}code,pre,samp,tfoot,thead{background-color:rgba(0,0,0,.05)}blockquote,ins,main aside{border:rgba(0,0,0,.05) solid}blockquote,main aside{border-width:0 0 0 .5ch}code,pre,samp{border:rgba(0,0,0,.1) solid}td,th{border:solid #dbdbdb}body>header{text-align:center}body>footer,main{display:block;max-width:78ch;margin:auto}main aside,main figure{float:right;margin:1.5rem 0 0 1ch}main aside{max-width:26ch;padding:0 0 0 .5ch}blockquote{margin-right:3ch;margin-left:1.5ch;padding:0 0 0 1ch}pre{border-width:1px;border-radius:2px;padding:0 .5ch}pre code{border:none;padding:0;background-color:transparent;white-space:inherit}code,ins,samp,td,th{border-width:1px}img{max-width:100%}dd,ol,ul{padding:0 0 0 3ch}ul>li{list-style-type:disc}li ul>li{list-style-type:circle}li li ul>li{list-style-type:square}ol>li{list-style-type:decimal}li ol>li{list-style-type:lower-roman}li li ol>li{list-style-type:lower-alpha}nav ul{padding:0;list-style-type:none}nav ul li{display:inline;padding-left:1ch;white-space:nowrap}nav ul li:first-child{padding-left:0}ins,mark{padding:1px}td,th{padding:0 .5ch}sub,sup{font-size:.75em;line-height:1em}code,samp{border-radius:2px;padding:.1em .2em;white-space:nowrap}
        </style>
    </head>

    <body>
        <header>
            <h1>HTTPBin</h1>
            <p>
                Cloudflare Worker version.
            </p>

            <nav>
                <ul>
                    <li><a href="https://adguard.com/">Made by AdGuard</a></li>
                    <li><a href="https://github.com/AdguardTeam/HttpBin">Github Repo</a></li>
                </ul>
            </nav>
        </header>

        <main>
            <h2>What is it?</h2>

            <p>
                This is a Cloudflare Worker port of httpbin.org HTTP request & response testing service.
            </p>

            <h3>Endpoints</h3>
            <ul>
                <li><a href="absolute-redirect/2">/absolute-redirect/:n</a> - Absolute redirects n times.</li>
                <li><a href="anything/test">/anything/:anything</a> - Returns anything that is passed to request.</li>
                <li><a href="base64/decode/aGVsbG8gd29ybGQ=">/base64/decode/:value</a> - Decodes a Base64 encoded string.
                </li>
                <li><a href="base64/encode/hello%20world">/base64/encode/:value</a> - Encodes a string into Base64.</li>
                <li><a href="basic-auth/admin/password">/basic-auth/:user/:passwd</a> - Challenges HTTPBasic Auth.</li>
                <li><a href="bytes/1024?seed=5">/bytes/:n</a> - Generates n random bytes of binary data, accepts optional
                    seed
                    integer parameter.</li>
                <li><a href="cache">/cache</a> - Returns 200 unless an If-Modified-Since or If-None-Match header is
                    provided,
                    when it returns a 304.</li>
                <li><a href="cache/60">/cache/:n</a> - Sets a Cache-Control header for n seconds.</li>
                <li><a href="cookies">/cookies</a> - Returns cookie data.</li>
                <li><a href="cookies/set?k1=v1&k2=v2">/cookies/set?name=value</a> - Sets one or more simple cookies.</li>
                <li><a href="cookies/delete?k1=&k2=">/cookies/delete?name</a> - Deletes one or more simple cookies.</li>
                <li><a href="delay/5">/delay/:n</a> - Delays responding for min(n, 10) seconds.</li>
                <li><a href="delete">/delete</a> - Returns request data. Allows only DELETE requests.</li>
                <li><a href="forms/post">/forms/post</a> - HTML form that submits to /post.</li>
                <li><a href="get">/get</a> - Returns request data. Allows only GET requests.</li>
                <li><a href="head">/head</a> - Returns request data. Allows only HEAD requests.</li>
                <li><a href="headers">/headers</a> - Returns request header dict.</li>
                <li><a href="html">/html</a> - Renders an HTML Page.</li>
                <li><a href="hostname">/hostname</a> - Returns the name of the host serving the request.</li>
                <li><a href="image">/image</a> - Returns page containing an image based on sent Accept header.</li>
                <li><a href="image/jpeg">/image/jpeg</a> - Returns a JPEG image.</li>
                <li><a href="image/png">/image/png</a> - Returns a PNG image.</li>
                <li><a href="image/svg">/image/svg</a> - Returns a SVG image.</li>
                <li><a href="image/webp">/image/webp</a> - Returns a WEBP image.</li>
                <li><a href="ip">/ip</a> - Returns Origin IP.</li>
                <li><a href="json">/json</a> - Returns JSON.</li>
                <li><a href="json/%7B%22test%22%3A1%7D">/json/:value</a> - Returns the specified JSON..</li>
                <li><a href="links/:n">/links/:n</a> - Returns page containing n HTML links.</li>
                <li><a href="patch">/patch</a> - Returns request data. Allows only PATCH requests.</li>
                <li><a href="post">/post</a> - Returns request data. Allows only POST requests.</li>
                <li><a href="put">/put</a> - Returns request data. Allows only PUT requests.</li>
                <li><a href="range/1024">/range/:n</a> - Streams n bytes, and allows specifying a Range header to select a
                    subset of the data.</li>
                <li><a
                        href="redirect-to?status_code=307&url=http%3A%2F%2Fexample.com%2F">/redirect-to?url=foo&status_code=307</a>
                    - Redirects to the foo URL.</li>
                <li><a href="redirect-to?url=http%3A%2F%2Fexample.com%2F">/redirect-to?url=foo</a> - 302 Redirects to the
                    foo
                    URL.</li>
                <li><a href="redirect/3">/redirect/:n</a> - 302 Redirects n times.</li>
                <li><a
                        href="response-headers?Servername=httpbin&Content-Type=text%2Fplain%3B+charset%3DUTF-8">/response-headers?key=val</a>
                    - Returns given response headers.</li>
                <li><a href="status/200">/status/:code</a> - Returns given HTTP Status code.</li>
                <li><a href="status-no-response/200">/status-no-response/:code</a> - Returns given HTTP Status code with empty body.</li>
                <li><a href="user-agent">/user-agent</a> - Returns user-agent.</li>
                <li><a href="ws">/ws</a> - Creates connection with websocket echo server. Allows only requests with upgrade header.</li>
                <li><a href="xml">/xml</a> - Returns some XML.</li>
                <li><a href="xml/%3Ctest%2F%3E">/xml/:value</a> - Returns some XML.</li>
            </ul>
        </main>
    </body>

    </html>
    `;

    return new Response(htmlContent, {
        headers: {
            'Content-Type': 'text/html'
        }
    });
}

function getIp(request) {
    const ip = request.headers.get('cf-connecting-ip');
    const responseBody = {
        origin: ip || 'unknown',
    };
    return new Response(JSON.stringify(responseBody), {
        headers: { 'Content-Type': 'application/json' },
    });
}

function getHeaders(request) {
    const headersObj = {};
    for (const [key, value] of request.headers) {
        headersObj[key] = value;
    }
    return new Response(JSON.stringify(headersObj), {
        headers: { 'Content-Type': 'application/json' },
    });
}

function getUserAgent(request) {
    const userAgent = request.headers.get('user-agent');
    const responseBody = {
        'user-agent': userAgent || 'unknown',
    };
    return new Response(JSON.stringify(responseBody), {
        headers: { 'Content-Type': 'application/json' },
    });
}

function checkCacheHeaders(request) {
    if (request.headers.get('If-Modified-Since') || request.headers.get('If-None-Match')) {
        return new Response(null, { status: 304 });
    }
    return new Response('Cache Endpoint');
}

function setCacheControl(request, path) {
    const seconds = parseInt(path.split('/').pop(), 10);
    if (isNaN(seconds)) {
        return new Response('Invalid cache time', { status: 400 });
    }
    return new Response('Cache-Control set', {
        headers: { 'Cache-Control': `public, max-age=${seconds}` },
    });
}

function getCookies(request) {
    const cookies = request.headers.get('Cookie');
    const cookiesObj = {};
    if (cookies) {
        cookies.split(';').forEach(cookie => {
            const [name, value] = cookie.trim().split('=');
            cookiesObj[name] = decodeURIComponent(value);
        });
    }
    return new Response(JSON.stringify(cookiesObj), {
        headers: { 'Content-Type': 'application/json' },
    });
}

function deleteCookies(request, url) {
    const searchParams = url.searchParams;
    const cookiesToDelete = [];
    for (const key of searchParams.keys()) {
        cookiesToDelete.push(key);
    }

    const responseHeaders = new Headers();
    cookiesToDelete.forEach(cookieName => {
        responseHeaders.append('Set-Cookie', `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`);
    });

    return new Response(`Cookies deleted: ${cookiesToDelete.join(',')}`, { headers: responseHeaders });
}

function setCookies(request, url) {
    const searchParams = url.searchParams;
    const responseHeaders = new Headers();

    for (const [key, value] of searchParams.entries()) {
        responseHeaders.append('Set-Cookie', `${key}=${encodeURIComponent(value)}; path=/`);
    }

    return new Response('Cookies set', { headers: responseHeaders });
}

function absoluteRedirect(path, url) {
    const numRedirects = parseInt(path.split('/').pop(), 10);
    if (isNaN(numRedirects) || numRedirects < 0) {
        return new Response('Invalid number of redirects', { status: 400 });
    }
    if (numRedirects === 0) {
        return new Response('Final redirect reached');
    }
    const newLocation = `${url.origin}/absolute-redirect/${numRedirects - 1}`;
    return new Response(null, {
        status: 302,
        headers: {
            'Location': newLocation
        }
    });
}

// Updated anythingResponse function to accept request object and return a detailed response
async function anythingResponse(request) {
    if (!request || !request.url) {
        return new Response('Invalid request URL', { status: 400 });
    }

    let url;
    try {
        url = new URL(request.url);
    } catch (e) {
        return new Response('Invalid URL string', { status: 400 });
    }

    const method = request.method;

    // Maintaining the case of header keys
    const headers = {};
    for (let [key, value] of request.headers.entries()) {
        headers[key.charAt(0).toUpperCase() + key.slice(1)] = [value];
    }

    const queryParams = Array.from(url.searchParams.entries()).reduce((acc, [key, value]) => {
        acc[key] = [value];
        return acc;
    }, {});

    let body = null;
    if (method === "POST") {
        body = await request.text();
    }

    const responseObj = {
        args: queryParams,
        headers: headers,
        method: method,
        origin: headers['X-Forwarded-For'] ? headers['X-Forwarded-For'][0].split(',')[0] : "", // Using the first IP in X-Forwarded-For header as origin
        url: request.url,
        data: body,
        files: {},
        form: {},
        json: null
    };

    return new Response(JSON.stringify(responseObj, null, 2), {
        headers: { 'Content-Type': 'application/json' },
    });
}

function decodeBase64(path) {
    try {
        const encodedValue = decodeURIComponent(path.split('/').pop());
        const decodedValue = atob(encodedValue);
        return new Response(decodedValue, {
            headers: { 'Content-Type': 'text/plain' },
        });
    } catch (err) {
        return new Response('Error decoding base64', { status: 400 });
    }
}

function encodeBase64(path) {
    try {
        const value = decodeURIComponent(path.split('/').pop());
        const encodedValue = btoa(value);
        return new Response(encodedValue, {
            headers: { 'Content-Type': 'text/plain' },
        });
    } catch (err) {
        return new Response('Error encoding to base64', { status: 400 });
    }
}

function challengeBasicAuth(request, path) {
    const [_, __, user, passwd] = path.split('/');
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return new Response('Unauthorized', {
            status: 401,
            headers: {
                'WWW-Authenticate': 'Basic realm="Secure Area"'
            }
        });
    }
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = atob(base64Credentials).split(':');
    if (credentials[0] === user && credentials[1] === passwd) {
        return new Response('Authorized');
    }

    return new Response(`Unauthorized, expected ${user}:${passwd}, got ${credentials[0]}:${credentials[1]}`, { status: 401 });
}

function generateRandomBytes(path, url) {
    const numBytes = parseInt(path.split('/').pop(), 10);
    if (isNaN(numBytes) || numBytes <= 0) {
        return new Response('Invalid number of bytes', { status: 400 });
    }

    if (numBytes > MAX_BYTES) {
        return new Response('Number of bytes exceeds the limit', { status: 400 });
    }

    const seedParam = url.searchParams.get('seed');
    const seed = seedParam ? parseInt(seedParam, 10) : Math.random() * 1000;

    const randomBytes = generateBytesWithSeed(numBytes, seed);
    return new Response(randomBytes, {
        headers: { 'Content-Type': 'application/octet-stream' },
    });
}

function generateBytesWithSeed(length, seed) {
    const result = new Uint8Array(length);
    let s = seed;
    for (let i = 0; i < length; i++) {
        s = (s * 16807) % 2147483647;
        result[i] = s % 256;
    }
    return result;
}

async function delayResponse(path) {
    const delayTime = parseInt(path.split('/').pop(), 10);
    const actualDelay = Math.min(isNaN(delayTime) ? 0 : delayTime, 10);
    await sleep(actualDelay * 1000);
    return new Response(`Delayed for ${actualDelay} seconds`, { status: 200 });
}

function handleDelete(request) {
    if (request.method !== 'DELETE') {
        return new Response('Only DELETE method is allowed', { status: 405 });
    }
    return new Response(JSON.stringify({
        method: request.method,
        headers: [...request.headers]
    }), {
        headers: { 'Content-Type': 'application/json' }
    });
}

function renderHtmlForm() {
    const html = `
      <form action="/post" method="post">
        <input type="text" name="sampleInput" placeholder="Enter something...">
        <input type="submit" value="Submit">
      </form>
    `;
    return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function handleGet(request) {
    if (request.method !== 'GET' && request.method !== 'POST') {
        return new Response('Only GET method is allowed', { status: 405 });
    }
    return returnRequestData(request);
}

function handleHead(request) {
    if (request.method !== 'HEAD') {
        return new Response('Only HEAD method is allowed', { status: 405 });
    }
    return new Response(null, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain'
        }
    });
}

function handlePatch(request) {
    if (request.method !== 'PATCH') {
        return new Response('Only PATCH method is allowed', { status: 405 });
    }
    return returnRequestData(request);
}

function handlePost(request) {
    if (request.method !== 'POST') {
        return new Response('Only POST method is allowed', { status: 405 });
    }
    return returnRequestData(request);
}

function handlePut(request) {
    if (request.method !== 'PUT') {
        return new Response('Only PUT method is allowed', { status: 405 });
    }
    return returnRequestData(request);
}

async function returnRequestData(request) {
    const body = await request.text();
    const headers = [...request.headers].filter(([key]) => !key.startsWith('cf-'));
    const ip = request.headers.get('cf-connecting-ip');
    const country = request.headers.get('cf-ipcountry');
    const resJson = JSON.stringify({
        headers: headers,
        method: request.method,
        url: request.url,
        ip: ip,
        country: country,
        body: body,
        cf: request.cf
    }, 0, 4);
    console.log(resJson);
    const url = new URL(request.url)
    const chl = url.searchParams.get('hub.challenge')
    return new Response(chl, {
        headers: { 'Content-Type': 'text/plain' }
    });
}

function renderHTMLPage() {
    const html = `
      <html>
        <head><title>Sample HTML Page</title></head>
        <body><h1>Welcome to the Sample Page!</h1></body>
      </html>
    `;
    return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

function getHostname(request) {
    const hostname = new URL(request.url).hostname;
    return new Response(hostname, { headers: { 'Content-Type': 'text/plain' } });
}

function serveImageBasedOnHeader(request) {
    const acceptHeader = request.headers.get('Accept');
    if (acceptHeader.includes('image/jpeg')) {
        return serveJpegImage();
    } else if (acceptHeader.includes('image/png')) {
        return servePngImage();
    } else if (acceptHeader.includes('image/svg+xml')) {
        return serveSvgImage();
    } else if (acceptHeader.includes('image/webp')) {
        return serveWebpImage();
    } else {
        return new Response('Unsupported image format', { status: 415 });
    }
}

function serveJpegImage() {
    const base64JPEG = '/9j/4AAQSkZJRgABAQAAZABkAAD/2wCEABQQEBkSGScXFycyJh8mMi4mJiYmLj41NTU1NT5EQUFBQUFBREREREREREREREREREREREREREREREREREREREQBFRkZIBwgJhgYJjYmICY2RDYrKzZERERCNUJERERERERERERERERERERERERERERERERERERERERERERERERERP/AABEIAAEAAQMBIgACEQEDEQH/xABMAAEBAAAAAAAAAAAAAAAAAAAABQEBAQAAAAAAAAAAAAAAAAAABQYQAQAAAAAAAAAAAAAAAAAAAAARAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AJQA9Yv/2Q==';  // Your Base64 encoded JPEG goes here

    // Decode Base64 to binary
    const binary = atob(base64JPEG);

    // Convert binary to UInt8Array
    const uint8Array = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        uint8Array[i] = binary.charCodeAt(i);
    }

    return new Response(uint8Array.buffer, { headers: { 'Content-Type': 'image/jpeg' } });
}

function servePngImage() {
    const base64PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/wcAAwAB/6o06a0AAAAASUVORK5CYII=';

    // Decode Base64 to binary
    const binary = atob(base64PNG);

    // Convert binary to UInt8Array
    const uint8Array = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        uint8Array[i] = binary.charCodeAt(i);
    }

    return new Response(uint8Array.buffer, { headers: { 'Content-Type': 'image/png' } });
}

function serveSvgImage() {
    const svg = `
      <svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
        <circle cx="50" cy="50" r="40" stroke="black" stroke-width="3" fill="red" />
      </svg>
    `;
    return new Response(svg, { headers: { 'Content-Type': 'image/svg+xml' } });
}

function serveWebpImage() {
    const base64WEBP = 'UklGRhIAAABXRUJQVlA4IBwAAAAwAQCdASoBAAEAAwA0JaQAA3AA/v7lpTDyAAAA';

    // Decode Base64 to binary
    const binary = atob(base64WEBP);

    // Convert binary to UInt8Array
    const uint8Array = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        uint8Array[i] = binary.charCodeAt(i);
    }

    return new Response(uint8Array.buffer, { headers: { 'Content-Type': 'image/webp' } });
}

function serveJSON() {
    const data = {
        message: "This is a simple JSON response.",
        status: "success"
    };
    return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
}

function serveJSONValue(path) {
    const value = decodeURIComponent(path.split('/')[2]);
    if (!value) {
        return new Response('Invalid value', { status: 400 });
    }
    try {
        const jsonObject = JSON.parse(value);
        return new Response(JSON.stringify(jsonObject), {
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err) {
        return new Response(`Invalid JSON format: ${value}`, { status: 400 });
    }
}


function serveLinks(path) {
    const n = parseInt(path.split('/')[2]);
    if (isNaN(n)) {
        return new Response('Invalid number', { status: 400 });
    }

    let linksHTML = '<html><body>';
    for (let i = 0; i < n; i++) {
        linksHTML += `<a href="#link${i}">Link ${i}</a><br>`;
    }
    linksHTML += '</body></html>';
    return new Response(linksHTML, { headers: { 'Content-Type': 'text/html' } });
}

function serveRange(path, request) {
    const n = parseInt(path.split('/')[2]);
    if (isNaN(n)) {
        return new Response('Invalid number', { status: 400 });
    }

    // This example assumes ASCII text data, for simplicity
    if (n > MAX_BYTES) {
        return new Response('Number of bytes exceeds the limit', { status: 400 });
    }

    const data = "a".repeat(n);

    const rangeHeader = request.headers.get("Range");
    if (rangeHeader) {
        const match = rangeHeader.match(/bytes=(\d+)-(\d+)?/);
        if (match) {
            const start = parseInt(match[1]);
            const end = match[2] ? parseInt(match[2]) : data.length - 1;

            // Provide Content-Range header and 206 status for partial content
            const headers = {
                'Content-Range': `bytes ${start}-${end}/${data.length}`
            };

            return new Response(data.slice(start, end + 1), {
                status: 206,
                headers: headers
            });
        }
    }

    return new Response(data);
}

function serveRedirectTo(params) {
    const redirectUrl = params.get('url');
    const statusCode = params.get('status_code') || 302;

    if (!redirectUrl) {
        return new Response('URL parameter is missing', { status: 400 });
    }

    return new Response('', {
        status: statusCode,
        headers: { 'Location': redirectUrl }
    });
}

function serveMultipleRedirects(path) {
    const n = parseInt(path.split('/')[2]);

    if (isNaN(n) || n < 0) {
        return new Response('Invalid redirect count', { status: 400 });
    }

    if (n === 0) {
        return new Response('Final Redirect', { status: 200 });
    }

    const nextRedirect = `/redirect/${n - 1}`;
    return new Response('', {
        status: 302,
        headers: { 'Location': nextRedirect }
    });
}

function serveRelativeRedirects(path, url) {
    const n = parseInt(path.split('/')[2]);

    if (isNaN(n) || n < 0) {
        return new Response('Invalid redirect count', { status: 400 });
    }

    if (n === 0) {
        return new Response('Final Redirect', { status: 200 });
    }

    const nextRedirect = `/relative-redirect/${n - 1}`;
    return new Response('', {
        status: 302,
        headers: { 'Location': nextRedirect }
    });
}

function serveResponseHeaders(params) {
    const headers = {};

    for (const [key, value] of params.entries()) {
        headers[key] = value;
    }

    return new Response('Returning provided headers', {
        headers: headers
    });
}

function serveStatus(path) {
    const code = parseInt(path.split('/')[2]);

    if (isNaN(code)) {
        return new Response('Invalid status code', { status: 400 });
    }

    return new Response(`Returning status ${code}`, { status: code });
}

function serveStatusNoResponse(path) {
    const code = parseInt(path.split('/')[2]);

    if (isNaN(code)) {
        return new Response('Invalid status code', { status: 400 });
    }

    return new Response(null, { status: code });
}

function serveWs(request) {
    const upgradeHeader = request.headers.get("Upgrade")
    if (upgradeHeader !== "websocket") {
        return new Response("Expected websocket", { status: 400 })
    }

    const [client, server] = Object.values(new WebSocketPair())

    server.accept()

    server.addEventListener("message", ({ data }) => {
        server.send(data);
    })

    return new Response(null, {
        status: 101,
        webSocket: client
    })
}

function serveXML() {
    const xmlData = `<?xml version="1.0"?>
    <note>
        <to>User</to>
        <from>Server</from>
        <heading>Reminder</heading>
        <body>Don't forget to study!</body>
    </note>`;

    return new Response(xmlData, {
        headers: { 'Content-Type': 'application/xml' }
    });
}

function serveXMLValue(path) {
    const value = path.split('/')[2];
    if (!value) {
        return new Response('Invalid value', { status: 400 });
    }
    const decodedValue = decodeURIComponent(value);

    return new Response(decodedValue, {
        headers: { 'Content-Type': 'application/xml' },
    });
}
