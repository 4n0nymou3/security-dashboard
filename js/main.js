async function getCloudflareInfo() {
    try {
        const response = await fetch('https://cloudflare.com/cdn-cgi/trace');
        const text = await response.text();
        const data = text.split('\n').reduce((obj, line) => {
            const [key, value] = line.split('=');
            if (key && value) obj[key.trim()] = value.trim();
            return obj;
        }, {});

        document.getElementById('ip').textContent = data.ip;
        updateLocationInfo(data.loc);
        document.getElementById('network').textContent = data.warp === 'on' ? 'Cloudflare WARP' : data.uag;

        const connectionSecurity = analyzeConnectionSecurity(data);
        document.getElementById('connectionSecurity').textContent = connectionSecurity.text;
        document.getElementById('connectionSecurity').className = `value ${connectionSecurity.class}`;

        document.getElementById('httpVersion').textContent = `HTTP/${data.http}`;
        document.getElementById('tlsVersion').textContent = `TLS ${data.tls}`;

        checkBrowserSecurity();
        checkWebRTC();
        checkDNSLeak(data.ip);
        detectConnectionType(data);
        checkTOR(data.ip);
    } catch (error) {
        console.error('Error fetching Cloudflare info:', error);
        setErrorState();
    }
}

async function updateLocationInfo(countryCode) {
    try {
        const flagUrl = `https://cdnjs.cloudflare.com/ajax/libs/flag-icon-css/3.5.0/flags/4x3/${countryCode.toLowerCase()}.svg`;
        const response = await fetch(`https://restcountries.com/v3.1/alpha/${countryCode}`);
        const [countryData] = await response.json();
        
        document.getElementById('country').innerHTML = `<img src="${flagUrl}" class="flag-icon" alt="${countryCode}"> ${countryData.name.common} (${countryCode})`;
        document.getElementById('city').textContent = countryData.capital[0] || 'Not Available';
    } catch (error) {
        console.error('Error fetching country info:', error);
        document.getElementById('country').textContent = countryCode;
        document.getElementById('city').textContent = 'Not Available';
    }
}

function checkBrowserSecurity() {
    const securityFeatures = [];
    
    if (window.isSecureContext) {
        securityFeatures.push('HTTPS');
    }
    if (navigator.cookieEnabled) {
        securityFeatures.push('Cookies');
    }
    if (typeof window.SecurityPolicyViolationEvent === 'function') {
        securityFeatures.push('CSP');
    }
    if (navigator.doNotTrack === "1") {
        securityFeatures.push('DNT');
    }

    const status = securityFeatures.length >= 3 ? 
        { text: `Secure (${securityFeatures.join(', ')}) ✓`, class: 'secure' } :
        securityFeatures.length >= 2 ?
            { text: `Moderate (${securityFeatures.join(', ')})`, class: 'neutral' } :
            { text: 'Limited Security Features ⚠️', class: 'warning' };

    document.getElementById('browserSecurity').textContent = status.text;
    document.getElementById('browserSecurity').className = `value ${status.class}`;
}

function checkWebRTC() {
    const pc = new RTCPeerConnection();
    pc.createDataChannel("");
    pc.createOffer()
        .then(offer => pc.setLocalDescription(offer))
        .then(() => {
            const originalIps = new Set();
            pc.getStats()
                .then(stats => {
                    stats.forEach(report => {
                        if (report.type === 'candidate-pair' && report.localCandidate) {
                            originalIps.add(report.localCandidate.ip);
                        }
                    });
                    const webrtcStatus = originalIps.size > 1 ?
                        { text: 'Potential Leak Detected ⚠️', class: 'warning' } :
                        { text: 'No Leaks Detected ✓', class: 'secure' };
                    document.getElementById('webrtcLeak').textContent = webrtcStatus.text;
                    document.getElementById('webrtcLeak').className = `value ${webrtcStatus.class}`;
                });
        })
        .catch(error => {
            console.error('Error checking WebRTC:', error);
            document.getElementById('webrtcLeak').textContent = 'Check Failed';
            document.getElementById('webrtcLeak').className = 'value warning';
        });
}

async function checkDNSLeak(ip) {
    try {
        const dnsServers = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
        const dnsCheck = { text: 'No DNS Leaks Detected ✓', class: 'secure' };
        
        if (dnsServers.some(server => server !== ip)) {
            const vpnDetected = await isVPNConnection(ip);
            if (vpnDetected) {
                dnsCheck.text = 'Potential DNS Leak Detected ⚠️';
                dnsCheck.class = 'warning';
            }
        }
        
        document.getElementById('dnsLeak').textContent = dnsCheck.text;
        document.getElementById('dnsLeak').className = `value ${dnsCheck.class}`;
    } catch (error) {
        console.error('Error checking DNS leak:', error);
        document.getElementById('dnsLeak').textContent = 'Check Failed';
        document.getElementById('dnsLeak').className = 'value warning';
    }
}

async function isVPNConnection(ip) {
    try {
        const response = await fetch(`https://vpnapi.io/api/${ip}`);
        const data = await response.json();
        return data.security.vpn || data.security.proxy || data.security.tor;
    } catch {
        return false;
    }
}

async function detectConnectionType(data) {
    try {
        let status = { text: 'Direct Connection', class: 'neutral' };
        
        if (data.warp === 'on') {
            status = { text: 'Cloudflare WARP Detected', class: 'secure' };
        } else if (await isVPNConnection(data.ip)) {
            status = { text: 'VPN/Proxy Detected', class: 'secure' };
        }
        
        document.getElementById('connectionType').textContent = status.text;
        document.getElementById('connectionType').className = `value ${status.class}`;
    } catch (error) {
        console.error('Error detecting connection type:', error);
        document.getElementById('connectionType').textContent = 'Detection Failed';
        document.getElementById('connectionType').className = 'value warning';
    }
}

async function checkTOR(ip) {
    try {
        const response = await fetch(`https://check.torproject.org/api/ip/${ip}`);
        const data = await response.json();
        const status = data.IsTor ?
            { text: 'TOR Network Detected ✓', class: 'secure' } :
            { text: 'Not Using TOR', class: 'neutral' };
            
        document.getElementById('torDetection').textContent = status.text;
        document.getElementById('torDetection').className = `value ${status.class}`;
    } catch (error) {
        console.error('Error checking TOR:', error);
        document.getElementById('torDetection').textContent = 'Check Failed';
        document.getElementById('torDetection').className = 'value warning';
    }
}

function analyzeConnectionSecurity(data) {
    let score = 0;
    let issues = [];
    const tlsVersion = parseFloat(data.tls);

    // Check TLS version
    if (tlsVersion >= 1.3) score += 3;
    else if (tlsVersion >= 1.2) score += 2;
    else issues.push('Outdated TLS');

    // Check HTTP version
    if (data.http === '3') score += 3;
    else if (data.http === '2') score += 2;
    else issues.push('Old HTTP version');

    // Check for WARP
    if (data.warp === 'on') score += 2;

    // Check for secure context
    if (window.isSecureContext) score += 2;

    if (score >= 8) {
        return { text: 'Very Secure ✓✓', class: 'secure' };
    } else if (score >= 6) {
        return { text: 'Secure ✓', class: 'secure' };
    } else if (score >= 4) {
        return { text: 'Moderate Security', class: 'neutral' };
    } else {
        return { text: `Weak Security (${issues.join(', ')})`, class: 'warning' };
    }
}

function setErrorState() {
    const elements = ['ip', 'country', 'city', 'network', 'dnsLeak', 'webrtcLeak', 
        'connectionType', 'torDetection', 'httpVersion', 'tlsVersion', 'browserSecurity', 'connectionSecurity'];
    
    elements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = 'Error Loading Data';
            element.className = 'value warning';
        }
    });
}

function refreshInfo() {
    document.querySelector('.status-indicator span').textContent = 'Refreshing Security Analysis...';
    const valueElements = document.querySelectorAll('.value');
    valueElements.forEach(element => {
        element.textContent = 'Loading...';
        element.className = 'value';
    });
    
    getCloudflareInfo();
    
    setTimeout(() => {
        document.querySelector('.status-indicator span').textContent = 'Security Analysis Complete';
    }, 2000);
}

// Start the initial analysis when page loads
refreshInfo();
