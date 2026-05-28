
async function scanWebsite() {

    const url = document.getElementById('urlInput').value;

    const logs = document.getElementById('logs');

    // =========================================
    // INITIAL LOGS
    // =========================================

    logs.innerHTML = `
        <p>[+] Initializing security scan...</p>
        <p>[+] Connecting to target...</p>
        <p>[+] Checking security headers...</p>
        <p>[+] Running vulnerability analysis...</p>
        <p>[+] Testing SQL Injection payloads...</p>
        <p>[+] Testing XSS payloads...</p>
    `;

    // =========================================
    // SCANNING SCREEN
    // =========================================

    document.getElementById('results').innerHTML = `
        <div class="flex flex-col justify-center items-center h-full">

            <div class="radar mb-10"></div>

            <div class="text-red-500 text-4xl scanning neon-red">
                SCANNING TARGET...
            </div>

        </div>
    `;

    // =========================================
    // FETCH REQUEST
    // =========================================

    const response = await fetch('/scan', {

        method: 'POST',

        headers: {
            'Content-Type': 'application/json'
        },

        body: JSON.stringify({ url })

    });

    const data = await response.json();

    // =========================================
    // SAVE DATA
    // =========================================

    window.latestScanData = data;

    // =========================================
    // ERROR HANDLING
    // =========================================

    if(data.error){

        document.getElementById('results').innerHTML = `
            <div class="bg-red-700 p-5 rounded-xl text-white text-xl">
                ERROR: ${data.error}
            </div>
        `;

        logs.innerHTML += `
            <p>[!] Scan failed</p>
        `;

        return;
    }

    // =========================================
    // UPDATE STATS
    // =========================================

    document.getElementById('threatScore').innerText =
        data.risk_score;

    document.getElementById('vulnCount').innerText =
        data.vulnerabilities.length;

    // =========================================
    // DYNAMIC PROGRESS BAR
    // =========================================

    const scoreBar = document.getElementById('scoreBar');

    scoreBar.style.width =
        data.risk_score + "%";

    scoreBar.classList.remove(
        "bg-green-400",
        "bg-yellow-400",
        "bg-red-500"
    );

    if(data.risk_score >= 70){

        scoreBar.classList.add("bg-red-500");

    }
    else if(data.risk_score >= 40){

        scoreBar.classList.add("bg-yellow-400");

    }
    else{

        scoreBar.classList.add("bg-green-400");
    }

    // =========================================
    // LOGS
    // =========================================

    logs.innerHTML += `
        <p>[✓] Scan completed successfully</p>
        <p>[✓] Threat score generated</p>
    `;

    // =========================================
    // MAIN REPORT
    // =========================================

    let html = `

        <h2 class="text-5xl font-black neon-red mb-8">
            Security Scan Report
        </h2>

        <!-- SUMMARY CARDS -->

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">

            <!-- TARGET -->

            <div class="glass p-6 rounded-3xl border border-red-500/30 vuln-card">

                <p class="text-gray-400 mb-3">
                    Target URL
                </p>

                <h3 class="text-lg font-bold break-all text-white">
                    ${data.url}
                </h3>

            </div>

            <!-- RISK LEVEL -->

            <div class="glass p-6 rounded-3xl border border-yellow-500/30 vuln-card">

                <p class="text-gray-400 mb-3">
                    Risk Level
                </p>

                <h3 class="text-4xl font-black text-yellow-400">
                    ${data.risk_level}
                </h3>

            </div>

            <!-- THREAT SCORE -->

            <div class="glass p-6 rounded-3xl border border-green-500/30 vuln-card">

                <p class="text-gray-400 mb-3">
                    Threat Score
                </p>

                <h3 class="text-4xl font-black text-green-400">
                    ${data.risk_score}/100
                </h3>

            </div>

        </div>

        <!-- DOWNLOAD BUTTON -->

        <div class="mb-8">

            <button
                onclick="downloadReport()"
                class="cyber-btn"
            >
                DOWNLOAD PDF REPORT
            </button>

        </div>

        <!-- RECOMMENDATIONS -->

        <div class="glass border border-green-500/30 rounded-3xl p-6 mb-10">

            <h3 class="text-3xl font-bold text-green-400 mb-5">
                Security Recommendations
            </h3>

    `;

    // =========================================
    // RECOMMENDATIONS LOOP
    // =========================================

    data.recommendations.forEach(rec => {

        html += `
            <div class="bg-black/40 border border-green-500/30 p-5 rounded-2xl mb-4 vuln-card">
                ${rec}
            </div>
        `;
    });

    html += `</div>`;

    // =========================================
    // VULNERABILITIES TITLE
    // =========================================

    html += `

        <h3 class="text-4xl font-black neon-red mb-8">
            Detected Vulnerabilities
        </h3>

    `;

    // =========================================
    // VULNERABILITY LOOP
    // =========================================

    data.vulnerabilities.forEach(vuln => {

        let color = "green";

        if(vuln.severity === "High" || vuln.severity === "HIGH"){
            color = "red";
        }
        else if(vuln.severity === "Medium" || vuln.severity === "MEDIUM"){
            color = "yellow";
        }

        logs.innerHTML += `
            <p>[!] ${vuln.type} detected</p>
        `;

        html += `

            <div class="vuln-card glass border border-${color}-500/30 rounded-3xl p-6 mb-6">

                <div class="flex justify-between items-center mb-4">

                    <h4 class="text-3xl font-bold text-${color}-400">
                        ${vuln.type}
                    </h4>

                    <span class="px-5 py-2 rounded-full bg-${color}-500 text-white font-bold">
                        ${vuln.severity}
                    </span>

                </div>

                <p class="text-gray-300 text-lg">
                    ${vuln.description}
                </p>

            </div>

        `;
    });

    // =========================================
    // FINAL OUTPUT
    // =========================================

    document.getElementById('results').innerHTML = html;
}

// =========================================
// PDF DOWNLOAD
// =========================================

async function downloadReport(){

    const response = await fetch('/generate_report', {

        method: 'POST',

        headers: {
            'Content-Type': 'application/json'
        },

        body: JSON.stringify(window.latestScanData)

    });

    const blob = await response.blob();

    const url = window.URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = 'security_report.pdf';

    a.click();
}

