async function scanWebsite() {

    const url =
        document.getElementById(
            "urlInput"
        ).value;

    if (!url) {

        alert(
            "Please enter a URL"
        );

        return;
    }

    const loading =
        document.getElementById(
            "loading"
        );

    const results =
        document.getElementById(
            "results"
        );

    loading.classList.remove(
        "hidden"
    );


    results.classList.add(
        "hidden"
    );

    try {

        const response =
            await fetch(
                "/scan",
                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                        "application/json"

                    },

                    body: JSON.stringify({

                        url: url

                    })

                }
            );

        const data =
            await response.json();

        loading.classList.add(
            "hidden"
        );

        results.classList.remove(
    "hidden"
);

document
.getElementById(
    "gradingPanel"
)
.classList.remove(
    "hidden"
);

        if (data.error) {

            alert(data.error);

            return;
        }

        /* =====================
           SCORE CARDS
        ===================== */

        document.getElementById(
            "riskScore"
        ).innerText =
            data.risk_score;

        document.getElementById(
            "attackSurface"
        ).innerText =
            data.attack_surface;

        document.getElementById(
            "securityScore"
        ).innerText =
            `${data.headers_score}/5`;

        let grade = "F";

        if (data.headers_score === 5)
            grade = "A+";

        else if (data.headers_score === 4)
            grade = "A";

        else if (data.headers_score === 3)
            grade = "B";

        else if (data.headers_score === 2)
            grade = "C";

        else if (data.headers_score === 1)
            grade = "D";

        document.getElementById(
            "securityGrade"
        ).innerText =
            grade;
        document.getElementById(
    "gradingContent"
).innerHTML =

`
<div class="header-item">

    <h3>

        Security Assessment Summary

    </h3>

    <br>

    <strong>Security Grade:</strong>

    ${grade}

    <br><br>

    <strong>Risk Level:</strong>

    ${data.risk_level}

    <br><br>

    <strong>Risk Score:</strong>

    ${data.risk_score}

    <br><br>

    <strong>Security Posture:</strong>

    ${data.security_posture}%

    <br><br>

    <strong>Assessment:</strong>

    <br><br>

    This website was evaluated based on:

    <ul>

        <li>Security Headers</li>

        <li>Open Ports</li>

        <li>Attack Surface</li>

        <li>Detected Vulnerabilities</li>

        <li>Overall Security Posture</li>

    </ul>

</div>
`;

        /* =====================
           RISK LEVEL
        ===================== */

        const riskElement =
            document.getElementById(
                "riskLevel"
            );

        riskElement.innerText =
            data.risk_level;

        riskElement.className = "";

        if (
            data.risk_level ===
            "HIGH"
        ) {

            riskElement.classList.add(
                "high-risk"
            );

        }

        else if (
            data.risk_level ===
            "MEDIUM"
        ) {

            riskElement.classList.add(
                "medium-risk"
            );

        }

        else {

            riskElement.classList.add(
                "low-risk"
            );

        }

        /* =====================
           EXECUTIVE OVERVIEW
        ===================== */

        document.getElementById(
            "highCount"
        ).innerText =
            data.high_count;

        document.getElementById(
            "mediumCount"
        ).innerText =
            data.medium_count;

        document.getElementById(
            "lowCount"
        ).innerText =
            data.low_count;

        document.getElementById(
            "securityPosture"
        ).innerText =
            data.security_posture +
            "%";

        /* =====================
           SCAN INFO
        ===================== */

        document.getElementById(
            "scanInfo"
        ).innerHTML =

        `
        <div class="info-box">

            <strong>
            Target URL
            </strong>

            <br><br>

            ${data.url}

        </div>

        <div class="info-box">

            <strong>
            Scan Date
            </strong>

            <br><br>

            ${data.scan_date}

        </div>

        <div class="info-box">

            <strong>
            Scan Duration
            </strong>

            <br><br>

            ${data.scan_time}

        </div>

        <div class="info-box">

            <strong>
            Forms Detected
            </strong>

            <br><br>

            ${data.forms_count}

        </div>
        `;

        /* =====================
           AI ASSESSMENT
        ===================== */

        document.getElementById(
            "aiAssessment"
        ).innerHTML =

        `
        <div class="ai-card">

            <h3>

            Executive Summary

            </h3>

            <br>

            <p>

            ${data.ai_assessment}

            </p>

            <br>

            <ul>

                <li>
                Risk Level:
                ${data.risk_level}
                </li>

                <li>
                Security Posture:
                ${data.security_posture}%
                </li>

                <li>
                Open Ports:
                ${data.open_ports.length}
                </li>

                <li>
                Security Headers:
                ${data.headers_score}/5
                </li>

            </ul>

        </div>
        `;

        /* =====================
           TECHNOLOGIES
        ===================== */

        let techHtml = "";

        if (
            data.technologies.length === 0
        ) {

            techHtml =

            `
            <div class="header-item">

                No technologies detected

            </div>
            `;

        }

        else {

            data.technologies.forEach(
                tech => {

                techHtml +=

                `
                <span class="tag">

                    ${tech}

                </span>
                `;

            });

        }

        document.getElementById(
            "technologySection"
        ).innerHTML =
            techHtml;

        /* =====================
           PORTS
        ===================== */

        let portHtml = "";

        if (
            data.open_ports.length === 0
        ) {

            portHtml =

            `
            <div class="header-item">

                No open ports detected

            </div>
            `;

        }

        else {

            data.open_ports.forEach(
                port => {

                portHtml +=

                `
                <span class="tag">

                    Port ${port}

                </span>
                `;

            });

        }

        document.getElementById(
            "portsSection"
        ).innerHTML =
            portHtml;

        /* =====================
           HEADERS
        ===================== */

        let headerHtml = "";

        for (
            const header
            in data.headers
        ) {

            const status =
                data.headers[
                    header
                ];

            headerHtml +=

            `
            <div class="header-item">

                <strong>

                ${header}

                </strong>

                <br><br>

                ${
                    status

                    ?

                    "✅ Present"

                    :

                    "❌ Missing"
                }

            </div>
            `;
        }

        document.getElementById(
            "headersSection"
        ).innerHTML =
            headerHtml;

        /* =====================
           VULNERABILITIES
        ===================== */

        let vulnHtml = "";

        if (
            data.vulnerabilities.length === 0
        ) {

            vulnHtml =

            `
            <div class="recommendation">

                No vulnerabilities found

            </div>
            `;

        }

        else {

            data.vulnerabilities.forEach(
                vuln => {

                let color =
                    "#f59e0b";

                if (
                    vuln.severity ===
                    "High"
                ) {

                    color =
                    "#ef4444";
                }

                vulnHtml +=

                `
                <div class="vuln-card">

                    <h3>

                    ${vuln.type}

                    </h3>

                    <br>

                    <span
                    style="
                    background:${color};
                    color:white;
                    padding:6px 12px;
                    border-radius:20px;
                    font-size:12px;
                    ">

                    ${vuln.severity}

                    </span>

                    <br><br>

                    <p>

                    ${vuln.description}

                    </p>

                </div>
                `;

            });

        }

        document.getElementById(
            "vulnerabilitySection"
        ).innerHTML =
            vulnHtml;

        /* =====================
           RECOMMENDATIONS
        ===================== */

        let recHtml = "";

        if (
            data.recommendations.length === 0
        ) {

            recHtml =

            `
            <div class="header-item">

                No recommendations generated

            </div>
            `;

        }

        else {

            data.recommendations.forEach(
                rec => {

                recHtml +=

                `
                <div class="recommendation">

                    ✔ ${rec}

                </div>
                `;

            });

        }

        document.getElementById(
            "recommendationSection"
        ).innerHTML =
            recHtml;

        /* =====================
           TERMINAL LOGS
        ===================== */

        document.getElementById(
            "logs"
        ).innerHTML =

        `
        [+] Target Loaded<br>
        [+] Security Header Analysis Complete<br>
        [+] Technology Detection Complete<br>
        [+] Form Enumeration Complete<br>
        [+] Open Port Scan Complete<br>
        [+] SQL Injection Testing Complete<br>
        [+] XSS Testing Complete<br>
        [+] Risk Assessment Generated<br>
        [+] Recommendations Generated<br>
        [✓] Security Scan Completed Successfully
        `;

    }

    catch (error) {

        loading.classList.add(
            "hidden"
        );

        alert(
            "Scan failed: " +
            error
        );
    }
}


function showDashboard(){

    window.scrollTo({

        top:0,

        behavior:"smooth"

    });

}

function scrollToSection(id){

    const section =
        document.getElementById(id);

    if(section){

        section.scrollIntoView({

            behavior:"smooth"

        });

    }

}