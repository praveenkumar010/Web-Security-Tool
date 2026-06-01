async function scanWebsite() {

    const url =
        document.getElementById("urlInput").value;

    if (!url) {

        alert("Please enter a URL");

        return;
    }

    const loading =
        document.getElementById("loading");

    const results =
        document.getElementById("results");

    loading.classList.remove("hidden");

    results.classList.add("hidden");

    try {

        const response =
            await fetch("/scan", {

                method: "POST",

                headers: {
                    "Content-Type":
                    "application/json"
                },

                body: JSON.stringify({
                    url: url
                })

            });

        const data =
            await response.json();

        loading.classList.add("hidden");

        results.classList.remove("hidden");

        if (data.error) {

            alert(data.error);

            return;
        }

        // RISK SCORE

        document.getElementById(
            "riskScore"
        ).innerText =
            data.risk_score;

        const riskElement =
            document.getElementById(
                "riskLevel"
            );

        riskElement.innerText =
            data.risk_level;

        riskElement.className = "";

        if(data.risk_level === "HIGH"){

            riskElement.classList.add(
                "high-risk"
            );

        }
        else if(
            data.risk_level === "MEDIUM"
        ){

            riskElement.classList.add(
                "medium-risk"
            );

        }
        else{

            riskElement.classList.add(
                "low-risk"
            );

        }

        // ATTACK SURFACE

        document.getElementById(
            "attackSurface"
        ).innerText =
            data.attack_surface;

        // SECURITY SCORE

        document.getElementById(
            "securityScore"
        ).innerText =
            `${data.headers_score}/5`;

        // SECURITY GRADE

        let grade = "F";

        if(data.headers_score === 5)
            grade = "A+";

        else if(data.headers_score === 4)
            grade = "A";

        else if(data.headers_score === 3)
            grade = "B";

        else if(data.headers_score === 2)
            grade = "C";

        else if(data.headers_score === 1)
            grade = "D";

        document.getElementById(
            "securityGrade"
        ).innerText = grade;

        // AI ASSESSMENT

        document.getElementById(
            "aiAssessment"
        ).innerHTML =

        `<div class="ai-card">
            ${data.ai_assessment}
        </div>`;

        // TECHNOLOGIES

        let techHtml = "";

        data.technologies.forEach(
            tech => {

            techHtml +=
            `<span class="tag">
                ${tech}
            </span>`;

        });

        if(
            data.technologies.length === 0
        ){

            techHtml =
            "No technologies detected";
        }

        document.getElementById(
            "technologySection"
        ).innerHTML =
            techHtml;

        // PORTS

        let portHtml = "";

        data.open_ports.forEach(
            port => {

            portHtml +=
            `<span class="tag">
                ${port}
            </span>`;

        });

        if(
            data.open_ports.length === 0
        ){

            portHtml =
            "No open ports found";
        }

        document.getElementById(
            "portsSection"
        ).innerHTML =
            portHtml;

        // HEADERS

        let headerHtml = "";

        for(
            const key
            in data.headers
        ){

            headerHtml += `

                <div
                    class="header-item">

                    <strong>
                        ${key}
                    </strong>

                    ${
                        data.headers[key]
                        ?
                        " ✅ Present"
                        :
                        " ❌ Missing"
                    }

                </div>

            `;
        }

        document.getElementById(
            "headersSection"
        ).innerHTML =
            headerHtml;

        // VULNERABILITIES

        let vulnHtml = "";

        data.vulnerabilities.forEach(
            vuln => {

            vulnHtml += `

                <div
                    class="vuln-card">

                    <h3>
                        ${vuln.type}
                    </h3>

                    <p>
                        Severity:
                        ${vuln.severity}
                    </p>

                    <p>
                        ${vuln.description}
                    </p>

                </div>

            `;
        });

        if(
            data.vulnerabilities.length === 0
        ){

            vulnHtml =
            "No vulnerabilities detected";
        }

        document.getElementById(
            "vulnerabilitySection"
        ).innerHTML =
            vulnHtml;

        // RECOMMENDATIONS

        let recHtml = "";

        data.recommendations.forEach(
            rec => {

            recHtml += `

                <div
                    class="recommendation">

                    ${rec}

                </div>

            `;

        });

        if(
            data.recommendations.length === 0
        ){

            recHtml =
            "No recommendations";
        }

        document.getElementById(
            "recommendationSection"
        ).innerHTML =
            recHtml;

        // LOGS

        document.getElementById(
            "logs"
        ).innerHTML = `

            [+] Target Loaded<br>
            [+] Security Headers Checked<br>
            [+] Technology Fingerprinting Completed<br>
            [+] Port Scanning Completed<br>
            [+] XSS Testing Completed<br>
            [+] SQL Injection Testing Completed<br>
            [+] Attack Surface Calculated<br>
            [+] AI Assessment Generated<br>
            [✓] Scan Finished Successfully

        `;

    }
    catch(error){

        loading.classList.add(
            "hidden"
        );

        alert(error);
    }
}