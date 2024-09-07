// Fungsi untuk menampilkan log di UI
function logToUI(message) {
    let logDiv = document.getElementById('log');
    let logEntry = document.createElement('p');
    logEntry.textContent = message;
    logDiv.appendChild(logEntry);
}

document.getElementById('scanBtn').addEventListener('click', () => {
    logToUI("Scan started...");

    // Eksekusi content script di tab saat ini
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            files: ['content.js']
        });
    });
});

chrome.runtime.onMessage.addListener((message) => {
    let result = document.getElementById('scan-result');
    let xssResult = '<p>XSS Vulnerable: No</p>';
    let sqliResult = '<p>SQL Injection Vulnerable: No</p>';
    
    if (message.xss.length > 0) {
        xssResult = `<p>XSS Vulnerable: Yes</p><ul>`;
        message.xss.forEach(url => {
            xssResult += `<li>${url}</li>`;
        });
        xssResult += `</ul>`;
        logToUI("XSS vulnerabilities found.");
    } else {
        logToUI("No XSS vulnerabilities found.");
    }
    
    if (message.sqli.length > 0) {
        sqliResult = `<p>SQL Injection Vulnerable: Yes</p><ul>`;
        message.sqli.forEach(url => {
            sqliResult += `<li>${url}</li>`;
        });
        sqliResult += `</ul>`;
        logToUI("SQL Injection vulnerabilities found.");
    } else {
        logToUI("No SQL Injection vulnerabilities found.");
    }
    
    result.innerHTML = xssResult + sqliResult;
    logToUI("Scan completed.");
});
