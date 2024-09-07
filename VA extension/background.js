chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.log) {
        chrome.scripting.executeScript({
            target: { tabId: sender.tab.id },
            func: logToConsole,
            args: [message.log]
        });
    }
});

function logToConsole(log) {
    console.log(log);
}
