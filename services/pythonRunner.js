const { exec } = require('child_process');
const path = require('path');

/**
 * Runs a python script and returns the parsed JSON result.
 * @param {string} scriptName - Name of the script in python_modules
 * @param {string} domain - Target domain to scan
 * @returns {Promise<Object>}
 */
const runPythonScript = (scriptName, domain) => {
    return new Promise((resolve, reject) => {
        const scriptPath = path.join(__dirname, '..', 'python_modules', scriptName);
        
        // Execute the python script with the domain as an argument
        exec(`python ${scriptPath} ${domain}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`[Error running ${scriptName}]:`, stderr);
                return resolve({ error: `Failed to execute ${scriptName}` });
            }
            
            try {
                // Parse stdout output as JSON
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (err) {
                console.error(`[Error parsing output from ${scriptName}]:`, err.message);
                console.error(`Raw output: ${stdout}`);
                resolve({ error: `Invalid JSON output from ${scriptName}` });
            }
        });
    });
};

module.exports = { runPythonScript };
