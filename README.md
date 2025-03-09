# Static Code Vulnerability Detection

A custom ESLint plugin for detecting mainly Insecure Direct Object Reference (IDOR) vulnerabilities in TypeScript/JavaScript applications. This example uses the OWASP Juice Shop application.

## Prerequisites

Before running this project, ensure you have the following installed on your system:

1. **Node.js**  
    - Download and install Node.js from [nodejs.org](https://nodejs.org/).  
    - Verify installation:  
        ```
        node -v
        ```

2. **npx (Node Package Executor)**  
    - Verify installation:  
        ```
        npx -v
        ```

## Installation

1. Clone the OWASP Juice Shop repository:
    ```
    git clone https://github.com/KarAshutosh/juice-shop-static-scan.git     
    ```

2. Change directory to `juice-shop`:
    ```
    cd juice-shop-static-scan
    cd juice-shop
    ```

3. Install dependencies:
    ```
    npm install
    ```

4. (Optional) Start the application:
    ```
    npm start
    ```

The application should now be running at `http://localhost:3000`.

## Using ESLint for Vulnerability Detection

To analyze the codebase for potential **Insecure Direct Object References (IDOR)** vulnerabilities:

1. Change directory if not in `juice-shop`:
    ```
    cd juice-shop
    ```

2. Run ESLint:
    ```
    npx eslint --ext .ts,.js routes/ -f json -o eslint-report.json
    ```

3. Parse the code into human readable format:
    ```
    cd .. 
    
    python3 eslint-report-parser.py
    ```

4. Review the output and inspect flagged code for potential IDOR vulnerabilities.

## Next Steps

- Modify `eslint-report.json` file to integrate with SonarQube (SAST) as an external issue report.

## Notes 

- If ESLint is not found or the command fails, install it globally: 
    ```
    npm install -g eslint
    ```
