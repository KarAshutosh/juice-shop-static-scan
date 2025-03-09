
// eslint-plugin-idor-detection/lib/rules/file-access.js
module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect potential IDOR vulnerabilities through direct file access by user input",
        category: "Security",
        recommended: true,
      },
      fixable: null,
      schema: [],
    },
    create(context) {
      return {
        CallExpression(node) {
          // Check if this is a file system method
          if (isFileAccessMethod(node)) {
            // Get the path argument
            const pathArg = node.arguments[0];
            
            // Check if the path contains user input
            if (isUserControlledPath(pathArg, context)) {
              // Check if there's no access control check
              if (!hasPathValidation(context.getAncestors())) {
                context.report({
                  node,
                  message: "Potential IDOR: Accessing files using user-controlled path without validation",
                });
              }
            }
          }
        }
      };
      
      // Helper functions
      function isFileAccessMethod(node) {
        if (!node.callee) return false;
        
        // Check for fs methods and path methods
        if (node.callee.type === 'MemberExpression') {
          const object = node.callee.object ? node.callee.object.name : '';
          const property = node.callee.property ? node.callee.property.name : '';
          
          return (object === 'fs' && ['readFile', 'createReadStream'].includes(property)) ||
                 (object === 'path' && ['join', 'resolve'].includes(property));
        }
        
        return false;
      }
      
      function isUserControlledPath(node, context) {
        if (!node) return false;
        
        const sourceCode = context.getSourceCode().getText(node);
        return /req\.params|req\.query|req\.body/.test(sourceCode);
      }
      
      function hasPathValidation(ancestors) {
        if (!ancestors || ancestors.length === 0) return false;
        
        // Look for validation functions or sanitization
        const code = ancestors.map(a => context.getSourceCode().getText(a)).join(' ');
        return /verifyAccess|validatePath|sanitizePath|isAuthorized/.test(code);
      }
    }
  };