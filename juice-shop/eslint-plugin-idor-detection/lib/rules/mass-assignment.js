
// eslint-plugin-idor-detection/lib/rules/mass-assignment.js
module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect potential mass assignment vulnerabilities that can lead to IDOR",
        category: "Security",
        recommended: true,
      },
      fixable: null,
      schema: [],
    },
    create(context) {
      return {
        CallExpression(node) {
          // Check if this is a database create/update method
          if (isDatabaseWriteMethod(node)) {
            // Get the data argument being passed
            const dataArg = node.arguments[0];
            
            // Check if the data comes directly from request body
            if (isDirectRequestBody(dataArg, context)) {
              // Check if there's no data filtering or sanitization
              if (!hasDataFiltering(context.getAncestors())) {
                context.report({
                  node,
                  message: "Potential IDOR via mass assignment: Using request body directly in database operation without filtering",
                });
              }
            }
          }
        }
      };
      
      // Helper functions
      function isDatabaseWriteMethod(node) {
        if (!node.callee || !node.callee.property) return false;
        
        const methodName = node.callee.property.name;
        return ['create', 'update', 'save'].includes(methodName);
      }
      
      function isDirectRequestBody(node, context) {
        if (!node) return false;
        
        const code = context.getSourceCode().getText(node);
        return /req\.body/.test(code);
      }
      
      function hasDataFiltering(ancestors) {
        if (!ancestors || ancestors.length === 0) return false;
        
        // Look for data filtering patterns
        const code = ancestors.map(a => context.getSourceCode().getText(a)).join(' ');
        return /allowedFields|pick\(|sanitizeInput|filterProperties/.test(code);
      }
    }
  };
  