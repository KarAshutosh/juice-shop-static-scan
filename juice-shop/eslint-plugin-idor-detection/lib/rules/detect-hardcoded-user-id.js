module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect hardcoded user IDs which could indicate IDOR vulnerabilities",
        category: "Security",
        recommended: true
      },
      fixable: null,
      schema: []
    },
  
    create: function(context) {
      // Patterns that might indicate a hardcoded ID
      const suspiciousPatterns = [
        /\b(user|account|profile|document)(Id|_id)\s*[=:]\s*(['"`]\d+['"`]|\d+)/i,
        /\b(user|account|profile|document)(Id|_id)\s*[=:]\s*['"`][0-9a-fA-F-]{8,}['"`]/i,
        /\b(user|account|profile|document)(Id|_id)\s*[=:]\s*(['"`]admin['"`]|['"`]root['"`])/i
      ];
  
      function checkForHardcodedIds(node) {
        const nodeText = context.getSourceCode().getText(node);
        
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(nodeText) && 
              !nodeText.includes("currentUser") && 
              !nodeText.includes("getLoggedInUser")) {
            context.report({
              node,
              message: "Potential IDOR vulnerability: Hardcoded user ID detected"
            });
            break;
          }
        }
      }
  
      return {
        // Check for hardcoded IDs in variables
        VariableDeclarator(node) {
          checkForHardcodedIds(node);
        },
        // Check for hardcoded IDs in assignments
        AssignmentExpression(node) {
          checkForHardcodedIds(node);
        },
        // Check for hardcoded IDs in object expressions
        Property(node) {
          checkForHardcodedIds(node);
        },
        // Check for hardcoded IDs in function arguments
        CallExpression(node) {
          checkForHardcodedIds(node);
        }
      };
    }
  };