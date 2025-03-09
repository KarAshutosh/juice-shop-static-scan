

// eslint-plugin-idor-detection/lib/rules/missing-object-authorization.js
module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect missing object-level authorization checks in API endpoints",
        category: "Security",
        recommended: true,
      },
      fixable: null,
      schema: [],
    },
    create(context) {
      return {
        CallExpression(node) {
          // Check for route definitions (app.get, router.get, etc)
          if (isModifyingRouteDefinition(node)) {
            // Check if there's a role check without an object ownership check
            if (hasRoleCheck(node, context) && !hasOwnershipCheck(node, context)) {
              context.report({
                node,
                message: "Potential IDOR: Role-based authorization without object-level ownership check",
              });
            }
          }
        }
      };
      
      // Helper functions
      function isModifyingRouteDefinition(node) {
        if (!node.callee || !node.callee.property) return false;
        
        const objectName = node.callee.object ? node.callee.object.name : '';
        const methodName = node.callee.property.name;
        
        return (objectName === 'app' || objectName === 'router') && 
               ['put', 'delete', 'patch'].includes(methodName);
      }
      
      function hasRoleCheck(node, context) {
        if (!node.arguments || node.arguments.length < 2) return false;
        
        // Check handler function for role-based checks
        const handlers = node.arguments.slice(1);
        
        for (const handler of handlers) {
          if (handler.type === 'FunctionExpression' || handler.type === 'ArrowFunctionExpression') {
            const code = context.getSourceCode().getText(handler);
            if (/req\.user\.role|user\.role|user\.isAdmin|req\.user\.admin/.test(code)) {
              return true;
            }
          }
        }
        
        return false;
      }
      
      function hasOwnershipCheck(node, context) {
        if (!node.arguments || node.arguments.length < 2) return false;
        
        // Check handler function for ownership checks
        const handlers = node.arguments.slice(1);
        
        for (const handler of handlers) {
          if (handler.type === 'FunctionExpression' || handler.type === 'ArrowFunctionExpression') {
            const code = context.getSourceCode().getText(handler);
            if (/createdBy\s*===\s*req\.user\.id|\.userId\s*===\s*req\.user\.id|\.user\s*===\s*req\.user|owner\s*===\s*req\.user/.test(code)) {
              return true;
            }
          }
        }
        
        return false;
      }
    }
  };
  