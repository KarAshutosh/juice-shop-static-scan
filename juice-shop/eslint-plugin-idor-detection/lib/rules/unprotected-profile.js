
// eslint-plugin-idor-detection/lib/rules/unprotected-profile.js
module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect unprotected profile endpoints without authentication checks",
        category: "Security",
        recommended: true,
      },
      fixable: null,
      schema: [],
    },
    create(context) {
      return {
        CallExpression(node) {
          // Check for route definitions that match profile endpoints
          if (isProfileRouteDefinition(node)) {
            // Check if authentication middleware is missing
            if (!hasAuthenticationMiddleware(node, context)) {
              context.report({
                node,
                message: "Potential IDOR: Profile endpoint without authentication middleware",
              });
            }
          }
        }
      };
      
      // Helper functions
      function isProfileRouteDefinition(node) {
        if (!node.callee || !node.callee.property) return false;
        
        const objectName = node.callee.object ? node.callee.object.name : '';
        const methodName = node.callee.property.name;
        
        if ((objectName === 'app' || objectName === 'router') && 
            ['get', 'post', 'put'].includes(methodName)) {
          
          // Check if path matches profile patterns
          if (node.arguments && node.arguments.length > 0) {
            const pathArg = node.arguments[0];
            if (pathArg.type === 'Literal') {
              const path = pathArg.value;
              return /\/me|\/profile|\/account|\/user\/current/.test(path);
            }
          }
        }
        
        return false;
      }
      
      function hasAuthenticationMiddleware(node, context) {
        if (!node.arguments || node.arguments.length < 2) return false;
        
        // Check for auth middleware in the route handler arguments
        const middlewares = node.arguments.slice(1, -1); // Exclude the last argument (handler)
        
        // Check if there's any authentication middleware
        for (const middleware of middlewares) {
          const code = context.getSourceCode().getText(middleware);
          if (/authenticate|isAuthenticated|requireAuth|jwt\.verify|passport\.authenticate/.test(code)) {
            return true;
          }
        }
        
        // Also check if auth middleware is used in the function body
        const handler = node.arguments[node.arguments.length - 1];
        if (handler && (handler.type === 'FunctionExpression' || handler.type === 'ArrowFunctionExpression')) {
          const code = context.getSourceCode().getText(handler);
          return /req\.isAuthenticated\(\)|req\.user|jwt\.verify|authenticate/.test(code);
        }
        
        return false;
      }
    }
  };