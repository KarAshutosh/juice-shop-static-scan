module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect endpoints that may be missing authentication checks",
        category: "Security",
        recommended: true
      },
      fixable: null,
      schema: []
    },
  
    create: function(context) {
      // Patterns that indicate authentication checks
      const authCheckPatterns = [
        "isAuthenticated",
        "verifyToken",
        "checkAuth",
        "requireAuth",
        "ensureAuthenticated",
        "authenticate",
        "verifyJwt",
        "authorization",
        "security.authentication"
      ];
  
      // Patterns of route definitions (commonly used in Express or similar frameworks)
      const routePatterns = [".get", ".post", ".put", ".delete", ".patch"];
      
      return {
        // Look for route definitions (e.g., app.get('/path', handler))
        CallExpression(node) {
          // Check if this is a route definition
          if (node.callee && 
              node.callee.type === "MemberExpression" && 
              routePatterns.some(pattern => context.getSourceCode().getText(node.callee).endsWith(pattern))) {
            
            // Route definition found, now check if any auth check exists in the route handler
            let hasAuthCheck = false;
            
            // For direct function definitions as route handlers
            if (node.arguments.length > 1) {
              // Check each argument that is a function (route handlers)
              node.arguments.forEach(arg => {
                if ((arg.type === "FunctionExpression" || arg.type === "ArrowFunctionExpression") && 
                    arg.body && arg.body.type === "BlockStatement") {
                  
                  // Check function body for auth checks
                  const functionBody = context.getSourceCode().getText(arg.body);
                  hasAuthCheck = authCheckPatterns.some(pattern => functionBody.includes(pattern));
                }
              });
            }
            
            // For named middleware or controller functions referenced in route
            if (node.arguments.length > 1) {
              // Check if any argument is an identifier that might be an auth middleware
              hasAuthCheck = hasAuthCheck || node.arguments.some(arg => {
                if (arg.type === "Identifier") {
                  const name = arg.name;
                  return authCheckPatterns.some(pattern => name.includes(pattern));
                }
                return false;
              });
            }
            
            // Report if no auth check is found
            if (!hasAuthCheck) {
              context.report({
                node,
                message: "Route handler may be missing authentication checks, potentially leading to IDOR vulnerability"
              });
            }
          }
        }
      };
    }
  };