

// eslint-plugin-idor-detection/lib/rules/predictable-ids.js
module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect API endpoints that use sequential or predictable resource identifiers",
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
          if (isRouteDefinition(node)) {
            // Check if the route uses numeric IDs
            const routePath = getRoutePath(node);
            
            if (routePath && hasPredictableIds(routePath)) {
              // Check if UUIDs or secure IDs are used
              if (!usesSecureIds(context.getAncestors())) {
                context.report({
                  node,
                  message: "Potential IDOR: API endpoint uses predictable resource IDs",
                });
              }
            }
          }
        }
      };
      
      // Helper functions
      function isRouteDefinition(node) {
        if (!node.callee || !node.callee.property) return false;
        
        const objectName = node.callee.object ? node.callee.object.name : '';
        const methodName = node.callee.property.name;
        
        return (objectName === 'app' || objectName === 'router') && 
               ['get', 'post', 'put', 'delete', 'patch'].includes(methodName);
      }
      
      function getRoutePath(node) {
        if (!node.arguments || node.arguments.length === 0) return null;
        
        // Route path is typically the first argument
        const pathArg = node.arguments[0];
        if (pathArg.type === 'Literal') {
          return pathArg.value;
        }
        
        return null;
      }
      
      function hasPredictableIds(path) {
        // Check if the path has :id or similar parameter
        return /\/\:id|\/:userId|\/:orderId/.test(path);
      }
      
      function usesSecureIds(ancestors) {
        if (!ancestors || ancestors.length === 0) return false;
        
        // Look for UUID usage throughout the function
        const code = ancestors.map(a => context.getSourceCode().getText(a)).join(' ');
        return /uuid|UUID|randomUUID|crypto\.randomBytes|uuidv4/.test(code);
      }
    }
  };
  
  