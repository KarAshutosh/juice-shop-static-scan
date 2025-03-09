

// eslint-plugin-idor-detection/lib/rules/graphql-resolver.js
module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect potential IDOR vulnerabilities in GraphQL resolvers without access control",
        category: "Security",
        recommended: true,
      },
      fixable: null,
      schema: [],
    },
    create(context) {
      return {
        ObjectExpression(node) {
          // Check if we're in a GraphQL resolver object
          if (isGraphQLResolver(node, context)) {
            // Check resolver functions for IDOR vulnerabilities
            const resolverFunctions = getResolverFunctions(node);
            
            resolverFunctions.forEach(func => {
              if (hasDbQuery(func, context) && !hasAccessCheck(func, context)) {
                context.report({
                  node: func,
                  message: "Potential IDOR in GraphQL resolver: Database query without access control checks",
                });
              }
            });
          }
        }
      };
      
      // Helper functions
      function isGraphQLResolver(node, context) {
        const code = context.getSourceCode().getText(node);
        return /resolvers|Resolvers|Query:|Mutation:|type:/.test(code);
      }
      
      function getResolverFunctions(node) {
        const functions = [];
        
        if (node.properties) {
          node.properties.forEach(prop => {
            if (prop.value && prop.value.type === 'ArrowFunctionExpression' || prop.value.type === 'FunctionExpression') {
              functions.push(prop.value);
            } else if (prop.value && prop.value.type === 'ObjectExpression') {
              // Handle nested resolver objects
              functions.push(...getResolverFunctions(prop.value));
            }
          });
        }
        
        return functions;
      }
      
      function hasDbQuery(node, context) {
        const code = context.getSourceCode().getText(node);
        return /findById|getById|findOne|\.find\(|\.get\(/.test(code);
      }
      
      function hasAccessCheck(node, context) {
        const code = context.getSourceCode().getText(node);
        return /context\.user|isAuthorized|checkPermission|!context\.user|throw.+Not authorized/.test(code);
      }
    }
  };
  