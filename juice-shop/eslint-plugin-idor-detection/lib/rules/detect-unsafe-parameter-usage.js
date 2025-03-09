module.exports = {
    meta: {
      type: "suggestion",
      docs: {
        description: "Detect unsafe use of user-provided parameters that could lead to IDOR",
        category: "Security",
        recommended: true
      },
      fixable: null,
      schema: []
    },
  
    create: function(context) {
      // Database operation patterns that might be vulnerable to IDOR
      const dbOperationPatterns = [
        "findById",
        "findOne",
        "findByPk",
        "getById",
        "deleteById",
        "updateById",
        "where",
        "query"
      ];
      
      // Risk parameters that often lead to IDOR
      const riskParamPatterns = [
        "id",
        "userId",
        "accountId",
        "documentId",
        "recordId",
        "profileId"
      ];
  
      // Functions to check for unsafe object property access
      function isRequestParameter(node) {
        if (!node) return false;
        if (node.type !== "MemberExpression") return false;
        
        const objText = context.getSourceCode().getText(node.object);
        return objText.includes("req.") || 
               objText.includes("request.") ||
               objText.includes("params.") || 
               objText.includes("query.") || 
               objText.includes("body.");
      }
  
      function isUnsafeDbOperation(node) {
        if (!node || !node.callee) return false;
        
        const calleeText = context.getSourceCode().getText(node.callee);
        return dbOperationPatterns.some(pattern => calleeText.includes(pattern));
      }
  
      function containsRiskParameter(node) {
        if (!node) return false;
        
        const nodeText = context.getSourceCode().getText(node);
        return riskParamPatterns.some(pattern => 
          new RegExp(`\\b${pattern}\\b`, "i").test(nodeText)
        );
      }
  
      return {
        // Check for database operations with user-supplied parameters
        CallExpression(node) {
          // Is this a database operation?
          if (isUnsafeDbOperation(node)) {
            // Check if any argument is from request parameters
            node.arguments.forEach(arg => {
              if ((isRequestParameter(arg) || containsRiskParameter(arg)) && 
                  !context.getSourceCode().getText(node).includes("verifyOwnership")) {
                context.report({
                  node,
                  message: "Potential IDOR: User-provided parameter used in database operation without ownership verification"
                });
              }
            });
          }
        },
        
        // Check for direct object lookups with user input
        MemberExpression(node) {
          // Is this accessing an object with a computed property from user input?
          if (node.computed && 
              isRequestParameter(node.property) && 
              containsRiskParameter(node)) {
            context.report({
              node,
              message: "Potential IDOR: User-provided parameter used for direct object reference without verification"
            });
          }
        }
      };
    }
  };